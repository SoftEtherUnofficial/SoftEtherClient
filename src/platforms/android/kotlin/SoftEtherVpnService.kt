/**
 * SoftEther VPN Service - Android VpnService Implementation
 * 
 * Android VpnService that integrates with unified mobile VPN FFI
 * Implements packet I/O between VPN tunnel and system VpnInterface
 * 
 * Package: com.softether.vpn
 */

package com.softether.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * SoftEther VPN Service
 * 
 * Manages VPN connection lifecycle and packet I/O
 */
class SoftEtherVpnService : VpnService() {
    
    companion object {
        private const val TAG = "SoftEtherVpnService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "softether_vpn_channel"
        private const val MTU = 1500
        private const val PACKET_BUFFER_SIZE = 2048
        
        // Service actions
        const val ACTION_CONNECT = "com.softether.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.softether.vpn.DISCONNECT"
        
        // Intent extras
        const val EXTRA_SERVER = "server"
        const val EXTRA_PORT = "port"
        const val EXTRA_HUB = "hub"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD_HASH = "password_hash"
        const val EXTRA_USE_ENCRYPT = "use_encrypt"
        const val EXTRA_USE_COMPRESS = "use_compress"
    }
    
    private var vpnClient: MobileVpnClient? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    
    private var readThread: Thread? = null
    private var writeThread: Thread? = null
    private var statsThread: Thread? = null
    
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "VPN Service created")
        Log.i(TAG, "Library version: ${MobileVpnClient.getVersion()}")
        Log.i(TAG, "Build info: ${MobileVpnClient.getBuildInfo()}")
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null) {
            Log.w(TAG, "Null intent received")
            return START_NOT_STICKY
        }
        
        when (intent.action) {
            ACTION_CONNECT -> {
                val config = extractConfig(intent)
                if (config != null) {
                    startVpn(config)
                } else {
                    Log.e(TAG, "Invalid VPN configuration")
                    stopSelf()
                }
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
            else -> {
                Log.w(TAG, "Unknown action: ${intent.action}")
            }
        }
        
        return START_STICKY
    }
    
    override fun onDestroy() {
        Log.i(TAG, "VPN Service destroyed")
        stopVpn()
        super.onDestroy()
    }
    
    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked")
        stopVpn()
        super.onRevoke()
    }
    
    // =========================================================================
    // VPN Lifecycle
    // =========================================================================
    
    private fun startVpn(config: VpnConfig) {
        if (isRunning.get()) {
            Log.w(TAG, "VPN already running")
            return
        }
        
        Log.i(TAG, "Starting VPN: server=${config.server}:${config.port} hub=${config.hub}")
        
        // Create VPN client
        val client = MobileVpnClient(config)
        if (!client.initialize()) {
            Log.e(TAG, "Failed to initialize VPN client")
            stopSelf()
            return
        }
        vpnClient = client
        
        // Connect to VPN server
        if (!client.connect()) {
            Log.e(TAG, "Failed to connect to VPN: ${client.getError()}")
            client.close()
            vpnClient = null
            stopSelf()
            return
        }
        
        // Wait for connection to establish (with timeout)
        var attempts = 0
        while (!client.isConnected() && attempts < 50) {
            Thread.sleep(100)
            attempts++
        }
        
        if (!client.isConnected()) {
            Log.e(TAG, "Connection timeout")
            client.disconnect()
            client.close()
            vpnClient = null
            stopSelf()
            return
        }
        
        Log.i(TAG, "VPN connected successfully")
        
        // Get network info from DHCP
        val networkInfo = client.getNetworkInfo()
        if (networkInfo == null) {
            Log.e(TAG, "Failed to get network info")
            client.disconnect()
            client.close()
            vpnClient = null
            stopSelf()
            return
        }
        
        Log.i(TAG, networkInfo.toLogString())
        
        // Configure VPN interface
        if (!configureVpnInterface(networkInfo)) {
            Log.e(TAG, "Failed to configure VPN interface")
            client.disconnect()
            client.close()
            vpnClient = null
            stopSelf()
            return
        }
        
        // Start foreground notification
        startForeground(NOTIFICATION_ID, createNotification("Connected to ${config.server}"))
        
        // Start packet I/O threads
        isRunning.set(true)
        startPacketThreads()
        
        Log.i(TAG, "VPN service fully operational")
    }
    
    private fun stopVpn() {
        if (!isRunning.getAndSet(false)) {
            return
        }
        
        Log.i(TAG, "Stopping VPN")
        
        // Stop packet threads
        stopPacketThreads()
        
        // Disconnect VPN client
        vpnClient?.let { client ->
            client.disconnect()
            client.close()
        }
        vpnClient = null
        
        // Close VPN interface
        vpnInterface?.close()
        vpnInterface = null
        
        inputStream?.close()
        inputStream = null
        outputStream?.close()
        outputStream = null
        
        stopForeground(true)
        stopSelf()
        
        Log.i(TAG, "VPN stopped")
    }
    
    // =========================================================================
    // VPN Interface Configuration
    // =========================================================================
    
    private fun configureVpnInterface(networkInfo: NetworkInfo): Boolean {
        try {
            val builder = Builder()
                .setSession("SoftEther VPN")
                .setMtu(networkInfo.mtu)
                .addAddress(networkInfo.ipAddress, 24)
                .addRoute("0.0.0.0", 0)  // Route all traffic
            
            // Add DNS servers
            networkInfo.dnsServers.forEach { dns ->
                if (dns.isNotEmpty()) {
                    builder.addDnsServer(dns)
                }
            }
            
            // Establish VPN interface
            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                return false
            }
            
            // Get I/O streams
            inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            
            Log.i(TAG, "VPN interface configured successfully")
            return true
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to configure VPN interface", e)
            return false
        }
    }
    
    // =========================================================================
    // Packet I/O Threads
    // =========================================================================
    
    private fun startPacketThreads() {
        // Thread 1: Read from VPN, write to TUN
        readThread = thread(name = "VPN-Read") {
            readFromVpn()
        }
        
        // Thread 2: Read from TUN, write to VPN
        writeThread = thread(name = "VPN-Write") {
            readFromTun()
        }
        
        // Thread 3: Log stats periodically
        statsThread = thread(name = "VPN-Stats") {
            logStats()
        }
        
        Log.i(TAG, "Packet I/O threads started")
    }
    
    private fun stopPacketThreads() {
        Log.i(TAG, "Stopping packet I/O threads")
        
        readThread?.interrupt()
        writeThread?.interrupt()
        statsThread?.interrupt()
        
        try {
            readThread?.join(2000)
            writeThread?.join(2000)
            statsThread?.join(2000)
        } catch (e: InterruptedException) {
            Log.w(TAG, "Thread join interrupted", e)
        }
        
        readThread = null
        writeThread = null
        statsThread = null
    }
    
    /**
     * Read packets from VPN, write to TUN interface
     */
    private fun readFromVpn() {
        val buffer = ByteArray(PACKET_BUFFER_SIZE)
        var packetsProcessed = 0
        
        Log.i(TAG, "VPN read thread started")
        
        while (isRunning.get()) {
            try {
                val client = vpnClient ?: break
                val output = outputStream ?: break
                
                // Read packet from VPN (100ms timeout)
                val length = client.readPacket(buffer, timeoutMs = 100)
                
                if (length > 0) {
                    // Write to TUN interface
                    output.write(buffer, 0, length)
                    packetsProcessed++
                    
                    if (packetsProcessed % 1000 == 0) {
                        Log.d(TAG, "Processed $packetsProcessed packets from VPN")
                    }
                } else if (length < 0) {
                    Log.e(TAG, "Error reading packet from VPN: $length")
                    break
                }
                // length == 0: timeout, continue
                
            } catch (e: IOException) {
                if (isRunning.get()) {
                    Log.e(TAG, "I/O error writing to TUN", e)
                    break
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e(TAG, "Unexpected error in read thread", e)
                    break
                }
            }
        }
        
        Log.i(TAG, "VPN read thread stopped (processed $packetsProcessed packets)")
    }
    
    /**
     * Read packets from TUN interface, write to VPN
     */
    private fun readFromTun() {
        val buffer = ByteArray(PACKET_BUFFER_SIZE)
        var packetsProcessed = 0
        
        Log.i(TAG, "TUN read thread started")
        
        while (isRunning.get()) {
            try {
                val client = vpnClient ?: break
                val input = inputStream ?: break
                
                // Read packet from TUN interface
                val length = input.read(buffer)
                
                if (length > 0) {
                    // Write to VPN
                    val result = client.writePacket(buffer, length)
                    if (result == 0) {
                        packetsProcessed++
                        
                        if (packetsProcessed % 1000 == 0) {
                            Log.d(TAG, "Processed $packetsProcessed packets to VPN")
                        }
                    } else {
                        Log.e(TAG, "Error writing packet to VPN: $result")
                        break
                    }
                } else if (length < 0) {
                    Log.e(TAG, "Error reading from TUN: $length")
                    break
                }
                
            } catch (e: IOException) {
                if (isRunning.get()) {
                    Log.e(TAG, "I/O error reading from TUN", e)
                    break
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e(TAG, "Unexpected error in write thread", e)
                    break
                }
            }
        }
        
        Log.i(TAG, "TUN read thread stopped (processed $packetsProcessed packets)")
    }
    
    /**
     * Log connection stats periodically
     */
    private fun logStats() {
        Log.i(TAG, "Stats thread started")
        
        while (isRunning.get()) {
            try {
                Thread.sleep(10000)  // Every 10 seconds
                
                val client = vpnClient ?: break
                val stats = client.getStats()
                
                if (stats != null) {
                    Log.i(TAG, stats.toLogString())
                }
                
            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                Log.e(TAG, "Error in stats thread", e)
            }
        }
        
        Log.i(TAG, "Stats thread stopped")
    }
    
    // =========================================================================
    // Notification
    // =========================================================================
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SoftEther VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "SoftEther VPN connection status"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager?.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(message: String): Notification {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SoftEther VPN")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }
    
    // =========================================================================
    // Helpers
    // =========================================================================
    
    private fun extractConfig(intent: Intent): VpnConfig? {
        val server = intent.getStringExtra(EXTRA_SERVER) ?: return null
        val port = intent.getIntExtra(EXTRA_PORT, 443)
        val hub = intent.getStringExtra(EXTRA_HUB) ?: return null
        val username = intent.getStringExtra(EXTRA_USERNAME) ?: return null
        val passwordHash = intent.getStringExtra(EXTRA_PASSWORD_HASH) ?: return null
        val useEncrypt = intent.getBooleanExtra(EXTRA_USE_ENCRYPT, true)
        val useCompress = intent.getBooleanExtra(EXTRA_USE_COMPRESS, false)
        
        return VpnConfig(server, port, hub, username, passwordHash, useEncrypt, useCompress)
    }
}
