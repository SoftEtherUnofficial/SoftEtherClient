/**
 * SoftEther VPN - Kotlin Wrapper
 * 
 * Kotlin interface to unified mobile VPN FFI via JNI
 * Thread-safe wrapper with lifecycle management
 * 
 * Package: com.softether.vpn
 */

package com.softether.vpn

import android.util.Log
import java.io.Closeable

/**
 * VPN Configuration
 */
data class VpnConfig(
    val server: String,
    val port: Int,
    val hub: String,
    val username: String,
    val passwordHash: String,
    val useEncrypt: Boolean = true,
    val useCompress: Boolean = false
)

/**
 * VPN Statistics
 */
data class VpnStats(
    val bytesSent: Long,
    val bytesReceived: Long,
    val packetsSent: Long,
    val packetsReceived: Long,
    val connectedDurationMs: Long,
    val queueDrops: Long,
    val errors: Long
)

/**
 * Network Information (from DHCP)
 */
data class NetworkInfo(
    val ipAddress: String,
    val gateway: String,
    val netmask: String,
    val dnsServers: Array<String>,
    val mtu: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as NetworkInfo
        if (!dnsServers.contentEquals(other.dnsServers)) return false
        return ipAddress == other.ipAddress && gateway == other.gateway && netmask == other.netmask && mtu == other.mtu
    }

    override fun hashCode(): Int {
        var result = ipAddress.hashCode()
        result = 31 * result + gateway.hashCode()
        result = 31 * result + netmask.hashCode()
        result = 31 * result + dnsServers.contentHashCode()
        result = 31 * result + mtu
        return result
    }
}

/**
 * VPN Status
 */
enum class VpnStatus(val value: Int) {
    IDLE(0),
    CONNECTING(1),
    CONNECTED(2),
    DISCONNECTING(3),
    ERROR(4);
    
    companion object {
        fun fromInt(value: Int) = values().find { it.value == value } ?: ERROR
    }
}

/**
 * Mobile VPN Client - Kotlin Wrapper
 * 
 * Thread-safe wrapper around unified FFI
 * Manages native handle lifecycle
 */
class MobileVpnClient(private val config: VpnConfig) : Closeable {
    
    companion object {
        private const val TAG = "MobileVpnClient"
        
        init {
            System.loadLibrary("softether")
            init()
        }
        
        // Native methods
        @JvmStatic private external fun init(): Int
        @JvmStatic private external fun cleanup()
        @JvmStatic external fun getVersion(): String
        @JvmStatic external fun getBuildInfo(): String
    }
    
    // Native handle (0 = invalid)
    @Volatile private var handle: Long = 0
    private val lock = Any()
    
    /**
     * Initialize VPN client
     * @return true if successful, false otherwise
     */
    fun initialize(): Boolean = synchronized(lock) {
        if (handle != 0L) {
            Log.w(TAG, "Already initialized")
            return true
        }
        
        handle = create(config)
        if (handle == 0L) {
            Log.e(TAG, "Failed to create VPN handle")
            return false
        }
        
        Log.i(TAG, "VPN client initialized: handle=$handle")
        return true
    }
    
    /**
     * Connect to VPN server
     * @return true if connection initiated successfully
     */
    fun connect(): Boolean = synchronized(lock) {
        if (handle == 0L) {
            Log.e(TAG, "Not initialized")
            return false
        }
        
        val result = connect(handle)
        if (result != 0) {
            Log.e(TAG, "Connection failed: ${getError()}")
            return false
        }
        
        Log.i(TAG, "VPN connection initiated")
        return true
    }
    
    /**
     * Disconnect from VPN server
     */
    fun disconnect() = synchronized(lock) {
        if (handle == 0L) {
            Log.w(TAG, "Not initialized")
            return
        }
        
        val result = disconnect(handle)
        if (result != 0) {
            Log.w(TAG, "Disconnect returned error: $result")
        }
        
        Log.i(TAG, "VPN disconnected")
    }
    
    /**
     * Check if connected
     */
    fun isConnected(): Boolean = synchronized(lock) {
        if (handle == 0L) return false
        return isConnected(handle)
    }
    
    /**
     * Get current status
     */
    fun getStatus(): VpnStatus = synchronized(lock) {
        if (handle == 0L) return VpnStatus.IDLE
        return VpnStatus.fromInt(getStatus(handle))
    }
    
    /**
     * Get connection statistics
     * @return VpnStats or null if unavailable
     */
    fun getStats(): VpnStats? = synchronized(lock) {
        if (handle == 0L) return null
        return getStats(handle)
    }
    
    /**
     * Get network information (DHCP-assigned)
     * @return NetworkInfo or null if unavailable
     */
    fun getNetworkInfo(): NetworkInfo? = synchronized(lock) {
        if (handle == 0L) return null
        return getNetworkInfo(handle)
    }
    
    /**
     * Read packet from VPN
     * @param buffer Buffer to read into
     * @param timeoutMs Timeout in milliseconds (default 100ms)
     * @return Number of bytes read, 0 if no packet, negative on error
     */
    fun readPacket(buffer: ByteArray, timeoutMs: Int = 100): Int = synchronized(lock) {
        if (handle == 0L) return -1
        return readPacket(handle, buffer, timeoutMs)
    }
    
    /**
     * Write packet to VPN
     * @param data Packet data
     * @param length Length of packet
     * @return 0 on success, negative on error
     */
    fun writePacket(data: ByteArray, length: Int): Int = synchronized(lock) {
        if (handle == 0L) return -1
        return writePacket(handle, data, length)
    }
    
    /**
     * Get last error message
     */
    fun getError(): String = synchronized(lock) {
        if (handle == 0L) return "Not initialized"
        return getError(handle)
    }
    
    /**
     * Clean up resources
     */
    override fun close() = synchronized(lock) {
        if (handle == 0L) return
        
        Log.i(TAG, "Destroying VPN handle: $handle")
        destroy(handle)
        handle = 0
    }
    
    // JNI native methods
    private external fun create(config: VpnConfig): Long
    private external fun destroy(handle: Long)
    private external fun connect(handle: Long): Int
    private external fun disconnect(handle: Long): Int
    private external fun getStatus(handle: Long): Int
    private external fun isConnected(handle: Long): Boolean
    private external fun getStats(handle: Long): VpnStats?
    private external fun getNetworkInfo(handle: Long): NetworkInfo?
    private external fun readPacket(handle: Long, buffer: ByteArray, timeout: Int): Int
    private external fun writePacket(handle: Long, data: ByteArray, length: Int): Int
    private external fun getError(handle: Long): String
}

/**
 * Extension functions for convenience
 */
fun VpnStats.toLogString(): String =
    "Stats: TX=${bytesSent}B RX=${bytesReceived}B TX_PKT=${packetsSent} RX_PKT=${packetsReceived} " +
    "Duration=${connectedDurationMs}ms Drops=${queueDrops} Errors=${errors}"

fun NetworkInfo.toLogString(): String =
    "Network: IP=${ipAddress} GW=${gateway} Mask=${netmask} DNS=[${dnsServers.joinToString(", ")}] MTU=${mtu}"
