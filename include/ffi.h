/**
 * SoftEtherZig - FFI (Foreign Function Interface)
 * 
 * Platform-agnostic C API for mobile (iOS/Android) and desktop platforms
 * 
 * This header can be used from Swift, Objective-C, Kotlin, Java, Python, Rust, and other languages
 */

#ifndef SOFTETHER_FFI_H
#define SOFTETHER_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Types
// ============================================================================

/// Opaque VPN connection handle
typedef void* MobileVpnHandle;

/// Platform-agnostic VPN configuration
typedef struct {
    // Connection parameters
    const char* server;
    uint16_t port;
    const char* hub;
    const char* username;
    const char* password_hash;
    
    // Connection options
    bool use_encrypt;
    bool use_compress;
    bool half_connection;
    uint8_t max_connection;
    
    // Performance tuning
    uint64_t recv_queue_size;
    uint64_t send_queue_size;
    uint64_t packet_pool_size;
    uint64_t batch_size;
    
    // Reserved for future use
    uint8_t _reserved[16];
} MobileVpnConfig;

/// VPN connection status
typedef enum {
    MOBILE_VPN_DISCONNECTED = 0,
    MOBILE_VPN_CONNECTING = 1,
    MOBILE_VPN_CONNECTED = 2,
    MOBILE_VPN_RECONNECTING = 3,
    MOBILE_VPN_ERROR = 4,
} MobileVpnStatus;

/// VPN statistics
typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t connected_duration_ms;
    uint64_t queue_drops;
    uint64_t errors;
} MobileVpnStats;

/// Network configuration info (obtained from DHCP)
typedef struct {
    uint8_t ip_address[4];      // IPv4 address
    uint8_t gateway[4];          // Gateway IP
    uint8_t netmask[4];          // Subnet mask
    uint8_t dns_servers[4][4];   // Up to 4 DNS servers
    uint16_t mtu;
    uint8_t _reserved[32];
} MobileNetworkInfo;

/// Status callback function type
typedef void (*MobileStatusCallback)(MobileVpnStatus status, void* user_data);

/// Stats callback function type
typedef void (*MobileStatsCallback)(const MobileVpnStats* stats, void* user_data);

/// Network info callback function type
typedef void (*MobileNetworkCallback)(const MobileNetworkInfo* info, void* user_data);

// ============================================================================
// Core API
// ============================================================================

/**
 * Initialize mobile VPN library
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_init(void);

/**
 * Create VPN connection handle
 * @param config Connection configuration
 * @return Handle on success, NULL on failure
 */
MobileVpnHandle mobile_vpn_create(const MobileVpnConfig* config);

/**
 * Free VPN connection handle
 * @param handle VPN handle to destroy
 */
void mobile_vpn_destroy(MobileVpnHandle handle);

/**
 * Connect to VPN server
 * @param handle VPN handle
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_connect(MobileVpnHandle handle);

/**
 * Disconnect from VPN server
 * @param handle VPN handle
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_disconnect(MobileVpnHandle handle);

/**
 * Get current VPN status
 * @param handle VPN handle
 * @return Current status
 */
MobileVpnStatus mobile_vpn_get_status(MobileVpnHandle handle);

/**
 * Get VPN statistics
 * @param handle VPN handle
 * @param out_stats Pointer to stats structure to fill
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_get_stats(MobileVpnHandle handle, MobileVpnStats* out_stats);

/**
 * Read packet from VPN (to write to TUN device)
 * @param handle VPN handle
 * @param buffer Buffer to receive packet data
 * @param buffer_len Size of buffer in bytes
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return Number of bytes read, 0 if no packet available, negative on error
 */
int mobile_vpn_read_packet(MobileVpnHandle handle, uint8_t* buffer, uint64_t buffer_len, uint32_t timeout_ms);

/**
 * Write packet to VPN (from TUN device)
 * @param handle VPN handle
 * @param data Packet data to write
 * @param data_len Length of packet data in bytes
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_write_packet(MobileVpnHandle handle, const uint8_t* data, uint64_t data_len);

// ============================================================================
// Batch Packet Operations (High Performance)
// ============================================================================

/// Packet buffer for batch operations (zero-copy friendly)
typedef struct {
    uint8_t* data;      // Pointer to packet data
    uint32_t length;    // Packet length in bytes
    uint8_t protocol;   // 4=IPv4, 6=IPv6
    uint8_t _padding[3];
} MobilePacketBuffer;

/**
 * Read multiple packets from VPN in one FFI call (OPTIMIZED)
 * This reduces FFI overhead by 32-128x compared to per-packet calls
 * 
 * @param handle VPN handle
 * @param packets Array of packet buffers (pre-allocated by caller)
 * @param max_packets Maximum number of packets to read (array size)
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return Number of packets read (0 to max_packets), negative on error
 * 
 * Example usage:
 *   MobilePacketBuffer packets[128];
 *   // Pre-allocate data buffers for each packet
 *   for (int i = 0; i < 128; i++) {
 *       packets[i].data = malloc(2048);
 *   }
 *   int count = mobile_vpn_read_packets_batch(handle, packets, 128, 10);
 *   for (int i = 0; i < count; i++) {
 *       // Process packets[i]
 *   }
 */
int mobile_vpn_read_packets_batch(MobileVpnHandle handle, MobilePacketBuffer* packets, uint32_t max_packets, uint32_t timeout_ms);

/**
 * Write multiple packets to VPN in one FFI call (OPTIMIZED)
 * This reduces FFI overhead by 32-128x compared to per-packet calls
 * 
 * @param handle VPN handle
 * @param packets Array of packet buffers to write
 * @param num_packets Number of packets in array
 * @return 0 on success, negative error code on failure
 * 
 * Example usage:
 *   MobilePacketBuffer packets[32];
 *   // Fill packet buffers
 *   int result = mobile_vpn_write_packets_batch(handle, packets, 32);
 */
int mobile_vpn_write_packets_batch(MobileVpnHandle handle, const MobilePacketBuffer* packets, uint32_t num_packets);

/**
 * Get network configuration (after DHCP completes)
 * @param handle VPN handle
 * @param out_info Pointer to network info structure to fill
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_get_network_info(MobileVpnHandle handle, MobileNetworkInfo* out_info);

/**
 * Set network configuration (called by platform after DHCP)
 * Platform layer (iOS/Android) handles DHCP and calls this to store the result
 * @param handle VPN handle
 * @param info Pointer to network info structure with DHCP results
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_set_network_info(MobileVpnHandle handle, const MobileNetworkInfo* info);

// ============================================================================
// Callbacks
// ============================================================================

/**
 * Set status callback
 * Called when connection status changes
 * @param handle VPN handle
 * @param callback Callback function
 * @param user_data User data passed to callback
 */
void mobile_vpn_set_status_callback(MobileVpnHandle handle, MobileStatusCallback callback, void* user_data);

/**
 * Set statistics callback
 * Called periodically with updated statistics
 * @param handle VPN handle
 * @param callback Callback function
 * @param user_data User data passed to callback
 */
void mobile_vpn_set_stats_callback(MobileVpnHandle handle, MobileStatsCallback callback, void* user_data);

/**
 * Set network info callback
 * Called when network configuration is received (DHCP complete)
 * @param handle VPN handle
 * @param callback Callback function
 * @param user_data User data passed to callback
 */
void mobile_vpn_set_network_callback(MobileVpnHandle handle, MobileNetworkCallback callback, void* user_data);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get last error message
 * @param handle VPN handle
 * @return Error string (valid until next error)
 */
const char* mobile_vpn_get_error(MobileVpnHandle handle);

/**
 * Check if VPN is connected
 * @param handle VPN handle
 * @return true if connected, false otherwise
 */
bool mobile_vpn_is_connected(MobileVpnHandle handle);

/**
 * Cleanup library resources
 */
void mobile_vpn_cleanup(void);

/**
 * Get version string
 * @return Version string
 */
const char* mobile_vpn_get_version(void);

/**
 * Get build info string
 * @return Build info string
 */
const char* mobile_vpn_get_build_info(void);

/**
 * Generate SoftEther password hash (SHA-0 based)
 * @param username Username
 * @param password Plain password
 * @param output Buffer to receive base64-encoded hash
 * @param output_size Size of output buffer (minimum 32 bytes recommended)
 * @return 0 on success, negative error code on failure
 */
int mobile_vpn_generate_password_hash(const char* username, const char* password, char* output, uint64_t output_size);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_FFI_H
