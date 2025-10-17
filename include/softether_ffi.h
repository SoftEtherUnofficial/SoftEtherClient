/*
 * SoftEther VPN Client FFI - iOS/macOS Compatible Interface
 * 
 * This header provides the same API as the Rust FFI implementation,
 * allowing iOS PacketTunnelProvider to work with the Zig backend.
 * 
 * Drop-in replacement for RustFramework/include/softether_ffi.h
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Opaque Client Handle
// ============================================================================

typedef struct softether_client_t softether_client_t;

// ============================================================================
// Client Lifecycle
// ============================================================================

/**
 * Create a VPN client from JSON configuration.
 * 
 * JSON format example:
 * {
 *   "server": "vpn.example.com",
 *   "port": 443,
 *   "hub": "VPN",
 *   "username": "user",
 *   "password_hash": "sha0_hash_here",
 *   "use_encrypt": true,
 *   "use_compress": true,
 *   "max_connection": 2,
 *   "skip_tls_verify": false
 * }
 * 
 * @param json_config Null-terminated JSON configuration string
 * @return Client handle on success, NULL on error
 */
softether_client_t* softether_client_create(const char* json_config);

/**
 * Connect to the VPN server.
 * This is asynchronous - use state callbacks to monitor connection progress.
 * 
 * @param handle Client handle
 * @return 0 on success, negative error code on failure
 */
int softether_client_connect(softether_client_t* handle);

/**
 * Disconnect from the VPN server.
 * 
 * @param handle Client handle
 * @return 0 on success, negative error code on failure
 */
int softether_client_disconnect(softether_client_t* handle);

/**
 * Free all resources associated with the client handle.
 * This will disconnect if still connected.
 * 
 * @param handle Client handle to free
 */
void softether_client_free(softether_client_t* handle);

// ============================================================================
// L2 Frame I/O (Ethernet)
// ============================================================================

/**
 * Callback type for receiving L2 Ethernet frames from the VPN tunnel.
 * This callback is invoked from an internal thread and must be thread-safe.
 * 
 * @param data Pointer to Ethernet frame data (includes 14-byte header)
 * @param len Length of frame in bytes
 * @param user User data pointer provided during registration
 */
typedef void (*softether_rx_cb_t)(const uint8_t* data, uint32_t len, void* user);

/**
 * Register callback to receive L2 Ethernet frames.
 * 
 * @param handle Client handle
 * @param cb Callback function
 * @param user User data pointer passed to callback
 * @return 0 on success, negative error code on failure
 */
int softether_client_set_rx_callback(softether_client_t* handle, softether_rx_cb_t cb, void* user);

/**
 * Send L2 Ethernet frame to the VPN tunnel.
 * 
 * @param handle Client handle
 * @param data Pointer to Ethernet frame (must include 14-byte header)
 * @param len Length of frame in bytes
 * @return 1 if frame queued, 0 if link unavailable, negative on error
 */
int softether_client_send_frame(softether_client_t* handle, const uint8_t* data, uint32_t len);

// ============================================================================
// L3 IP Packet I/O (for iOS NEPacketTunnelFlow)
// ============================================================================

/**
 * Callback type for receiving IPv4 packets (L3) from the VPN tunnel.
 * EtherType 0x0800 is stripped - only IP packet payload is provided.
 * Non-IPv4 frames are filtered out.
 * 
 * @param ip_packet Pointer to IPv4 packet data (no Ethernet header)
 * @param len Length of IP packet in bytes
 * @param user User data pointer provided during registration
 */
typedef void (*softether_ip_rx_cb_t)(const uint8_t* ip_packet, uint32_t len, void* user);

/**
 * Register callback to receive IPv4 packets (L3 mode).
 * This is preferred for iOS NEPacketTunnelFlow integration.
 * 
 * @param handle Client handle
 * @param cb Callback function
 * @param user User data pointer passed to callback
 * @return 0 on success, negative error code on failure
 */
int softether_client_set_ip_rx_callback(softether_client_t* handle, softether_ip_rx_cb_t cb, void* user);

/**
 * Send IPv4 packet to the VPN tunnel.
 * The packet will be wrapped with Ethernet headers automatically.
 * 
 * @param handle Client handle
 * @param data Pointer to IPv4 packet (no Ethernet header)
 * @param len Length of IP packet in bytes
 * @return 1 if packet queued, 0 if link unavailable, negative on error
 */
int softether_client_send_ip_packet(softether_client_t* handle, const uint8_t* data, uint32_t len);

// ============================================================================
// ARP Management
// ============================================================================

/**
 * Add static ARP entry for next-hop routing.
 * This maps an IPv4 address to a MAC address for L2 frame construction.
 * 
 * @param handle Client handle
 * @param ipv4_be IPv4 address in big-endian (network byte order)
 * @param mac MAC address (6 bytes)
 * @return 0 on success, negative error code on failure
 */
int softether_client_arp_add(softether_client_t* handle, uint32_t ipv4_be, const uint8_t mac[6]);

// ============================================================================
// State and Event Callbacks
// ============================================================================

/**
 * Connection state values.
 */
typedef enum {
    SOFTETHER_STATE_IDLE = 0,           ///< Not connected
    SOFTETHER_STATE_CONNECTING = 1,     ///< Connection in progress
    SOFTETHER_STATE_ESTABLISHED = 2,    ///< Connected and active
    SOFTETHER_STATE_DISCONNECTING = 3   ///< Disconnection in progress
} softether_state_t;

/**
 * State callback for connection status changes.
 * 
 * @param state New connection state
 * @param user User data pointer provided during registration
 */
typedef void (*softether_state_cb_t)(int state, void* user);

/**
 * Register callback for connection state changes.
 * 
 * @param handle Client handle
 * @param cb Callback function
 * @param user User data pointer passed to callback
 * @return 0 on success, negative error code on failure
 */
int softether_client_set_state_callback(softether_client_t* handle, softether_state_cb_t cb, void* user);

/**
 * Event severity levels.
 */
typedef enum {
    SOFTETHER_EVENT_INFO = 0,    ///< Informational message
    SOFTETHER_EVENT_WARNING = 1, ///< Warning message
    SOFTETHER_EVENT_ERROR = 2    ///< Error message
} softether_event_level_t;

/**
 * Event callback for diagnostic messages.
 * 
 * @param level Event severity level (0=info, 1=warn, 2=error)
 * @param code Implementation-defined event code
 * @param message Human-readable message (null-terminated)
 * @param user User data pointer provided during registration
 */
typedef void (*softether_event_cb_t)(int level, int code, const char* message, void* user);

/**
 * Register callback for diagnostic events.
 * 
 * @param handle Client handle
 * @param cb Callback function
 * @param user User data pointer passed to callback
 * @return 0 on success, negative error code on failure
 */
int softether_client_set_event_callback(softether_client_t* handle, softether_event_cb_t cb, void* user);

// ============================================================================
// Network Configuration Queries
// ============================================================================

/**
 * Get network configuration obtained from VPN server (via DHCP).
 * 
 * Returns JSON with the following structure:
 * {
 *   "assigned_ipv4": "192.168.30.10",
 *   "subnet_mask": "255.255.255.0",
 *   "gateway": "192.168.30.1",
 *   "dns_servers": ["8.8.8.8", "8.8.4.4"]
 * }
 * 
 * @param handle Client handle
 * @return JSON string (must be freed with softether_string_free), or NULL if unavailable
 */
char* softether_client_get_network_settings_json(softether_client_t* handle);

/**
 * Get the locally-administered MAC address used by this client.
 * 
 * @param handle Client handle
 * @param out_mac Buffer to receive 6-byte MAC address
 * @return 0 on success, negative error code on failure
 */
int softether_client_get_mac(softether_client_t* handle, uint8_t out_mac[6]);

// ============================================================================
// Error Handling
// ============================================================================

/**
 * Get and clear the last error message.
 * 
 * @param handle Client handle
 * @return Error string (must be freed with softether_string_free), or NULL if no error
 */
char* softether_client_last_error(softether_client_t* handle);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Decode Base64 string into binary buffer.
 * 
 * @param b64 Null-terminated Base64 string
 * @param out_buf Output buffer for decoded bytes
 * @param out_cap Capacity of output buffer
 * @return Number of decoded bytes on success, negative error code on failure
 */
int softether_b64_decode(const char* b64, unsigned char* out_buf, unsigned int out_cap);

/**
 * Get library version string.
 * 
 * @return Version string (static, do not free)
 */
char* softether_client_version(void);

/**
 * Free strings allocated by this library.
 * Use this to free strings returned by:
 * - softether_client_get_network_settings_json()
 * - softether_client_last_error()
 * - softether_client_version()
 * 
 * @param str String pointer to free (can be NULL)
 */
void softether_string_free(char* str);

// ============================================================================
// Build Information
// ============================================================================

/**
 * Get build and platform information.
 * 
 * @return Build info string (static, do not free)
 */
char* softether_client_get_build_info(void);

/**
 * Check if handle is valid (for debugging).
 * 
 * @param handle Client handle to validate
 * @return true if handle is non-NULL, false otherwise
 */
bool softether_client_is_valid_handle(softether_client_t* handle);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_FFI_H
