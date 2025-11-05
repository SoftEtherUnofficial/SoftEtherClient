/**
 * SoftEther VPN Client - Direct C API
 * 
 * Zero-overhead API that matches vpnclient CLI architecture:
 * - Direct CLIENT* and SESSION* object usage
 * - Event-driven callbacks (no polling)
 * - Native PACKET_ADAPTER integration
 * 
 * This eliminates ALL FFI overhead by exposing SoftEther C objects directly
 * to platform code (Swift/ObjC for iOS, JNI for Android).
 */

#ifndef SOFTETHER_DIRECT_API_H
#define SOFTETHER_DIRECT_API_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * Type Definitions
 * ======================================================================== */

/// Opaque session handle (internally points to SESessionContext)
typedef void* SESessionHandle;

/// Connection configuration
typedef struct SEConfig {
    const char* server;              ///< VPN server hostname or IP
    uint16_t port;                   ///< VPN server port (default: 443)
    const char* hub;                 ///< Virtual hub name
    const char* username;            ///< Username for authentication
    const char* password_hash;       ///< SHA0(password + username) hex string
    bool use_encrypt;                ///< Enable encryption (recommended: true)
    bool use_compress;               ///< Enable compression
    const char* client_name;         ///< Optional client identifier
} SEConfig;

/// Network configuration from DHCP
typedef struct SENetworkConfig {
    uint32_t ip_address;             ///< Assigned IP (network byte order)
    uint32_t subnet_mask;            ///< Subnet mask (network byte order)
    uint32_t gateway;                ///< Default gateway (network byte order)
    uint32_t dns_server;             ///< Primary DNS (network byte order)
    uint32_t dns_server2;            ///< Secondary DNS (network byte order)
    uint8_t gateway_mac[6];          ///< Gateway MAC from ARP
    uint16_t mtu;                    ///< MTU size (default: 1500)
} SENetworkConfig;

/// Connection status codes
typedef enum SEStatus {
    SE_STATUS_DISCONNECTED = 0,      ///< Not connected
    SE_STATUS_CONNECTING = 1,        ///< Connection in progress
    SE_STATUS_CONNECTED = 2,         ///< Connected and ready
    SE_STATUS_RECONNECTING = 3,      ///< Reconnecting after error
    SE_STATUS_ERROR = 4              ///< Fatal error
} SEStatus;

/// Error codes
typedef enum SEError {
    SE_ERROR_NONE = 0,               ///< No error
    SE_ERROR_INVALID_PARAM = -1,     ///< Invalid parameter
    SE_ERROR_CONNECT_FAILED = -2,    ///< Connection failed
    SE_ERROR_AUTH_FAILED = -3,       ///< Authentication failed
    SE_ERROR_TIMEOUT = -4,           ///< Operation timeout
    SE_ERROR_DISCONNECTED = -5,      ///< Session disconnected
    SE_ERROR_PACKET_BUFFER = -6,     ///< Packet buffer error
    SE_ERROR_INTERNAL = -99          ///< Internal error
} SEError;

/* ========================================================================
 * Callback Function Types
 * ======================================================================== */

/**
 * Network configuration callback (DHCP complete)
 * Called when DHCP negotiation completes and network config is available.
 * 
 * @param config Network configuration (valid only during callback)
 * @param user_data User data passed to se_connect
 */
typedef void (*SENetworkCallback)(const SENetworkConfig* config, void* user_data);

/**
 * Status change callback
 * Called when connection status changes.
 * 
 * @param status New connection status
 * @param message Human-readable status message
 * @param user_data User data passed to se_connect
 */
typedef void (*SEStatusCallback)(SEStatus status, const char* message, void* user_data);

/**
 * Error callback
 * Called when an error occurs.
 * 
 * @param error_code Error code (SEError)
 * @param message Error message
 * @param user_data User data passed to se_connect
 */
typedef void (*SEErrorCallback)(int error_code, const char* message, void* user_data);

/* ========================================================================
 * Core API Functions
 * ======================================================================== */

/**
 * Initialize SoftEther library
 * Must be called once before any other API functions.
 * 
 * @return 0 on success, negative error code on failure
 */
int se_init(void);

/**
 * Shutdown SoftEther library
 * Cleans up global resources. Call at program exit.
 */
void se_shutdown(void);

/**
 * Connect to VPN server
 * Creates CLIENT* and SESSION* objects and initiates connection.
 * Connection proceeds asynchronously; callbacks notify progress.
 * 
 * @param config Connection configuration
 * @param network_callback Called when DHCP completes (can be NULL)
 * @param status_callback Called on status changes (can be NULL)
 * @param error_callback Called on errors (can be NULL)
 * @param user_data Passed to all callbacks
 * @return Session handle on success, NULL on failure
 */
SESessionHandle se_connect(
    const SEConfig* config,
    SENetworkCallback network_callback,
    SEStatusCallback status_callback,
    SEErrorCallback error_callback,
    void* user_data
);

/**
 * Disconnect from VPN server
 * Stops SESSION, releases resources, and frees session handle.
 * 
 * @param session Session handle from se_connect
 */
void se_disconnect(SESessionHandle session);

/**
 * Get current connection status
 * 
 * @param session Session handle
 * @return Current status (SEStatus)
 */
SEStatus se_get_status(SESessionHandle session);

/**
 * Check if session is connected
 * Thread-safe check of session validity and connection state.
 * 
 * @param session Session handle
 * @return true if session is valid and connected, false otherwise
 */
bool se_is_connected(SESessionHandle session);

/**
 * Get last error code
 * 
 * @param session Session handle
 * @return Last error code (SEError)
 */
int se_get_last_error(SESessionHandle session);

/**
 * Get last error message
 * 
 * @param session Session handle
 * @return Error message string (valid until next API call)
 */
const char* se_get_error_message(SESessionHandle session);

/* ========================================================================
 * Packet I/O Functions
 * ======================================================================== */

/**
 * Read packet from VPN session (non-blocking)
 * Retrieves next packet from SESSION->PacketAdapter->GetNextPacket
 * 
 * @param session Session handle
 * @param buffer Buffer to receive packet data
 * @param buffer_size Size of buffer
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return Number of bytes read, 0 if no packet available, negative on error
 */
int se_read_packet(SESessionHandle session, uint8_t* buffer, size_t buffer_size, uint32_t timeout_ms);

/**
 * Write packet to VPN session
 * Sends packet via SESSION->PacketAdapter->PutPacket
 * 
 * @param session Session handle
 * @param data Packet data
 * @param size Packet size
 * @return 0 on success, negative error code on failure
 */
int se_write_packet(SESessionHandle session, const uint8_t* data, size_t size);

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

/**
 * Generate SoftEther password hash
 * Computes SHA0(password + username) as hex string
 * 
 * @param password Plain text password
 * @param username Username
 * @return Hex string (caller must free with free()), NULL on error
 */
char* se_generate_password_hash(const char* password, const char* username);

/**
 * Get library version string
 * 
 * @return Version string (e.g., "1.0.0")
 */
const char* se_get_version(void);

/**
 * Get build information
 * 
 * @return Build info string (e.g., "iOS arm64 Debug")
 */
const char* se_get_build_info(void);

/* ========================================================================
 * Statistics Functions
 * ======================================================================== */

/// Connection statistics
typedef struct SEStats {
    uint64_t bytes_sent;             ///< Total bytes sent
    uint64_t bytes_received;         ///< Total bytes received
    uint64_t packets_sent;           ///< Total packets sent
    uint64_t packets_received;       ///< Total packets received
    uint64_t connected_time_ms;      ///< Connection duration (ms)
} SEStats;

/**
 * Get connection statistics
 * 
 * @param session Session handle
 * @param stats Pointer to stats structure to fill
 * @return 0 on success, negative error code on failure
 */
int se_get_stats(SESessionHandle session, SEStats* stats);

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_DIRECT_API_H
