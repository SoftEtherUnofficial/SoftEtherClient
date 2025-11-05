/**
 * Direct C API for SoftEther VPN Client
 * 
 * Zero-overhead bridge that eliminates FFI layer.
 * Matches vpnclient CLI flow: CiNewClient → SessionMain → DHCP → ARP
 */

#ifndef DIRECT_API_H
#define DIRECT_API_H

#include <stdint.h>
#include <stddef.h>

// Opaque session handle
typedef void* SESessionHandle;

// Configuration structure
typedef struct {
    const char* server;
    uint16_t port;
    const char* hub;
    const char* username;
    const char* password_hash;  // SHA0(password + username) hex string
    int use_encrypt;            // Use int instead of bool for C compatibility
    int use_compress;           // Use int instead of bool for C compatibility
} SEConfig;

// Network configuration (DHCP-assigned)
typedef struct {
    uint32_t ip_address;        // Network byte order
    uint32_t subnet_mask;       // Network byte order
    uint32_t gateway;           // Network byte order
    uint32_t dns_server;        // Network byte order
    uint8_t gateway_mac[6];     // From ARP
} SENetworkConfig;

// Callback types
typedef void (*SENetworkCallback)(const SENetworkConfig* config, void* user_data);
typedef void (*SEStatusCallback)(const char* message, void* user_data);
typedef void (*SEErrorCallback)(int error_code, const char* message, void* user_data);

/**
 * Initialize SoftEther library (call once at startup)
 */
int se_init(void);

/**
 * Connect to VPN server
 * Returns session handle or NULL on failure
 */
SESessionHandle se_connect(const SEConfig* config,
                           SENetworkCallback network_callback,
                           SEStatusCallback status_callback,
                           SEErrorCallback error_callback,
                           void* user_data);

/**
 * Read packet from VPN (non-blocking)
 * Returns packet size or -1 on error, 0 if no packet available
 */
int se_read_packet(SESessionHandle session, uint8_t* buffer, size_t buffer_size);

/**
 * Write packet to VPN
 * Returns 0 on success, -1 on error
 */
int se_write_packet(SESessionHandle session, const uint8_t* data, size_t size);

/**
 * Disconnect and cleanup session
 */
void se_disconnect(SESessionHandle session);

/**
 * Get session status
 * Returns: 0=disconnected, 1=connecting, 2=connected, 3=reconnecting, 4=error
 */
int se_get_status(SESessionHandle session);

/**
 * Generate password hash (SHA0(password + username))
 * Returns hex string (caller must free)
 */
char* se_generate_password_hash(const char* password, const char* username);

#endif // DIRECT_API_H
