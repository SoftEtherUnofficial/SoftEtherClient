/*
 * SoftEther VPN - Zig Bridge Layer Implementation
 * 
 * This implements the bridge layer between Zig and SoftEther C code.
 */

#include "softether_bridge.h"
#include "security_utils.h"  // Secure password handling
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ============================================
 * SoftEther Headers
 * ============================================ */
#include "Mayaqua/Mayaqua.h"
#include "Cedar/Cedar.h"
#include "Cedar/Client.h"
#include "Cedar/Connection.h"
#include "Cedar/Session.h"
#include "Cedar/Account.h"
#include "Cedar/IPsec_IPC.h"  // Add IPC header for DHCP

// Include logging.h AFTER SoftEther headers to avoid bool conflicts
#include "logging.h"

// Platform-specific packet adapter
// Zig adapter is preferred for iOS and macOS (better performance)
#ifndef USE_ZIG_ADAPTER
#define USE_ZIG_ADAPTER 1  // Default: use Zig adapter (set to 0 for legacy C adapter)
#endif

#if USE_ZIG_ADAPTER && (defined(UNIX_IOS) || defined(UNIX_MACOS))
    // Use Zig packet adapter (iOS and macOS)
    #include "zig_packet_adapter.h"
    #define NEW_PACKET_ADAPTER() NewZigPacketAdapter()
#elif defined(UNIX_IOS)
    // Legacy iOS C adapter (deprecated - use Zig adapter instead)
    #include "packet_adapter_ios.h"
    #define NEW_PACKET_ADAPTER() NewIosPacketAdapter()
#elif defined(UNIX_MACOS)
    // Legacy macOS C adapter
    #include "packet_adapter_macos.h"
    #define NEW_PACKET_ADAPTER() NewMacOsTunAdapter()
#elif defined(UNIX_LINUX)
    #include "packet_adapter_linux.h"
    #define NEW_PACKET_ADAPTER() NewLinuxTunAdapter()
#elif defined(_WIN32)
    #include "packet_adapter_windows.h"
    #define NEW_PACKET_ADAPTER() NewWindowsTapAdapter()
#else
    #define NEW_PACKET_ADAPTER() NULL
#endif

/* ============================================
 * Internal State
 * ============================================ */

static uint32_t g_initialized = 0;  // 0 = false, 1 = true

/* ============================================
 * Client Structure
 * ============================================ */

struct VpnBridgeClient {
    // Configuration
    char hostname[256];
    uint16_t port;
    char hub_name[256];
    char username[256];
    char password[256];
    bool password_is_hashed;  // Flag: true if password field contains pre-hashed password
    uint32_t max_connection;   // Maximum number of concurrent TCP connections (1-32)
    
    // IP Configuration
    int ip_version;  // VPN_IP_VERSION_* constants
    bool use_static_ipv4;
    char static_ipv4[64];
    char static_ipv4_netmask[64];
    char static_ipv4_gateway[64];
    bool use_static_ipv6;
    char static_ipv6[128];
    uint8_t static_ipv6_prefix;
    char static_ipv6_gateway[128];
    char* dns_servers[8];  // Max 8 DNS servers
    int dns_server_count;
    
    // Adapter configuration
    int use_zig_adapter;                // 0=C adapter (legacy), 1=Zig adapter (default, better performance)
    
    // State
    VpnBridgeStatus status;
    uint32_t last_error;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t connect_time;
    
    // Reconnection Configuration
    int reconnect_enabled;              // 0=disabled, 1=enabled
    uint32_t max_reconnect_attempts;    // 0=infinite, >0=max retries
    uint32_t min_backoff_seconds;       // Minimum backoff delay (default: 5)
    uint32_t max_backoff_seconds;       // Maximum backoff delay (default: 300)
    
    // Reconnection Runtime State
    uint32_t reconnect_attempt;         // Current attempt number (0=no reconnection yet)
    uint32_t current_backoff_seconds;   // Current backoff delay
    uint64_t last_disconnect_time;      // Timestamp when connection was lost (milliseconds since epoch)
    uint64_t next_reconnect_time;       // Timestamp when next reconnect should occur
    int user_requested_disconnect;      // 1=user pressed Ctrl+C, 0=network failure
    uint32_t consecutive_failures;      // Count of consecutive connection failures
    
    // SoftEther internal handles
    CLIENT* softether_client;
    ACCOUNT* softether_account;
    SESSION* softether_session;
    PACKET_ADAPTER* packet_adapter;
    IPC* softether_ipc;  // IPC connection for DHCP
};

/* ============================================
 * Helper Functions
 * ============================================ */

static const char* get_error_message_internal(int error_code) {
    switch (error_code) {
        case VPN_BRIDGE_SUCCESS:              return "Success";
        case VPN_BRIDGE_ERROR_INIT_FAILED:    return "Library initialization failed";
        case VPN_BRIDGE_ERROR_INVALID_PARAM:  return "Invalid parameter";
        case VPN_BRIDGE_ERROR_ALLOC_FAILED:   return "Memory allocation failed";
        case VPN_BRIDGE_ERROR_CONNECT_FAILED: return "Connection failed";
        case VPN_BRIDGE_ERROR_AUTH_FAILED:    return "Authentication failed";
        case VPN_BRIDGE_ERROR_NOT_CONNECTED:  return "Not connected";
        case VPN_BRIDGE_ERROR_ALREADY_INIT:   return "Already initialized";
        case VPN_BRIDGE_ERROR_NOT_INIT:       return "Not initialized";
        
        // SoftEther error codes (from Cedar.h)
        case 9:  return "Authentication failed - Invalid username or password";
        case 22: return "Device driver error - TAP adapter issue";
        case 23: return "Offline mode - Network unavailable";
        case 24: return "Server certificate verification failed";
        
        default: 
            if (error_code > 0 && error_code < 100) {
                return "Connection error - Check server and credentials";
            }
            return "Unknown error";
    }
}

/* ============================================
 * Library Initialization
 * ============================================ */

int vpn_bridge_init(uint32_t debug) {
    LOG_DEBUG("VPN", "Initializing SoftEther client (minimal mode)");
    
    // Enable minimal mode BEFORE Init to skip hamcore.se2 and string table loading
    MayaquaMinimalMode();
    
    // Provide a simple executable name - the exe path check is disabled in development mode
    char *fake_argv[] = { "vpnclient", NULL };
    
    // Initialize Mayaqua and Cedar libraries
    InitMayaqua(false, true, 1, fake_argv);
    InitCedar();
    
    LOG_INFO("VPN", "SoftEther client initialized successfully");
    
    g_initialized = 1;  // 1 = true
    return VPN_BRIDGE_SUCCESS;
}

void vpn_bridge_cleanup(void) {
    if (!g_initialized) {
        return;
    }
    
    // Cleanup SoftEther layers
    FreeCedar();
    FreeMayaqua();
    
    g_initialized = 0;  // 0 = false
}

/**
 * Check if library is initialized
 */
uint32_t vpn_bridge_is_initialized(void) {
    return g_initialized ? 1 : 0;
}

/* ============================================
 * Helper Functions
 * ============================================ */

/**
 * Get current time in milliseconds since epoch
 */
static uint64_t get_current_time_ms(void) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t time = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return time / 10000 - 11644473600000ULL; // Convert from 100ns intervals since 1601 to ms since 1970
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
#endif
}

/* ============================================
 * Client Management
 * ============================================ */

VpnBridgeClient* vpn_bridge_create_client(void) {
    if (!g_initialized) {
        LOG_ERROR("VPN", "Cannot create client: library not initialized");
        return NULL;
    }
    
    VpnBridgeClient* client = (VpnBridgeClient*)calloc(1, sizeof(VpnBridgeClient));
    if (!client) {
        LOG_ERROR("VPN", "Failed to allocate client structure");
        return NULL;
    }
    
    // Initialize with defaults
    client->status = VPN_STATUS_DISCONNECTED;
    client->last_error = VPN_BRIDGE_SUCCESS;
    client->port = 443;
    client->max_connection = 1;  // Default to 1 connection
    client->use_zig_adapter = 1;  // Default to Zig adapter (better performance)
    
    // Initialize IP configuration (defaults)
    client->ip_version = VPN_IP_VERSION_AUTO;
    client->use_static_ipv4 = false;
    client->use_static_ipv6 = false;
    client->dns_server_count = 0;
    memset(client->static_ipv4, 0, sizeof(client->static_ipv4));
    memset(client->static_ipv4_netmask, 0, sizeof(client->static_ipv4_netmask));
    memset(client->static_ipv4_gateway, 0, sizeof(client->static_ipv4_gateway));
    memset(client->static_ipv6, 0, sizeof(client->static_ipv6));
    client->static_ipv6_prefix = 0;
    memset(client->static_ipv6_gateway, 0, sizeof(client->static_ipv6_gateway));
    for (int i = 0; i < 8; i++) {
        client->dns_servers[i] = NULL;
    }
    
    // Initialize reconnection state (default: enabled, infinite retries)
    client->reconnect_enabled = 1;
    client->max_reconnect_attempts = 0;  // 0 = infinite
    client->min_backoff_seconds = 5;
    client->max_backoff_seconds = 300;
    client->reconnect_attempt = 0;
    client->current_backoff_seconds = 0;
    client->last_disconnect_time = 0;
    client->next_reconnect_time = 0;
    client->user_requested_disconnect = 0;
    client->consecutive_failures = 0;
    
    // Create real SoftEther CLIENT structure
    client->softether_client = CiNewClient();
    if (!client->softether_client) {
        LOG_ERROR("VPN", "CiNewClient() failed");
        free(client);
        return NULL;
    }
    
    LOG_DEBUG("VPN", "Client created successfully");
    return client;
}

void vpn_bridge_free_client(VpnBridgeClient* client) {
    if (!client) {
        return;
    }
    
    // Disconnect if still connected
    if (client->status == VPN_STATUS_CONNECTED) {
        LOG_DEBUG("VPN", "Disconnecting client before cleanup");
        vpn_bridge_disconnect(client);
    }
    
    // Free DNS servers (FIX LEAK #1)
    for (int i = 0; i < client->dns_server_count; i++) {
        if (client->dns_servers[i]) {
            Free(client->dns_servers[i]);
            client->dns_servers[i] = NULL;
        }
    }
    client->dns_server_count = 0;
    
    // Free real SoftEther CLIENT structure
    // NOTE: If we already disconnected, skip CiCleanupClient as it may access freed resources
    if (client->softether_client && client->status != VPN_STATUS_DISCONNECTED) {
        CiCleanupClient(client->softether_client);
        client->softether_client = NULL;
    } else {
        // Just free the CLIENT structure directly
        if (client->softether_client) {
            Free(client->softether_client);
            client->softether_client = NULL;
        }
    }
    
    // Clear sensitive data securely (cannot be optimized away)
    secure_zero_explicit(client->password, sizeof(client->password));
    
    free(client);
    LOG_DEBUG("VPN", "Client freed successfully");
}

/* ============================================
 * Reconnection Management
 * ============================================ */

/**
 * Enable automatic reconnection for a VPN client.
 */
int vpn_bridge_enable_reconnect(
    VpnBridgeClient* client,
    uint32_t max_attempts,
    uint32_t min_backoff,
    uint32_t max_backoff
) {
    if (!client) {
        LOG_ERROR("VPN", "vpn_bridge_enable_reconnect: NULL client");
        return -1;
    }
    
    client->reconnect_enabled = 1;
    client->max_reconnect_attempts = max_attempts;
    client->min_backoff_seconds = min_backoff > 0 ? min_backoff : 5;
    client->max_backoff_seconds = max_backoff > 0 ? max_backoff : 300;
    
    // Ensure min <= max
    if (client->min_backoff_seconds > client->max_backoff_seconds) {
        client->min_backoff_seconds = client->max_backoff_seconds;
    }
    
    LOG_INFO("VPN", "Auto-reconnect enabled: max_attempts=%u (0=infinite), backoff=%u-%u seconds",
        max_attempts, client->min_backoff_seconds, client->max_backoff_seconds);
    
    return 0;
}

/**
 * Disable automatic reconnection for a VPN client.
 */
int vpn_bridge_disable_reconnect(VpnBridgeClient* client) {
    if (!client) {
        LOG_ERROR("VPN", "vpn_bridge_disable_reconnect: NULL client");
        return -1;
    }
    
    client->reconnect_enabled = 0;
    LOG_INFO("VPN", "Auto-reconnect disabled");
    
    return 0;
}

/**
 * Calculate next backoff delay using exponential backoff algorithm.
 * Formula: delay = min(min_backoff * (2 ^ (attempt - 1)), max_backoff)
 */
uint32_t vpn_bridge_calculate_backoff(const VpnBridgeClient* client) {
    if (!client || client->reconnect_attempt == 0) {
        return 0;  // First connection has no delay
    }
    
    // Start with minimum backoff
    uint32_t delay = client->min_backoff_seconds;
    
    // Apply exponential growth: multiply by 2 for each attempt
    for (uint32_t i = 1; i < client->reconnect_attempt; i++) {
        delay *= 2;
        if (delay >= client->max_backoff_seconds) {
            return client->max_backoff_seconds;
        }
    }
    
    return delay;
}

/**
 * Reset reconnection state after successful connection.
 */
int vpn_bridge_reset_reconnect_state(VpnBridgeClient* client) {
    if (!client) {
        return -1;
    }
    
    client->reconnect_attempt = 0;
    client->current_backoff_seconds = 0;
    client->consecutive_failures = 0;
    client->last_disconnect_time = 0;
    client->next_reconnect_time = 0;
    client->user_requested_disconnect = 0;
    
    LOG_DEBUG("VPN", "Reconnection state reset");
    
    return 0;
}

/**
 * Mark a disconnect as user-requested (e.g., Ctrl+C).
 * This prevents automatic reconnection.
 */
int vpn_bridge_mark_user_disconnect(VpnBridgeClient* client) {
    if (!client) {
        return -1;
    }
    
    client->user_requested_disconnect = 1;
    LOG_DEBUG("VPN", "Marked as user-requested disconnect");
    
    return 0;
}

/**
 * Get reconnection state and configuration.
 * 
 * @return 1 if should reconnect, 0 if should not reconnect, -1 on error
 */
int vpn_bridge_get_reconnect_info(
    const VpnBridgeClient* client,
    uint8_t* enabled,
    uint32_t* attempt,
    uint32_t* max_attempts,
    uint32_t* current_backoff,
    uint64_t* next_retry_time,
    uint32_t* consecutive_failures,
    uint64_t* last_disconnect_time
) {
    if (!client) {
        return -1;
    }
    
    // Fill output parameters
    if (enabled) *enabled = client->reconnect_enabled;
    if (attempt) *attempt = client->reconnect_attempt;
    if (max_attempts) *max_attempts = client->max_reconnect_attempts;
    if (current_backoff) *current_backoff = client->current_backoff_seconds;
    if (next_retry_time) *next_retry_time = client->next_reconnect_time;
    if (consecutive_failures) *consecutive_failures = client->consecutive_failures;
    if (last_disconnect_time) *last_disconnect_time = client->last_disconnect_time;
    
    // Determine if should reconnect
    // Don't reconnect if:
    // 1. Reconnect is disabled
    // 2. User requested disconnect
    // 3. Max attempts exceeded (if max_attempts > 0)
    
    if (!client->reconnect_enabled) {
        LOG_DEBUG("VPN", "Should not reconnect: disabled");
        return 0;
    }
    
    if (client->user_requested_disconnect) {
        LOG_DEBUG("VPN", "Should not reconnect: user requested disconnect");
        return 0;
    }
    
    if (client->max_reconnect_attempts > 0 && 
        client->reconnect_attempt >= client->max_reconnect_attempts) {
        LOG_WARN("VPN", "Max reconnection attempts (%u) exceeded", client->max_reconnect_attempts);
        return 0;
    }
    
    // Should reconnect
    return 1;
}

/* ============================================
 * Connection Configuration
 * ============================================ */

int vpn_bridge_configure(
    VpnBridgeClient* client,
    const char* hostname,
    uint16_t port,
    const char* hub_name,
    const char* username,
    const char* password
) {
    if (!client || !hostname || !hub_name || !username || !password) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Store configuration
    strncpy(client->hostname, hostname, sizeof(client->hostname) - 1);
    client->hostname[sizeof(client->hostname) - 1] = '\0';
    
    client->port = port;
    
    strncpy(client->hub_name, hub_name, sizeof(client->hub_name) - 1);
    client->hub_name[sizeof(client->hub_name) - 1] = '\0';
    
    strncpy(client->username, username, sizeof(client->username) - 1);
    client->username[sizeof(client->username) - 1] = '\0';
    
    strncpy(client->password, password, sizeof(client->password) - 1);
    client->password[sizeof(client->password) - 1] = '\0';
    
    client->password_is_hashed = false;  // Plain password
    
    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_configure_with_hash(
    VpnBridgeClient* client,
    const char* hostname,
    uint16_t port,
    const char* hub_name,
    const char* username,
    const char* password_hash
) {
    if (!client || !hostname || !hub_name || !username || !password_hash) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Store configuration
    strncpy(client->hostname, hostname, sizeof(client->hostname) - 1);
    client->hostname[sizeof(client->hostname) - 1] = '\0';
    
    client->port = port;
    
    strncpy(client->hub_name, hub_name, sizeof(client->hub_name) - 1);
    client->hub_name[sizeof(client->hub_name) - 1] = '\0';
    
    strncpy(client->username, username, sizeof(client->username) - 1);
    client->username[sizeof(client->username) - 1] = '\0';
    
    strncpy(client->password, password_hash, sizeof(client->password) - 1);
    client->password[sizeof(client->password) - 1] = '\0';
    
    client->password_is_hashed = true;  // Pre-hashed password
    
    return VPN_BRIDGE_SUCCESS;
}

/* ============================================
 * Connection Operations
 * ============================================ */

int vpn_bridge_connect(VpnBridgeClient* client) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    if (!g_initialized) {
        client->last_error = VPN_BRIDGE_ERROR_NOT_INIT;
        return VPN_BRIDGE_ERROR_NOT_INIT;
    }
    
    if (client->status == VPN_STATUS_CONNECTED) {
        return VPN_BRIDGE_SUCCESS; // Already connected
    }
    
    // Log reconnection attempt if this is not the first connection
    if (client->reconnect_attempt > 0) {
        if (client->max_reconnect_attempts > 0) {
            LOG_INFO("VPN", "Reconnection attempt %u/%u", 
                client->reconnect_attempt, client->max_reconnect_attempts);
        } else {
            LOG_INFO("VPN", "Reconnection attempt %u (unlimited)", client->reconnect_attempt);
        }
    }
    
    // Validate configuration
    if (client->hostname[0] == '\0' || 
        client->hub_name[0] == '\0' ||
        client->username[0] == '\0') {
        client->last_error = VPN_BRIDGE_ERROR_INVALID_PARAM;
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    LOG_INFO("VPN", "Creating account");
    
    client->status = VPN_STATUS_CONNECTING;
    
    // Create CLIENT_OPTION structure
    CLIENT_OPTION* opt = ZeroMalloc(sizeof(CLIENT_OPTION));
    
    // Set account name (used internally)
    UniStrCpy(opt->AccountName, sizeof(opt->AccountName), L"ZigBridge");
    
    // Set server connection details
    StrCpy(opt->Hostname, sizeof(opt->Hostname), client->hostname);
    opt->Port = client->port;
    StrCpy(opt->HubName, sizeof(opt->HubName), client->hub_name);
    
    // CRITICAL: Disable NAT-T (per Stanislav's requirement)
    // Setting PortUDP = 0 forces TCP-only mode without NAT-T server lookups
    opt->PortUDP = 0;  // 0 = Use only TCP, no UDP/NAT-T
    
    LOG_DEBUG("VPN", "TCP-ONLY MODE: PortUDP=%u (TCP only, no NAT-T, no UDP accel)", opt->PortUDP);
    
    // iOS: Use Layer 2 bridge mode with VirtualTap handling ARP internally
    // iOS PacketTunnelProvider is Layer 3-only, but we send/receive full Ethernet frames
    // VirtualTap intercepts ARP requests and generates replies before they reach iOS tunnel
    // This matches the behavior of SSTP Connect (which successfully handles ARP on iOS)
    #ifdef UNIX_IOS
        StrCpy(opt->DeviceName, sizeof(opt->DeviceName), "vpn_ios");  // Named adapter = Layer 2 mode
        LOG_INFO("VPN", "🍎 iOS Layer 2 mode: DeviceName=\"vpn_ios\" (VirtualTap handles ARP internally)");
    #else
        StrCpy(opt->DeviceName, sizeof(opt->DeviceName), "vpn_adapter");
        LOG_DEBUG("VPN", "�️ Desktop mode: DeviceName=\"vpn_adapter\" (standard Layer 2 bridge)");
    #endif
    
    // Connection settings - TCP ONLY, configurable max connections
    // Multiple connections improve throughput through parallelization
    opt->MaxConnection = client->max_connection;  // User-configurable (1-32)
    LOG_VPN_INFO("🔧 MaxConnection set to %u (1=single conn, >1=parallel)", opt->MaxConnection);
    opt->UseEncrypt = true;              // Use encryption (SSTP: use_encrypt=[1])
    opt->UseCompress = false;            // No compression (SSTP: use_compress=[0])
    opt->HalfConnection = false;         // Full-duplex (SSTP: half_connection=[0])
    opt->NoRoutingTracking = true;       // Don't track routing
    opt->NumRetry = 10;                  // Retry attempts
    opt->RetryInterval = 5;              // 5 seconds between retries
    opt->AdditionalConnectionInterval = 1;
    opt->NoUdpAcceleration = true;       // CRITICAL: No UDP acceleration
    opt->DisableQoS = true;              // Disable QoS features
    
    // ⚠️ CRITICAL FIX FOR DHCP: Request bridge/routing mode
    // Without this, server FORCES policy->NoBridge = true and policy->NoRouting = true
    // even if server policy allows it! (Protocol.c:3318-3321)
    // This prevents DHCP packets from being delivered to the client.
    opt->RequireBridgeRoutingMode = true;
    
    LOG_DEBUG("VPN", "Connection options: %s:%d hub=%s, device=vpn_adapter, bridge_mode=true",
              opt->Hostname, opt->Port, opt->HubName);
    
    // Create CLIENT_AUTH structure for password authentication
    CLIENT_AUTH* auth = ZeroMalloc(sizeof(CLIENT_AUTH));
    auth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
    
    // Set username
    StrCpy(auth->Username, sizeof(auth->Username), client->username);
    
    // Log credentials (ONLY username and lengths, NEVER log actual password)
    LOG_INFO("VPN", "🔐 AUTH: user='%s' (len=%zu), pwd_len=%zu, is_hashed=%d",
             client->username, strlen(client->username), 
             strlen(client->password), client->password_is_hashed);
    
    // Log password hash preview for visual verification (first 12 chars only, safe for base64)
    if (client->password_is_hashed && strlen(client->password) > 0) {
        char preview[16] = {0};
        strncpy(preview, client->password, 12);
        LOG_INFO("VPN", "🔑 Password hash preview: %s... (total len=%zu)", preview, strlen(client->password));
    }
    
    // Handle password: hash it if plain, or decode base64 if pre-hashed
    if (client->password_is_hashed) {
        // Password is already hashed (base64-encoded SHA1)
        // Decode base64 to get the 20-byte SHA1 hash
        LOG_INFO("VPN", "🔑 Using pre-hashed password (base64-encoded)");
        
        // Decode base64 into secure buffer
        char decoded[256];
        secure_lock_memory(decoded, sizeof(decoded));  // Lock in memory (prevent swap)
        
        int decoded_len = B64_Decode(decoded, client->password, strlen(client->password));
        
        LOG_INFO("VPN", "🔑 Decoded %d bytes from base64 (expected 20 for SHA-0)", decoded_len);
        
        if (decoded_len == 20) {
            // Copy the 20-byte hash to HashedPassword
            memcpy(auth->HashedPassword, decoded, 20);
            LOG_INFO("VPN", "✓ Using pre-hashed password (20 bytes decoded)");
        } else {
            LOG_INFO("VPN", "⚠️ Base64 password hash decoded to %d bytes (expected 20), rehashing", decoded_len);
            // Fall back to hashing the password string itself
            HashPassword(auth->HashedPassword, client->username, client->password);
        }
        
        // Securely zero and unlock the decoded password
        secure_zero_explicit(decoded, sizeof(decoded));
        secure_unlock_memory(decoded, sizeof(decoded));
        
    } else {
        // Plain password - hash it using SoftEther's method
        LOG_DEBUG("VPN", "Hashing plaintext password");
        HashPassword(auth->HashedPassword, client->username, client->password);
        
        // Securely zero the plaintext password immediately after hashing
        secure_zero_explicit(client->password, sizeof(client->password));
    }
    
    LOG_DEBUG("VPN", "Authentication configured: user=%s, type=PASSWORD", auth->Username);
    
    // Create ACCOUNT structure
    ACCOUNT* account = ZeroMalloc(sizeof(ACCOUNT));
    account->lock = NewLock();
    account->ClientOption = opt;
    account->ClientAuth = auth;
    account->CheckServerCert = false;  // Don't validate server cert for now
    account->ServerCert = NULL;
    account->ClientSession = NULL;  // Will be set by SESSION
    
    client->softether_account = account;
    
    // Set global IP configuration for packet adapter (only for C adapter on macOS/Linux, not iOS)
    #if ((defined(UNIX_MACOS) && !defined(UNIX_IOS)) || defined(UNIX_LINUX)) && !USE_ZIG_ADAPTER
        extern IP_CONFIG g_ip_config;
        g_ip_config.ip_version = client->ip_version;
        g_ip_config.use_static_ipv4 = client->use_static_ipv4;
        g_ip_config.use_static_ipv6 = client->use_static_ipv6;
        if (client->use_static_ipv4) {
            strncpy(g_ip_config.static_ipv4, client->static_ipv4, sizeof(g_ip_config.static_ipv4) - 1);
            strncpy(g_ip_config.static_ipv4_netmask, client->static_ipv4_netmask, sizeof(g_ip_config.static_ipv4_netmask) - 1);
            strncpy(g_ip_config.static_ipv4_gateway, client->static_ipv4_gateway, sizeof(g_ip_config.static_ipv4_gateway) - 1);
        }
        if (client->use_static_ipv6) {
            strncpy(g_ip_config.static_ipv6, client->static_ipv6, sizeof(g_ip_config.static_ipv6) - 1);
            g_ip_config.static_ipv6_prefix = client->static_ipv6_prefix;
            strncpy(g_ip_config.static_ipv6_gateway, client->static_ipv6_gateway, sizeof(g_ip_config.static_ipv6_gateway) - 1);
        }
        LOG_VPN_INFO("IP configuration set: version=%d, static_v4=%d, static_v6=%d\n",
                     g_ip_config.ip_version, g_ip_config.use_static_ipv4, g_ip_config.use_static_ipv6);
    #endif
    
    // Create packet adapter
    PACKET_ADAPTER* pa = NULL;
    
    // Create packet adapter based on platform and compile-time configuration
    LOG_DEBUG("VPN", "Creating packet adapter (use_zig_adapter=%d)", client->use_zig_adapter);
    
    #if USE_ZIG_ADAPTER && (defined(UNIX_IOS) || defined(UNIX_MACOS))
        // iOS/macOS: Use Zig adapter (universal DHCP support)
        pa = NewZigPacketAdapter();
        if (pa) {
            LOG_INFO("VPN", "✅ Using Zig packet adapter (optimized for iOS/macOS)");
        } else {
            LOG_ERROR("VPN", "❌ Failed to create Zig packet adapter");
        }
    #elif defined(UNIX_IOS)
        // Legacy iOS: Use specialized iOS packet adapter (NEPacketTunnelProvider integration)
        pa = NewIosPacketAdapter();
        if (pa) {
            LOG_INFO("VPN", "✅ Using iOS packet adapter (optimized for NEPacketTunnelProvider)");
        } else {
            LOG_ERROR("VPN", "❌ Failed to create iOS packet adapter");
        }
    #else
        // Other platforms: Use Zig adapter
        pa = NewZigPacketAdapter();
        if (pa) {
            LOG_INFO("VPN", "✅ Using Zig packet adapter (with TUN device management)");
        } else {
            LOG_ERROR("VPN", "❌ Failed to create Zig packet adapter");
        }
    #endif
    
    if (!pa) {
        LOG_ERROR("VPN", "❌ Failed to create packet adapter");
        
        // Update reconnection state
        client->consecutive_failures++;
        client->last_disconnect_time = get_current_time_ms();
        client->current_backoff_seconds = vpn_bridge_calculate_backoff(client);
        client->next_reconnect_time = client->last_disconnect_time + (client->current_backoff_seconds * 1000);
        
        // FIX LEAK #2: Clean up allocated structures
        Free(opt);
        secure_zero_explicit(auth, sizeof(CLIENT_AUTH));
        Free(auth);
        DeleteLock(account->lock);
        Free(account);
        client->last_error = VPN_BRIDGE_ERROR_CONNECT_FAILED;
        client->status = VPN_STATUS_ERROR;
        return VPN_BRIDGE_ERROR_CONNECT_FAILED;
    }
    LOG_DEBUG("VPN", "Packet adapter created (Id=%u)", pa->Id);
    
    client->packet_adapter = pa;
    
    LOG_DEBUG("VPN", "Creating VPN session");
    
    // Create session - this will automatically connect in background
    SESSION* session = NewClientSessionEx(
        client->softether_client->Cedar,
        opt,
        auth,
        pa,
        account
    );
    
    if (!session) {
        LOG_ERROR("VPN", "Failed to create VPN session");
        
        // Update reconnection state
        client->consecutive_failures++;
        client->last_disconnect_time = get_current_time_ms();
        client->current_backoff_seconds = vpn_bridge_calculate_backoff(client);
        client->next_reconnect_time = client->last_disconnect_time + (client->current_backoff_seconds * 1000);
        
        FreePacketAdapter(pa);
        // FIX LEAK #3: Clean up allocated structures
        Free(opt);
        secure_zero_explicit(auth, sizeof(CLIENT_AUTH));
        Free(auth);
        DeleteLock(account->lock);
        Free(account);
        client->last_error = VPN_BRIDGE_ERROR_CONNECT_FAILED;
        client->status = VPN_STATUS_ERROR;
        return VPN_BRIDGE_ERROR_CONNECT_FAILED;
    }
    
    client->softether_session = session;
    account->ClientSession = session;
    
    LOG_INFO("VPN", "Session created - connecting in background (async mode for mobile)");
    LOG_INFO("VPN", "Initial session state: ClientStatus=%u Halt=%d Err=%u", 
             session->ClientStatus, session->Halt, session->Err);
    
    // For mobile/iOS: Return immediately, connection continues in background
    // Status will be reported via callbacks when session->ClientStatus changes
    client->status = VPN_STATUS_CONNECTING;
    client->last_error = VPN_BRIDGE_SUCCESS;
    
    // Reset reconnection state on successful session creation
    vpn_bridge_reset_reconnect_state(client);
    
    return VPN_BRIDGE_SUCCESS;
}

/* ============================================
 * Disconnection
 * ============================================ */

int vpn_bridge_disconnect(VpnBridgeClient* client) {
    SESSION* session;
    
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Mark as user-requested disconnect to prevent reconnection
    vpn_bridge_mark_user_disconnect(client);
    
    if (client->status != VPN_STATUS_CONNECTED) {
        return VPN_BRIDGE_ERROR_NOT_CONNECTED;
    }
    
    LOG_INFO("VPN", "Disconnecting from server");
    
    // Save session pointer and clear it first to avoid double-free
    session = client->softether_session;
    client->softether_session = NULL;
    client->packet_adapter = NULL; // Will be freed by SESSION cleanup
    
    // Stop and release SESSION
    // Note: StopSession waits for ClientThread to finish
    // The ClientThread will call ReleaseSession twice before exiting, which will free the session
    // So we should NOT call ReleaseSession ourselves!
    if (session) {
        LOG_DEBUG("VPN", "Stopping session (waiting for ClientThread to exit)");
        StopSession(session);
        LOG_DEBUG("VPN", "Session stopped successfully");
        // Session is now freed by ClientThread - don't touch it!
        // DO NOT call ReleaseSession here!
    }
    
    // Cleanup ACCOUNT
    if (client->softether_account) {
        ACCOUNT* account = client->softether_account;
        account->ClientSession = NULL;
        
        if (account->lock) {
            DeleteLock(account->lock);
        }
        
        // CLIENT_OPTION and CLIENT_AUTH are freed by SESSION
        Free(account);
        client->softether_account = NULL;
    }
    
    // Cleanup IPC connection
    if (client->softether_ipc) {
        FreeIPC(client->softether_ipc);
        client->softether_ipc = NULL;
    }
    
    client->status = VPN_STATUS_DISCONNECTED;
    client->last_error = VPN_BRIDGE_SUCCESS;
    
    LOG_INFO("VPN", "Disconnected successfully");
    
    return VPN_BRIDGE_SUCCESS;
}

VpnBridgeStatus vpn_bridge_get_status(const VpnBridgeClient* client) {
    if (!client) {
        return VPN_STATUS_ERROR;
    }
    
    // Cast away const to allow status updates during health checks
    VpnBridgeClient* mutable_client = (VpnBridgeClient*)client;
    
    // If we have an active session, check its real-time health
    if (client->softether_session) {
        SESSION* s = client->softether_session;
        
        // Lock and read session state atomically
        Lock(s->lock);
        bool halted = s->Halt;
        UINT session_status = s->ClientStatus;
        UINT session_err = s->Err;
        Unlock(s->lock);
        
        // Debug: Log ALL status checks for iOS troubleshooting (no filtering)
        // Status values: 0=CONNECTING, 1=NEGOTIATION, 2=AUTH, 3=ESTABLISHED, 4=RETRY, 5=IDLE
        LOG_INFO("VPN", "Status check: ClientStatus=%u Halt=%d Err=%u bridge_status=%u", 
                 session_status, halted, session_err, mutable_client->status);
        
        // Check for FATAL errors
        if (halted && session_err != 0) {
            LOG_INFO("VPN", "❌ Session HALTED with error: Err=%u (9=AUTH_FAILED, 22=DEVICE_ERROR)", session_err);
            mutable_client->status = VPN_STATUS_ERROR;
            mutable_client->last_error = session_err;
            return VPN_STATUS_ERROR;
        }
        
        // CRITICAL: Check if we're in RETRY state with an error
        // ClientStatus=4 (RETRY) means connection attempt failed and waiting to retry
        // If Err != 0 in RETRY state, the error is real (e.g., auth failure)
        if (session_status == CLIENT_STATUS_RETRY && session_err != 0) {
            LOG_INFO("VPN", "❌ Connection in RETRY state with Err=%u - authentication failed", session_err);
            mutable_client->status = VPN_STATUS_ERROR;
            mutable_client->last_error = session_err;
            return VPN_STATUS_ERROR;
        }
        
        // CRITICAL: Check if we're in ESTABLISHED state but with a persistent error
        // If Err != 0 while ESTABLISHED, authentication/connection has failed
        // Desktop client would have Err=0 when successfully connected
        if (session_status == CLIENT_STATUS_ESTABLISHED && session_err != 0) {
            LOG_INFO("VPN", "❌ Connection ESTABLISHED but with error Err=%u - authentication failed", session_err);
            mutable_client->status = VPN_STATUS_ERROR;
            mutable_client->last_error = session_err;
            return VPN_STATUS_ERROR;
        }
        
        if (session_status == CLIENT_STATUS_ESTABLISHED) {
            // Update client status to CONNECTED if it's still CONNECTING
            if (mutable_client->status == VPN_STATUS_CONNECTING) {
                LOG_INFO("VPN", "✓ Session ESTABLISHED with Err=0 - connection successful!");
                mutable_client->status = VPN_STATUS_CONNECTED;
                mutable_client->connect_time = Tick64();
                mutable_client->last_error = VPN_BRIDGE_SUCCESS;
            }
            return VPN_STATUS_CONNECTED;
        } else if (session_status == CLIENT_STATUS_CONNECTING ||
                   session_status == CLIENT_STATUS_NEGOTIATION ||
                   session_status == CLIENT_STATUS_AUTH) {
            return VPN_STATUS_CONNECTING;
        } else if (halted || session_status == CLIENT_STATUS_IDLE) {
            // Session died! Update our status to trigger reconnection
            if (mutable_client->status == VPN_STATUS_CONNECTED) {
                LOG_WARN("VPN", "Session died (Halt=%d, Status=%u), triggering reconnection", 
                         halted, session_status);
                
                // Update status to disconnected
                mutable_client->status = VPN_STATUS_DISCONNECTED;
                
                // Update reconnection state
                mutable_client->last_disconnect_time = get_current_time_ms();
                mutable_client->consecutive_failures++;
                mutable_client->reconnect_attempt++;
                mutable_client->current_backoff_seconds = vpn_bridge_calculate_backoff(mutable_client);
                mutable_client->next_reconnect_time = mutable_client->last_disconnect_time + 
                                                      (mutable_client->current_backoff_seconds * 1000);
                
                if (mutable_client->reconnect_enabled && !mutable_client->user_requested_disconnect) {
                    if (mutable_client->max_reconnect_attempts == 0) {
                        LOG_INFO("VPN", "Will retry connection in %u seconds (attempt %u, unlimited retries)",
                                 mutable_client->current_backoff_seconds, mutable_client->reconnect_attempt);
                    } else if (mutable_client->reconnect_attempt < mutable_client->max_reconnect_attempts) {
                        LOG_INFO("VPN", "Will retry connection in %u seconds (attempt %u/%u)",
                                 mutable_client->current_backoff_seconds, 
                                 mutable_client->reconnect_attempt,
                                 mutable_client->max_reconnect_attempts);
                    } else {
                        LOG_WARN("VPN", "Max reconnection attempts (%u) will be exceeded on next attempt",
                                 mutable_client->max_reconnect_attempts);
                    }
                }
            }
            return VPN_STATUS_DISCONNECTED;
        }
    }
    
    return client->status;
}

/* ============================================
 * Connection Information
 * ============================================ */

int vpn_bridge_get_connection_info(
    const VpnBridgeClient* client,
    uint64_t* bytes_sent,
    uint64_t* bytes_received,
    uint64_t* connected_time
) {
    if (!client || !bytes_sent || !bytes_received || !connected_time) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Get real statistics from SESSION if available
    if (client->softether_session) {
        SESSION* s = client->softether_session;
        
        // Safely read stats with lock
        Lock(s->lock);
        {
            *bytes_sent = s->TotalSendSize;
            *bytes_received = s->TotalRecvSize;
        }
        Unlock(s->lock);
    } else {
        *bytes_sent = client->bytes_sent;
        *bytes_received = client->bytes_received;
    }
    
    if (client->connect_time > 0 && client->status == VPN_STATUS_CONNECTED) {
        *connected_time = (Tick64() - client->connect_time) / 1000;
    } else {
        *connected_time = 0;
    }
    
    return VPN_BRIDGE_SUCCESS;
}

uint32_t vpn_bridge_get_last_error(const VpnBridgeClient* client) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    return client->last_error;
}

// Get DHCP information
int vpn_bridge_get_dhcp_info(const VpnBridgeClient* client, VpnBridgeDhcpInfo* dhcp_info) {
    if (!client || !dhcp_info) {
        LOG_ERROR("BRIDGE", "vpn_bridge_get_dhcp_info: Invalid parameters");
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Clear the structure
    Zero(dhcp_info, sizeof(VpnBridgeDhcpInfo));
    dhcp_info->valid = false;
    
    LOG_INFO("BRIDGE", "vpn_bridge_get_dhcp_info: Checking session status=%d (need %d=CONNECTED)", 
             client->status, VPN_STATUS_CONNECTED);
    
    if (!client->softether_session || client->status != VPN_STATUS_CONNECTED) {
        LOG_INFO("BRIDGE", "vpn_bridge_get_dhcp_info: Session not ready (session=%p, status=%d)", 
                 client->softether_session, client->status);
        return VPN_BRIDGE_ERROR_NOT_CONNECTED;
    }
    
    LOG_INFO("BRIDGE", "vpn_bridge_get_dhcp_info: Session OK, checking ClientStatus...");
    
    // ============================================================================
    // PROPER STATIC IP CONFIGURATION SUPPORT
    // SoftEther VPN uses MAC-level virtual routing, not real IP routing!
    // The actual IP values don't matter much - desktop works with broadcast IP!
    // What matters: netmask in correct byte order
    // ============================================================================
    
    SESSION *s = client->softether_session;
    LOG_INFO("BRIDGE", "vpn_bridge_get_dhcp_info: s=%p, ClientStatus=%d (need %d=ESTABLISHED)", 
             s, s ? s->ClientStatus : -1, CLIENT_STATUS_ESTABLISHED);
    
    if (s != NULL && s->ClientStatus == CLIENT_STATUS_ESTABLISHED) {
        // Check if static IPv4 configuration is provided
        if (client->use_static_ipv4 && 
            client->static_ipv4[0] != '\0' &&
            client->static_ipv4_netmask[0] != '\0') {
            
            printf("[vpn_bridge_get_dhcp_info] ✅ Using STATIC IPv4 config from settings\n");
            
            // Parse static IP configuration
            IP ip, mask, gw;
            StrToIP(&ip, client->static_ipv4);
            StrToIP(&mask, client->static_ipv4_netmask);
            
            if (client->static_ipv4_gateway[0] != '\0') {
                StrToIP(&gw, client->static_ipv4_gateway);
            } else {
                // Default gateway: use first address in subnet
                UINT ip_uint = IPToUINT(&ip);
                UINT mask_uint = IPToUINT(&mask);
                UINT gw_uint = (ip_uint & mask_uint) | 0x01000000; // x.x.x.1 in network byte order
                UINTToIP(&gw, gw_uint);
            }
            
            dhcp_info->client_ip = IPToUINT(&ip);
            dhcp_info->subnet_mask = IPToUINT(&mask);
            dhcp_info->gateway = IPToUINT(&gw);
            
            printf("[vpn_bridge_get_dhcp_info] 📡 Static IP=%s, Mask=%s, GW=%s\n",
                   client->static_ipv4, client->static_ipv4_netmask, 
                   client->static_ipv4_gateway[0] ? client->static_ipv4_gateway : "(auto)");
            
        } else {
#ifdef UNIX_IOS
            // iOS: Get DHCP info from iOS adapter
            extern int ios_adapter_get_dhcp_info(uint32_t*, uint32_t*, uint32_t*, uint32_t*, uint32_t*);
            
            int result = ios_adapter_get_dhcp_info(
                &dhcp_info->client_ip,
                &dhcp_info->subnet_mask,
                &dhcp_info->gateway,
                &dhcp_info->dns_server1,
                &dhcp_info->dns_server2
            );
            
            if (result == 0) {
                printf("[vpn_bridge_get_dhcp_info] ✅ Using DHCP from iOS adapter: IP=%u.%u.%u.%u Mask=%u.%u.%u.%u GW=%u.%u.%u.%u\n",
                       (dhcp_info->client_ip >> 24) & 0xFF, (dhcp_info->client_ip >> 16) & 0xFF, 
                       (dhcp_info->client_ip >> 8) & 0xFF, dhcp_info->client_ip & 0xFF,
                       (dhcp_info->subnet_mask >> 24) & 0xFF, (dhcp_info->subnet_mask >> 16) & 0xFF, 
                       (dhcp_info->subnet_mask >> 8) & 0xFF, dhcp_info->subnet_mask & 0xFF,
                       (dhcp_info->gateway >> 24) & 0xFF, (dhcp_info->gateway >> 16) & 0xFF, 
                       (dhcp_info->gateway >> 8) & 0xFF, dhcp_info->gateway & 0xFF);
            } else {
                printf("[vpn_bridge_get_dhcp_info] ⚠️ iOS DHCP not configured yet\n");
                return VPN_BRIDGE_ERROR_NOT_CONNECTED;
            }
#else
            // Check if using Zig adapter with DHCP-assigned IP
            if (s->PacketAdapter && s->PacketAdapter->Param) {
                ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
                
                // Check if DHCP has configured the interface (state >= DHCP_STATE_CONFIGURED)
                if (ctx->dhcp_state >= 5 && ctx->our_ip != 0) {
                    // Use DHCP-assigned values
                    dhcp_info->client_ip = ctx->our_ip;
                    dhcp_info->subnet_mask = ctx->offered_mask;
                    dhcp_info->gateway = ctx->offered_gw;
                    
                    printf("[vpn_bridge_get_dhcp_info] ✅ Using DHCP-assigned IP from Zig adapter: IP=%u.%u.%u.%u Mask=%u.%u.%u.%u GW=%u.%u.%u.%u\n",
                           (ctx->our_ip >> 24) & 0xFF, (ctx->our_ip >> 16) & 0xFF, (ctx->our_ip >> 8) & 0xFF, ctx->our_ip & 0xFF,
                           (ctx->offered_mask >> 24) & 0xFF, (ctx->offered_mask >> 16) & 0xFF, (ctx->offered_mask >> 8) & 0xFF, ctx->offered_mask & 0xFF,
                           (ctx->offered_gw >> 24) & 0xFF, (ctx->offered_gw >> 16) & 0xFF, (ctx->offered_gw >> 8) & 0xFF, ctx->offered_gw & 0xFF);
                } else {
                    // DHCP not ready yet - return error
                    printf("[vpn_bridge_get_dhcp_info] ⚠️ DHCP not configured yet (state=%d, our_ip=0x%08X)\n", ctx->dhcp_state, ctx->our_ip);
                    return VPN_BRIDGE_ERROR_NOT_CONNECTED;
                }
            } else {
                // No DHCP info available
                printf("[vpn_bridge_get_dhcp_info] ⚠️ DHCP not available (no adapter context)\n");
                return VPN_BRIDGE_ERROR_NOT_CONNECTED;
            }
#endif
        }
        
        // DNS servers: use configured DNS or fallback to Google DNS
        if (client->dns_server_count > 0 && client->dns_servers[0]) {
            IP dns1;
            StrToIP(&dns1, client->dns_servers[0]);
            dhcp_info->dns_server1 = IPToUINT(&dns1);
            printf("[vpn_bridge_get_dhcp_info] 🌐 DNS1=%s\n", client->dns_servers[0]);
        } else {
            dhcp_info->dns_server1 = 0x08080808;  // 8.8.8.8
        }
        
        if (client->dns_server_count > 1 && client->dns_servers[1]) {
            IP dns2;
            StrToIP(&dns2, client->dns_servers[1]);
            dhcp_info->dns_server2 = IPToUINT(&dns2);
            printf("[vpn_bridge_get_dhcp_info] 🌐 DNS2=%s\n", client->dns_servers[1]);
        } else {
            dhcp_info->dns_server2 = 0x08080404;  // 8.8.4.4
        }
        
        dhcp_info->dhcp_server = dhcp_info->gateway;
        dhcp_info->lease_time = 86400;
        StrCpy(dhcp_info->domain_name, sizeof(dhcp_info->domain_name), "vpn.local");
        dhcp_info->valid = true;
        
        return VPN_BRIDGE_SUCCESS;
    }
    
    LOG_INFO("BRIDGE", "vpn_bridge_get_dhcp_info: ❌ Session not ESTABLISHED (ClientStatus=%d, need %d)", 
             s ? s->ClientStatus : -1, CLIENT_STATUS_ESTABLISHED);
    return VPN_BRIDGE_ERROR_NOT_CONNECTED;
}

const char* vpn_bridge_get_error_message(int error_code) {
    return get_error_message_internal(error_code);
}

/* ============================================
 * Version Information
 * ============================================ */

const char* vpn_bridge_version(void) {
    return "0.1.0-bridge";
}

const char* vpn_bridge_softether_version(void) {
    // TODO: Return real SoftEther version
    // return CEDAR_VERSION_STR;
    return "4.44-9807 (stub)";
}

/* ============================================
 * Utility Functions Implementation
 * ============================================ */

int vpn_bridge_generate_password_hash(
    const char* username,
    const char* password,
    char* output,
    size_t output_size
) {
    if (!username || !password || !output || output_size < 32) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }

    // Generate the hash using SoftEther's HashPassword function
    UCHAR hash[20];  // SHA-0 produces 20 bytes (SHA1_SIZE)
    HashPassword(hash, (char*)username, (char*)password);

    // Base64 encode the hash
    char encoded[64];  // Base64 of 20 bytes needs ~28 chars + null
    int encoded_len = B64_Encode(encoded, (char*)hash, 20);
    if (encoded_len <= 0) {
        return VPN_BRIDGE_ERROR_INIT_FAILED;
    }

    // Copy to output buffer
    if ((size_t)encoded_len >= output_size) {
        return VPN_BRIDGE_ERROR_ALLOC_FAILED;
    }

    strcpy(output, encoded);
    output[encoded_len] = '\0';  // Explicit null terminator for safety

    return VPN_BRIDGE_SUCCESS;
}

/* ============================================
 * Runtime Network Information Implementation
 * ============================================ */

int vpn_bridge_get_device_name(
    const VpnBridgeClient* client,
    char* output,
    size_t output_size
) {
    if (!client || !output || output_size == 0) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }

    if (!client->softether_session || !client->softether_session->PacketAdapter) {
        // Not connected - return placeholder
        strncpy(output, "not_connected", output_size - 1);
        output[output_size - 1] = '\0';
        return VPN_BRIDGE_SUCCESS;
    }

    // Get device name based on adapter type
    #if USE_ZIG_ADAPTER && (defined(UNIX_MACOS) || defined(UNIX_IOS))
        // Zig adapter - get name from adapter
        ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)client->softether_session->PacketAdapter->Param;
        if (ctx && ctx->zig_adapter) {
            const size_t len = zig_adapter_get_device_name(ctx->zig_adapter, (uint8_t*)output, output_size);
            if (len > 0) {
                return VPN_BRIDGE_SUCCESS;
            }
        }
        strncpy(output, "utun?", output_size - 1);
        output[output_size - 1] = '\0';
    #elif defined(UNIX_MACOS) && !defined(UNIX_IOS)
        // Legacy C adapter - get from context
        MACOS_TUN_CONTEXT* ctx = (MACOS_TUN_CONTEXT*)client->softether_session->PacketAdapter->Param;
        if (ctx && ctx->device_name[0] != '\0') {
            strncpy(output, ctx->device_name, output_size - 1);
            output[output_size - 1] = '\0';
        } else {
            strncpy(output, "utun?", output_size - 1);
            output[output_size - 1] = '\0';
        }
    #else
        // Other platforms (iOS, Linux, Windows) - return generic name
        strncpy(output, "tun0", output_size - 1);
        output[output_size - 1] = '\0';
    #endif

    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_get_learned_ip(
    const VpnBridgeClient* client,
    uint32_t* ip
) {
    if (!client || !ip) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }

    *ip = 0;  // Default: not learned

    if (!client->softether_session || !client->softether_session->PacketAdapter) {
        return VPN_BRIDGE_SUCCESS;
    }

    // Skip for Zig adapter - Zig adapter manages TUN internally
    #if USE_ZIG_ADAPTER
        return VPN_BRIDGE_SUCCESS;
    #elif (defined(UNIX_MACOS) && !defined(UNIX_IOS)) || defined(UNIX_LINUX)
        // Try to get IP from translator (only for C adapter)
        void* ctx_ptr = client->softether_session->PacketAdapter->Param;
        if (!ctx_ptr) {
            return VPN_BRIDGE_SUCCESS;
        }

        #if defined(UNIX_MACOS) && !defined(UNIX_IOS)
            // C adapter uses translator
            MACOS_TUN_CONTEXT* ctx = (MACOS_TUN_CONTEXT*)ctx_ptr;
            if (ctx->translator) {
                *ip = taptun_get_learned_ip(ctx->translator);
            }
        #endif
        // Linux implementation can be added similarly
    #endif

    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_get_gateway_mac(
    const VpnBridgeClient* client,
    uint8_t* mac,
    uint32_t* has_mac
) {
    if (!client || !mac || !has_mac) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }

    *has_mac = 0;  // Default: not learned
    memset(mac, 0, 6);

    if (!client->softether_session || !client->softether_session->PacketAdapter) {
        return VPN_BRIDGE_SUCCESS;
    }

    // Try to get MAC from translator
    #if USE_ZIG_ADAPTER
        // Zig adapter: translator is inside the Zig adapter structure
        // For now, skip MAC retrieval (Zig adapter handles it internally)
        // TODO: Add zig_adapter_get_gateway_mac() function
        return VPN_BRIDGE_SUCCESS;
    #elif (defined(UNIX_MACOS) && !defined(UNIX_IOS)) || defined(UNIX_LINUX)
        void* ctx_ptr = client->softether_session->PacketAdapter->Param;
        if (!ctx_ptr) {
            return VPN_BRIDGE_SUCCESS;
        }

        #if defined(UNIX_MACOS) && !defined(UNIX_IOS)
            // C adapter: translator is in MACOS_TUN_CONTEXT
            MACOS_TUN_CONTEXT* ctx = (MACOS_TUN_CONTEXT*)ctx_ptr;
            if (ctx->translator) {
                *has_mac = taptun_get_gateway_mac(ctx->translator, mac) ? 1 : 0;
            }
        #endif
        // Linux implementation can be added similarly
    #endif

    return VPN_BRIDGE_SUCCESS;
}

/* ============================================
 * IP Configuration Functions
 * ============================================ */

int vpn_bridge_set_ip_version(VpnBridgeClient* client, int ip_version) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    if (ip_version < VPN_IP_VERSION_AUTO || ip_version > VPN_IP_VERSION_DUAL) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    client->ip_version = ip_version;
    LOG_VPN_INFO("IP version set to: %d\n", ip_version);
    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_set_max_connection(VpnBridgeClient* client, uint32_t max_connection) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    if (max_connection < 1 || max_connection > 32) {
        LOG_VPN_ERROR("max_connection must be 1-32, got %u\n", max_connection);
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    client->max_connection = max_connection;
    LOG_VPN_INFO("🔗 Max connections set to %u\n", max_connection);
    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_set_static_ipv4(VpnBridgeClient* client, const char* ip, const char* netmask, const char* gateway) {
    if (!client || !ip) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    strncpy(client->static_ipv4, ip, sizeof(client->static_ipv4) - 1);
    if (netmask) {
        strncpy(client->static_ipv4_netmask, netmask, sizeof(client->static_ipv4_netmask) - 1);
    }
    if (gateway) {
        strncpy(client->static_ipv4_gateway, gateway, sizeof(client->static_ipv4_gateway) - 1);
    }
    client->use_static_ipv4 = true;
    
    LOG_VPN_INFO("Static IPv4 configured: %s/%s via %s\n", 
                 ip, netmask ? netmask : "(none)", gateway ? gateway : "(none)");
    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_set_static_ipv6(VpnBridgeClient* client, const char* ip, uint8_t prefix_len, const char* gateway) {
    if (!client || !ip) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    strncpy(client->static_ipv6, ip, sizeof(client->static_ipv6) - 1);
    client->static_ipv6_prefix = prefix_len;
    if (gateway) {
        strncpy(client->static_ipv6_gateway, gateway, sizeof(client->static_ipv6_gateway) - 1);
    }
    client->use_static_ipv6 = true;
    
    LOG_VPN_INFO("Static IPv6 configured: %s/%d via %s\n", 
                 ip, prefix_len, gateway ? gateway : "(none)");
    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_set_dns_servers(VpnBridgeClient* client, const char** dns_servers, int count) {
    if (!client || !dns_servers || count < 0 || count > 8) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    // Free existing DNS servers
    for (int i = 0; i < client->dns_server_count; i++) {
        if (client->dns_servers[i]) {
            Free(client->dns_servers[i]);
            client->dns_servers[i] = NULL;
        }
    }
    
    // Copy new DNS servers
    client->dns_server_count = count;
    for (int i = 0; i < count; i++) {
        size_t len = strlen(dns_servers[i]) + 1;
        client->dns_servers[i] = (char*)Malloc(len);
        strncpy(client->dns_servers[i], dns_servers[i], len);
        LOG_VPN_INFO("DNS server %d: %s\n", i + 1, dns_servers[i]);
    }
    
    return VPN_BRIDGE_SUCCESS;
}

int vpn_bridge_set_use_zig_adapter(VpnBridgeClient* client, int use_zig_adapter) {
    if (!client) {
        return VPN_BRIDGE_ERROR_INVALID_PARAM;
    }
    
    if (client->status != VPN_STATUS_DISCONNECTED) {
        LOG_ERROR("VPN", "Cannot change adapter type while connected");
        return VPN_BRIDGE_ERROR_INVALID_STATE;
    }
    
    client->use_zig_adapter = use_zig_adapter ? 1 : 0;
    LOG_VPN_INFO("Packet adapter set to: %s\n", 
                 client->use_zig_adapter ? "Zig (experimental)" : "C (default)");
    
    return VPN_BRIDGE_SUCCESS;
}

/* ============================================
 * Packet I/O for Mobile Integration
 * ============================================ */

int vpn_bridge_read_packet(
    VpnBridgeClient* client,
    uint8_t* buffer,
    uint32_t buffer_len,
    uint32_t timeout_ms
) {
    if (!client || !buffer || buffer_len == 0) {
        return -1;
    }
    
    if (client->status != VPN_STATUS_CONNECTED || !client->softether_session) {
        return -1;
    }
    
    SESSION* session = client->softether_session;
    if (!session || !session->PacketAdapter) {
        LOG_ERROR("VPN", "❌ read_packet: session=%p PacketAdapter=%p", session, session ? session->PacketAdapter : NULL);
        return -1;
    }
    
    static uint64_t read_call_count = 0;
    read_call_count++;
    
#ifdef UNIX_IOS
    // **iOS DIRECT PATH**: Call ios_adapter_get_outgoing_packet to get IP packets
    // This bypasses SessionMain's Ethernet-based routing and returns L3 IP packets
    // directly to PacketTunnelProvider (which needs IP, not Ethernet)
    
    extern int ios_adapter_get_outgoing_packet(uint8_t* buffer, uint32_t buffer_size, void (*log_callback)(const char*, int));
    
    // Callback for Zig logging
    extern void zig_ios_log(const char* msg, int value); // Reuse existing callback from zig_packet_adapter.c
    
    int packet_size = ios_adapter_get_outgoing_packet(buffer, buffer_len, zig_ios_log);
    
    if (read_call_count <= 10) {
        LOG_INFO("VPN", "📡 read_packet #%llu: ios_adapter_get_outgoing_packet returned size=%d", read_call_count, packet_size);
    }
    
    return packet_size;  // Return directly (IP packet or 0 if none, -1 on error)
#else
    // **macOS/Linux/Android**: Use the packet adapter's GetNextPacket function
    void* packet_data = NULL;
    UINT packet_size = session->PacketAdapter->GetNextPacket(session, &packet_data);
    
    if (read_call_count <= 10) {
        LOG_INFO("VPN", "📡 read_packet #%llu: GetNextPacket returned size=%u data=%p", read_call_count, packet_size, packet_data);
    }
    
    if (packet_size == 0 || !packet_data) {
        // No packet available
        return 0;
    }
    
    if (packet_size > buffer_len) {
        // Packet too large for buffer
        LOG_ERROR("VPN", "Packet size %u exceeds buffer size %u", packet_size, buffer_len);
        Free(packet_data);
        return -1;
    }
    
    // Copy packet data to output buffer
    memcpy(buffer, packet_data, packet_size);
    Free(packet_data);
#endif
    
    return (int)packet_size;
}

int vpn_bridge_write_packet(
    VpnBridgeClient* client,
    const uint8_t* data,
    uint32_t data_len
) {
    if (!client || !data || data_len == 0) {
        return -1;
    }
    
    if (client->status != VPN_STATUS_CONNECTED || !client->softether_session) {
        return -1;
    }
    
    SESSION* session = client->softether_session;
    if (!session || !session->PacketAdapter) {
        return -1;
    }
    
#ifdef UNIX_IOS
    // **iOS DIRECT PATH**: iOS sends L3 (IP) packets, need L3→L2 translation
    // Use ios_adapter_inject_packet which wraps IP in Ethernet headers
    extern int ios_adapter_inject_packet(const uint8_t* data, uint32_t length);
    
    int result = ios_adapter_inject_packet(data, data_len);
    return result; // Returns 0 on success, -1 on error
#else
    // **macOS/Linux/Android**: Allocate and use PutPacket directly
    // (These platforms send Ethernet frames already)
    void* packet_data = Malloc(data_len);
    if (!packet_data) {
        LOG_ERROR("VPN", "Failed to allocate packet buffer");
        return -1;
    }
    
    // Copy data to packet buffer
    memcpy(packet_data, data, data_len);
    
    // Use the packet adapter's PutPacket function
    bool result = session->PacketAdapter->PutPacket(session, packet_data, data_len);
    
    if (!result) {
        Free(packet_data);
        return -1;
    }
    
    return 0;
#endif
}


