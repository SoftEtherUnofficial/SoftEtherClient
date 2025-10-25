// Mobile FFI C Implementation for iOS - Full SoftEther VPN Integration
// Include SoftEther headers FIRST to get their bool typedef (before any standard headers)
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Now include our headers
#include "ffi.h"
#include "../bridge/softether_bridge.h"
#include "../bridge/client_bridge.h"
#include "../bridge/logging.h"
#include <stdlib.h>
#include <string.h>

static int g_initialized = 0;

typedef struct {
    MobileVpnConfig config;
    void* bridge_client;  // VpnBridgeClient handle
    VpnBridgeDhcpInfo dhcp_info;
    int is_connected;
    MobileStatusCallback status_callback;
    void* status_callback_context;
    MobileStatsCallback stats_callback;
    void* stats_callback_context;
    MobileNetworkCallback network_callback;
    void* network_callback_context;
} MobileVpnContextC;

// Initialize VPN subsystem
int mobile_vpn_init(void) {
    if (g_initialized) {
        return 0; // Already initialized
    }
    
    // Initialize SoftEther VPN bridge (debug=0)
    int result = vpn_bridge_init(0);
    if (result != 0) {
        return -1;
    }
    
    g_initialized = 1;
    return 0;
}

// Cleanup VPN subsystem
void mobile_vpn_cleanup(void) {
    if (!g_initialized) {
        return;
    }
    
    vpn_bridge_cleanup();
    g_initialized = 0;
}

// Create VPN client context
MobileVpnHandle mobile_vpn_create(const MobileVpnConfig* config) {
    if (!config) return NULL;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)calloc(1, sizeof(MobileVpnContextC));
    if (!ctx) return NULL;
    
    memcpy(&ctx->config, config, sizeof(MobileVpnConfig));
    
    // Create bridge client
    ctx->bridge_client = vpn_bridge_create_client();
    if (!ctx->bridge_client) {
        free(ctx);
        return NULL;
    }
    
    // Configure connection parameters
    // password_hash field contains pre-hashed password (SHA-0 base64)
    // Use vpn_bridge_configure_with_hash to skip double-hashing
    int result = vpn_bridge_configure_with_hash(
        ctx->bridge_client,
        config->server,
        config->port,
        config->hub,
        config->username,
        config->password_hash  // Pre-hashed password (base64 encoded SHA-0)
    );
    
    if (result != 0) {
        vpn_bridge_free_client(ctx->bridge_client);
        free(ctx);
        return NULL;
    }
    
    // Set advanced options if specified
    if (config->max_connection > 0) {
        vpn_bridge_set_max_connection(ctx->bridge_client, config->max_connection);
    }
    
    // Enable reconnection with reasonable defaults
    vpn_bridge_enable_reconnect(ctx->bridge_client, 0, 5, 300); // Infinite retries, 5s-300s backoff
    
    ctx->is_connected = 0;
    memset(&ctx->dhcp_info, 0, sizeof(VpnBridgeDhcpInfo));
    
    return (MobileVpnHandle)ctx;
}

// Destroy VPN client context
void mobile_vpn_destroy(MobileVpnHandle handle) {
    if (!handle) return;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    
    // Disconnect if still connected
    if (ctx->is_connected) {
        mobile_vpn_disconnect(handle);
    }
    
    // Destroy bridge client
    if (ctx->bridge_client) {
        vpn_bridge_free_client(ctx->bridge_client);
    }
    
    free(ctx);
}

// Connect to VPN server (async - connection completes in background)
int mobile_vpn_connect(MobileVpnHandle handle) {
    LOG_INFO("MOBILE_FFI", "=== mobile_vpn_connect: START ===");
    
    if (!handle) {
        LOG_INFO("MOBILE_FFI", "mobile_vpn_connect: NULL handle");
        return -1;
    }
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (ctx->is_connected) {
        LOG_INFO("MOBILE_FFI", "mobile_vpn_connect: Already connected");
        return 0; // Already connected
    }
    
    LOG_INFO("MOBILE_FFI", "mobile_vpn_connect: Calling vpn_bridge_connect...");
    
    // Notify connecting status
    if (ctx->status_callback) {
        ctx->status_callback(MOBILE_VPN_CONNECTING, ctx->status_callback_context);
    }
    
    // Establish VPN connection (async - returns immediately with CONNECTING status)
    int result = vpn_bridge_connect(ctx->bridge_client);
    LOG_INFO("MOBILE_FFI", "mobile_vpn_connect: vpn_bridge_connect returned %d", result);
    
    if (result != 0) {
        LOG_INFO("MOBILE_FFI", "mobile_vpn_connect: Connection failed!");
        if (ctx->status_callback) {
            ctx->status_callback(MOBILE_VPN_ERROR, ctx->status_callback_context);
        }
        return -1;
    }
    
    LOG_INFO("MOBILE_FFI", "mobile_vpn_connect: Connection initiated successfully");
    
    // SUCCESS: Connection initiated
    // Note: Connection completes in background. The caller should:
    // 1. Poll mobile_vpn_get_status() until it returns MOBILE_VPN_CONNECTED
    // 2. Then call mobile_vpn_get_network_info() to retrieve DHCP config
    // 3. Configure the network interface with the DHCP settings
    // 4. Start the packet pump with read_packet()/write_packet()
    
    return 0;
}

// Disconnect from VPN server
int mobile_vpn_disconnect(MobileVpnHandle handle) {
    if (!handle) return -1;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (!ctx->is_connected) {
        return 0; // Already disconnected
    }
    
    // Disconnect from bridge
    int result = vpn_bridge_disconnect(ctx->bridge_client);
    
    ctx->is_connected = 0;
    memset(&ctx->dhcp_info, 0, sizeof(VpnBridgeDhcpInfo));
    
    // Notify disconnected status
    if (ctx->status_callback) {
        ctx->status_callback(MOBILE_VPN_DISCONNECTED, ctx->status_callback_context);
    }
    
    return result;
}

// Check if connected to VPN (checks actual bridge status, not cached flag)
bool mobile_vpn_is_connected(MobileVpnHandle handle) {
    if (!handle) return false;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (!ctx->bridge_client) return false;
    
    // Check actual bridge status (dynamic check)
    VpnBridgeStatus status = vpn_bridge_get_status(ctx->bridge_client);
    
    // Update internal flag for consistency
    if (status == VPN_STATUS_CONNECTED) {
        ctx->is_connected = 1;
        return true;
    } else {
        if (status == VPN_STATUS_DISCONNECTED || status == VPN_STATUS_ERROR) {
            ctx->is_connected = 0;
        }
        return false;
    }
}

// Get current VPN connection status
MobileVpnStatus mobile_vpn_get_status(MobileVpnHandle handle) {
    if (!handle) {
        LOG_INFO("MOBILE_FFI", "mobile_vpn_get_status: NULL handle");
        return MOBILE_VPN_ERROR;
    }
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    
    if (!ctx->bridge_client) {
        LOG_INFO("MOBILE_FFI", "mobile_vpn_get_status: NULL bridge_client");
        return MOBILE_VPN_ERROR;
    }
    
    LOG_INFO("MOBILE_FFI", "mobile_vpn_get_status: calling vpn_bridge_get_status...");
    
    // Get bridge status
    VpnBridgeStatus bridge_status = vpn_bridge_get_status(ctx->bridge_client);
    
    LOG_INFO("MOBILE_FFI", "mobile_vpn_get_status: bridge returned status=%u", bridge_status);
    
    // Map bridge status to mobile status
    switch (bridge_status) {
        case VPN_STATUS_DISCONNECTED:
            ctx->is_connected = 0;
            return MOBILE_VPN_DISCONNECTED;
        case VPN_STATUS_CONNECTING:
            return MOBILE_VPN_CONNECTING;
        case VPN_STATUS_CONNECTED:
            ctx->is_connected = 1;
            return MOBILE_VPN_CONNECTED;
        case VPN_STATUS_ERROR:
            ctx->is_connected = 0;
            return MOBILE_VPN_ERROR;
        default:
            return MOBILE_VPN_ERROR;
    }
}

// Get VPN connection statistics
int mobile_vpn_get_stats(MobileVpnHandle handle, MobileVpnStats* stats) {
    if (!handle || !stats) return -1;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (!ctx->bridge_client || !ctx->is_connected) {
        memset(stats, 0, sizeof(MobileVpnStats));
        return -1;
    }
    
    // Get statistics from bridge
    uint64_t bytes_sent = 0, bytes_received = 0, connected_time = 0;
    int result = vpn_bridge_get_connection_info(
        ctx->bridge_client,
        &bytes_sent,
        &bytes_received,
        &connected_time
    );
    
    if (result != 0) {
        memset(stats, 0, sizeof(MobileVpnStats));
        return -1;
    }
    
    // Fill mobile stats structure
    stats->bytes_sent = bytes_sent;
    stats->bytes_received = bytes_received;
    stats->packets_sent = 0;  // Not tracked by bridge
    stats->packets_received = 0;  // Not tracked by bridge
    stats->connected_duration_ms = connected_time * 1000;  // Convert to ms
    stats->queue_drops = 0;
    stats->errors = 0;
    
    return 0;
}

// Read packet from VPN tunnel
int mobile_vpn_read_packet(MobileVpnHandle handle, uint8_t* buffer, uint64_t buffer_len, uint32_t timeout_ms) {
    if (!handle || !buffer || buffer_len == 0) return -1;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (!ctx->bridge_client || !ctx->is_connected) {
        return -1;
    }
    
    // Read packet from bridge session
    return vpn_bridge_read_packet(
        ctx->bridge_client,
        buffer,
        (uint32_t)buffer_len,
        timeout_ms
    );
}

// Write packet to VPN tunnel
int mobile_vpn_write_packet(MobileVpnHandle handle, const uint8_t* data, uint64_t data_len) {
    if (!handle || !data || data_len == 0) return -1;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (!ctx->bridge_client || !ctx->is_connected) {
        return -1;
    }
    
    // Write packet to bridge session
    return vpn_bridge_write_packet(
        ctx->bridge_client,
        data,
        (uint32_t)data_len
    );
}

// Get network configuration from VPN DHCP
int mobile_vpn_get_network_info(MobileVpnHandle handle, MobileNetworkInfo* info) {
    if (!handle || !info) return -1;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (!ctx->bridge_client || !ctx->is_connected) {
        memset(info, 0, sizeof(MobileNetworkInfo));
        return -1;
    }
    
    // Fetch fresh DHCP info from the bridge
    VpnBridgeDhcpInfo bridge_dhcp;
    int result = vpn_bridge_get_dhcp_info(ctx->bridge_client, &bridge_dhcp);
    
    if (result != 0 || !bridge_dhcp.valid) {
        printf("[mobile_vpn_get_network_info] Failed to get DHCP info from bridge (result=%d, valid=%d)\n", result, bridge_dhcp.valid);
        memset(info, 0, sizeof(MobileNetworkInfo));
        return -1;
    }
    
    printf("[mobile_vpn_get_network_info] Got DHCP: IP=%u.%u.%u.%u Gateway=%u.%u.%u.%u Mask=%u.%u.%u.%u\n",
           (bridge_dhcp.client_ip >> 24) & 0xFF, (bridge_dhcp.client_ip >> 16) & 0xFF,
           (bridge_dhcp.client_ip >> 8) & 0xFF, bridge_dhcp.client_ip & 0xFF,
           (bridge_dhcp.gateway >> 24) & 0xFF, (bridge_dhcp.gateway >> 16) & 0xFF,
           (bridge_dhcp.gateway >> 8) & 0xFF, bridge_dhcp.gateway & 0xFF,
           (bridge_dhcp.subnet_mask >> 24) & 0xFF, (bridge_dhcp.subnet_mask >> 16) & 0xFF,
           (bridge_dhcp.subnet_mask >> 8) & 0xFF, bridge_dhcp.subnet_mask & 0xFF);
    
    // Convert uint32_t network byte order to byte arrays
    uint32_t client_ip = bridge_dhcp.client_ip;
    uint32_t gateway = bridge_dhcp.gateway;
    uint32_t netmask = bridge_dhcp.subnet_mask;
    uint32_t dns1 = bridge_dhcp.dns_server1;
    uint32_t dns2 = bridge_dhcp.dns_server2;
    
    // IP address (network byte order)
    info->ip_address[0] = (client_ip >> 24) & 0xFF;
    info->ip_address[1] = (client_ip >> 16) & 0xFF;
    info->ip_address[2] = (client_ip >> 8) & 0xFF;
    info->ip_address[3] = client_ip & 0xFF;
    
    // Gateway
    info->gateway[0] = (gateway >> 24) & 0xFF;
    info->gateway[1] = (gateway >> 16) & 0xFF;
    info->gateway[2] = (gateway >> 8) & 0xFF;
    info->gateway[3] = gateway & 0xFF;
    
    // Netmask
    info->netmask[0] = (netmask >> 24) & 0xFF;
    info->netmask[1] = (netmask >> 16) & 0xFF;
    info->netmask[2] = (netmask >> 8) & 0xFF;
    info->netmask[3] = netmask & 0xFF;
    
    // DNS servers
    info->dns_servers[0][0] = (dns1 >> 24) & 0xFF;
    info->dns_servers[0][1] = (dns1 >> 16) & 0xFF;
    info->dns_servers[0][2] = (dns1 >> 8) & 0xFF;
    info->dns_servers[0][3] = dns1 & 0xFF;
    
    info->dns_servers[1][0] = (dns2 >> 24) & 0xFF;
    info->dns_servers[1][1] = (dns2 >> 16) & 0xFF;
    info->dns_servers[1][2] = (dns2 >> 8) & 0xFF;
    info->dns_servers[1][3] = dns2 & 0xFF;
    
    // MTU (use standard 1500 or get from DHCP if available)
    info->mtu = 1500;
    
    return 0;
}

// Set network info (for manual DHCP configuration)
int mobile_vpn_set_network_info(MobileVpnHandle handle, const MobileNetworkInfo* info) {
    if (!handle || !info) return -1;
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    
    // Convert byte arrays back to uint32_t network byte order
    ctx->dhcp_info.client_ip = ((uint32_t)info->ip_address[0] << 24) |
                                ((uint32_t)info->ip_address[1] << 16) |
                                ((uint32_t)info->ip_address[2] << 8) |
                                ((uint32_t)info->ip_address[3]);
    
    ctx->dhcp_info.gateway = ((uint32_t)info->gateway[0] << 24) |
                             ((uint32_t)info->gateway[1] << 16) |
                             ((uint32_t)info->gateway[2] << 8) |
                             ((uint32_t)info->gateway[3]);
    
    ctx->dhcp_info.subnet_mask = ((uint32_t)info->netmask[0] << 24) |
                                  ((uint32_t)info->netmask[1] << 16) |
                                  ((uint32_t)info->netmask[2] << 8) |
                                  ((uint32_t)info->netmask[3]);
    
    ctx->dhcp_info.dns_server1 = ((uint32_t)info->dns_servers[0][0] << 24) |
                                  ((uint32_t)info->dns_servers[0][1] << 16) |
                                  ((uint32_t)info->dns_servers[0][2] << 8) |
                                  ((uint32_t)info->dns_servers[0][3]);
    
    ctx->dhcp_info.dns_server2 = ((uint32_t)info->dns_servers[1][0] << 24) |
                                  ((uint32_t)info->dns_servers[1][1] << 16) |
                                  ((uint32_t)info->dns_servers[1][2] << 8) |
                                  ((uint32_t)info->dns_servers[1][3]);
    
    ctx->dhcp_info.valid = 1;
    
    return 0;
}

// Set status callback
void mobile_vpn_set_status_callback(MobileVpnHandle handle, MobileStatusCallback callback, void* context) {
    if (!handle) return;
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    ctx->status_callback = callback;
    ctx->status_callback_context = context;
}

// Set stats callback (called periodically with connection statistics)
void mobile_vpn_set_stats_callback(MobileVpnHandle handle, MobileStatsCallback callback, void* context) {
    if (!handle) return;
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    ctx->stats_callback = callback;
    ctx->stats_callback_context = context;
}

// Set network callback (called when DHCP completes and network config is available)
void mobile_vpn_set_network_callback(MobileVpnHandle handle, MobileNetworkCallback callback, void* context) {
    if (!handle) return;
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    ctx->network_callback = callback;
    ctx->network_callback_context = context;
}

// Get last error message
const char* mobile_vpn_get_error(MobileVpnHandle handle) {
    if (!handle) return "Invalid handle";
    
    MobileVpnContextC* ctx = (MobileVpnContextC*)handle;
    if (!ctx->bridge_client) {
        return "No bridge client";
    }
    
    // Get last error from bridge
    uint32_t error_code = vpn_bridge_get_last_error(ctx->bridge_client);
    return vpn_bridge_get_error_message((int)error_code);
}

// Version
const char* mobile_vpn_get_version(void) {
    return vpn_bridge_softether_version();
}

// Build info
const char* mobile_vpn_get_build_info(void) {
    return "SoftEther VPN iOS/Mobile FFI - Built with Zig";
}

// Generate SoftEther password hash (SHA-0 based, base64 encoded)
int mobile_vpn_generate_password_hash(const char* username, const char* password, char* output, uint64_t output_size) {
    if (!username || !password || !output || output_size < 32) {
        return -1;
    }
    
    return vpn_bridge_generate_password_hash(username, password, output, (size_t)output_size);
}

// Stubs for undefined symbols - these should match Cedar's real signatures but return dummy values
// These are needed because the iOS build doesn't link the full Native Stack implementation
NATIVE_STACK* NewNativeStack(CEDAR *cedar, char *device_name, char *mac_address_seed) { return NULL; }
void FreeNativeStack(NATIVE_STACK *a) {}
void* NewMacOsTunAdapter(void) { return NULL; }
BOOL NsIsMacAddressOnLocalhost(UCHAR *mac) { return FALSE; }
BOOL NsStartIpTablesTracking(NATIVE_STACK *a) { return FALSE; }
int getch(void) { return 0; }
void* g_ip_config = NULL;

// Zig adapter stubs
void* zig_adapter_create(void) { return NULL; }
void zig_adapter_destroy(void* adapter) {}
int zig_adapter_open(void* adapter, const char* name) { return -1; }
void zig_adapter_stop(void* adapter) {}
int zig_adapter_configure_routing(void* adapter, void* ip, void* mask, void* gw) { return -1; }
int zig_adapter_set_gateway(void* adapter, void* ip) { return -1; }
int zig_adapter_set_gateway_mac(void* adapter, void* mac) { return -1; }
const char* zig_adapter_get_device_name(void* adapter) { return "ios0"; }
int zig_adapter_read_sync(void* adapter, void* buf, int len, int timeout) { return 0; }
int zig_adapter_write_sync(void* adapter, const void* buf, int len) { return 0; }
int zig_adapter_put_packet(void* adapter, const void* data, int len) { return 0; }
void zig_adapter_print_stats(void* adapter) {}
void* zig_build_dhcp_discover(void* mac, int* len) { *len = 0; return NULL; }
void* zig_build_dhcp_request(void* mac, void* ip, void* server, int* len) { *len = 0; return NULL; }
void* zig_build_arp_request(void* src_mac, void* src_ip, void* target_ip, int* len) { *len = 0; return NULL; }
void* zig_build_arp_reply(void* src_mac, void* src_ip, void* dst_mac, void* dst_ip, int* len) { *len = 0; return NULL; }
void* zig_build_gratuitous_arp(void* mac, void* ip, int* len) { *len = 0; return NULL; }
int zig_dhcp_parse(const void* data, int len, void* result) { return -1; }
