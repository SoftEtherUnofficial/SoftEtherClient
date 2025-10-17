/*
 * iOS FFI Adapter Stubs
 * 
 * This file implements the adapter interface expected by ios_compat.zig
 * It bridges the iOS FFI layer to the SoftEther VPN client implementation.
 * 
 * Architecture:
 *   ios_compat.zig (Zig FFI)
 *     ↓ calls zig_adapter_* functions
 *   ios_adapter_stubs.c (this file)
 *     ↓ calls SoftEther C API
 *   SoftEther VPN Client (Cedar/Mayaqua)
 */

#include "../bridge/Mayaqua/Mayaqua.h"
#include "../bridge/Mayaqua/TcpIp.h"
#include "../bridge/Cedar/Cedar.h"
#include "../bridge/Cedar/Client.h"
#include "../bridge/Cedar/Session.h"
#include "../bridge/Cedar/Connection.h"
#include "../bridge/Cedar/NullLan.h"
#include "../bridge/session_helper.h"
#include "../bridge/softether_bridge.h"
#include "../../include/zig_packet_adapter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdarg.h>
#include <unistd.h>

// ============================================================================
// Adapter Context
// ============================================================================

typedef struct {
    // SoftEther structures
    CLIENT *client;
    SESSION *session;
    ACCOUNT *account;
    
    // Callbacks
    void (*rx_callback)(const uint8_t* data, uint32_t len, void* user);
    void* rx_user_data;
    
    void (*ip_rx_callback)(const uint8_t* ip_packet, uint32_t len, void* user);
    void* ip_rx_user_data;
    
    void (*state_callback)(int state, void* user);
    void* state_user_data;
    
    void (*event_callback)(int level, int code, const char* message, void* user);
    void* event_user_data;
    
    // State
    bool connected;
    bool running;
    pthread_t rx_thread;
    pthread_mutex_t mutex;
    
    // Network configuration (from DHCP)
    char assigned_ipv4[64];
    char subnet_mask[64];
    char gateway[64];
    char dns_servers[256];
    uint8_t mac[6];
    
    // Parsed configuration (stored for later use)
    char server[256];
    char hub[128];
    char username[128];
    char password_hash[256];
    int port;
    bool use_encrypt;
    bool use_compress;
    int max_connection;
    
    // ARP table (simple array)
    struct {
        uint32_t ip;
        uint8_t mac[6];
        bool valid;
    } arp_table[256];
    int arp_table_count;
    
    // Error tracking
    char last_error[512];
} AdapterContext;

// ============================================================================
// Helper Functions
// ============================================================================

// Simple JSON value extractor (finds "key":"value" or "key":number)
static bool get_json_string(const char* json, const char* key, char* out, size_t out_size) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return false;
    
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    
    if (*pos == '"') {
        pos++;
        const char* end = strchr(pos, '"');
        if (!end) return false;
        
        size_t len = end - pos;
        if (len >= out_size) len = out_size - 1;
        memcpy(out, pos, len);
        out[len] = '\0';
        return true;
    }
    
    return false;
}

static int get_json_int(const char* json, const char* key, int default_val) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return default_val;
    
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    
    return atoi(pos);
}

static bool get_json_bool(const char* json, const char* key, bool default_val) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    
    const char* pos = strstr(json, search);
    if (!pos) return default_val;
    
    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t') pos++;
    
    if (strncmp(pos, "true", 4) == 0) return true;
    if (strncmp(pos, "false", 5) == 0) return false;
    
    return default_val;
}

static void set_error(AdapterContext* ctx, const char* format, ...) {
    if (!ctx) return;
    
    va_list args;
    va_start(args, format);
    vsnprintf(ctx->last_error, sizeof(ctx->last_error), format, args);
    va_end(args);
}

static void clear_error(AdapterContext* ctx) {
    if (ctx) {
        ctx->last_error[0] = '\0';
    }
}

/**
 * Get human-readable error message from SoftEther error code
 * Step 6: Enhanced error reporting
 */
static const char* get_error_string(UINT error_code) {
    switch (error_code) {
        case 0: return "No error";
        case 1: return "Connection to server failed";
        case 2: return "Server is not a VPN server";
        case 3: return "Connection interrupted";
        case 4: return "Protocol error";
        case 5: return "Client is not a VPN client";
        case 6: return "User cancelled";
        case 7: return "Authentication method not supported";
        case 8: return "HUB not found";
        case 9: return "Authentication failed";
        case 10: return "HUB is stopped";
        case 11: return "Session removed";
        case 12: return "Access denied";
        case 13: return "Session timeout";
        case 14: return "Invalid protocol";
        case 15: return "Too many connections";
        case 16: return "Invalid username";
        case 17: return "Invalid password";
        case 18: return "Password expired";
        case 19: return "Access denied (policy)";
        case 20: return "Proxy connection failed";
        case 21: return "Proxy authentication failed";
        case 22: return "Target not found";
        case 23: return "Target unreachable";
        case 24: return "Target stopped";
        case 25: return "Bad version";
        case 26: return "Bad server certificate";
        case 27: return "Server certificate expired";
        case 28: return "Server certificate not verified";
        default: return "Unknown error";
    }
}

static void notify_state(AdapterContext* ctx, int state) {
    if (ctx && ctx->state_callback) {
        ctx->state_callback(state, ctx->state_user_data);
    }
}

static void notify_event(AdapterContext* ctx, int level, int code, const char* message) {
    if (ctx && ctx->event_callback) {
        ctx->event_callback(level, code, message, ctx->event_user_data);
    }
}

// ============================================================================
// Packet Reception Thread
// ============================================================================

static void* rx_thread_func(void* arg) {
    AdapterContext* ctx = (AdapterContext*)arg;
    
    notify_event(ctx, 0, 0, "Packet reception thread started");
    
    while (ctx->running) {
        // Get SESSION (thread-safe read)
        pthread_mutex_lock(&ctx->mutex);
        SESSION *s = (ctx->account && ctx->account->ClientSession) ? ctx->account->ClientSession : NULL;
        pthread_mutex_unlock(&ctx->mutex);
        
        if (!s) {
            // No session yet, wait a bit
            usleep(100000); // 100ms
            continue;
        }
        
        // Get next packet from NullLan adapter
        void *packet_data = NULL;
        UINT packet_size = NullPaGetNextPacket(s, &packet_data);
        
        if (packet_size == 0 || packet_size == INFINITE) {
            // No packet available, wait a bit
            usleep(10000); // 10ms
            continue;
        }
        
        if (!packet_data || packet_size < 14) {
            // Invalid packet (too small for Ethernet header)
            if (packet_data) Free(packet_data);
            continue;
        }
        
        // Step 6: Validate packet size bounds
        if (packet_size > 65535) {
            notify_event(ctx, 2, 0, "RX: Invalid packet size (too large)");
            Free(packet_data);
            continue;
        }
        
        // Parse Ethernet frame
        MAC_HEADER *mac_hdr = (MAC_HEADER*)packet_data;
        USHORT protocol = Endian16(mac_hdr->Protocol);
        
        // Call L2 frame callback if registered
        pthread_mutex_lock(&ctx->mutex);
        if (ctx->rx_callback) {
            ctx->rx_callback((const uint8_t*)packet_data, packet_size, ctx->rx_user_data);
        }
        pthread_mutex_unlock(&ctx->mutex);
        
        // If it's an IPv4 packet, also call IP callback
        if (protocol == MAC_PROTO_IPV4 && packet_size > 14) {
            // Extract IP packet (skip 14-byte Ethernet header)
            const uint8_t *ip_packet = (const uint8_t*)packet_data + 14;
            uint32_t ip_packet_size = packet_size - 14;
            
            pthread_mutex_lock(&ctx->mutex);
            if (ctx->ip_rx_callback) {
                ctx->ip_rx_callback(ip_packet, ip_packet_size, ctx->ip_rx_user_data);
            }
            pthread_mutex_unlock(&ctx->mutex);
        }
        
        // Free packet buffer (allocated by SoftEther)
        Free(packet_data);
    }
    
    notify_event(ctx, 0, 0, "Packet reception thread stopped");
    return NULL;
}

// ============================================================================
// JSON Configuration Parsing
// ============================================================================

static bool parse_json_config(AdapterContext* ctx, const char* json) {
    // Expected JSON format:
    // {
    //   "server": "vpn.example.com",
    //   "port": 443,
    //   "hub": "VPN",
    //   "username": "user",
    //   "password_hash": "sha0_hash",
    //   "use_encrypt": true,
    //   "use_compress": true,
    //   "max_connection": 2
    // }
    
    char server[256] = {0};
    char hub[128] = {0};
    char username[128] = {0};
    char password_hash[256] = {0};
    
    if (!get_json_string(json, "server", server, sizeof(server))) {
        set_error(ctx, "Missing 'server' in configuration");
        return false;
    }
    
    if (!get_json_string(json, "hub", hub, sizeof(hub))) {
        strcpy(hub, "VPN"); // Default hub name
    }
    
    if (!get_json_string(json, "username", username, sizeof(username))) {
        set_error(ctx, "Missing 'username' in configuration");
        return false;
    }
    
    if (!get_json_string(json, "password_hash", password_hash, sizeof(password_hash))) {
        set_error(ctx, "Missing 'password_hash' in configuration");
        return false;
    }
    
    int port = get_json_int(json, "port", 443);
    bool use_encrypt = get_json_bool(json, "use_encrypt", true);
    bool use_compress = get_json_bool(json, "use_compress", true);
    int max_connection = get_json_int(json, "max_connection", 1);
    
    notify_event(ctx, 0, 0, "Configuration parsed successfully");
    
    char msg[512];
    snprintf(msg, sizeof(msg), "Server: %s:%d, Hub: %s, User: %s", 
             server, port, hub, username);
    notify_event(ctx, 0, 0, msg);
    
    // Store configuration in context for later use
    strncpy(ctx->server, server, sizeof(ctx->server) - 1);
    strncpy(ctx->hub, hub, sizeof(ctx->hub) - 1);
    strncpy(ctx->username, username, sizeof(ctx->username) - 1);
    strncpy(ctx->password_hash, password_hash, sizeof(ctx->password_hash) - 1);
    ctx->port = port;
    ctx->use_encrypt = use_encrypt;
    ctx->use_compress = use_compress;
    ctx->max_connection = max_connection;
    
    return true;
}

// ============================================================================
// Exported FFI Functions
// ============================================================================

/**
 * Create adapter from JSON configuration
 */
void* zig_adapter_create_from_json(const char* json) {
    if (!json) return NULL;
    
    AdapterContext* ctx = (AdapterContext*)calloc(1, sizeof(AdapterContext));
    if (!ctx) return NULL;
    
    pthread_mutex_init(&ctx->mutex, NULL);
    
    // Initialize SoftEther
    InitCedar();
    
    // Parse configuration
    if (!parse_json_config(ctx, json)) {
        set_error(ctx, "Failed to parse JSON configuration");
        free(ctx);
        return NULL;
    }
    
    // Generate MAC address (locally administered)
    ctx->mac[0] = 0x02;  // Locally administered
    ctx->mac[1] = 0xAC;
    for (int i = 2; i < 6; i++) {
        ctx->mac[i] = (uint8_t)rand();
    }
    
    // Create SoftEther CLIENT
    notify_event(ctx, 0, 0, "Creating SoftEther CLIENT");
    ctx->client = CiNewClient();
    if (!ctx->client) {
        set_error(ctx, "Failed to create SoftEther CLIENT");
        pthread_mutex_destroy(&ctx->mutex);
        free(ctx);
        return NULL;
    }
    
    // Create ACCOUNT
    notify_event(ctx, 0, 0, "Creating VPN account");
    ctx->account = ZeroMalloc(sizeof(ACCOUNT));
    if (!ctx->account) {
        set_error(ctx, "Failed to allocate ACCOUNT");
        CiCleanupClient(ctx->client);
        pthread_mutex_destroy(&ctx->mutex);
        free(ctx);
        return NULL;
    }

    // Allocate CLIENT_OPTION
    ctx->account->ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
    if (!ctx->account->ClientOption) {
        Free(ctx->account);
        CiCleanupClient(ctx->client);
        pthread_mutex_destroy(&ctx->mutex);
        free(ctx);
        return NULL;
    }

    // Allocate CLIENT_AUTH
    ctx->account->ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
    if (!ctx->account->ClientAuth) {
        Free(ctx->account->ClientOption);
        Free(ctx->account);
        CiCleanupClient(ctx->client);
        pthread_mutex_destroy(&ctx->mutex);
        free(ctx);
        return NULL;
    }
    
    // Configure CLIENT_OPTION fields from parsed JSON
    // AccountName is wchar_t, so we need to convert from char*
    StrToUni(ctx->account->ClientOption->AccountName, sizeof(ctx->account->ClientOption->AccountName), ctx->username);
    StrCpy(ctx->account->ClientOption->Hostname, sizeof(ctx->account->ClientOption->Hostname), ctx->server);
    ctx->account->ClientOption->Port = ctx->port;
    StrCpy(ctx->account->ClientOption->HubName, sizeof(ctx->account->ClientOption->HubName), ctx->hub);
    
    // Configure CLIENT_AUTH - username and password
    StrCpy(ctx->account->ClientAuth->Username, sizeof(ctx->account->ClientAuth->Username), ctx->username);
    
    // Set authentication type to password
    SetClientAuthType(ctx->account->ClientAuth, CLIENT_AUTHTYPE_PASSWORD);
    
    // Parse password hash from hex string and set it
    BUF *pwd_buf = StrToBin(ctx->password_hash);
    if (pwd_buf) {
        // Use helper function for safe password hash setting
        if (pwd_buf->Size == 20) {  // SHA1 hash is 20 bytes
            SetClientAuthHashedPassword(ctx->account->ClientAuth, pwd_buf->Buf, pwd_buf->Size);
        }
        FreeBuf(pwd_buf);
    }
    
    // Set connection options using helper function
    SetClientOptionFlags(
        ctx->account->ClientOption,
        ctx->use_encrypt,      // use_encrypt
        ctx->use_compress,     // use_compress
        false,                 // half_connection
        true,                  // no_routing_tracking (important for iOS!)
        false,                 // no_udp_accel
        false,                 // disable_qos
        false                  // require_bridge_routing
    );
    
    // Set max connections
    SetClientOptionMaxConnection(ctx->account->ClientOption, ctx->max_connection);
    
    // Additional connection settings
    ctx->account->ClientOption->AdditionalConnectionInterval = 1;
    ctx->account->ClientOption->ConnectionDisconnectSpan = 0;
    ctx->account->ClientOption->HideStatusWindow = false;
    ctx->account->ClientOption->HideNicInfoWindow = false;
    ctx->account->ClientOption->RequireMonitorMode = false;
    
    notify_event(ctx, 0, 0, "Account configured successfully");
    
    clear_error(ctx);
    return ctx;
}

/**
 * Destroy adapter and free resources
 */
/**
 * Destroy adapter and free all resources
 * This is Step 5: Complete resource cleanup to prevent memory leaks
 */
void zig_adapter_destroy(ZigPacketAdapter *adapter) {
    if (!adapter) return;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    // Step 1: Disconnect if still connected (this stops RX thread and SESSION)
    if (ctx->connected || ctx->running) {
        zig_adapter_disconnect(adapter);
    }
    
    // Step 2: Free ACCOUNT structure and its members (proper SoftEther cleanup)
    if (ctx->account) {
        // Free CLIENT_OPTION if allocated
        if (ctx->account->ClientOption) {
            Free(ctx->account->ClientOption);
            ctx->account->ClientOption = NULL;
        }
        
        // Free CLIENT_AUTH if allocated
        if (ctx->account->ClientAuth) {
            Free(ctx->account->ClientAuth);
            ctx->account->ClientAuth = NULL;
        }
        
        // Verify SESSION was cleaned up
        if (ctx->account->ClientSession) {
            // This shouldn't happen if disconnect was called, but safety check
            StopSession(ctx->account->ClientSession);
            ReleaseSession(ctx->account->ClientSession);
            ctx->account->ClientSession = NULL;
        }
        
        // Free ACCOUNT structure itself
        Free(ctx->account);
        ctx->account = NULL;
    }
    
    // Step 3: Cleanup CLIENT (releases all internal resources)
    if (ctx->client) {
        CiCleanupClient(ctx->client);
        ctx->client = NULL;
    }
    
    // Step 4: Destroy mutex (must be done before freeing context)
    pthread_mutex_destroy(&ctx->mutex);
    
    // Step 5: Free adapter context itself
    free(ctx);
    
    // Note: FreeCedar() should only be called once globally on app shutdown
    // It's not safe to call here as other adapters may still be using Cedar
}

/**
 * Connect to VPN server
 */
int zig_adapter_connect(void* adapter) {
    if (!adapter) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    pthread_mutex_lock(&ctx->mutex);
    
    if (ctx->connected) {
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "Already connected");
        return -2;
    }
    
    if (!ctx->client || !ctx->account) {
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "CLIENT or ACCOUNT not initialized");
        return -3;
    }
    
    notify_state(ctx, 1); // Connecting
    notify_event(ctx, 0, 0, "Creating NullLan packet adapter for iOS");
    
    // Get NullLan packet adapter (iOS-compatible, no system VLan needed)
    PACKET_ADAPTER *pa = NullGetPacketAdapter();
    if (!pa) {
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "Failed to create NullLan packet adapter");
        notify_state(ctx, 4); // Error
        return -4;
    }
    
    notify_event(ctx, 0, 0, "Creating VPN session");
    
    // Set account status printer and update last connect time
    ctx->account->StatusPrinter = NULL;  // We don't use status printer
    ctx->account->LastConnectDateTime = SystemTime64();
    
    // Create CLIENT SESSION (this starts the connection process)
    ctx->account->ClientSession = NewClientSessionEx(
        ctx->client->Cedar,
        ctx->account->ClientOption,
        ctx->account->ClientAuth,
        pa,
        ctx->account
    );
    
    if (!ctx->account->ClientSession) {
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "Failed to create CLIENT SESSION");
        notify_state(ctx, 4); // Error
        return -5;
    }
    
    notify_event(ctx, 0, 0, "Waiting for VPN connection to establish");
    
    // Wait for connection to establish (poll SESSION status)
    // This is similar to how CtConnect works but adapted for iOS
    SESSION *s = ctx->account->ClientSession;
    int wait_count = 0;
    int max_wait = 300; // 30 seconds (100ms * 300)
    
    pthread_mutex_unlock(&ctx->mutex);
    
    while (wait_count < max_wait) {
        // Get session status (thread-safe)
        UINT status = GetSessionClientStatus(s);
        
        // Check if session halted (connection failed)
        if (GetSessionHalt(s)) {
            // Step 6: Extract actual error code from SESSION
            UINT err_code = 0;
            if (s->lock) Lock(s->lock);
            err_code = s->Err;
            if (s->lock) Unlock(s->lock);
            
            pthread_mutex_lock(&ctx->mutex);
            // Clean up failed session
            if (ctx->account->ClientSession) {
                StopSession(ctx->account->ClientSession);
                ReleaseSession(ctx->account->ClientSession);
                ctx->account->ClientSession = NULL;
            }
            pthread_mutex_unlock(&ctx->mutex);
            
            // Report detailed error
            const char* err_str = get_error_string(err_code);
            set_error(ctx, "Connection failed: %s (code %u)", err_str, err_code);
            notify_event(ctx, 2, err_code, err_str);  // level=2 (error)
            notify_state(ctx, 4); // Error
            return -6;
        }
        
        // Check if established
        if (status == CLIENT_STATUS_ESTABLISHED) {
            // Connection established!
            break;
        }
        
        // Wait a bit before checking again
        SleepThread(100);  // 100ms
        wait_count++;
        
        // Send progress updates
        if (wait_count % 10 == 0) {
            if (status == CLIENT_STATUS_CONNECTING) {
                notify_event(ctx, 0, 0, "Connecting to VPN server...");
            } else if (status == CLIENT_STATUS_NEGOTIATION) {
                notify_event(ctx, 0, 0, "Negotiating connection...");
            } else if (status == CLIENT_STATUS_AUTH) {
                notify_event(ctx, 0, 0, "Authenticating...");
            }
        }
    }
    
    if (wait_count >= max_wait) {
        pthread_mutex_lock(&ctx->mutex);
        // Timeout - disconnect
        if (ctx->account && ctx->account->ClientSession) {
            notify_event(ctx, 1, 0, "Connection timeout - cleaning up session");
            SESSION *timeout_session = ctx->account->ClientSession;
            
            // Get error code if available
            UINT err_code = 0;
            if (timeout_session->lock) Lock(timeout_session->lock);
            err_code = timeout_session->Err;
            if (timeout_session->lock) Unlock(timeout_session->lock);
            
            StopSession(timeout_session);
            ReleaseSession(timeout_session);
            ctx->account->ClientSession = NULL;
            
            if (err_code != 0) {
                const char* err_str = get_error_string(err_code);
                set_error(ctx, "Connection timeout: %s (code %u)", err_str, err_code);
            } else {
                set_error(ctx, "Connection timeout after 30 seconds");
            }
        } else {
            set_error(ctx, "Connection timeout (session lost)");
        }
        pthread_mutex_unlock(&ctx->mutex);
        notify_state(ctx, 4); // Error
        return -7;
    }
    
    pthread_mutex_lock(&ctx->mutex);
    
    // Start RX thread for packet reception
    notify_event(ctx, 0, 0, "Starting packet reception thread");
    ctx->running = true;
    if (pthread_create(&ctx->rx_thread, NULL, rx_thread_func, ctx) != 0) {
        ctx->running = false;
        // Stop session
        if (ctx->account->ClientSession) {
            StopSession(ctx->account->ClientSession);
            ReleaseSession(ctx->account->ClientSession);
            ctx->account->ClientSession = NULL;
        }
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "Failed to create RX thread");
        notify_state(ctx, 4); // Error
        return -8;
    }
    
    ctx->connected = true;
    pthread_mutex_unlock(&ctx->mutex);
    
    // Connection complete!
    notify_state(ctx, 2); // Established
    notify_event(ctx, 0, 0, "VPN connection established successfully");
    
    clear_error(ctx);
    return 0;
}

/**
 * Disconnect from VPN server
 */
/**
 * Disconnect from VPN server and cleanup session
 * This is Step 5: Complete disconnect with proper resource cleanup
 */
int zig_adapter_disconnect(void* adapter) {
    if (!adapter) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    pthread_mutex_lock(&ctx->mutex);
    
    if (!ctx->connected) {
        pthread_mutex_unlock(&ctx->mutex);
        return 0; // Already disconnected
    }
    
    notify_state(ctx, 3); // Disconnecting
    notify_event(ctx, 0, 0, "Disconnecting from VPN");
    
    // Step 1: Stop RX thread first (signal shutdown)
    ctx->running = false;
    pthread_mutex_unlock(&ctx->mutex);
    
    // Step 2: Wait for RX thread to finish (may block briefly)
    notify_event(ctx, 0, 0, "Waiting for RX thread to stop");
    pthread_join(ctx->rx_thread, NULL);
    
    pthread_mutex_lock(&ctx->mutex);
    
    // Step 3: Stop and cleanup SESSION (proper SoftEther shutdown sequence)
    if (ctx->account && ctx->account->ClientSession) {
        SESSION *s = ctx->account->ClientSession;
        
        notify_event(ctx, 0, 0, "Stopping VPN session");
        
        // Stop session (initiates disconnect, waits for completion)
        StopSession(s);
        
        // Release session (decrements ref count, may trigger cleanup)
        ReleaseSession(s);
        
        // Nullify pointer to prevent double-free
        ctx->account->ClientSession = NULL;
        
        notify_event(ctx, 0, 0, "Session stopped and released");
    }
    
    // Step 4: Clear ARP table
    ctx->arp_table_count = 0;
    for (int i = 0; i < 256; i++) {
        ctx->arp_table[i].valid = false;
    }
    
    // Step 5: Mark as disconnected
    ctx->connected = false;
    pthread_mutex_unlock(&ctx->mutex);
    
    notify_state(ctx, 0); // Idle
    notify_event(ctx, 0, 0, "VPN disconnected successfully");
    
    clear_error(ctx);
    return 0;
}

/**
 * Send L2 Ethernet frame
 */
int zig_adapter_send_frame(void* adapter, const uint8_t* data, uint32_t len) {
    if (!adapter || !data) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    if (!ctx->connected) {
        set_error(ctx, "Not connected");
        return -2;
    }
    
    // Check if we have a valid SESSION
    pthread_mutex_lock(&ctx->mutex);
    if (!ctx->account || !ctx->account->ClientSession) {
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "No active VPN session");
        return -3;
    }
    
    SESSION *s = ctx->account->ClientSession;
    pthread_mutex_unlock(&ctx->mutex);
    
    // Minimum Ethernet frame is 14 bytes (MAC header)
    if (len < 14) {
        set_error(ctx, "Frame too small (< 14 bytes)");
        return -4;
    }
    
    // Allocate buffer for frame data (SoftEther will free it)
    void *frame_buf = Malloc(len);
    if (!frame_buf) {
        set_error(ctx, "Failed to allocate frame buffer (OOM)");
        return -5;
    }
    
    // Copy frame data
    Copy(frame_buf, data, len);
    
    // Step 6: Validate SESSION is still valid before sending
    if (s->Halt) {
        Free(frame_buf);
        set_error(ctx, "Cannot send: session halted");
        return -6;
    }
    
    // Send frame to NullLan adapter (injects into VPN tunnel)
    bool result = NullPaPutPacket(s, frame_buf, len);
    
    if (!result) {
        Free(frame_buf);  // Free if put failed
        set_error(ctx, "Failed to send frame (queue full or link down)");
        return 0;  // No link or queue full
    }
    
    clear_error(ctx);
    return 1;  // Successfully queued
}

/**
 * Send IPv4 packet (L3)
 */
int zig_adapter_send_ip_packet(void* adapter, const uint8_t* data, uint32_t len) {
    if (!adapter || !data) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    if (!ctx->connected) {
        set_error(ctx, "Not connected");
        return -2;
    }
    
    // Minimum IPv4 header is 20 bytes
    if (len < 20) {
        set_error(ctx, "IP packet too small (< 20 bytes)");
        return -3;
    }
    
    // Extract destination IP address (bytes 16-19 in IPv4 header)
    uint32_t dest_ip;
    Copy(&dest_ip, data + 16, 4);
    
    // Look up destination MAC in ARP table
    uint8_t dest_mac[6];
    bool found_arp = false;
    
    pthread_mutex_lock(&ctx->mutex);
    // Step 6: Validate ARP table integrity before lookup
    if (ctx->arp_table_count > 256 || ctx->arp_table_count < 0) {
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "ARP table corrupted (count=%d)", ctx->arp_table_count);
        return -3;
    }
    
    for (int i = 0; i < ctx->arp_table_count; i++) {
        if (ctx->arp_table[i].valid && ctx->arp_table[i].ip == dest_ip) {
            Copy(dest_mac, ctx->arp_table[i].mac, 6);
            found_arp = true;
            break;
        }
    }
    pthread_mutex_unlock(&ctx->mutex);
    
    if (!found_arp) {
        // No ARP entry - use broadcast MAC (typical for gateway)
        // In real network, this would trigger ARP request
        dest_mac[0] = 0xFF;
        dest_mac[1] = 0xFF;
        dest_mac[2] = 0xFF;
        dest_mac[3] = 0xFF;
        dest_mac[4] = 0xFF;
        dest_mac[5] = 0xFF;
    }
    
    // Allocate buffer for Ethernet frame (14-byte header + IP packet)
    uint32_t frame_len = 14 + len;
    uint8_t *frame = (uint8_t*)Malloc(frame_len);
    if (!frame) {
        set_error(ctx, "Failed to allocate frame buffer");
        return -4;
    }
    
    // Build Ethernet header (MAC_HEADER structure)
    MAC_HEADER *mac_hdr = (MAC_HEADER*)frame;
    
    // Destination MAC
    Copy(mac_hdr->DestAddress, dest_mac, 6);
    
    // Source MAC (our adapter MAC)
    Copy(mac_hdr->SrcAddress, ctx->mac, 6);
    
    // Protocol: IPv4 (0x0800 in network byte order)
    mac_hdr->Protocol = Endian16(MAC_PROTO_IPV4);
    
    // Copy IP packet after header
    Copy(frame + 14, data, len);
    
    // Send the complete Ethernet frame
    int result = zig_adapter_send_frame(adapter, frame, frame_len);
    
    Free(frame);
    
    if (result < 0) {
        // Error already set by send_frame
        return result;
    }
    
    clear_error(ctx);
    return result;  // 1 if queued, 0 if no link
}

/**
 * Add static ARP entry
 */
int zig_adapter_arp_add(void* adapter, uint32_t ipv4_be, const uint8_t* mac) {
    if (!adapter || !mac) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    pthread_mutex_lock(&ctx->mutex);
    
    // Check if entry already exists (update if so)
    for (int i = 0; i < ctx->arp_table_count; i++) {
        if (ctx->arp_table[i].valid && ctx->arp_table[i].ip == ipv4_be) {
            // Update existing entry
            Copy(ctx->arp_table[i].mac, mac, 6);
            pthread_mutex_unlock(&ctx->mutex);
            
            // Format IP for logging
            char ip_str[32];
            UCHAR *ip_bytes = (UCHAR*)&ipv4_be;
            snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", 
                     ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
            
            notify_event(ctx, 0, 0, "Updated ARP entry");
            clear_error(ctx);
            return 0;
        }
    }
    
    // Add new entry if space available
    if (ctx->arp_table_count >= 256) {
        pthread_mutex_unlock(&ctx->mutex);
        set_error(ctx, "ARP table full (256 entries)");
        return -2;
    }
    
    // Add new entry
    int idx = ctx->arp_table_count;
    ctx->arp_table[idx].ip = ipv4_be;
    Copy(ctx->arp_table[idx].mac, mac, 6);
    ctx->arp_table[idx].valid = true;
    ctx->arp_table_count++;
    
    pthread_mutex_unlock(&ctx->mutex);
    
    // Format IP and MAC for logging
    char ip_str[32];
    UCHAR *ip_bytes = (UCHAR*)&ipv4_be;
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", 
             ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    
    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "Added ARP: %s → %02X:%02X:%02X:%02X:%02X:%02X",
             ip_str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    notify_event(ctx, 0, 0, log_msg);
    
    clear_error(ctx);
    return 0;
}

/**
 * Get client MAC address
 */
int zig_adapter_get_mac(void* adapter, uint8_t* out_mac) {
    if (!adapter || !out_mac) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    memcpy(out_mac, ctx->mac, 6);
    
    clear_error(ctx);
    return 0;
}

/**
 * Get network settings as JSON
 * Extracts DHCP configuration from the active SESSION
 */
char* zig_adapter_get_network_settings_json(void* adapter) {
    if (!adapter) return NULL;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    // Get the global VPN client to access IPC
    VpnBridgeClient* client = vpn_bridge_get_global_client();
    IPC* ipc = client ? (IPC*)vpn_bridge_get_ipc(client) : NULL;
    
    // Default values if IPC not available
    char ip_str[64] = "0.0.0.0";
    char mask_str[64] = "255.255.255.0";
    char gateway_str[64] = "0.0.0.0";
    char dns_str[256] = "\"8.8.8.8\",\"1.1.1.1\"";  // Default DNS servers
    char mac_str[32] = "00:00:00:00:00:00";
    
    if (ipc != NULL && IsZeroIP(&ipc->ClientIPAddress) == false) {
        // Use the DHCP-assigned IP from IPC
        IPToStr(ip_str, sizeof(ip_str), &ipc->ClientIPAddress);
        
        // Get subnet mask from IPC
        if (IsZeroIP(&ipc->SubnetMask) == false) {
            IPToStr(mask_str, sizeof(mask_str), &ipc->SubnetMask);
        }
        
        // Get gateway from IPC
        if (IsZeroIP(&ipc->DefaultGateway) == false) {
            IPToStr(gateway_str, sizeof(gateway_str), &ipc->DefaultGateway);
        }
        
        // DNS is handled by iOS - use defaults or query from policy/server options
        // For now, use public DNS servers (iOS will override these anyway)
        
        // Get MAC address from IPC
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ipc->MacAddress[0], ipc->MacAddress[1], ipc->MacAddress[2],
                 ipc->MacAddress[3], ipc->MacAddress[4], ipc->MacAddress[5]);
    }
    
    // Build JSON response
    const char* json_template = 
        "{"
        "\"assigned_ipv4\":\"%s\","
        "\"subnet_mask\":\"%s\","
        "\"gateway\":\"%s\","
        "\"dns_servers\":[%s],"
        "\"mac_address\":\"%s\""
        "}";
    
    char* result = (char*)malloc(1024);
    if (result) {
        snprintf(result, 1024, json_template, ip_str, mask_str, gateway_str, dns_str, mac_str);
    }
    
    clear_error(ctx);
    return result;
}

/**
 * Get last error message
 */
const char* zig_adapter_get_error(void* adapter) {
    if (!adapter) return NULL;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    return ctx->last_error[0] ? ctx->last_error : NULL;
}

// ============================================================================
// Callback Registration
// ============================================================================

int zig_adapter_set_rx_callback(void* adapter, void (*cb)(const uint8_t*, uint32_t, void*), void* user) {
    if (!adapter) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->rx_callback = cb;
    ctx->rx_user_data = user;
    pthread_mutex_unlock(&ctx->mutex);
    
    return 0;
}

int zig_adapter_set_ip_rx_callback(void* adapter, void (*cb)(const uint8_t*, uint32_t, void*), void* user) {
    if (!adapter) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->ip_rx_callback = cb;
    ctx->ip_rx_user_data = user;
    pthread_mutex_unlock(&ctx->mutex);
    
    return 0;
}

int zig_adapter_set_state_callback(void* adapter, void (*cb)(int, void*), void* user) {
    if (!adapter) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->state_callback = cb;
    ctx->state_user_data = user;
    pthread_mutex_unlock(&ctx->mutex);
    
    return 0;
}

int zig_adapter_set_event_callback(void* adapter, void (*cb)(int, int, const char*, void*), void* user) {
    if (!adapter) return -1;
    
    AdapterContext* ctx = (AdapterContext*)adapter;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->event_callback = cb;
    ctx->event_user_data = user;
    pthread_mutex_unlock(&ctx->mutex);
    
    return 0;
}
