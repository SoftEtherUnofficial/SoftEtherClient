/**
 * SoftEther Direct C API Implementation
 * 
 * Direct C interface with zero FFI overhead.
 * Matches vpnclient CLI flow exactly.
 */

#include "direct_api.h"
#include "Mayaqua.h"
#include "Cedar.h"
#include "Client.h"
#include "Account.h"
#include "Session.h"
#include "Connection.h"
#include "logging.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __APPLE__
#include <os/log.h>
// Use printf for iOS debugging
#define STATUS_LOG(...) do { printf(__VA_ARGS__); printf("\n"); fflush(stdout); } while(0)
#else
#define STATUS_LOG(...) printf(__VA_ARGS__); fflush(stdout)
#endif

// Forward declarations for iOS adapter functions
typedef void (*NetworkConfiguredCallback)(const void* info, void* user_data);

// Global network callback (shared with Zig adapter)
static NetworkConfiguredCallback g_network_callback = NULL;
static void* g_network_callback_user_data = NULL;

// Zig DHCP state structure (must match ios_adapter.zig)
typedef struct {
    uint32_t client_ip;     // Network byte order
    uint32_t subnet_mask;   // Network byte order
    uint32_t gateway;       // Network byte order
    uint32_t dns_server1;   // Network byte order
    uint32_t dns_server2;   // Network byte order
    uint32_t dhcp_server;   // Network byte order
    bool valid;
    uint32_t xid;
    uint8_t client_mac[6];
} ZigDhcpState;

// Called by Zig adapter when DHCP completes (called from parseDhcpIfNeeded in ios_adapter.zig)
void ios_adapter_notify_dhcp_complete(const ZigDhcpState* zig_state) {
    if (!g_network_callback || !zig_state) {
        return;
    }

    // Convert Zig DhcpState to SENetworkConfig
    SENetworkConfig config;
    memset(&config, 0, sizeof(config));
    
    config.ip_address = zig_state->client_ip;
    config.subnet_mask = zig_state->subnet_mask;
    config.gateway = zig_state->gateway;
    config.dns_server = zig_state->dns_server1;  // Use first DNS server
    // gateway_mac will be learned from traffic

    // Call the Swift callback
    g_network_callback(&config, g_network_callback_user_data);
}

// Implementation for iOS - called by Zig adapter when DHCP completes
void ios_adapter_set_network_callback(NetworkConfiguredCallback callback, void* user_data) {
    g_network_callback = callback;
    g_network_callback_user_data = user_data;
}

// Called by Zig adapter when DHCP completes (legacy, now uses ios_adapter_notify_dhcp_complete)
void ios_adapter_network_configured(const void* info) {
    if (g_network_callback) {
        g_network_callback(info, g_network_callback_user_data);
    }
}

// iOS Packet Adapter State
typedef struct {
    QUEUE* tx_queue;  // Packets from iOS TUN → SoftEther (Swift writes here)
    QUEUE* rx_queue;  // Packets from SoftEther → iOS TUN (Swift reads here)
    LOCK* tx_lock;
    LOCK* rx_lock;
    EVENT* tx_event;  // Signal when TX data available
    CANCEL* cancel;   // For cancellation
    bool active;
} IOSAdapterState;

// Internal session context (wraps CLIENT + ACCOUNT + SESSION + iOS adapter)
typedef struct {
    CLIENT* client;
    ACCOUNT* account;
    SESSION* session;
    PACKET_ADAPTER* packet_adapter;
    IOSAdapterState* adapter_state;
    SENetworkCallback network_callback;
    SEStatusCallback status_callback;
    SEErrorCallback error_callback;
    void* user_data;
    volatile int current_status;  // 0=disconnected, 1=connecting, 2=connected, 4=error
} SESessionContext;

// iOS Packet Adapter Implementation
// These functions bridge between Swift TUN I/O and SoftEther session

static bool ios_adapter_init(SESSION* s, void* param) {
    // Already initialized in se_connect
    return true;
}

static CANCEL* ios_adapter_get_cancel(SESSION* s) {
    if (!s || !s->PacketAdapter) {
        return NULL;
    }
    IOSAdapterState* state = (IOSAdapterState*)s->PacketAdapter->Param;
    if (!state) {
        return NULL;
    }
    return state->cancel;
}

static UINT ios_adapter_get_next_packet(SESSION* s, void** data) {
    if (!s || !s->PacketAdapter) {
        return 0;
    }
    IOSAdapterState* state = (IOSAdapterState*)s->PacketAdapter->Param;
    if (!state || !state->active) {
        return 0;
    }
    
    // Try to get packet from TX queue (iOS TUN → Server)
    Lock(state->tx_lock);
    if (state->tx_queue->num_item > 0) {
        BLOCK* block = GetNext(state->tx_queue);
        Unlock(state->tx_lock);
        
        if (block && block->Buf && block->Size > 0) {
            *data = Malloc(block->Size);
            Copy(*data, block->Buf, block->Size);
            UINT size = block->Size;
            FreeBlock(block);
            return size;
        }
    }
    Unlock(state->tx_lock);
    
    // No packet available - wait for event with timeout
    Wait(state->tx_event, 100);
    return 0;
}

// Forward declaration for DHCP parsing
extern void* ios_adapter_get_global_instance(void);
extern void ios_adapter_parse_dhcp_from_c(void* adapter, const void* eth_frame, size_t length);

// Helper to parse DHCP packets as they arrive from server
void ios_adapter_parse_dhcp_packet(const void* eth_frame, size_t length) {
    STATUS_LOG("[ParseDHCP] 🔍 Checking packet: size=%zu", length);
    void* adapter = ios_adapter_get_global_instance();
    if (adapter) {
        STATUS_LOG("[ParseDHCP] ✅ Got adapter instance, calling Zig parser...");
        ios_adapter_parse_dhcp_from_c(adapter, eth_frame, length);
        STATUS_LOG("[ParseDHCP] ✅ Zig parser returned");
    } else {
        STATUS_LOG("[ParseDHCP] ❌ No adapter instance!");
    }
}

static bool ios_adapter_put_packet(SESSION* s, void* data, UINT size) {
    if (!s || !s->PacketAdapter || !data || size == 0) {
        return false;
    }
    IOSAdapterState* state = (IOSAdapterState*)s->PacketAdapter->Param;
    if (!state || !state->active) {
        return false;
    }
    
    // Log every packet for debugging
    STATUS_LOG("[PutPacket] 📦 Received packet from server: size=%u", size);
    
    // Check if this is a DHCP packet (for callback notification)
    // This allows DHCP to be detected even before Swift starts reading packets
    ios_adapter_parse_dhcp_packet(data, size);
    
    // Put packet in RX queue (Server → iOS TUN)
    BLOCK* block = NewBlock(Clone(data, size), size, 0);
    
    Lock(state->rx_lock);
    if (state->rx_queue->num_item < 4096) {  // Prevent unbounded growth
        InsertQueue(state->rx_queue, block);
        Unlock(state->rx_lock);
        return true;
    }
    Unlock(state->rx_lock);
    
    FreeBlock(block);
    return false;
}

static void ios_adapter_free(SESSION* s) {
    // Cleanup handled in se_disconnect
}

// Network callback wrapper for iOS adapter
static void ios_network_callback_wrapper(const void* info, void* user_data) {
    SESessionContext* ctx = (SESessionContext*)user_data;
    if (!ctx || !ctx->network_callback) {
        return;
    }
    
    // The info is SENetworkConfig struct, pass it through
    const SENetworkConfig* config = (const SENetworkConfig*)info;
    ctx->network_callback(config, ctx->user_data);
}

static PACKET_ADAPTER* create_ios_packet_adapter(SESessionContext* ctx) {
    // Create adapter state
    IOSAdapterState* state = ZeroMalloc(sizeof(IOSAdapterState));
    state->tx_queue = NewQueue();
    state->rx_queue = NewQueue();
    state->tx_lock = NewLock();
    state->rx_lock = NewLock();
    state->tx_event = NewEvent();
    state->cancel = NewCancel();
    state->active = true;
    
    ctx->adapter_state = state;
    
    // Create packet adapter
    PACKET_ADAPTER* pa = NewPacketAdapter(
        ios_adapter_init,
        ios_adapter_get_cancel,
        ios_adapter_get_next_packet,
        ios_adapter_put_packet,
        ios_adapter_free
    );
    
    if (pa) {
        pa->Id = 0;  // Custom iOS adapter
        pa->Param = state;  // Store state for callback access
    }
    
    // Register network callback with iOS adapter (DHCP configuration)
    if (ctx->network_callback) {
        ios_adapter_set_network_callback(ios_network_callback_wrapper, ctx);
    }
    
    return pa;
}

int se_init(void) {
    InitMayaqua(false, false, 0, NULL);
    InitCedar();
    return 0;
}

SESessionHandle se_connect(const SEConfig* config,
                           SENetworkCallback network_callback,
                           SEStatusCallback status_callback,
                           SEErrorCallback error_callback,
                           void* user_data) {
    if (!config || !config->server || !config->hub || !config->username) {
        if (error_callback) {
            error_callback(-1, "Invalid configuration", user_data);
        }
        return NULL;
    }
    
    // Create session context
    SESessionContext* ctx = (SESessionContext*)ZeroMalloc(sizeof(SESessionContext));
    if (!ctx) {
        if (error_callback) {
            error_callback(-2, "Memory allocation failed", user_data);
        }
        return NULL;
    }
    
    ctx->network_callback = network_callback;
    ctx->status_callback = status_callback;
    ctx->error_callback = error_callback;
    ctx->user_data = user_data;
    ctx->current_status = 1;  // CONNECTING
    
    if (status_callback) {
        status_callback("Creating client...", user_data);
    }
    
    // Create CLIENT structure (matches vpnclient)
    ctx->client = CiNewClient();
    if (!ctx->client) {
        if (error_callback) {
            error_callback(-3, "Failed to create client", user_data);
        }
        Free(ctx);
        return NULL;
    }
    
    if (status_callback) {
        status_callback("Creating account...", user_data);
    }
    
    // Create CLIENT_OPTION structure (matches softether_bridge.c pattern)
    CLIENT_OPTION* opt = ZeroMalloc(sizeof(CLIENT_OPTION));
    if (!opt) {
        if (error_callback) {
            error_callback(-4, "Failed to create client option", user_data);
        }
        CiCleanupClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    // Configure connection options
    StrCpy(opt->Hostname, sizeof(opt->Hostname), config->server);
    opt->Port = config->port;
    StrCpy(opt->HubName, sizeof(opt->HubName), config->hub);
    
    // Set encryption and compression
    opt->UseEncrypt = config->use_encrypt ? true : false;
    opt->UseCompress = config->use_compress ? true : false;
    
    // Additional settings for reliability
    opt->NoRoutingTracking = true;
    opt->HalfConnection = false;
    opt->MaxConnection = 1;
    opt->NumRetry = 3;
    opt->RetryInterval = 5;
    
    // Disable UDP/NAT-T (TCP only)
    opt->PortUDP = 0;
    
    // Create CLIENT_AUTH structure for authentication
    CLIENT_AUTH* auth = ZeroMalloc(sizeof(CLIENT_AUTH));
    if (!auth) {
        if (error_callback) {
            error_callback(-5, "Failed to create auth structure", user_data);
        }
        Free(opt);
        CiCleanupClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    auth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
    StrCpy(auth->Username, sizeof(auth->Username), config->username);
    
    // Set password hash if provided (convert hex string to binary)
    if (config->password_hash && strlen(config->password_hash) > 0) {
        // Hex string to binary conversion (password_hash should be 40 hex chars = 20 bytes)
        const char* hex = config->password_hash;
        size_t hex_len = strlen(hex);
        size_t bin_len = hex_len / 2;
        if (bin_len > sizeof(auth->HashedPassword)) {
            bin_len = sizeof(auth->HashedPassword);
        }
        for (size_t i = 0; i < bin_len; i++) {
            unsigned int byte;
            sscanf(hex + (i * 2), "%2x", &byte);
            auth->HashedPassword[i] = (UCHAR)byte;
        }
    }
    
    if (status_callback) {
        status_callback("Starting session...", user_data);
    }
    
    // Create iOS packet adapter (bridges Swift TUN I/O to SoftEther session)
    PACKET_ADAPTER* pa = create_ios_packet_adapter(ctx);
    if (!pa) {
        if (error_callback) {
            error_callback(-5, "Failed to create packet adapter", user_data);
        }
        Free(auth);
        Free(opt);
        CiCleanupClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    ctx->packet_adapter = pa;
    
    // Create ACCOUNT for the session
    ACCOUNT* account = ZeroMalloc(sizeof(ACCOUNT));
    account->ClientOption = opt;  // Store pointer (will be freed with account)
    account->ClientAuth = auth;   // Store pointer (will be freed with account)
    
    if (status_callback) {
        status_callback("Starting session...", user_data);
    }
    
    // ✅ Use NewClientSessionEx to create proper VPN session with packet processing!
    // This creates the SessionThread that processes packets via the iOS adapter.
    // The session will:
    // - Read packets from iOS TUN via ios_adapter_get_next_packet (TX queue)
    // - Send packets to iOS TUN via ios_adapter_put_packet (RX queue)
    // - Handle DHCP and protocol negotiation automatically
    STATUS_LOG("[se_connect] 🔧 Creating session with packet adapter: pa=%p", pa);
    ctx->session = NewClientSessionEx(ctx->client->Cedar, opt, auth, pa, account);
    if (!ctx->session) {
        STATUS_LOG("[se_connect] ❌ NewClientSessionEx FAILED!");
        if (error_callback) {
            error_callback(-6, "Failed to create session", user_data);
        }
        Free(account);
        Free(pa);
        Free(auth);
        Free(opt);
        CiCleanupClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    STATUS_LOG("[se_connect] ✅ Session created: session=%p, PacketAdapter=%p", ctx->session, ctx->session->PacketAdapter);
    
    // Store account for later cleanup
    ctx->account = account;
    
    if (status_callback) {
        status_callback("Session created - connecting...", user_data);
    }
    
    // Mark as connected now that SessionThread has started
    ctx->current_status = 2;  // CONNECTED
    
    // Session will connect in background and trigger DHCP automatically
    // The network_callback will be called when DHCP completes
    // (This matches vpnclient CLI flow)
    
    STATUS_LOG("[se_connect] ✅ Session initialization complete, SessionThread should be running");
    
    // TODO: Auto-inject DHCP DISCOVER packet to kickstart DHCP negotiation
    // Without this, DHCP won't complete because iOS doesn't send packets until after
    // VPN is marked "connected" (chicken-and-egg problem)
    // For now, rely on timeout fallback in Swift layer (calls completeStartOnce after 30s)
    
    return (SESessionHandle)ctx;
}

int se_read_packet(SESessionHandle session, uint8_t* buffer, size_t buffer_size) {
    if (!session || !buffer || buffer_size == 0) {
        return -1;
    }
    
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx->adapter_state) {
        return -1;
    }
    
    IOSAdapterState* state = ctx->adapter_state;
    
    // Read packet from RX queue (Server → iOS TUN)
    // SessionThread writes to this queue via ios_adapter_put_packet
    Lock(state->rx_lock);
    
    if (state->rx_queue->num_item > 0) {
        BLOCK* block = GetNext(state->rx_queue);
        Unlock(state->rx_lock);
        
        if (block->Size > buffer_size) {
            // Packet too large for buffer
            FreeBlock(block);
            return -1;
        }
        
        // Copy packet to buffer
        Copy(buffer, block->Buf, block->Size);
        UINT size = block->Size;
        FreeBlock(block);
        
        return (int)size;
    }
    
    Unlock(state->rx_lock);
    return 0;  // No packet available
}

int se_write_packet(SESessionHandle session, const uint8_t* data, size_t size) {
    if (!session || !data || size == 0) {
        return -1;
    }
    
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx->adapter_state) {
        return -1;
    }
    
    IOSAdapterState* state = ctx->adapter_state;
    
    // Write packet to TX queue (iOS TUN → Server)
    // SessionThread reads from this queue via ios_adapter_get_next_packet
    BLOCK* block = NewBlock(Clone((void*)data, size), size, 0);
    
    Lock(state->tx_lock);
    
    if (state->tx_queue->num_item < 4096) {
        InsertQueue(state->tx_queue, block);
        Unlock(state->tx_lock);
        
        // Signal SessionThread that packet is available
        Set(state->tx_event);
        
        return 0;
    }
    
    Unlock(state->tx_lock);
    FreeBlock(block);
    return -1;  // Queue full
}

void se_disconnect(SESessionHandle session) {
    if (!session) {
        return;
    }
    
    SESessionContext* ctx = (SESessionContext*)session;
    
    // Mark as disconnected
    ctx->current_status = 0;
    
    // Mark adapter as inactive to stop packet processing
    if (ctx->adapter_state) {
        ctx->adapter_state->active = false;
    }
    
    // Stop and free session
    if (ctx->session) {
        StopSession(ctx->session);
        ReleaseSession(ctx->session);
        ctx->session = NULL;
    }
    
    // Cleanup adapter state
    if (ctx->adapter_state) {
        IOSAdapterState* state = ctx->adapter_state;
        
        // Drain TX queue
        if (state->tx_queue) {
            Lock(state->tx_lock);
            while (state->tx_queue->num_item > 0) {
                BLOCK* block = GetNext(state->tx_queue);
                FreeBlock(block);
            }
            Unlock(state->tx_lock);
            ReleaseQueue(state->tx_queue);
        }
        
        // Drain RX queue
        if (state->rx_queue) {
            Lock(state->rx_lock);
            while (state->rx_queue->num_item > 0) {
                BLOCK* block = GetNext(state->rx_queue);
                FreeBlock(block);
            }
            Unlock(state->rx_lock);
            ReleaseQueue(state->rx_queue);
        }
        
        // Release locks and events
        if (state->tx_lock) DeleteLock(state->tx_lock);
        if (state->rx_lock) DeleteLock(state->rx_lock);
        if (state->tx_event) ReleaseEvent(state->tx_event);
        if (state->cancel) ReleaseCancel(state->cancel);
        
        Free(state);
        ctx->adapter_state = NULL;
    }
    
    // Free packet adapter
    if (ctx->packet_adapter) {
        Free(ctx->packet_adapter);
        ctx->packet_adapter = NULL;
    }
    
    // Free account
    if (ctx->account) {
        Free(ctx->account);
        ctx->account = NULL;
    }
    
    // Free client
    if (ctx->client) {
        CiCleanupClient(ctx->client);
        ctx->client = NULL;
    }
    
    // Free context
    Free(ctx);
}

int se_get_status(SESessionHandle session) {
    // Use SoftEther's Debug() which we know works
    Debug("[STATUS_DEBUG] === se_get_status() CALLED ===\n");
    
    if (!session) {
        Debug("[STATUS_DEBUG] session is NULL, returning 0\n");
        return 0;  // DISCONNECTED
    }
    
    SESessionContext* ctx = (SESessionContext*)session;
    Debug("[STATUS_DEBUG] ctx = %p\n", ctx);
    
    // Check if session exists and is active
    if (!ctx->session) {
        Debug("[STATUS_DEBUG] ctx->session is NULL, cached_status=%d\n", ctx->current_status);
        ctx->current_status = 0;
        return 0;
    }
    Debug("[STATUS_DEBUG] ctx->session = %p\n", ctx->session);
    
    if (!ctx->adapter_state) {
        Debug("[STATUS_DEBUG] ctx->adapter_state is NULL, cached_status=%d\n", ctx->current_status);
        ctx->current_status = 0;
        return 0;
    }
    Debug("[STATUS_DEBUG] ctx->adapter_state = %p, active=%d\n", ctx->adapter_state, ctx->adapter_state->active);
    
    if (!ctx->adapter_state->active) {
        Debug("[STATUS_DEBUG] adapter not active, cached_status=%d, returning 0\n", ctx->current_status);
        ctx->current_status = 0;
        return 0;
    }
    
    // Check session status from SoftEther
    if (ctx->session->Halt || ctx->session->UserCanceled) {
        Debug("[STATUS_DEBUG] session halted or cancelled, returning 0\n");
        ctx->current_status = 0;  // DISCONNECTED
        return 0;
    }
    
    // Check ClientStatus field
    UINT client_status = ctx->session->ClientStatus;
    Debug("[STATUS_DEBUG] ClientStatus=%u, cached_status=%d\n", client_status, ctx->current_status);
    
    switch (ctx->session->ClientStatus) {
        case CLIENT_STATUS_CONNECTING:
            Debug("[STATUS_DEBUG] CONNECTING, returning 1\n");
            ctx->current_status = 1;
            return 1;  // CONNECTING
        
        case CLIENT_STATUS_ESTABLISHED:
            Debug("[STATUS_DEBUG] ESTABLISHED, returning 2\n");
            ctx->current_status = 2;
            return 2;  // CONNECTED
        
        case CLIENT_STATUS_RETRY:
            Debug("[STATUS_DEBUG] RETRY, returning 3\n");
            ctx->current_status = 3;
            return 3;  // RECONNECTING
        
        case CLIENT_STATUS_IDLE:
            // IDLE can mean "not started yet" OR "actually disconnected"
            // If we have a positive cached status, the session is still initializing
            // Return cached status to prevent premature read loop exit
            if (ctx->current_status > 0) {
                Debug("[STATUS_DEBUG] IDLE but cached=%d, returning cached\n", ctx->current_status);
                return ctx->current_status;  // Use cached status during initialization
            }
            Debug("[STATUS_DEBUG] IDLE and cached=%d, returning DISCONNECTED\n", ctx->current_status);
            ctx->current_status = 0;
            return 0;  // DISCONNECTED
        
        default:
            Debug("[STATUS_DEBUG] unknown status=%u, cached=%d, returning cached\n", client_status, ctx->current_status);
            return ctx->current_status;  // Return cached status
    }
}

char* se_generate_password_hash(const char* password, const char* username) {
    if (!username || !password) {
        return NULL;
    }
    
    UCHAR hash[SHA1_SIZE];
    SecurePassword(hash, password, username);
    
    // Convert to hex string
    char* hex = Malloc(SHA1_SIZE * 2 + 1);
    if (!hex) {
        return NULL;
    }
    
    BinToStr(hex, SHA1_SIZE * 2 + 1, hash, sizeof(hash));
    return hex;
}
