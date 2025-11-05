/**
 * SoftEther VPN Client - Direct C API Implementation
 * 
 * Direct usage of SoftEther C objects (CLIENT*, SESSION*, PACKET_ADAPTER*)
 * Zero FFI overhead - matches vpnclient CLI architecture
 */

// SoftEther headers MUST come first (defines bool as UINT)
#include "Mayaqua/Mayaqua.h"
#include "Cedar/Cedar.h"
#include "Cedar/Client.h"
#include "Cedar/Connection.h"
#include "Cedar/Session.h"
#include "Cedar/Account.h"

// Now include our header and standard C headers
#include "../../include/direct_api.h"
#include <stdio.h>
#include <stdlib.h>

// Logging
#include "logging.h"

/* ========================================================================
 * Internal Session Context (Direct SoftEther Objects!)
 * ======================================================================== */

typedef struct SESessionContext {
    // Direct SoftEther objects (ZERO abstraction!)
    CLIENT* client;                  // SoftEther CLIENT object
    SESSION* session;                // SoftEther SESSION object  
    PACKET_ADAPTER* packet_adapter;  // Direct packet adapter
    ACCOUNT* account;                // Account object
    
    // Configuration (owned strings)
    char server[256];
    char hub[256];
    char username[256];
    UCHAR password_hash[SHA1_SIZE];  // Binary hash, not string!
    char client_name[256];
    UINT port;
    UINT use_encrypt;
    UINT use_compress;
    
    // Callbacks
    SENetworkCallback network_callback;
    SEStatusCallback status_callback;
    SEErrorCallback error_callback;
    void* user_data;
    
    // State monitoring (event-driven)
    THREAD* monitor_thread;
    EVENT* stop_monitor_event;
    volatile BOOL monitor_running;
    
    // State
    SEStatus status;
    int last_error;
    char error_message[512];
    
    // Statistics (use UINT64 for SoftEther compatibility)
    UINT64 bytes_sent;
    UINT64 bytes_received;
    UINT64 packets_sent;
    UINT64 packets_received;
    UINT64 connect_start_time;
    
} SESessionContext;

/* ========================================================================
 * Global State
 * ======================================================================== */

static UINT g_se_initialized = 0;

/* ========================================================================
 * Internal Helper Functions
 * ======================================================================== */

static void se_set_error(SESessionContext* ctx, int error_code, const char* message) {
    if (!ctx) return;
    
    ctx->last_error = error_code;
    if (message) {
        strncpy(ctx->error_message, message, sizeof(ctx->error_message) - 1);
        ctx->error_message[sizeof(ctx->error_message) - 1] = '\0';
    }
    
    LOG_ERROR("DirectAPI", "%s (code: %d)", message ? message : "Unknown error", error_code);
    
    if (ctx->error_callback) {
        ctx->error_callback(error_code, message, ctx->user_data);
    }
}

static void se_set_status(SESessionContext* ctx, SEStatus new_status, const char* message) {
    if (!ctx) return;
    
    ctx->status = new_status;
    
    LOG_INFO("DirectAPI", "Status: %d - %s", new_status, message ? message : "");
    
    if (ctx->status_callback) {
        ctx->status_callback(new_status, message ? message : "", ctx->user_data);
    }
}

/* ========================================================================
 * Status Monitoring Thread (Event-Driven)
 * ======================================================================== */

// Background thread that monitors session state and fires callbacks automatically
static void StatusMonitorThread(THREAD *thread, void *param) {
    SESessionContext* ctx = (SESessionContext*)param;
    if (!ctx) return;
    
    LOG_INFO("DirectAPI", "Status monitor thread started (event-driven)");
    
    SEStatus last_status = ctx->status;
    bool dhcp_callback_fired = false;  // Track if we've fired DHCP callback
    
    while (ctx->monitor_running) {
        // Check for stop signal every 100ms
        if (Wait(ctx->stop_monitor_event, 100)) {
            break; // Stop requested
        }
        
        // Check session state
        if (!ctx->session) {
            continue;
        }
        
        // Check for DHCP configuration (iOS adapter stores this)
        if (!dhcp_callback_fired && ctx->network_callback && ctx->session->ClientStatus == CLIENT_STATUS_ESTABLISHED) {
            // Try to get DHCP info from iOS adapter
            extern int ios_adapter_get_dhcp_info(uint32_t* client_ip, uint32_t* subnet_mask, 
                                                 uint32_t* gateway, uint32_t* dns1, uint32_t* dns2);
            
            uint32_t client_ip = 0, gateway = 0, subnet_mask = 0, dns1 = 0, dns2 = 0;
            if (ios_adapter_get_dhcp_info(&client_ip, &subnet_mask, &gateway, &dns1, &dns2) == 0) {
                
                LOG_INFO("DirectAPI", "DHCP configured: IP=%u.%u.%u.%u GW=%u.%u.%u.%u MASK=%u.%u.%u.%u",
                        (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF, (client_ip >> 8) & 0xFF, client_ip & 0xFF,
                        (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF, (gateway >> 8) & 0xFF, gateway & 0xFF,
                        (subnet_mask >> 24) & 0xFF, (subnet_mask >> 16) & 0xFF, (subnet_mask >> 8) & 0xFF, subnet_mask & 0xFF);
                
                // Fire network callback with DHCP info
                SENetworkConfig net_config = {0};
                net_config.ip_address = client_ip;
                net_config.subnet_mask = subnet_mask;
                net_config.gateway = gateway;
                net_config.dns_server = dns1;
                net_config.dns_server2 = dns2;
                net_config.mtu = 1500;
                
                ctx->network_callback(&net_config, ctx->user_data);
                dhcp_callback_fired = true;
                LOG_INFO("DirectAPI", "Network callback fired with DHCP configuration");
            }
        }
        
        SEStatus new_status = SE_STATUS_CONNECTING;
        
        if (ctx->session->Halt) {
            new_status = SE_STATUS_DISCONNECTED;
        } else if (ctx->session->ClientStatus == 3) {  // CLIENT_STATUS_ESTABLISHED = 3
            new_status = SE_STATUS_CONNECTED;
        } else if (ctx->session->ClientStatus == 0 || ctx->session->ClientStatus == 1 || ctx->session->ClientStatus == 2) {
            // CONNECTING (0), NEGOTIATION (1), AUTH (2)
            new_status = SE_STATUS_CONNECTING;
        } else if (ctx->session->ClientStatus == 4) {
            // RETRY (4) - this is normal, don't treat as error unless ForceStopFlag is set
            if (ctx->session->ForceStopFlag) {
                new_status = SE_STATUS_ERROR;
            } else {
                new_status = SE_STATUS_CONNECTING;  // Still attempting to connect
            }
        } else if (ctx->session->Err != 0 && ctx->session->ForceStopFlag) {
            // Only treat as error if ForceStopFlag is set (fatal error)
            new_status = SE_STATUS_ERROR;
            LOG_ERROR("DirectAPI", "Fatal error detected: Err=%u, ClientStatus=%u", 
                     ctx->session->Err, ctx->session->ClientStatus);
        }
        
        // Fire callback only when status changes
        if (new_status != last_status) {
            LOG_INFO("DirectAPI", "Status changed: %d -> %d", last_status, new_status);
            ctx->status = new_status;
            
            if (new_status == SE_STATUS_CONNECTED) {
                se_set_status(ctx, SE_STATUS_CONNECTED, "Connection established");
            } else if (new_status == SE_STATUS_ERROR) {
                se_set_error(ctx, SE_ERROR_CONNECT_FAILED, "Connection error");
                // ForceStopFlag should already be set by SoftEther if this is a fatal error
                LOG_INFO("DirectAPI", "Connection failed with error");
            } else if (new_status == SE_STATUS_DISCONNECTED) {
                se_set_status(ctx, SE_STATUS_DISCONNECTED, "Disconnected");
            }
            
            last_status = new_status;
        }
    }
    
    LOG_INFO("DirectAPI", "Status monitor thread stopped");
}

/* ========================================================================
 * Packet Adapter Implementation (Direct SESSION Integration)
 * ======================================================================== */

typedef struct SEPacketAdapterContext {
    SESessionContext* session_ctx;
    CANCEL* cancel;
} SEPacketAdapterContext;

// Initialize packet adapter
static UINT se_pa_init(SESSION* session) {
    LOG_DEBUG("DirectAPI", "Packet adapter initialized");
    return 1;
}

// Get cancel object
static CANCEL* se_pa_get_cancel(SESSION* session) {
    if (!session || !session->PacketAdapter || !session->PacketAdapter->Param) {
        return NULL;
    }
    
    SEPacketAdapterContext* ctx = (SEPacketAdapterContext*)session->PacketAdapter->Param;
    if (!ctx->cancel) {
        ctx->cancel = NewCancel();
    }
    return ctx->cancel;
}

// Get next packet (called by SoftEther to read FROM platform/TUN)
static UINT se_pa_get_next_packet(SESSION* session, void** data, UINT* size) {
    // Platform will push packets via se_write_packet()
    // Return 0 to indicate no packet available from platform right now
    return 0;
}

// Put packet (called by SoftEther to send TO platform/TUN)
static UINT se_pa_put_packet(SESSION* session, void* data, UINT size) {
    if (!session || !data || size == 0) {
        return 0;
    }
    
    // Packet from VPN server - platform will read via se_read_packet()
    // SoftEther will queue this in SESSION->Connection->ReceivedBlocks
    return 1;
}

// Free packet adapter
static void se_pa_free(SESSION* session) {
    if (!session || !session->PacketAdapter || !session->PacketAdapter->Param) {
        return;
    }
    
    SEPacketAdapterContext* ctx = (SEPacketAdapterContext*)session->PacketAdapter->Param;
    if (ctx->cancel) {
        ReleaseCancel(ctx->cancel);
        ctx->cancel = NULL;
    }
    Free(ctx);
    
    LOG_DEBUG("DirectAPI", "Packet adapter freed");
}

// Create packet adapter
static PACKET_ADAPTER* se_create_packet_adapter(SESessionContext* session_ctx) {
    PACKET_ADAPTER* pa = ZeroMalloc(sizeof(PACKET_ADAPTER));
    if (!pa) return NULL;
    
    SEPacketAdapterContext* pa_ctx = ZeroMalloc(sizeof(SEPacketAdapterContext));
    if (!pa_ctx) {
        Free(pa);
        return NULL;
    }
    
    pa_ctx->session_ctx = session_ctx;
    pa_ctx->cancel = NULL;
    
    pa->Id = 0;
    pa->Param = pa_ctx;
    pa->Init = (PA_INIT*)se_pa_init;
    pa->GetCancel = (PA_GETCANCEL*)se_pa_get_cancel;
    pa->GetNextPacket = (PA_GETNEXTPACKET*)se_pa_get_next_packet;
    pa->PutPacket = (PA_PUTPACKET*)se_pa_put_packet;
    pa->Free = (PA_FREE*)se_pa_free;
    
    LOG_DEBUG("DirectAPI", "Packet adapter created");
    return pa;
}

/* ========================================================================
 * Library Initialization
 * ======================================================================== */

int se_init(void) {
    if (g_se_initialized) {
        LOG_INFO("DirectAPI", "Already initialized");
        return 0;
    }
    
    LOG_INFO("DirectAPI", "Initializing SoftEther libraries");
    
    // Initialize Mayaqua library
    InitMayaqua(0, 0, 0, NULL);
    
    // Initialize Cedar library  
    InitCedar();
    
    g_se_initialized = 1;
    
    LOG_INFO("DirectAPI", "Initialization complete");
    return 0;
}

void se_shutdown(void) {
    if (!g_se_initialized) {
        return;
    }
    
    LOG_INFO("DirectAPI", "Shutting down SoftEther libraries");
    
    // Cleanup Cedar
    FreeCedar();
    
    // Cleanup Mayaqua
    FreeMayaqua();
    
    g_se_initialized = 0;
    
    LOG_INFO("DirectAPI", "Shutdown complete");
}

/* ========================================================================
 * Connection Functions
 * ======================================================================== */

SESessionHandle se_connect(
    const SEConfig* config,
    SENetworkCallback network_callback,
    SEStatusCallback status_callback,
    SEErrorCallback error_callback,
    void* user_data
) {
    if (!g_se_initialized) {
        se_init();
    }
    
    if (!config || !config->server || !config->hub || !config->username) {
        LOG_ERROR("DirectAPI", "Invalid configuration");
        return NULL;
    }
    
    LOG_INFO("DirectAPI", "Connecting to %s:%d hub:%s user:%s", 
             config->server, config->port, config->hub, config->username);
    
    // Allocate session context
    SESessionContext* ctx = ZeroMalloc(sizeof(SESessionContext));
    if (!ctx) {
        LOG_ERROR("DirectAPI", "Failed to allocate session context");
        return NULL;
    }
    
    // Copy configuration
    strncpy(ctx->server, config->server, sizeof(ctx->server) - 1);
    strncpy(ctx->hub, config->hub, sizeof(ctx->hub) - 1);
    strncpy(ctx->username, config->username, sizeof(ctx->username) - 1);
    if (config->password_hash) {
        strncpy((char*)ctx->password_hash, config->password_hash, sizeof(ctx->password_hash) - 1);
    }
    if (config->client_name) {
        strncpy(ctx->client_name, config->client_name, sizeof(ctx->client_name) - 1);
    } else {
        strcpy(ctx->client_name, "SoftEther_Direct");
    }
    
    ctx->port = config->port > 0 ? config->port : 443;
    ctx->use_encrypt = config->use_encrypt ? 1 : 0;
    ctx->use_compress = config->use_compress ? 1 : 0;
    
    // Store callbacks
    ctx->network_callback = network_callback;
    ctx->status_callback = status_callback;
    ctx->error_callback = error_callback;
    ctx->user_data = user_data;
    
    ctx->status = SE_STATUS_CONNECTING;
    ctx->connect_start_time = Tick64();
    
    se_set_status(ctx, SE_STATUS_CONNECTING, "Creating CLIENT object");
    
    // Create CLIENT object (direct SoftEther!)
    ctx->client = CiNewClient();
    if (!ctx->client) {
        se_set_error(ctx, SE_ERROR_INTERNAL, "Failed to create CLIENT object");
        Free(ctx);
        return NULL;
    }
    
    LOG_DEBUG("DirectAPI", "CLIENT object created");
    
    // Create CLIENT_OPTION
    CLIENT_OPTION* option = ZeroMalloc(sizeof(CLIENT_OPTION));
    if (!option) {
        se_set_error(ctx, SE_ERROR_INTERNAL, "Failed to allocate CLIENT_OPTION");
        CtReleaseClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    // Configure connection options
    StrCpy(option->Hostname, sizeof(option->Hostname), ctx->server);
    option->Port = ctx->port;
    StrCpy(option->HubName, sizeof(option->HubName), ctx->hub);
    option->UseEncrypt = ctx->use_encrypt;
    option->UseCompress = ctx->use_compress;
    option->MaxConnection = 1;
    option->HalfConnection = 0;
    option->NoRoutingTracking = 1;
    option->NumRetry = 3;
    option->RetryInterval = 5;
    
    LOG_DEBUG("DirectAPI", "CLIENT_OPTION configured");
    
    // Create CLIENT_AUTH
    CLIENT_AUTH* auth = ZeroMalloc(sizeof(CLIENT_AUTH));
    if (!auth) {
        se_set_error(ctx, SE_ERROR_INTERNAL, "Failed to allocate CLIENT_AUTH");
        Free(option);
        CtReleaseClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    auth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
    StrCpy(auth->Username, sizeof(auth->Username), ctx->username);
    
    // Decode Base64 password hash to binary (SHA-1 hash = 20 bytes)
    if (config->password_hash && strlen(config->password_hash) > 0) {
        char decoded[SHA1_SIZE * 2];  // Extra space for safety
        int decoded_len = B64_Decode(decoded, (char*)config->password_hash, strlen(config->password_hash));
        
        if (decoded_len == SHA1_SIZE) {
            Copy(auth->HashedPassword, decoded, SHA1_SIZE);
            LOG_DEBUG("DirectAPI", "Password hash decoded: %d bytes", decoded_len);
        } else {
            LOG_ERROR("DirectAPI", "Invalid password hash length: got %d bytes, expected %d", 
                     decoded_len, SHA1_SIZE);
            se_set_error(ctx, SE_ERROR_INTERNAL, "Invalid password hash");
            Free(auth);
            Free(option);
            CtReleaseClient(ctx->client);
            Free(ctx);
            return NULL;
        }
    }
    
    LOG_DEBUG("DirectAPI", "CLIENT_AUTH configured");
    
    se_set_status(ctx, SE_STATUS_CONNECTING, "Creating packet adapter");
    
    // Create Zig packet adapter (with DHCP support)
    extern PACKET_ADAPTER* NewZigPacketAdapter(void);
    ctx->packet_adapter = NewZigPacketAdapter();
    if (!ctx->packet_adapter) {
        se_set_error(ctx, SE_ERROR_INTERNAL, "Failed to create packet adapter");
        Free(auth);
        Free(option);
        CtReleaseClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    LOG_DEBUG("DirectAPI", "Zig packet adapter created");
    
    // Create ACCOUNT
    ctx->account = ZeroMalloc(sizeof(ACCOUNT));
    if (!ctx->account) {
        se_set_error(ctx, SE_ERROR_INTERNAL, "Failed to allocate ACCOUNT");
        FreePacketAdapter(ctx->packet_adapter);
        Free(auth);
        Free(option);
        CtReleaseClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    ctx->account->lock = NewLock();
    ctx->account->ClientOption = option;  // Store the option pointer
    ctx->account->ClientAuth = auth;      // Store the auth pointer
    
    // Set account name (wchar_t string) using conversion
    wchar_t* account_name_uni = CopyStrToUni(ctx->client_name);
    UniStrCpy(ctx->account->ClientOption->AccountName, 
              sizeof(ctx->account->ClientOption->AccountName), 
              account_name_uni);
    Free(account_name_uni);
    
    LOG_DEBUG("DirectAPI", "ACCOUNT created");
    
    se_set_status(ctx, SE_STATUS_CONNECTING, "Creating SESSION");
    
    // Create SESSION (direct SoftEther object!)
    ctx->session = NewClientSessionEx(
        ctx->client->Cedar,
        option,
        auth,
        ctx->packet_adapter,
        ctx->account
    );
    
    if (!ctx->session) {
        se_set_error(ctx, SE_ERROR_CONNECT_FAILED, "Failed to create SESSION");
        DeleteLock(ctx->account->lock);
        Free(ctx->account);
        FreePacketAdapter(ctx->packet_adapter);
        Free(auth);
        Free(option);
        CtReleaseClient(ctx->client);
        Free(ctx);
        return NULL;
    }
    
    // AddRef to prevent ClientThread from freeing the SESSION while we're monitoring it
    // This matches vpnclient behavior where the session is kept alive by external references
    AddRef(ctx->session->ref);
    LOG_DEBUG("DirectAPI", "SESSION ref incremented (ref=%p count=%u)", ctx->session->ref, ctx->session->ref->c);
    
    LOG_INFO("DirectAPI", "SESSION created successfully - connecting asynchronously");
    se_set_status(ctx, SE_STATUS_CONNECTING, "Session created - connecting to server");
    
    // Start event-driven status monitoring thread
    ctx->stop_monitor_event = NewEvent();
    ctx->monitor_running = TRUE;
    ctx->monitor_thread = NewThread(StatusMonitorThread, ctx);
    WaitThreadInit(ctx->monitor_thread);
    LOG_INFO("DirectAPI", "Status monitor thread started - fully event-driven");
    
    return (SESessionHandle)ctx;
}

void se_disconnect(SESessionHandle session) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx) {
        return;
    }
    
    LOG_INFO("DirectAPI", "Disconnecting session");
    
    // Stop monitor thread first
    if (ctx->monitor_thread) {
        LOG_DEBUG("DirectAPI", "Stopping status monitor thread");
        ctx->monitor_running = FALSE;
        Set(ctx->stop_monitor_event);
        WaitThread(ctx->monitor_thread, INFINITE);
        ReleaseThread(ctx->monitor_thread);
        ctx->monitor_thread = NULL;
    }
    if (ctx->stop_monitor_event) {
        ReleaseEvent(ctx->stop_monitor_event);
        ctx->stop_monitor_event = NULL;
    }
    
    se_set_status(ctx, SE_STATUS_DISCONNECTED, "Disconnecting");
    
    // Stop session (this will signal ClientThread to exit)
    if (ctx->session) {
        LOG_DEBUG("DirectAPI", "Stopping SESSION");
        StopSession(ctx->session);
        
        // Release our reference - ClientThread will free the SESSION when its ref reaches 0
        LOG_DEBUG("DirectAPI", "Releasing SESSION ref (ref=%p count=%u)", ctx->session->ref, ctx->session->ref->c);
        ReleaseSession(ctx->session);
        ctx->session = NULL;
    }
    
    // Cleanup account
    if (ctx->account) {
        if (ctx->account->lock) {
            DeleteLock(ctx->account->lock);
        }
        Free(ctx->account);
        ctx->account = NULL;
    }
    
    // Release client
    if (ctx->client) {
        LOG_DEBUG("DirectAPI", "Releasing CLIENT");
        CtReleaseClient(ctx->client);
        ctx->client = NULL;
    }
    
    // Free context
    Free(ctx);
    
    LOG_INFO("DirectAPI", "Disconnection complete");
}

SEStatus se_get_status(SESessionHandle session) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx) {
        return SE_STATUS_DISCONNECTED;
    }
    
    // Update status based on session state
    if (ctx->session) {
        if (ctx->session->Halt) {
            ctx->status = SE_STATUS_DISCONNECTED;
        } else if (ctx->session->ClientStatus == CLIENT_STATUS_ESTABLISHED) {
            if (ctx->status != SE_STATUS_CONNECTED) {
                ctx->status = SE_STATUS_CONNECTED;
                se_set_status(ctx, SE_STATUS_CONNECTED, "Connection established");
            }
        } else if (ctx->session->ClientStatus == CLIENT_STATUS_CONNECTING) {
            if (ctx->status != SE_STATUS_CONNECTING) {
                ctx->status = SE_STATUS_CONNECTING;
            }
        } else if (ctx->session->Err != 0) {
            if (ctx->status != SE_STATUS_ERROR) {
                ctx->status = SE_STATUS_ERROR;
                se_set_error(ctx, SE_ERROR_CONNECT_FAILED, "Connection error");
            }
        }
    }
    
    return ctx->status;
}

bool se_is_connected(SESessionHandle session) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx || !ctx->session) {
        return false;
    }
    
    // Check if session is alive and established
    if (ctx->session->Halt || ctx->session->ForceStopFlag) {
        return false;
    }
    
    if (ctx->session->ClientStatus != CLIENT_STATUS_ESTABLISHED) {
        return false;
    }
    
    return true;
}

int se_get_last_error(SESessionHandle session) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx) {
        return SE_ERROR_INVALID_PARAM;
    }
    return ctx->last_error;
}

const char* se_get_error_message(SESessionHandle session) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx) {
        return "Invalid session handle";
    }
    return ctx->error_message;
}

/* ========================================================================
 * Packet I/O Functions (Direct SESSION access!)
 * ======================================================================== */

int se_read_packet(SESessionHandle session, uint8_t* buffer, size_t buffer_size, uint32_t timeout_ms) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx || !ctx->session || !buffer || buffer_size == 0) {
        return SE_ERROR_INVALID_PARAM;
    }
    
    // Read directly from SESSION->Connection->ReceivedBlocks
    if (ctx->session->Connection && ctx->session->Connection->ReceivedBlocks) {
        BLOCK* block = GetNext(ctx->session->Connection->ReceivedBlocks);
        if (block) {
            if (block->Size <= buffer_size) {
                Copy(buffer, block->Buf, block->Size);
                UINT size = block->Size;
                
                ctx->bytes_received += size;
                ctx->packets_received++;
                
                FreeBlock(block);
                return (int)size;
            } else {
                // Buffer too small
                FreeBlock(block);
                return SE_ERROR_PACKET_BUFFER;
            }
        }
    }
    
    // No packet available
    return 0;
}

int se_write_packet(SESessionHandle session, const uint8_t* data, size_t size) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx || !ctx->session || !data || size == 0) {
        return SE_ERROR_INVALID_PARAM;
    }
    
    if (size > MAX_PACKET_SIZE) {
        return SE_ERROR_PACKET_BUFFER;
    }
    
    // Create block and add directly to SESSION->Connection->SendBlocks
    UCHAR* buf_copy = Malloc(size);
    if (!buf_copy) {
        return SE_ERROR_INTERNAL;
    }
    Copy(buf_copy, data, size);
    
    BLOCK* block = NewBlock(buf_copy, size, 0);
    if (!block) {
        Free(buf_copy);
        return SE_ERROR_INTERNAL;
    }
    
    // Add to send queue
    if (ctx->session->Connection && ctx->session->Connection->SendBlocks) {
        InsertQueue(ctx->session->Connection->SendBlocks, block);
        
        ctx->bytes_sent += size;
        ctx->packets_sent++;
        
        return 0;
    }
    
    FreeBlock(block);
    return SE_ERROR_DISCONNECTED;
}

/* ========================================================================
 * Utility Functions
 * ======================================================================== */

char* se_generate_password_hash(const char* password, const char* username) {
    if (!password || !username) {
        return NULL;
    }
    
    // Combine password + username
    UINT pass_len = StrLen(password);
    UINT user_len = StrLen(username);
    char* combined = Malloc(pass_len + user_len + 1);
    if (!combined) {
        return NULL;
    }
    
    StrCpy(combined, pass_len + user_len + 1, password);
    StrCat(combined, pass_len + user_len + 1, username);
    
    // Generate SHA-0 hash (SoftEther's hashing algorithm)
    UCHAR hash[SHA1_SIZE];
    Sha(SHA1_160, hash, combined, StrLen(combined));
    
    // Convert to hex string
    char* hex = Malloc(SHA1_SIZE * 2 + 1);
    if (!hex) {
        Free(combined);
        return NULL;
    }
    
    BinToStr(hex, SHA1_SIZE * 2 + 1, hash, SHA1_SIZE);
    
    Free(combined);
    
    LOG_DEBUG("DirectAPI", "Password hash generated");
    return hex;
}

const char* se_get_version(void) {
    return "1.0.0-direct";
}

const char* se_get_build_info(void) {
    return "SoftEther Direct API - Zero FFI";
}

/* ========================================================================
 * Statistics Functions
 * ======================================================================== */

int se_get_stats(SESessionHandle session, SEStats* stats) {
    SESessionContext* ctx = (SESessionContext*)session;
    if (!ctx || !stats) {
        return SE_ERROR_INVALID_PARAM;
    }
    
    stats->bytes_sent = ctx->bytes_sent;
    stats->bytes_received = ctx->bytes_received;
    stats->packets_sent = ctx->packets_sent;
    stats->packets_received = ctx->packets_received;
    
    if (ctx->status == SE_STATUS_CONNECTED) {
        stats->connected_time_ms = Tick64() - ctx->connect_start_time;
    } else {
        stats->connected_time_ms = 0;
    }
    
    return 0;
}
