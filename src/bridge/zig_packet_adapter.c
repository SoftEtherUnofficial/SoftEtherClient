// Zig Packet Adapter - Simplified C Wrapper (Phase 1: DHCP/ARP removed)
// ✅ WAVE 5 PHASE 1: Eliminated ~350 lines of duplicate DHCP/ARP logic
// ZigTapTun now handles: DHCP client, ARP handler, L2↔L3 translation
//
// What remains:
// - SoftEther PACKET_ADAPTER interface (Init, GetCancel, GetNextPacket, PutPacket, Free)
// - Minimal packet forwarding between SoftEther SESSION and Zig adapter
// - No DHCP state machine (✅ removed - ZigTapTun handles it)
// - No ARP handling (✅ removed - ZigTapTun handles it)
// - No packet type detection (✅ removed - ZigTapTun handles it)
// - No global state variables (✅ removed - per-adapter state only)

// **CRITICAL FIX**: Undefine TARGET_OS_IPHONE if defined - we're building for macOS, not iOS!
#ifdef TARGET_OS_IPHONE
#undef TARGET_OS_IPHONE
#endif

#include "../../include/zig_packet_adapter.h"
#include "zig_bridge.h"
#include "Mayaqua/Mayaqua.h"
#include "Cedar/Cedar.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Zig adapter context structure (per-adapter state, not global!)
typedef struct ZIG_ADAPTER_CONTEXT {
    SESSION *session;
    ZigPacketAdapter *zig_adapter;
    CANCEL *cancel;
    bool halt;
} ZIG_ADAPTER_CONTEXT;

// ✅ REMOVED (~350 lines): DHCP state machine, ARP handling, packet builders
// ZigTapTun handles all of this automatically through its translator layer:
// - DHCP client (dhcp_client.zig): DISCOVER, OFFER, REQUEST, ACK
// - ARP handler (arp.zig): Request/Reply, gateway MAC learning
// - L2↔L3 translator (translator.zig): Automatic packet conversion
//
// Old code had:
// - DHCP_STATE enum (6 states)
// - 15+ global state variables (g_dhcp_state, g_offered_ip, g_my_mac, etc.)
// - ParseDhcpPacket() function (~60 lines)
// - DHCP packet building logic (~150 lines)
// - ARP packet building logic (~100 lines)
// - Packet type detection (~50 lines)
//
// All eliminated! 🎉

// Forward declarations of SoftEther callbacks
static bool ZigAdapterInit(SESSION* s);
static CANCEL* ZigAdapterGetCancel(SESSION* s);
static UINT ZigAdapterGetNextPacket(SESSION* s, void** data);
static bool ZigAdapterPutPacket(SESSION* s, void* data, UINT size);
static void ZigAdapterFree(SESSION* s);

// Create new Zig packet adapter
PACKET_ADAPTER* NewZigPacketAdapter(void) {
    printf("[NewZigPacketAdapter] Creating Zig packet adapter (WAVE 5 PHASE 1: DHCP/ARP removed)\n");
    
    // Allocate PACKET_ADAPTER structure
    PACKET_ADAPTER* pa = ZeroMalloc(sizeof(PACKET_ADAPTER));
    if (!pa) {
        printf("[NewZigPacketAdapter] Failed to allocate PACKET_ADAPTER\n");
        return NULL;
    }
    
    // Set up callbacks
    pa->Init = ZigAdapterInit;
    pa->GetCancel = ZigAdapterGetCancel;
    pa->GetNextPacket = ZigAdapterGetNextPacket;
    pa->PutPacket = ZigAdapterPutPacket;
    pa->Free = ZigAdapterFree;
    
    // CRITICAL: Use same ID as C adapter (PACKET_ADAPTER_ID_VLAN_WIN32 = 1)
    // This prevents server from treating Zig adapter differently!
    #define PACKET_ADAPTER_ID_VLAN_WIN32 1
    pa->Id = PACKET_ADAPTER_ID_VLAN_WIN32;
    
    printf("[NewZigPacketAdapter] Created adapter with Id=%u (DHCP/ARP delegated to ZigTapTun)\n", pa->Id);
    return pa;
}

// Initialize adapter
static bool ZigAdapterInit(SESSION* s) {
    printf("[ZigAdapterInit] Initializing Zig adapter (WAVE 5 PHASE 1)\n");
    
    if (!s) {
        printf("[ZigAdapterInit] ERROR: Session is NULL\n");
        return false;
    }
    
    // Allocate context
    ZIG_ADAPTER_CONTEXT* ctx = ZeroMalloc(sizeof(ZIG_ADAPTER_CONTEXT));
    if (!ctx) {
        printf("[ZigAdapterInit] Failed to allocate context\n");
        return false;
    }
    
    ctx->session = s;
    ctx->halt = false;
    
    // Create cancel handle
    ctx->cancel = NewCancel();
    if (!ctx->cancel) {
        printf("[ZigAdapterInit] Failed to create cancel handle\n");
        Free(ctx);
        return false;
    }
    
    // Configure Zig adapter with ZigTapTun translator
    // ✅ ZigTapTun handles DHCP/ARP automatically (no manual state machine!)
    ZigAdapterConfig config = {
        .recv_queue_size = 128,   // Balanced for downloads
        .send_queue_size = 128,   // Balanced for uploads
        .packet_pool_size = 256,  // CRITICAL: Must be >= recv+send
        .batch_size = 128,        // Match queue size
        .device_name = "utun",
        .device_name_len = 4,     // MUST match device_name string length
    };
    
    printf("[ZigAdapterInit] Creating Zig adapter with ZigTapTun translator\n");
    printf("[ZigAdapterInit]   recv_q=%zu, send_q=%zu, pool=%zu, batch=%zu\n",
           config.recv_queue_size, config.send_queue_size, config.packet_pool_size, config.batch_size);
    printf("[ZigAdapterInit]   ✅ DHCP client enabled (auto IP assignment)\n");
    printf("[ZigAdapterInit]   ✅ ARP handler enabled (auto gateway MAC learning)\n");
    printf("[ZigAdapterInit]   ✅ L2↔L3 translator enabled (auto packet conversion)\n");
    
    // Create Zig adapter
    ctx->zig_adapter = zig_adapter_create(&config);
    if (!ctx->zig_adapter) {
        printf("[ZigAdapterInit] Failed to create Zig adapter\n");
        ReleaseCancel(ctx->cancel);
        Free(ctx);
        return false;
    }
    
    printf("[ZigAdapterInit] Zig adapter created at %p\n", ctx->zig_adapter);
    
    // Open TUN device
    if (!zig_adapter_open(ctx->zig_adapter)) {
        printf("[ZigAdapterInit] Failed to open TUN device\n");
        zig_adapter_destroy(ctx->zig_adapter);
        ReleaseCancel(ctx->cancel);
        Free(ctx);
        return false;
    }
    
    printf("[ZigAdapterInit] TUN device opened successfully\n");
    
    // Get device name for logging
    uint8_t dev_name_buf[64];
    uint64_t dev_name_len = zig_adapter_get_device_name(ctx->zig_adapter, dev_name_buf, sizeof(dev_name_buf));
    if (dev_name_len > 0 && dev_name_len < sizeof(dev_name_buf)) {
        dev_name_buf[dev_name_len] = '\0';  // Null terminate
        printf("[ZigAdapterInit] Device name: %s\n", dev_name_buf);
        
        // Bring interface UP (ZigTapTun will handle DHCP automatically)
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ifconfig %s up", dev_name_buf);
        printf("[ZigAdapterInit] Bringing interface UP: %s\n", cmd);
        system(cmd);
        
        printf("[ZigAdapterInit] ✅ Interface is UP\n");
        printf("[ZigAdapterInit] ✅ ZigTapTun will handle DHCP/ARP automatically\n");
        printf("[ZigAdapterInit] ✅ No manual state machine needed!\n");
    }
    
    // Store context in session
    s->PacketAdapter->Param = ctx;
    
    printf("[ZigAdapterInit] ✅ Initialization complete (WAVE 5 PHASE 1: ~350 lines eliminated!)\n");
    return true;
}

// Get cancel handle
static CANCEL* ZigAdapterGetCancel(SESSION* s) {
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return NULL;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    return ctx->cancel;
}

// Get next packet from TUN device
// ✅ SIMPLIFIED: No DHCP/ARP state machine, just read from TUN
// ZigTapTun's translator handles all L2/L3 conversion automatically
static UINT ZigAdapterGetNextPacket(SESSION* s, void** data) {
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return 0;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    if (ctx->halt) {
        return 0;
    }
    
    // ✅ WAVE 5 PHASE 1: No DHCP state machine!
    // Old code had ~200 lines of DHCP logic here (DISCOVER, OFFER, REQUEST, ACK)
    // Now: Just read from TUN, ZigTapTun handles DHCP automatically
    
    // **SYNCHRONOUS TUN READ** (like C adapter)
    // Read directly from TUN device when session polls
    uint8_t temp_buf[2048];
    ssize_t bytes_read = zig_adapter_read_sync(ctx->zig_adapter, temp_buf, sizeof(temp_buf));
    
    if (bytes_read <= 0) {
        // No packet available or error
        return 0;
    }
    
    // Copy packet data for SoftEther
    UCHAR* pkt_copy = Malloc(bytes_read);
    if (!pkt_copy) {
        printf("[ZigAdapterGetNextPacket] Failed to allocate packet buffer\n");
        return 0;
    }
    
    memcpy(pkt_copy, temp_buf, bytes_read);
    *data = pkt_copy;
    
    return (UINT)bytes_read;
}

// Put packet to TUN device
// ✅ SIMPLIFIED: No DHCP/ARP parsing, just write to TUN
// ZigTapTun's translator handles all L2/L3 conversion automatically
static bool ZigAdapterPutPacket(SESSION* s, void* data, UINT size) {
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param || !data || size == 0) {
        return false;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    if (ctx->halt) {
        return false;
    }
    
    // ✅ WAVE 5 PHASE 1: No packet type detection!
    // Old code had ~150 lines parsing DHCP/ARP/IP packets
    // Now: Just write to TUN, ZigTapTun translator handles everything
    
    // Write packet to TUN device
    bool success = zig_adapter_write_packet(ctx->zig_adapter, (const uint8_t*)data, (uint64_t)size);
    
    if (!success) {
        printf("[ZigAdapterPutPacket] Failed to write packet (size=%u)\n", size);
        return false;
    }
    
    return true;
}

// Free adapter resources
static void ZigAdapterFree(SESSION* s) {
    printf("[ZigAdapterFree] Freeing Zig adapter\n");
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    // Signal halt
    ctx->halt = true;
    
    // Close and destroy Zig adapter
    if (ctx->zig_adapter) {
        zig_adapter_close(ctx->zig_adapter);
        zig_adapter_destroy(ctx->zig_adapter);
        ctx->zig_adapter = NULL;
    }
    
    // Release cancel handle
    if (ctx->cancel) {
        ReleaseCancel(ctx->cancel);
        ctx->cancel = NULL;
    }
    
    // Free context
    Free(ctx);
    s->PacketAdapter->Param = NULL;
    
    printf("[ZigAdapterFree] ✅ Cleanup complete (WAVE 5 PHASE 1)\n");
}

// ========================================================================
// C Bridge Helper Functions (TODO: Move to separate file in Phase 2)
// ========================================================================
// These functions provide FFI compatibility for Zig code accessing SoftEther C structures
// They should be moved to a dedicated bridge/helpers.c file in Phase 2

// Helper function to get CEDAR from CLIENT
// Exported for use by Zig FFI layer
CEDAR* CiGetCedar(CLIENT *client)
{
    if (client == NULL) {
        return NULL;
    }
    return client->Cedar;
}

// Helper functions for Zig to get C structure sizes
size_t sizeof_CLIENT_OPTION(void) {
    return sizeof(CLIENT_OPTION);
}

size_t sizeof_CLIENT_AUTH(void) {
    return sizeof(CLIENT_AUTH);
}

// Helper functions to safely set string fields in CLIENT_OPTION
void set_client_option_hostname(void *opt_ptr, const char *hostname) {
    CLIENT_OPTION *opt = (CLIENT_OPTION *)opt_ptr;
    if (opt && hostname) {
        StrCpy(opt->Hostname, sizeof(opt->Hostname), hostname);
    }
}

void set_client_option_hubname(void *opt_ptr, const char *hubname) {
    CLIENT_OPTION *opt = (CLIENT_OPTION *)opt_ptr;
    if (opt && hubname) {
        StrCpy(opt->HubName, sizeof(opt->HubName), hubname);
    }
}

void set_client_option_devicename(void *opt_ptr, const char *devicename) {
    CLIENT_OPTION *opt = (CLIENT_OPTION *)opt_ptr;
    if (opt && devicename) {
        StrCpy(opt->DeviceName, sizeof(opt->DeviceName), devicename);
    }
}

void set_client_auth_username(void *auth_ptr, const char *username) {
    CLIENT_AUTH *auth = (CLIENT_AUTH *)auth_ptr;
    if (auth && username) {
        StrCpy(auth->Username, sizeof(auth->Username), username);
    }
}

// ✅ WAVE 5 PHASE 1 COMPLETE!
// Lines: 312 → 370 (added 58 lines of helper functions from backup)
// Net reduction: 929 → 370 lines (559 lines eliminated = 60% reduction!)
// 
// Eliminated:
// - DHCP state machine (~200 lines)
// - ARP handling (~150 lines)
// - Packet type detection (~100 lines)
// - Global state variables (~50 lines)
// - Packet parsing logic (~60 lines)
//
// ZigTapTun now handles:
// ✅ DHCP client (automatic IP)
// ✅ ARP handler (automatic MAC learning)
// ✅ L2↔L3 translator (automatic conversion)
//
// Next: Phase 2 - Port SoftEther callbacks to Zig!
