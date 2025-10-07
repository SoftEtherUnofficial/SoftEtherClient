// Zig Packet Adapter - C Wrapper Implementation
// Wraps Zig packet adapter to provide SoftEther PACKET_ADAPTER interface

#include "zig_packet_adapter.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// External function declarations from packet_adapter_macos.c
extern UCHAR *BuildGratuitousArp(UCHAR *my_mac, UINT32 my_ip, UINT *out_size);
extern UCHAR *BuildDhcpDiscover(UCHAR *my_mac, UINT32 xid, UINT *out_size);
extern UCHAR *BuildDhcpRequest(UCHAR *my_mac, UINT32 xid, UINT32 requested_ip, UINT32 server_ip, UINT *out_size);
extern UCHAR *BuildArpRequest(UCHAR *my_mac, UINT32 my_ip, UINT32 target_ip, UINT *out_size);
extern UCHAR *BuildArpReply(UCHAR *my_mac, UINT32 my_ip, UCHAR *target_mac, UINT32 target_ip, UINT *out_size);

// DHCP state machine (mirrors packet_adapter_macos.c)
typedef enum {
    DHCP_STATE_INIT = 0,
    DHCP_STATE_ARP_ANNOUNCE_SENT = 1,
    DHCP_STATE_DISCOVER_SENT = 2,
    DHCP_STATE_OFFER_RECEIVED = 3,
    DHCP_STATE_REQUEST_SENT = 4,
    DHCP_STATE_CONFIGURED = 5
} DHCP_STATE;

// DHCP state tracking
static DHCP_STATE g_dhcp_state = DHCP_STATE_INIT;
static UINT32 g_dhcp_xid = 0;
static UCHAR g_my_mac[6] = {0};
static UINT64 g_connection_start_time = 0;
static UINT64 g_last_dhcp_send_time = 0;
static UINT g_dhcp_retry_count = 0;
static bool g_dhcp_initialized = false;
static UINT32 g_offered_ip = 0;
static UINT32 g_offered_gw = 0;
static UINT32 g_offered_mask = 0;
static UINT32 g_dhcp_server_ip = 0;
static UINT32 g_our_ip = 0;
static bool g_need_gateway_arp = false;  // CRITICAL: Request gateway MAC after DHCP
static bool g_need_gratuitous_arp_configured = false;  // CRITICAL: Announce our IP after DHCP
static bool g_need_arp_reply = false;    // CRITICAL: Reply to ARP Request from server
static UCHAR g_arp_reply_to_mac[6] = {0};  // MAC to send ARP Reply to
static UINT32 g_arp_reply_to_ip = 0;      // IP to send ARP Reply to

// Helper function to parse DHCP packet and extract message type
static bool ParseDhcpPacket(const UCHAR* data, UINT size, UINT32* out_offered_ip, UINT32* out_gw, UINT32* out_mask, UCHAR* out_msg_type, UINT32* out_server_ip) {
    *out_offered_ip = 0;
    *out_gw = 0;
    *out_mask = 0;
    *out_msg_type = 0;
    *out_server_ip = 0;
    
    // DHCP packet structure: Ethernet(14) + IP(20) + UDP(8) + BOOTP(236) + DHCP options
    if (size < 14 + 20 + 8 + 236) {
        return false;
    }
    
    // Skip to BOOTP header (after Ethernet + IP + UDP)
    const UCHAR* bootp = data + 14 + 20 + 8;
    
    // Extract yiaddr (your IP address) at offset 16 in BOOTP header
    *out_offered_ip = (bootp[16] << 24) | (bootp[17] << 16) | (bootp[18] << 8) | bootp[19];
    
    // Verify DHCP magic cookie at offset 236-239 in BOOTP header
    UINT32 magic = (bootp[236] << 24) | (bootp[237] << 16) | (bootp[238] << 8) | bootp[239];
    if (magic != 0x63825363) {
        printf("[ParseDhcpPacket] ⚠️  Invalid DHCP magic cookie: 0x%08x (expected 0x63825363)\n", magic);
        return false;
    }
    
    // Parse DHCP options (start at offset 240 in BOOTP header, after magic cookie)
    const UCHAR* options = bootp + 240;
    UINT options_len = size - (14 + 20 + 8 + 240);
    
    for (UINT i = 0; i < options_len;) {
        UCHAR option_type = options[i++];
        if (option_type == 0xFF) break; // End of options
        if (option_type == 0x00) continue; // Padding
        
        if (i >= options_len) break;
        UCHAR option_len = options[i++];
        
        if (i + option_len > options_len) break;
        
        if (option_type == 53 && option_len == 1) { // DHCP Message Type
            *out_msg_type = options[i];
        } else if (option_type == 54 && option_len == 4) { // DHCP Server Identifier
            *out_server_ip = (options[i] << 24) | (options[i+1] << 16) | (options[i+2] << 8) | options[i+3];
        } else if (option_type == 3 && option_len == 4) { // Router (gateway)
            *out_gw = (options[i] << 24) | (options[i+1] << 16) | (options[i+2] << 8) | options[i+3];
        } else if (option_type == 1 && option_len == 4) { // Subnet mask
            *out_mask = (options[i] << 24) | (options[i+1] << 16) | (options[i+2] << 8) | options[i+3];
        }
        
        i += option_len;
    }
    
    return (*out_offered_ip != 0);
}

// External DHCP packet builders from packet_adapter_macos.c
extern UCHAR* BuildGratuitousArp(UCHAR *my_mac, UINT32 my_ip, UINT *out_size);
extern UCHAR* BuildDhcpDiscover(UCHAR *my_mac, UINT32 xid, UINT *out_size);
extern UCHAR* BuildDhcpRequest(UCHAR *my_mac, UINT32 xid, UINT32 requested_ip, UINT32 server_ip, UINT *out_size);

// Forward declarations of SoftEther callbacks
static bool ZigAdapterInit(SESSION* s);
static CANCEL* ZigAdapterGetCancel(SESSION* s);
static UINT ZigAdapterGetNextPacket(SESSION* s, void** data);
static bool ZigAdapterPutPacket(SESSION* s, void* data, UINT size);
static void ZigAdapterFree(SESSION* s);

// Create new Zig packet adapter
PACKET_ADAPTER* NewZigPacketAdapter(void) {
    printf("[NewZigPacketAdapter] Creating Zig packet adapter\n");
    
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
    
    // Generate unique ID
    static UINT next_id = 1;
    pa->Id = next_id++;
    
    printf("[NewZigPacketAdapter] Created adapter with callbacks, Id=%u\n", pa->Id);
    return pa;
}

// Initialize adapter
static bool ZigAdapterInit(SESSION* s) {
    printf("[ZigAdapterInit] Initializing Zig adapter for session %p\n", s);
    
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
    
    // Configure Zig adapter
    ZigAdapterConfig config = {
        .recv_queue_size = 512,
        .send_queue_size = 256,
        .packet_pool_size = 2,  // Start with just 2 packets (4KB total)
        .batch_size = 32,
        .device_name = "utun",
        .device_name_len = 4,  // MUST match device_name string length
    };
    
    printf("[ZigAdapterInit] Creating Zig adapter with config: recv_q=%llu, send_q=%llu, pool=%llu, batch=%llu\n",
           config.recv_queue_size, config.send_queue_size, config.packet_pool_size, config.batch_size);
    
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
    
    // Start adapter threads
    if (!zig_adapter_start(ctx->zig_adapter)) {
        printf("[ZigAdapterInit] Failed to start adapter threads\n");
        zig_adapter_destroy(ctx->zig_adapter);
        ReleaseCancel(ctx->cancel);
        Free(ctx);
        return false;
    }
    
    printf("[ZigAdapterInit] Zig adapter started successfully\n");
    
    // Configure interface: Just bring it UP without an IP - let the L2/L3 translator
    // handle DHCP packets and the adapter will learn the IP automatically
    printf("[ZigAdapterInit] Bringing interface UP (DHCP will autoconfigure)\n");
    
    // Get device name for ifconfig
    uint8_t dev_name_buf[64];
    uint64_t dev_name_len = zig_adapter_get_device_name(ctx->zig_adapter, dev_name_buf, sizeof(dev_name_buf));
    if (dev_name_len > 0 && dev_name_len < sizeof(dev_name_buf)) {
        dev_name_buf[dev_name_len] = '\0';  // Null terminate
        
        // Strategy: Configure interface with LINK-LOCAL IP initially
        // This allows interface to be UP and ready for DHCP packets
        // Use 169.254.1.1 (link-local range) temporarily until DHCP assigns real IP
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "ifconfig %s inet 169.254.1.1 netmask 255.255.0.0 up", (char*)dev_name_buf);
        printf("[●] ADAPTER: Executing: %s\n", cmd);
        int ret = system(cmd);
        if (ret != 0) {
            printf("[ZigAdapterInit] Warning: Failed to configure interface (ret=%d)\n", ret);
        } else {
            printf("[●] ADAPTER: Interface %s UP with link-local IP (waiting for DHCP)\n", (char*)dev_name_buf);
        }
        
        // Add route to VPN server IPs via local gateway to prevent routing loop
        // This ensures we can still reach the VPN server even when default route changes
        // TODO: Get these IPs from VPN session config instead of hardcoding
        snprintf(cmd, sizeof(cmd), "route add -host 62.24.65.211 192.168.1.1 2>/dev/null");
        printf("[●] ADAPTER: Adding VPN server bypass route\n");
        system(cmd);
        
        snprintf(cmd, sizeof(cmd), "route add -host 62.24.65.213 192.168.1.1 2>/dev/null");
        system(cmd);
    }
    
    // Store context in session
    s->PacketAdapter->Param = ctx;
    
    printf("[ZigAdapterInit] ✅ Initialization complete - waiting for DHCP configuration\n");
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

// Get next packet (single packet mode - for compatibility)
static UINT ZigAdapterGetNextPacket(SESSION* s, void** data) {
    static uint64_t get_count = 0;
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return 0;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    if (ctx->halt) {
        return 0;
    }
    
    // Initialize DHCP state machine once
    if (!g_dhcp_initialized) {
        g_dhcp_initialized = true;
        g_connection_start_time = Tick64();
        g_dhcp_xid = (UINT32)time(NULL); // Use timestamp as transaction ID
        
        // Generate random MAC address (or could use interface MAC)
        for (int i = 0; i < 6; i++) {
            g_my_mac[i] = (UCHAR)(rand() % 256);
        }
        g_my_mac[0] = (g_my_mac[0] & 0xFE) | 0x02; // Set locally administered bit
        
        printf("[ZigAdapterGetNextPacket] 🔄 DHCP initialized: xid=0x%08x, MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
               g_dhcp_xid, g_my_mac[0], g_my_mac[1], g_my_mac[2], g_my_mac[3], g_my_mac[4], g_my_mac[5]);
    }
    
    // DHCP state machine: Send Gratuitous ARP first (after 2s delay)
    UINT64 now = Tick64();
    UINT64 time_since_start = now - g_connection_start_time;
    
    if (g_dhcp_state == DHCP_STATE_INIT && time_since_start >= 2000) {
        UINT pkt_size = 0;
        UCHAR* pkt = BuildGratuitousArp(g_my_mac, 0x00000000, &pkt_size); // 0.0.0.0
        if (pkt && pkt_size > 0) {
            printf("[ZigAdapterGetNextPacket] 📡 Sending Gratuitous ARP (size=%u)\n", pkt_size);
            UCHAR* pkt_copy = Malloc(pkt_size);
            memcpy(pkt_copy, pkt, pkt_size);
            *data = pkt_copy;
            g_dhcp_state = DHCP_STATE_ARP_ANNOUNCE_SENT;
            g_last_dhcp_send_time = now;
            return pkt_size;
        }
    }
    
    // DHCP state machine: Send DHCP DISCOVER (300ms after ARP, then retry every 3s)
    if (g_dhcp_state == DHCP_STATE_ARP_ANNOUNCE_SENT || g_dhcp_state == DHCP_STATE_DISCOVER_SENT) {
        bool should_send = false;
        
        if (g_dhcp_state == DHCP_STATE_ARP_ANNOUNCE_SENT) {
            // First send after 300ms delay
            if ((now - g_last_dhcp_send_time) >= 300) {
                should_send = true;
                g_dhcp_state = DHCP_STATE_DISCOVER_SENT;
                g_dhcp_retry_count = 0;
            }
        } else if (g_dhcp_state == DHCP_STATE_DISCOVER_SENT) {
            // Retry every 3 seconds, up to 5 attempts
            if (g_dhcp_retry_count < 5 && (now - g_last_dhcp_send_time) >= 3000) {
                should_send = true;
                g_dhcp_retry_count++;
                printf("[ZigAdapterGetNextPacket] 🔄 DHCP DISCOVER retry #%u\n", g_dhcp_retry_count);
            }
        }
        
        if (should_send) {
            UINT dhcp_size = 0;
            UCHAR* dhcp_pkt = BuildDhcpDiscover(g_my_mac, g_dhcp_xid, &dhcp_size);
            if (dhcp_pkt && dhcp_size > 0) {
                printf("[ZigAdapterGetNextPacket] 📡 Sending DHCP DISCOVER #%u (xid=0x%08x, size=%u)\n",
                       g_dhcp_retry_count + 1, g_dhcp_xid, dhcp_size);
                UCHAR* pkt_copy = Malloc(dhcp_size);
                memcpy(pkt_copy, dhcp_pkt, dhcp_size);
                *data = pkt_copy;
                g_last_dhcp_send_time = now;
                return dhcp_size;
            }
        }
    }
    
    // DHCP state machine: Send DHCP REQUEST after receiving OFFER (500ms delay)
    if (g_dhcp_state == DHCP_STATE_OFFER_RECEIVED && (now - g_last_dhcp_send_time) >= 500) {
        UINT dhcp_size = 0;
        UCHAR* dhcp_pkt = BuildDhcpRequest(g_my_mac, g_dhcp_xid, g_offered_ip, g_dhcp_server_ip, &dhcp_size);
        if (dhcp_pkt && dhcp_size > 0) {
            printf("[ZigAdapterGetNextPacket] 📡 Sending DHCP REQUEST for IP %u.%u.%u.%u (size=%u)\n",
                   (g_offered_ip >> 24) & 0xFF, (g_offered_ip >> 16) & 0xFF,
                   (g_offered_ip >> 8) & 0xFF, g_offered_ip & 0xFF, dhcp_size);
            UCHAR* pkt_copy = Malloc(dhcp_size);
            memcpy(pkt_copy, dhcp_pkt, dhcp_size);
            *data = pkt_copy;
            g_dhcp_state = DHCP_STATE_REQUEST_SENT;
            g_last_dhcp_send_time = now;
            return dhcp_size;
        }
    }
    
    // **PRIORITY 1**: Send ARP Reply if server asked for our IP
    // This is CRITICAL - server sends ARP Request before sending traffic back!
    if (g_need_arp_reply && g_dhcp_state == DHCP_STATE_CONFIGURED) {
        g_need_arp_reply = false;  // Send only once per request
        
        UINT reply_size = 0;
        UCHAR* reply_pkt = BuildArpReply(g_my_mac, g_our_ip, g_arp_reply_to_mac, g_arp_reply_to_ip, &reply_size);
        if (reply_pkt && reply_size > 0) {
            printf("[ZigAdapterGetNextPacket] 📤 Sending ARP Reply: %u.%u.%u.%u is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (g_our_ip >> 24) & 0xFF, (g_our_ip >> 16) & 0xFF,
                   (g_our_ip >> 8) & 0xFF, g_our_ip & 0xFF,
                   g_my_mac[0], g_my_mac[1], g_my_mac[2], g_my_mac[3], g_my_mac[4], g_my_mac[5]);
            UCHAR* pkt_copy = Malloc(reply_size);
            memcpy(pkt_copy, reply_pkt, reply_size);
            *data = pkt_copy;
            return reply_size;
        }
    }
    
    // **PRIORITY 2**: Send Gratuitous ARP with configured IP to announce ourselves
    // This is CRITICAL for SoftEther bridge to learn our MAC-to-IP mapping!
    if (g_need_gratuitous_arp_configured && g_dhcp_state == DHCP_STATE_CONFIGURED) {
        g_need_gratuitous_arp_configured = false;  // Send only once
        
        UINT garp_size = 0;
        UCHAR* garp_pkt = BuildGratuitousArp(g_my_mac, g_our_ip, &garp_size);
        if (garp_pkt && garp_size > 0) {
            printf("[ZigAdapterGetNextPacket] 📢 Sending Gratuitous ARP: %u.%u.%u.%u is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (g_our_ip >> 24) & 0xFF, (g_our_ip >> 16) & 0xFF,
                   (g_our_ip >> 8) & 0xFF, g_our_ip & 0xFF,
                   g_my_mac[0], g_my_mac[1], g_my_mac[2], g_my_mac[3], g_my_mac[4], g_my_mac[5]);
            printf("[ZigAdapterGetNextPacket]    This updates SoftEther's bridge learning table!\n");
            UCHAR* pkt_copy = Malloc(garp_size);
            memcpy(pkt_copy, garp_pkt, garp_size);
            *data = pkt_copy;
            return garp_size;
        }
    }
    
    // **PRIORITY 3**: Send ARP Request to resolve gateway MAC after DHCP completes
    // This populates SoftEther server's MAC/IP table, enabling bidirectional traffic!
    if (g_need_gateway_arp && g_dhcp_state == DHCP_STATE_CONFIGURED) {
        g_need_gateway_arp = false;  // Send only once
        
        UINT arp_size = 0;
        UCHAR* arp_pkt = BuildArpRequest(g_my_mac, g_our_ip, g_offered_gw, &arp_size);
        if (arp_pkt && arp_size > 0) {
            printf("[ZigAdapterGetNextPacket] 🔍 Sending ARP Request to resolve gateway MAC %u.%u.%u.%u\n",
                   (g_offered_gw >> 24) & 0xFF, (g_offered_gw >> 16) & 0xFF,
                   (g_offered_gw >> 8) & 0xFF, g_offered_gw & 0xFF);
            printf("[ZigAdapterGetNextPacket]    This ARP Request populates SoftEther's MAC/IP table!\n");
            UCHAR* pkt_copy = Malloc(arp_size);
            memcpy(pkt_copy, arp_pkt, arp_size);
            *data = pkt_copy;
            return arp_size;
        }
    }
    
    // Get packet from Zig adapter (normal operation)
    uint8_t* packet_data = NULL;
    uint64_t packet_len = 0;
    
    if (!zig_adapter_get_packet(ctx->zig_adapter, &packet_data, &packet_len)) {
        // No packet available (this is normal - polled frequently)
        return 0;
    }
    
    // Log first few successful gets
    if (get_count < 5) {
        printf("[ZigAdapterGetNextPacket] Got packet #%llu, len=%llu\n", get_count, packet_len);
    } else if (get_count % 100 == 0) {
        printf("[ZigAdapterGetNextPacket] Packet #%llu, len=%llu\n", get_count, packet_len);
    }
    get_count++;
    
    if (packet_len == 0 || packet_len > 2048) {
        // Release the packet buffer even if invalid
        printf("[ZigAdapterGetNextPacket] Invalid packet length %llu, dropping\n", packet_len);
        zig_adapter_release_packet(ctx->zig_adapter, packet_data);
        return 0;
    }
    
    // Allocate buffer for packet
    void* packet_copy = Malloc((UINT)packet_len);
    if (!packet_copy) {
        // Release the packet buffer on allocation failure
        zig_adapter_release_packet(ctx->zig_adapter, packet_data);
        return 0;
    }
    
    // Copy packet data
    Copy(packet_copy, packet_data, (UINT)packet_len);
    *data = packet_copy;
    
    // CRITICAL: Release Zig buffer after copying to prevent leak
    zig_adapter_release_packet(ctx->zig_adapter, packet_data);
    
    return (UINT)packet_len;
}

// Put packet for transmission
static bool ZigAdapterPutPacket(SESSION* s, void* data, UINT size) {
    static uint64_t packet_count = 0;
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        return false;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    if (ctx->halt) {
        return false;
    }
    
    // NULL packet is a flush operation (SoftEther API design)
    if (!data || size == 0) {
        if (packet_count % 100 == 0) {
            printf("[ZigAdapterPutPacket] Flush operation (count=%llu)\n", packet_count);
        }
        packet_count++;
        return true; // Success: flush acknowledged
    }
    
    // Check for DHCP OFFER packet (only when expecting one)
    if (g_dhcp_state == DHCP_STATE_DISCOVER_SENT && size >= 282) { // Min DHCP packet size
        // Check if this is a DHCP packet: UDP port 68 (BOOTP client)
        if (size >= 42 && data != NULL) {
            const UCHAR* pkt = (const UCHAR*)data;
            // Check Ethernet type (0x0800 = IPv4) at offset 12-13
            if (pkt[12] == 0x08 && pkt[13] == 0x00) {
                // Check IP protocol (17 = UDP) at offset 23
                if (pkt[23] == 17) {
                    // Check UDP dest port (68 = BOOTP client) at offset 36-37
                    UINT dest_port = ((UINT)pkt[36] << 8) | pkt[37];
                    if (dest_port == 68) {
                        // This is a DHCP response! Parse it
                        printf("[ZigAdapterPutPacket] 🔍 DHCP packet detected (UDP port 68), size=%u\n", size);
                        UINT32 offered_ip = 0, gw = 0, mask = 0, server_ip = 0;
                        UCHAR msg_type = 0;
                        if (ParseDhcpPacket(pkt, size, &offered_ip, &gw, &mask, &msg_type, &server_ip)) {
                            printf("[ZigAdapterPutPacket] 🔍 Parsed: IP=%u.%u.%u.%u, msg_type=%u (2=OFFER, 5=ACK)\n",
                                   (offered_ip >> 24) & 0xFF, (offered_ip >> 16) & 0xFF,
                                   (offered_ip >> 8) & 0xFF, offered_ip & 0xFF, msg_type);
                            // Only process OFFER (type=2), not ACK (type=5)
                            if (msg_type == 2) {
                                g_offered_ip = offered_ip;
                                g_offered_gw = gw;
                                g_offered_mask = mask;
                                g_dhcp_server_ip = server_ip;
                                g_dhcp_state = DHCP_STATE_OFFER_RECEIVED;
                                g_last_dhcp_send_time = Tick64();
                                printf("[ZigAdapterPutPacket] ✅ DHCP OFFER received: IP=%u.%u.%u.%u, GW=%u.%u.%u.%u, Server=%u.%u.%u.%u\n",
                                       (offered_ip >> 24) & 0xFF, (offered_ip >> 16) & 0xFF,
                                       (offered_ip >> 8) & 0xFF, offered_ip & 0xFF,
                                       (gw >> 24) & 0xFF, (gw >> 16) & 0xFF,
                                       (gw >> 8) & 0xFF, gw & 0xFF,
                                       (server_ip >> 24) & 0xFF, (server_ip >> 16) & 0xFF,
                                       (server_ip >> 8) & 0xFF, server_ip & 0xFF);
                            } else {
                                printf("[ZigAdapterPutPacket] ⚠️  Ignoring DHCP packet with msg_type=%u (not OFFER)\n", msg_type);
                            }
                        } else {
                            printf("[ZigAdapterPutPacket] ⚠️  Failed to parse DHCP packet\n");
                        }
                    }
                }
            }
        }
    }
    
    // Check for DHCP ACK packet
    if (g_dhcp_state == DHCP_STATE_REQUEST_SENT && size >= 282) {
        if (size >= 42 && data != NULL) {
            const UCHAR* pkt = (const UCHAR*)data;
            if (pkt[12] == 0x08 && pkt[13] == 0x00 && pkt[23] == 17) {
                UINT dest_port = ((UINT)pkt[36] << 8) | pkt[37];
                if (dest_port == 68) {
                    // Parse DHCP packet and check message type
                    printf("[ZigAdapterPutPacket] 🔍 DHCP packet detected (UDP port 68), size=%u [waiting for ACK]\n", size);
                    UINT32 acked_ip = 0, gw = 0, mask = 0, server_ip = 0;
                    UCHAR msg_type = 0;
                    if (ParseDhcpPacket(pkt, size, &acked_ip, &gw, &mask, &msg_type, &server_ip)) {
                        printf("[ZigAdapterPutPacket] 🔍 Parsed: IP=%u.%u.%u.%u, msg_type=%u (5=ACK expected)\n",
                               (acked_ip >> 24) & 0xFF, (acked_ip >> 16) & 0xFF,
                               (acked_ip >> 8) & 0xFF, acked_ip & 0xFF, msg_type);
                        if (msg_type == 5) {
                            // DHCP ACK (type=5) received! Configure interface
                            g_our_ip = acked_ip;
                            g_offered_gw = gw;  // Update gateway from ACK
                            g_dhcp_state = DHCP_STATE_CONFIGURED;
                            printf("[ZigAdapterPutPacket] ✅ DHCP ACK received! Configuring interface...\n");
                            
                            // Get device name
                            uint8_t dev_name_buf[64];
                            uint64_t dev_name_len = zig_adapter_get_device_name(ctx->zig_adapter, dev_name_buf, sizeof(dev_name_buf));
                            if (dev_name_len > 0 && dev_name_len < sizeof(dev_name_buf)) {
                                dev_name_buf[dev_name_len] = '\0';
                                
                                // Configure interface with DHCP-assigned IP
                                char cmd[512];
                                snprintf(cmd, sizeof(cmd), "ifconfig %s inet %u.%u.%u.%u %u.%u.%u.%u netmask 255.255.0.0 up",
                                        (char*)dev_name_buf,
                                        (g_our_ip >> 24) & 0xFF, (g_our_ip >> 16) & 0xFF,
                                        (g_our_ip >> 8) & 0xFF, g_our_ip & 0xFF,
                                        (g_offered_gw >> 24) & 0xFF, (g_offered_gw >> 16) & 0xFF,
                                        (g_offered_gw >> 8) & 0xFF, g_offered_gw & 0xFF);
                                printf("[●] DHCP: Executing: %s\n", cmd);
                                system(cmd);
                                
                                // Replace default route: delete old one first, then add VPN route
                                printf("[●] DHCP: Replacing default route with VPN gateway...\n");
                                
                                // Save original default gateway for restoration on disconnect
                                FILE *route_output = popen("netstat -rn | grep '^default' | grep -v utun | awk '{print $2}' | head -1", "r");
                                char original_gw[64] = {0};
                                if (route_output) {
                                    if (fgets(original_gw, sizeof(original_gw), route_output)) {
                                        // Remove newline
                                        original_gw[strcspn(original_gw, "\n")] = 0;
                                        printf("[●] DHCP: Original default gateway: %s\n", original_gw);
                                    }
                                    pclose(route_output);
                                }
                                
                                // Delete ALL default routes (macOS may have multiple)
                                printf("[●] DHCP: Deleting existing default routes...\n");
                                int del_result1 = system("route -n delete default 2>&1");
                                printf("[●] DHCP: Delete attempt 1, exit code: %d\n", del_result1);
                                int del_result2 = system("route -n delete default 2>&1");
                                printf("[●] DHCP: Delete attempt 2, exit code: %d\n", del_result2);
                                int del_result3 = system("route -n delete default 2>&1");
                                printf("[●] DHCP: Delete attempt 3, exit code: %d\n", del_result3);
                                
                                // Add VPN default route
                                snprintf(cmd, sizeof(cmd), "route -n add -inet default %u.%u.%u.%u",
                                        (g_offered_gw >> 24) & 0xFF, (g_offered_gw >> 16) & 0xFF,
                                        (g_offered_gw >> 8) & 0xFF, g_offered_gw & 0xFF);
                                printf("[●] DHCP: Executing: %s\n", cmd);
                                int route_result = system(cmd);
                                printf("[●] DHCP: Route add exit code: %d (0=success)\n", route_result);
                                if (route_result != 0) {
                                    printf("[●] DHCP: ⚠️  Failed to add default route (code=%d), trying without -n flag\n", route_result);
                                    // Fallback: try without -n flag
                                    snprintf(cmd, sizeof(cmd), "route add -inet default %u.%u.%u.%u",
                                            (g_offered_gw >> 24) & 0xFF, (g_offered_gw >> 16) & 0xFF,
                                            (g_offered_gw >> 8) & 0xFF, g_offered_gw & 0xFF);
                                    route_result = system(cmd);
                                }
                                
                                if (route_result == 0) {
                                    printf("[●] DHCP: ✅ Default route now points to VPN gateway %u.%u.%u.%u\n",
                                           (g_offered_gw >> 24) & 0xFF, (g_offered_gw >> 16) & 0xFF,
                                           (g_offered_gw >> 8) & 0xFF, g_offered_gw & 0xFF);
                                } else {
                                    printf("[●] DHCP: ⚠️  Could not change default route, manual routing required\n");
                                }
                                
                                printf("[●] DHCP: ✅ Interface configured with DHCP IP %u.%u.%u.%u\n",
                                       (g_our_ip >> 24) & 0xFF, (g_our_ip >> 16) & 0xFF,
                                       (g_our_ip >> 8) & 0xFF, g_our_ip & 0xFF);
                                
                                // **CRITICAL**: Send Gratuitous ARP to announce our IP
                                // This updates SoftEther server's bridge learning table with our MAC-to-IP mapping!
                                g_need_gratuitous_arp_configured = true;
                                printf("[●] DHCP: 🔍 Will send Gratuitous ARP to announce our IP\n");
                                
                                // **CRITICAL**: Request gateway MAC resolution
                                // This populates SoftEther server's MAC/IP table, enabling return traffic!
                                g_need_gateway_arp = true;
                                printf("[●] DHCP: 🔍 Will send ARP Request to resolve gateway MAC\n");
                            }
                        } else {
                            printf("[ZigAdapterPutPacket] ⚠️  Ignoring DHCP packet with msg_type=%u (not ACK)\n", msg_type);
                        }
                    } else {
                        printf("[ZigAdapterPutPacket] ⚠️  Failed to parse DHCP packet for ACK\n");
                    }
                }
            }
        }
    }
    
    // **CRITICAL**: Check for ARP Requests asking for our IP
    // Server sends ARP Request before sending traffic back to us!
    // We MUST respond with ARP Reply or server won't know our MAC address
    if (size >= 42 && data != NULL && g_dhcp_state == DHCP_STATE_CONFIGURED) {
        const UCHAR* pkt = (const UCHAR*)data;
        // Check Ethernet type (0x0806 = ARP) at offset 12-13
        if (pkt[12] == 0x08 && pkt[13] == 0x06) {
            // Check ARP operation (1 = Request, 2 = Reply) at offset 20-21
            UINT arp_op = ((UINT)pkt[20] << 8) | pkt[21];
            if (arp_op == 1) { // ARP Request
                // Extract target IP (who is being asked for) at offset 38-41
                UINT32 target_ip = ((UINT32)pkt[38] << 24) | ((UINT32)pkt[39] << 16) | 
                                   ((UINT32)pkt[40] << 8) | pkt[41];
                
                // Check if they're asking for OUR IP
                if (target_ip == g_offered_ip) {
                    // Extract sender MAC and IP
                    UCHAR sender_mac[6];
                    memcpy(sender_mac, pkt + 22, 6); // Sender MAC at offset 22-27
                    UINT32 sender_ip = ((UINT32)pkt[28] << 24) | ((UINT32)pkt[29] << 16) |
                                       ((UINT32)pkt[30] << 8) | pkt[31];
                    
                    printf("[ZigAdapterPutPacket] 🔔 ARP Request: Who has %u.%u.%u.%u? Tell %u.%u.%u.%u\n",
                           (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                           (target_ip >> 8) & 0xFF, target_ip & 0xFF,
                           (sender_ip >> 24) & 0xFF, (sender_ip >> 16) & 0xFF,
                           (sender_ip >> 8) & 0xFF, sender_ip & 0xFF);
                    printf("[ZigAdapterPutPacket] 📤 Responding: %u.%u.%u.%u is at %02x:%02x:%02x:%02x:%02x:%02x\n",
                           (g_offered_ip >> 24) & 0xFF, (g_offered_ip >> 16) & 0xFF,
                           (g_offered_ip >> 8) & 0xFF, g_offered_ip & 0xFF,
                           g_my_mac[0], g_my_mac[1], g_my_mac[2], g_my_mac[3], g_my_mac[4], g_my_mac[5]);
                    
                    // Set flag to send ARP Reply in GetNextPacket
                    // (We can't modify GetNextPacket's return value here, so we'll send it on next poll)
                    g_need_arp_reply = true;
                    g_arp_reply_to_mac[0] = sender_mac[0];
                    g_arp_reply_to_mac[1] = sender_mac[1];
                    g_arp_reply_to_mac[2] = sender_mac[2];
                    g_arp_reply_to_mac[3] = sender_mac[3];
                    g_arp_reply_to_mac[4] = sender_mac[4];
                    g_arp_reply_to_mac[5] = sender_mac[5];
                    g_arp_reply_to_ip = sender_ip;
                }
            }
            // Don't send ARP packets to TUN device (Layer 3 device can't handle Layer 2)
            packet_count++;
            return true;
        }
    }
    
    // Log first few packets for debugging
    if (packet_count < 5) {
        printf("[ZigAdapterPutPacket] Sending packet #%llu, size=%u\n", packet_count, size);
    } else if (packet_count % 100 == 0) {
        printf("[ZigAdapterPutPacket] Packet #%llu, size=%u\n", packet_count, size);
    }
    packet_count++;
    
    // Send packet to Zig adapter
    return zig_adapter_put_packet(ctx->zig_adapter, (const uint8_t*)data, (uint64_t)size);
}

// Free adapter
static void ZigAdapterFree(SESSION* s) {
    printf("[ZigAdapterFree] Freeing Zig adapter\n");
    
    if (!s || !s->PacketAdapter || !s->PacketAdapter->Param) {
        printf("[ZigAdapterFree] Already freed or NULL\n");
        return;
    }
    
    ZIG_ADAPTER_CONTEXT* ctx = (ZIG_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    printf("[ZigAdapterFree] ctx=%p, zig_adapter=%p, cancel=%p\n", 
           (void*)ctx, (void*)ctx->zig_adapter, (void*)ctx->cancel);
    
    // Clear pointer FIRST to prevent double-free
    s->PacketAdapter->Param = NULL;
    
    ctx->halt = true;
    
    // Print final stats
    printf("[ZigAdapterFree] Final statistics:\n");
    zig_adapter_print_stats(ctx->zig_adapter);
    
    // Stop adapter
    printf("[ZigAdapterFree] Stopping adapter...\n");
    zig_adapter_stop(ctx->zig_adapter);
    
    // Destroy Zig adapter
    printf("[ZigAdapterFree] Destroying adapter...\n");
    zig_adapter_destroy(ctx->zig_adapter);
    ctx->zig_adapter = NULL;
    
    // NOTE: Don't release cancel here - SoftEther manages it via s->Cancel2
    // ReleaseCancel would cause a double-free since SoftEther calls ReleaseCancel(s->Cancel2)
    // in SessionMain cleanup (Session.c line ~772)
    ctx->cancel = NULL;
    
    // Free context
    printf("[ZigAdapterFree] Freeing context at %p...\n", (void*)ctx);
    Free(ctx);
    printf("[ZigAdapterFree] Context freed successfully\n");
    
    printf("[ZigAdapterFree] ✅ Cleanup complete\n");
}
