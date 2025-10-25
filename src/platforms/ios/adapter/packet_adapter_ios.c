/*
 * iOS Network Extension Packet Adapter for SoftEther VPN
 * 
 * This adapter bridges iOS NEPacketTunnelProvider (callback-based async)
 * with SoftEther's PACKET_ADAPTER (synchronous polling).
 * 
 * Thread-safe packet queues handle async→sync conversion.
 * Swift calls inject_packet (iOS→SoftEther), polls get_outgoing_packet (SoftEther→iOS).
 */

#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>
#include "../../bridge/logging.h"
#include "../../../TapTun/include/taptun_ffi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

#define MAX_PACKET_QUEUE_SIZE 512
#define IOS_MAX_PACKET_SIZE 2048
#define IOS_ADAPTER_PACKET_QUEUE_SIZE 4096  // SoftEther packet queue size (for GetNextPacket/PutPacket)

// ============================================================================
// Packet Queue (Thread-Safe Circular Buffer)
// ============================================================================

typedef struct {
    uint8_t data[IOS_MAX_PACKET_SIZE];
    uint32_t length;
} QueuedPacket;

typedef struct {
    QueuedPacket packets[MAX_PACKET_QUEUE_SIZE];
    uint32_t read_idx;
    uint32_t write_idx;
    uint32_t count;
    pthread_mutex_t mutex;
    pthread_cond_t cond_not_empty;
    pthread_cond_t cond_not_full;
} PacketQueue;

static PacketQueue* packet_queue_create(void) {
    PacketQueue* q = (PacketQueue*)calloc(1, sizeof(PacketQueue));
    if (!q) return NULL;
    
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_not_empty, NULL);
    pthread_cond_init(&q->cond_not_full, NULL);
    
    return q;
}

static void packet_queue_destroy(PacketQueue* q) {
    if (!q) return;
    
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond_not_empty);
    pthread_cond_destroy(&q->cond_not_full);
    free(q);
}

// Enqueue: Returns 0 on success, -1 if queue full (non-blocking for Swift threads)
static int packet_queue_enqueue(PacketQueue* q, const uint8_t* data, uint32_t length, bool blocking) {
    if (!q || !data || length == 0 || length > IOS_MAX_PACKET_SIZE) {
        return -1;
    }
    
    pthread_mutex_lock(&q->mutex);
    
    // Non-blocking mode: return immediately if full
    if (!blocking && q->count >= MAX_PACKET_QUEUE_SIZE) {
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    // Blocking mode: wait for space (used by C threads if needed)
    while (blocking && q->count >= MAX_PACKET_QUEUE_SIZE) {
        pthread_cond_wait(&q->cond_not_full, &q->mutex);
    }
    
    // Copy packet data
    memcpy(q->packets[q->write_idx].data, data, length);
    q->packets[q->write_idx].length = length;
    
    q->write_idx = (q->write_idx + 1) % MAX_PACKET_QUEUE_SIZE;
    q->count++;
    
    pthread_cond_signal(&q->cond_not_empty);
    pthread_mutex_unlock(&q->mutex);
    
    return 0;
}

// Dequeue: Returns packet length (>0), 0 if empty/timeout, -1 on error
// timeout_ms: 0=non-blocking, -1=blocking, >0=timeout in milliseconds
static int packet_queue_dequeue(PacketQueue* q, uint8_t* buffer, uint32_t buffer_size, int timeout_ms) {
    if (!q || !buffer || buffer_size < IOS_MAX_PACKET_SIZE) {
        LOG_ERROR("IOS_ADAPTER", "packet_queue_dequeue: Invalid params: q=%p buffer=%p size=%u", q, buffer, buffer_size);
        return -1;
    }
    
    pthread_mutex_lock(&q->mutex);
    
    // Non-blocking mode
    if (timeout_ms == 0) {
        if (q->count == 0) {
            pthread_mutex_unlock(&q->mutex);
            return 0; // Empty
        }
    }
    // Blocking with timeout
    else if (timeout_ms > 0) {
        if (q->count == 0) {
            struct timespec ts;
            struct timeval now;
            gettimeofday(&now, NULL);
            
            ts.tv_sec = now.tv_sec + (timeout_ms / 1000);
            ts.tv_nsec = (now.tv_usec + (timeout_ms % 1000) * 1000) * 1000;
            
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            
            int ret = pthread_cond_timedwait(&q->cond_not_empty, &q->mutex, &ts);
            if (ret == ETIMEDOUT || q->count == 0) {
                pthread_mutex_unlock(&q->mutex);
                return 0; // Timeout/still empty - NOT AN ERROR
            }
            if (ret != 0 && ret != ETIMEDOUT) {
                LOG_ERROR("IOS_ADAPTER", "packet_queue_dequeue: pthread_cond_timedwait failed: %d", ret);
                pthread_mutex_unlock(&q->mutex);
                return -1; // Real error
            }
        }
    }
    // Infinite blocking mode
    else {
        while (q->count == 0) {
            pthread_cond_wait(&q->cond_not_empty, &q->mutex);
        }
    }
    
    // At this point, we must have a packet (unless timeout occurred)
    if (q->count == 0) {
        LOG_ERROR("IOS_ADAPTER", "packet_queue_dequeue: Unexpected: count=0 after wait");
        pthread_mutex_unlock(&q->mutex);
        return 0;
    }
    
    // Dequeue packet
    QueuedPacket* pkt = &q->packets[q->read_idx];
    uint32_t length = pkt->length;
    
    if (length == 0 || length > IOS_MAX_PACKET_SIZE) {
        LOG_ERROR("IOS_ADAPTER", "packet_queue_dequeue: Invalid packet length: %u", length);
        // Skip this corrupted packet
        q->read_idx = (q->read_idx + 1) % MAX_PACKET_QUEUE_SIZE;
        q->count--;
        pthread_mutex_unlock(&q->mutex);
        return -1;
    }
    
    memcpy(buffer, pkt->data, length);
    
    q->read_idx = (q->read_idx + 1) % MAX_PACKET_QUEUE_SIZE;
    q->count--;
    
    pthread_cond_signal(&q->cond_not_full);
    pthread_mutex_unlock(&q->mutex);
    
    return (int)length;
}

// ============================================================================
// iOS Adapter Context
// ============================================================================

// DHCP state
typedef struct {
    uint32_t client_ip;       // Assigned IP address (network byte order)
    uint32_t subnet_mask;     // Subnet mask (network byte order)
    uint32_t gateway;         // Gateway IP (network byte order)
    uint32_t dns_server1;     // Primary DNS (network byte order)
    uint32_t dns_server2;     // Secondary DNS (network byte order)
    uint32_t dhcp_server;     // DHCP server IP (network byte order)
    bool valid;               // True if DHCP info has been received
    uint32_t xid;             // DHCP transaction ID
    uint8_t client_mac[6];    // Client MAC address
} DHCPState;

typedef struct {
    SESSION* session;
    CANCEL* cancel;
    
    PacketQueue* incoming_queue;  // iOS → SoftEther (packets from NEPacketTunnelFlow)
    PacketQueue* outgoing_queue;  // SoftEther → iOS (packets to NEPacketTunnelFlow)
    
    // TapTun L2↔L3 translator
    TapTunTranslator* translator;
    uint64_t l2_to_l3_translated;  // Statistics: Ethernet→IP conversions
    uint64_t l3_to_l2_translated;  // Statistics: IP→Ethernet conversions
    uint64_t arp_packets_handled;  // Statistics: ARP requests handled internally
    uint64_t arp_replies_sent;     // Statistics: ARP replies sent back to server
    
    // DHCP state
    DHCPState dhcp_state;
    pthread_mutex_t dhcp_mutex;
    
    // Statistics
    uint64_t packets_received;    // Total packets received from iOS
    uint64_t packets_sent;        // Total packets sent to iOS
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t queue_drops_in;      // Dropped packets (incoming queue full)
    uint64_t queue_drops_out;     // Dropped packets (outgoing queue full)
    
    bool initialized;
} IOS_ADAPTER_CONTEXT;

static IOS_ADAPTER_CONTEXT* global_ios_adapter_ctx = NULL;

// ============================================================================
// DHCP Packet Parsing
// ============================================================================

// DHCP message types
#define DHCP_DISCOVER 1
#define DHCP_OFFER    2
#define DHCP_REQUEST  3
#define DHCP_ACK      5

// Parse DHCP options and extract network configuration
static bool parse_dhcp_packet(const uint8_t* data, uint32_t length, DHCPState* dhcp) {
    // Minimum DHCP packet: 14 (Ethernet) + 20 (IP) + 8 (UDP) + 236 (DHCP minimum) = 278
    if (length < 278) return false;
    
    // Skip Ethernet header (14 bytes)
    const uint8_t* ip_header = data + 14;
    
    // Verify IPv4
    if ((ip_header[0] >> 4) != 4) return false;
    
    // Get IP header length
    uint32_t ip_hdr_len = (ip_header[0] & 0x0F) * 4;
    
    // Check if it's UDP (protocol 17)
    if (ip_header[9] != 17) return false;
    
    const uint8_t* udp_header = ip_header + ip_hdr_len;
    
    // Check UDP ports (68 = client, 67 = server)
    uint16_t src_port = (udp_header[0] << 8) | udp_header[1];
    uint16_t dst_port = (udp_header[2] << 8) | udp_header[3];
    
    // Only parse DHCP replies (server → client)
    if (src_port != 67 || dst_port != 68) return false;
    
    const uint8_t* dhcp_packet = udp_header + 8;
    uint32_t dhcp_len = length - (dhcp_packet - data);
    
    if (dhcp_len < 236) return false;
    
    // Parse DHCP fields
    // uint8_t op = dhcp_packet[0];  // 2 = BOOTREPLY
    uint32_t xid = (dhcp_packet[4] << 24) | (dhcp_packet[5] << 16) | 
                   (dhcp_packet[6] << 8) | dhcp_packet[7];
    
    // Verify XID matches our request (if we sent one)
    if (dhcp->xid != 0 && dhcp->xid != xid) {
        return false;  // Not our transaction
    }
    
    // Extract yiaddr (your IP address) - offered IP
    uint32_t your_ip = (dhcp_packet[16] << 24) | (dhcp_packet[17] << 16) |
                       (dhcp_packet[18] << 8) | dhcp_packet[19];
    
    // Extract siaddr (server IP address)
    uint32_t server_ip = (dhcp_packet[20] << 24) | (dhcp_packet[21] << 16) |
                         (dhcp_packet[22] << 8) | dhcp_packet[23];
    
    // Parse DHCP options (starts at offset 236)
    if (dhcp_len < 240) return false;
    
    // Check magic cookie (0x63825363)
    if (dhcp_packet[236] != 0x63 || dhcp_packet[237] != 0x82 ||
        dhcp_packet[238] != 0x53 || dhcp_packet[239] != 0x63) {
        return false;
    }
    
    // Parse options
    uint32_t offset = 240;
    uint8_t msg_type = 0;
    uint32_t subnet_mask = 0;
    uint32_t gateway = 0;
    uint32_t dns1 = 0, dns2 = 0;
    
    while (offset < dhcp_len) {
        uint8_t option = dhcp_packet[offset++];
        
        if (option == 0xFF) break;  // End option
        if (option == 0x00) continue;  // Pad option
        
        if (offset >= dhcp_len) break;
        uint8_t opt_len = dhcp_packet[offset++];
        
        if (offset + opt_len > dhcp_len) break;
        
        switch (option) {
            case 53:  // DHCP Message Type
                if (opt_len >= 1) {
                    msg_type = dhcp_packet[offset];
                }
                break;
                
            case 1:  // Subnet Mask
                if (opt_len >= 4) {
                    subnet_mask = (dhcp_packet[offset] << 24) | (dhcp_packet[offset + 1] << 16) |
                                  (dhcp_packet[offset + 2] << 8) | dhcp_packet[offset + 3];
                }
                break;
                
            case 3:  // Router (Gateway)
                if (opt_len >= 4) {
                    gateway = (dhcp_packet[offset] << 24) | (dhcp_packet[offset + 1] << 16) |
                              (dhcp_packet[offset + 2] << 8) | dhcp_packet[offset + 3];
                }
                break;
                
            case 6:  // DNS Servers
                if (opt_len >= 4) {
                    dns1 = (dhcp_packet[offset] << 24) | (dhcp_packet[offset + 1] << 16) |
                           (dhcp_packet[offset + 2] << 8) | dhcp_packet[offset + 3];
                }
                if (opt_len >= 8) {
                    dns2 = (dhcp_packet[offset + 4] << 24) | (dhcp_packet[offset + 5] << 16) |
                           (dhcp_packet[offset + 6] << 8) | dhcp_packet[offset + 7];
                }
                break;
        }
        
        offset += opt_len;
    }
    
    // Only process DHCP OFFER (2) or ACK (5)
    if (msg_type == DHCP_OFFER || msg_type == DHCP_ACK) {
        dhcp->client_ip = your_ip;
        dhcp->subnet_mask = subnet_mask ? subnet_mask : 0xFFFF0000;  // Default /16
        dhcp->gateway = gateway ? gateway : (your_ip & 0xFF000000) | 0x00000001;  // x.x.0.1
        dhcp->dns_server1 = dns1 ? dns1 : 0x08080808;  // Default 8.8.8.8
        dhcp->dns_server2 = dns2 ? dns2 : 0x08080404;  // Default 8.8.4.4
        dhcp->dhcp_server = server_ip;
        dhcp->valid = true;
        
        LOG_INFO("IOS_ADAPTER", "📡 DHCP %s received: IP=%u.%u.%u.%u, GW=%u.%u.%u.%u, Mask=%u.%u.%u.%u",
               msg_type == DHCP_OFFER ? "OFFER" : "ACK",
               (your_ip >> 24) & 0xFF, (your_ip >> 16) & 0xFF, (your_ip >> 8) & 0xFF, your_ip & 0xFF,
               (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF, (gateway >> 8) & 0xFF, gateway & 0xFF,
               (subnet_mask >> 24) & 0xFF, (subnet_mask >> 16) & 0xFF, (subnet_mask >> 8) & 0xFF, subnet_mask & 0xFF);
        
        return true;
    }
    
    return false;
}

/**
 * Generate and send DHCP DISCOVER packet to request IP configuration
 * Called during adapter initialization to actively request DHCP from VPN server
 */
static void send_dhcp_discover(IOS_ADAPTER_CONTEXT* ctx) {
    if (!ctx || !ctx->outgoing_queue) {
        LOG_ERROR("IOS_ADAPTER", "Cannot send DHCP DISCOVER - invalid context");
        return;
    }
    
    // Generate random transaction ID
    uint32_t xid = (uint32_t)time(NULL) ^ (uint32_t)((uintptr_t)ctx);
    
    // Generate random client MAC address (locally administered)
    uint8_t client_mac[6];
    client_mac[0] = 0x02; // Locally administered unicast
    for (int i = 1; i < 6; i++) {
        client_mac[i] = (uint8_t)(rand() % 256);
    }
    
    // Store MAC and XID for matching responses
    memcpy(ctx->dhcp_state.client_mac, client_mac, 6);
    ctx->dhcp_state.xid = xid;
    
    // Build DHCP DISCOVER packet
    // Ethernet (14) + IP (20) + UDP (8) + DHCP (236 base + options)
    uint8_t packet[590];
    memset(packet, 0, sizeof(packet));
    
    uint8_t* ptr = packet;
    
    // === Ethernet Header (14 bytes) ===
    memset(ptr, 0xFF, 6);              // Destination: Broadcast
    memcpy(ptr + 6, client_mac, 6);    // Source: Our MAC
    ptr[12] = 0x08;                    // EtherType: IPv4 (0x0800)
    ptr[13] = 0x00;
    ptr += 14;
    
    // === IPv4 Header (20 bytes) ===
    ptr[0] = 0x45;                     // Version=4, IHL=5
    ptr[1] = 0x00;                     // DSCP/ECN
    ptr[2] = 0x01; ptr[3] = 0x48;      // Total Length: 328 (20+8+300)
    ptr[4] = ptr[5] = 0x00;            // Identification
    ptr[6] = 0x40; ptr[7] = 0x00;      // Flags: Don't Fragment
    ptr[8] = 0x40;                     // TTL: 64
    ptr[9] = 0x11;                     // Protocol: UDP (17)
    ptr[10] = ptr[11] = 0x00;          // Checksum (calculated later)
    memset(ptr + 12, 0, 4);            // Source IP: 0.0.0.0
    memset(ptr + 16, 0xFF, 4);         // Dest IP: 255.255.255.255
    
    // Calculate IP checksum
    uint32_t ip_sum = 0;
    for (int i = 0; i < 20; i += 2) {
        ip_sum += (ptr[i] << 8) | ptr[i+1];
    }
    while (ip_sum >> 16) {
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    }
    uint16_t ip_checksum = ~ip_sum;
    ptr[10] = (ip_checksum >> 8) & 0xFF;
    ptr[11] = ip_checksum & 0xFF;
    ptr += 20;
    
    // === UDP Header (8 bytes) ===
    ptr[0] = 0x00; ptr[1] = 0x44;      // Source Port: 68 (DHCP client)
    ptr[2] = 0x00; ptr[3] = 0x43;      // Dest Port: 67 (DHCP server)
    ptr[4] = 0x01; ptr[5] = 0x34;      // Length: 308 (8+300)
    ptr[6] = ptr[7] = 0x00;            // Checksum: 0 (optional for IPv4)
    ptr += 8;
    
    // === DHCP Packet (300 bytes) ===
    ptr[0] = 0x01;                     // op: BOOTREQUEST (1)
    ptr[1] = 0x01;                     // htype: Ethernet (1)
    ptr[2] = 0x06;                     // hlen: 6 (MAC length)
    ptr[3] = 0x00;                     // hops: 0
    
    // Transaction ID (4 bytes)
    ptr[4] = (xid >> 24) & 0xFF;
    ptr[5] = (xid >> 16) & 0xFF;
    ptr[6] = (xid >> 8) & 0xFF;
    ptr[7] = xid & 0xFF;
    
    ptr[8] = ptr[9] = 0x00;            // secs: 0
    ptr[10] = 0x80; ptr[11] = 0x00;    // flags: Broadcast (0x8000)
    
    memset(ptr + 12, 0, 4);            // ciaddr: 0.0.0.0
    memset(ptr + 16, 0, 4);            // yiaddr: 0.0.0.0
    memset(ptr + 20, 0, 4);            // siaddr: 0.0.0.0
    memset(ptr + 24, 0, 4);            // giaddr: 0.0.0.0
    
    // chaddr: Client MAC address (16 bytes, only first 6 used)
    memcpy(ptr + 28, client_mac, 6);
    memset(ptr + 34, 0, 10);
    
    memset(ptr + 44, 0, 192);          // sname + file: zeros
    
    // Magic cookie (offset 236)
    ptr[236] = 0x63;
    ptr[237] = 0x82;
    ptr[238] = 0x53;
    ptr[239] = 0x63;
    
    // === DHCP Options ===
    uint8_t* opt = ptr + 240;
    
    // Option 53: DHCP Message Type = DISCOVER (1)
    *opt++ = 53; *opt++ = 1; *opt++ = 1;
    
    // Option 55: Parameter Request List
    *opt++ = 55; *opt++ = 4;
    *opt++ = 1;   // Subnet Mask
    *opt++ = 3;   // Router
    *opt++ = 6;   // DNS Server
    *opt++ = 15;  // Domain Name
    
    // Option 255: End
    *opt++ = 255;
    
    uint32_t packet_length = (opt - packet);
    
    // Enqueue DHCP DISCOVER packet to outgoing queue
    int ret = packet_queue_enqueue(ctx->outgoing_queue, packet, packet_length, false);
    
    if (ret == 0) {
        LOG_INFO("IOS_ADAPTER", "📡 DHCP DISCOVER sent (xid=0x%08X, MAC=%02X:%02X:%02X:%02X:%02X:%02X)",
               xid,
               client_mac[0], client_mac[1], client_mac[2],
               client_mac[3], client_mac[4], client_mac[5]);
    } else {
        LOG_ERROR("IOS_ADAPTER", "Failed to enqueue DHCP DISCOVER packet");
    }
}

// ============================================================================
// FFI Bridge Functions (Called from Swift)
// ============================================================================

/**
 * Inject packet from iOS into SoftEther (iOS → VPN server direction)
 * Called from Swift PacketTunnelProvider when packetFlow.readPackets() receives data
 * Returns: 0 on success, -1 on error
 */
int ios_adapter_inject_packet(const uint8_t* data, uint32_t length) {
    if (!global_ios_adapter_ctx || !global_ios_adapter_ctx->initialized) {
        LOG_ERROR("IOS_ADAPTER", "inject_packet: Adapter not initialized");
        return -1;
    }
    
    if (!data || length == 0) {
        LOG_ERROR("IOS_ADAPTER", "inject_packet: Invalid packet (data=%p, len=%u)", data, length);
        return -1;
    }
    
    IOS_ADAPTER_CONTEXT* ctx = global_ios_adapter_ctx;
    
    // Enqueue packet (non-blocking to avoid stalling Swift thread)
    int ret = packet_queue_enqueue(ctx->incoming_queue, data, length, false);
    
    if (ret == 0) {
        ctx->packets_received++;
        ctx->bytes_received += length;
        
        // Wake up SoftEther's GetNextPacket if it's waiting
        Cancel(ctx->cancel);
    } else {
        ctx->queue_drops_in++;
        LOG_ERROR("IOS_ADAPTER", "inject_packet: Incoming queue full, dropped packet (%u bytes)", length);
    }
    
    return ret;
}

/**
 * Retrieve outgoing packet from SoftEther to iOS (VPN server → iOS direction)
 * Called from Swift PacketTunnelProvider in polling loop
 * Returns: Packet length (>0), 0 if no packet available, -1 on error
 */
int ios_adapter_get_outgoing_packet(uint8_t* buffer, uint32_t buffer_size) {
    if (!global_ios_adapter_ctx || !global_ios_adapter_ctx->initialized) {
        return -1;
    }
    
    if (!buffer || buffer_size < IOS_MAX_PACKET_SIZE) {
        return -1;
    }
    
    IOS_ADAPTER_CONTEXT* ctx = global_ios_adapter_ctx;
    
    // Dequeue packet (non-blocking)
    int length = packet_queue_dequeue(ctx->outgoing_queue, buffer, buffer_size, 0);
    
    if (length > 0) {
        ctx->packets_sent++;
        ctx->bytes_sent += length;
        
        // Check if this is a DHCP packet and parse it
        pthread_mutex_lock(&ctx->dhcp_mutex);
        if (!ctx->dhcp_state.valid) {
            // Try to parse DHCP info from this packet
            if (parse_dhcp_packet(buffer, length, &ctx->dhcp_state)) {
                LOG_INFO("IOS_ADAPTER", "✅ DHCP configuration acquired!");
            }
        }
        pthread_mutex_unlock(&ctx->dhcp_mutex);
    }
    
    return length;
}

/**
 * Get adapter statistics (for monitoring/debugging)
 */
void ios_adapter_get_stats(uint64_t* rx_packets, uint64_t* tx_packets,
                           uint64_t* rx_bytes, uint64_t* tx_bytes,
                           uint64_t* drops_in, uint64_t* drops_out) {
    if (!global_ios_adapter_ctx || !global_ios_adapter_ctx->initialized) {
        return;
    }
    
    IOS_ADAPTER_CONTEXT* ctx = global_ios_adapter_ctx;
    
    if (rx_packets) *rx_packets = ctx->packets_received;
    if (tx_packets) *tx_packets = ctx->packets_sent;
    if (rx_bytes) *rx_bytes = ctx->bytes_received;
    if (tx_bytes) *tx_bytes = ctx->bytes_sent;
    if (drops_in) *drops_in = ctx->queue_drops_in;
    if (drops_out) *drops_out = ctx->queue_drops_out;
}

/**
 * Get DHCP configuration (called by vpn_bridge_get_dhcp_info)
 * Returns: 0 on success with valid DHCP data, -1 if not available
 */
int ios_adapter_get_dhcp_info(uint32_t* client_ip, uint32_t* subnet_mask,
                               uint32_t* gateway, uint32_t* dns_server1,
                               uint32_t* dns_server2) {
    if (!global_ios_adapter_ctx || !global_ios_adapter_ctx->initialized) {
        return -1;
    }
    
    IOS_ADAPTER_CONTEXT* ctx = global_ios_adapter_ctx;
    
    pthread_mutex_lock(&ctx->dhcp_mutex);
    
    if (!ctx->dhcp_state.valid) {
        pthread_mutex_unlock(&ctx->dhcp_mutex);
        return -1;  // DHCP info not yet available
    }
    
    // Copy DHCP info
    if (client_ip) *client_ip = ctx->dhcp_state.client_ip;
    if (subnet_mask) *subnet_mask = ctx->dhcp_state.subnet_mask;
    if (gateway) *gateway = ctx->dhcp_state.gateway;
    if (dns_server1) *dns_server1 = ctx->dhcp_state.dns_server1;
    if (dns_server2) *dns_server2 = ctx->dhcp_state.dns_server2;
    
    pthread_mutex_unlock(&ctx->dhcp_mutex);
    
    return 0;
}

// ============================================================================
// SoftEther PACKET_ADAPTER Callbacks
// ============================================================================

/**
 * Initialize iOS adapter
 * NOTE: Actual initialization now happens in NewIosPacketAdapter()
 * This callback stores the session reference and sends DHCP DISCOVER
 */
static bool IosAdapterInit(SESSION* s) {
    if (!s) {
        LOG_ERROR("IOS_ADAPTER", "IosAdapterInit: Session is NULL");
        return false;
    }
    
    if (!s->PacketAdapter || !s->PacketAdapter->Param) {
        LOG_ERROR("IOS_ADAPTER", "IosAdapterInit: Adapter context not initialized");
        return false;
    }
    
    IOS_ADAPTER_CONTEXT* ctx = (IOS_ADAPTER_CONTEXT*)s->PacketAdapter->Param;
    
    // Store session reference (needed for some operations)
    ctx->session = s;
    
    LOG_INFO("IOS_ADAPTER", "IosAdapterInit: Session attached (adapter already initialized)");
    
    // Send DHCP DISCOVER to request IP configuration from VPN server
    LOG_INFO("IOS_ADAPTER", "IosAdapterInit: Sending DHCP DISCOVER to initiate IP configuration...");
    send_dhcp_discover(ctx);
    
    return true;
}

/**
 * Get cancel handle (for waking up blocked operations)
 */
static CANCEL* IosAdapterGetCancel(SESSION *s) {
    PACKET_ADAPTER *pa = s->PacketAdapter;
    if (!s || !pa || !pa->Param) return NULL;
    
    IOS_ADAPTER_CONTEXT* ctx = (IOS_ADAPTER_CONTEXT*)pa->Param;
    return ctx->cancel;
}

/**
 * Get next packet from iOS (to send to VPN server)
 * SoftEther calls this repeatedly to poll for incoming packets
 * 
 * RETURN VALUES:
 * - >0: Packet size (success, *data points to packet buffer)
 * - 0: No packet available (normal, not an error - will be called again)
 * - UINT_MAX: Fatal error (causes pa_fail=1 and session termination)
 * 
 * PRIORITY: Check outgoing queue FIRST (for DHCP DISCOVER), then incoming queue (from iOS)
 */
static UINT IosAdapterGetNextPacket(SESSION *s, void **data) {
    PACKET_ADAPTER *pa = s->PacketAdapter;
    if (!s || !pa || !pa->Param || !data) {
        LOG_ERROR("IOS_ADAPTER", "GetNextPacket: FATAL - Invalid parameters (s=%p pa=%p data=%p)", s, pa, data);
        return INFINITE;
    }
    
    IOS_ADAPTER_CONTEXT* ctx = (IOS_ADAPTER_CONTEXT*)pa->Param;
    
    // Allocate buffer for dequeue
    uint8_t buffer[IOS_MAX_PACKET_SIZE];
    
    // ===================================================================
    // PRIORITY 1: Check outgoing queue FIRST (for DHCP DISCOVER packets)
    // ===================================================================
    int length = packet_queue_dequeue(ctx->outgoing_queue, buffer, IOS_MAX_PACKET_SIZE, 0);  // No wait
    
    if (length > 0) {
        // Got a packet from outgoing queue (DHCP DISCOVER)
        static uint64_t outgoing_count = 0;
        outgoing_count++;
        LOG_INFO("IOS_ADAPTER", "GetNextPacket: 📤 OUTGOING #%llu (DHCP): %d bytes (L2 Ethernet)", outgoing_count, length);
        
        // Allocate and copy (SessionMain expects Malloc'd data)
        void* packet = Malloc(length);
        if (!packet) {
            LOG_ERROR("IOS_ADAPTER", "GetNextPacket: MALLOC FAILED for %d bytes", length);
            return INFINITE;
        }
        memcpy(packet, buffer, length);
        *data = packet;
        return length;
    }
    
    // ===================================================================
    // PRIORITY 2: Check incoming queue (packets from iOS device)
    // ===================================================================
    // Try to dequeue packet (with SHORT timeout to avoid blocking SessionMain loop)
    // Using 10ms timeout - SessionMain expects frequent polling
    length = packet_queue_dequeue(ctx->incoming_queue, buffer, IOS_MAX_PACKET_SIZE, 10);
    
    if (length < 0) {
        // Actual error from dequeue function
        LOG_ERROR("IOS_ADAPTER", "GetNextPacket: DEQUEUE ERROR (fatal)");
        return INFINITE;
    }
    
    if (length == 0) {
        // Queue empty - this is NORMAL, not an error!
        // Return 0 to tell SessionMain "no packet right now, try again"
        static uint64_t empty_count = 0;
        empty_count++;
        if (empty_count % 1000 == 0) {
            LOG_INFO("IOS_ADAPTER", "GetNextPacket: Queue empty (called %llu times with no packet)", empty_count);
        }
        return 0; // NO PACKET (not an error!)
    }
    
    // Got a packet!
    static uint64_t get_count = 0;
    get_count++;
    LOG_INFO("IOS_ADAPTER", "GetNextPacket: 📤 PACKET #%llu FROM iOS: %d bytes (L3 IP)", get_count, length);
    
    // Log first 20 bytes of IP packet for debugging (first 3 packets only)
    if (get_count <= 3 && length >= 20) {
        LOG_INFO("IOS_ADAPTER", "GetNextPacket: First 20 bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                 buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9],
                 buffer[10], buffer[11], buffer[12], buffer[13], buffer[14], buffer[15], buffer[16], buffer[17], buffer[18], buffer[19]);
        LOG_INFO("IOS_ADAPTER", "GetNextPacket: IP version=%d, header_len=%d", (buffer[0] >> 4), (buffer[0] & 0x0F) * 4);
    }
    
    // === TapTun L3→L2 Translation ===
    // Convert IP packet from iOS to Ethernet frame for SoftEther
    // iOS NEPacketTunnelProvider provides pure IP packets (L3)
    // SoftEther SessionMain expects Ethernet frames (L2)
    uint8_t eth_frame_buf[IOS_MAX_PACKET_SIZE];
    
    LOG_INFO("IOS_ADAPTER", "GetNextPacket: Calling taptun_ip_to_ethernet(translator=%p, packet=%p, len=%d, out=%p, out_size=%d)",
             ctx->translator, buffer, length, eth_frame_buf, (int)sizeof(eth_frame_buf));
    
    int eth_len = taptun_ip_to_ethernet(
        ctx->translator,
        buffer,
        length,
        eth_frame_buf,
        sizeof(eth_frame_buf)
    );
    
    LOG_INFO("IOS_ADAPTER", "GetNextPacket: taptun_ip_to_ethernet returned: %d", eth_len);
    
    if (eth_len < 0) {
        LOG_ERROR("IOS_ADAPTER", "GetNextPacket: ❌ TapTun L3→L2 translation failed (error=%d)", eth_len);
        LOG_ERROR("IOS_ADAPTER", "GetNextPacket: Translator=%p, IP packet length=%d", ctx->translator, length);
        return INFINITE; // Translation error = fatal
    }
    
    // Successfully translated IP→Ethernet
    ctx->l3_to_l2_translated++;
    LOG_INFO("IOS_ADAPTER", "GetNextPacket: 🔄 Translated L3→L2: %d bytes IP → %d bytes Ethernet (total: %llu)",
             length, eth_len, ctx->l3_to_l2_translated);
    
    // Allocate memory for Ethernet frame (SoftEther will free this with Free())
    void* packet = Malloc(eth_len);
    if (!packet) {
        LOG_ERROR("IOS_ADAPTER", "GetNextPacket: MALLOC FAILED for %d bytes", eth_len);
        return INFINITE; // Out of memory = fatal
    }
    
    memcpy(packet, eth_frame_buf, eth_len);
    *data = packet;
    
    LOG_INFO("IOS_ADAPTER", "GetNextPacket: ✅ Returning Ethernet frame #%llu (size=%d, ptr=%p)", get_count, eth_len, packet);
    return eth_len;
}

/**
 * Put packet to iOS (received from VPN server)
 * SoftEther calls this when it has a packet to send to the device
 * 
 * NOTE: SoftEther may call this with NULL data or size=0 for control/keepalive purposes.
 * We must return true for these cases to avoid setting pa_fail=1.
 */
static bool IosAdapterPutPacket(SESSION *s, void *data, UINT size) {
    PACKET_ADAPTER *pa = s->PacketAdapter;
    if (!s || !pa || !pa->Param) {
        LOG_ERROR("IOS_ADAPTER", "PutPacket: FATAL - Invalid session or adapter (s=%p pa=%p)", s, pa);
        return false;
    }
    
    // Handle NULL/empty packets gracefully - these are control packets (keepalive, etc.)
    // Returning false here would set pa_fail=1 and kill the session!
    if (!data || size == 0) {
        static uint64_t null_count = 0;
        null_count++;
        if (null_count % 100 == 1) {
            LOG_INFO("IOS_ADAPTER", "PutPacket: Control packet (NULL/empty) #%llu - ignoring (this is normal)", null_count);
        }
        return true; // Success - don't treat control packets as errors
    }
    
    IOS_ADAPTER_CONTEXT* ctx = (IOS_ADAPTER_CONTEXT*)pa->Param;
    
    // Log actual data packets
    static uint64_t put_count = 0;
    put_count++;
    LOG_INFO("IOS_ADAPTER", "PutPacket: 📩 PACKET #%llu FROM SERVER: %u bytes (L2 Ethernet)", put_count, size);
    
    // === TapTun L2→L3 Translation ===
    // Convert Ethernet frame to IP packet before queuing
    // iOS NEPacketTunnelProvider expects pure IP packets (L3), not Ethernet (L2)
    uint8_t ip_packet_buf[IOS_MAX_PACKET_SIZE];
    int ip_len = taptun_ethernet_to_ip(
        ctx->translator,
        (const uint8_t*)data,
        size,
        ip_packet_buf,
        sizeof(ip_packet_buf)
    );
    
    if (ip_len < 0) {
        LOG_ERROR("IOS_ADAPTER", "PutPacket: ❌ TapTun translation failed for packet #%llu (error=%d)", put_count, ip_len);
        return false; // Translation error
    }
    
    if (ip_len == 0) {
        // ARP packet handled internally by TapTun - this is NORMAL!
        ctx->arp_packets_handled++;
        if (ctx->arp_packets_handled % 10 == 1) {
            LOG_INFO("IOS_ADAPTER", "PutPacket: 🔧 ARP #%llu handled by TapTun (total: %llu)", put_count, ctx->arp_packets_handled);
        }
        
        // Check if TapTun generated an ARP reply to send back to server
        // ARP replies go back via GetNextPacket (iOS→Server direction)
        while (taptun_translator_has_arp_reply(ctx->translator)) {
            uint8_t arp_reply_buf[IOS_MAX_PACKET_SIZE];
            int arp_len = taptun_translator_pop_arp_reply(
                ctx->translator,
                arp_reply_buf,
                sizeof(arp_reply_buf)
            );
            
            if (arp_len > 0) {
                // Enqueue ARP reply in incoming_queue (will be sent to server via GetNextPacket)
                int ret = packet_queue_enqueue(ctx->incoming_queue, arp_reply_buf, arp_len, false);
                
                if (ret == 0) {
                    ctx->arp_replies_sent++;
                    LOG_INFO("IOS_ADAPTER", "PutPacket: 📤 ARP REPLY #%llu queued for server (%d bytes, queue→GetNextPacket)", 
                             ctx->arp_replies_sent, arp_len);
                } else {
                    LOG_ERROR("IOS_ADAPTER", "PutPacket: ❌ Incoming queue full, ARP reply dropped!");
                }
            } else if (arp_len < 0) {
                LOG_ERROR("IOS_ADAPTER", "PutPacket: ❌ pop_arp_reply failed (error=%d)", arp_len);
                break;
            }
        }
        
        return true; // Success - ARP handled transparently
    }
    
    // Successfully translated Ethernet→IP
    ctx->l2_to_l3_translated++;
    LOG_INFO("IOS_ADAPTER", "PutPacket: 🔄 Translated L2→L3: %u bytes Ethernet → %d bytes IP (total: %llu)", 
             size, ip_len, ctx->l2_to_l3_translated);
    
    // Check if this is a DHCP packet - DON'T enqueue, handle via state machine
    if (ip_len >= 20) {
        const uint8_t* ip_hdr = ip_packet_buf;
        uint8_t protocol = ip_hdr[9];
        
        // UDP (DHCP)
        if (protocol == 17 && ip_len >= 28) {
            const uint8_t* udp_hdr = ip_hdr + 20;
            uint16_t src_port = (udp_hdr[0] << 8) | udp_hdr[1];
            uint16_t dst_port = (udp_hdr[2] << 8) | udp_hdr[3];
            
            // DHCP server→client (67→68)
            if (src_port == 67 && dst_port == 68 && ip_len >= 236) {
                // Reconstruct full Ethernet frame for parse_dhcp_packet
                uint8_t full_packet[IOS_MAX_PACKET_SIZE];
                memcpy(full_packet, data, size);  // Copy original Ethernet packet
                
                // Parse DHCP packet to extract full configuration
                pthread_mutex_lock(&ctx->dhcp_mutex);
                bool parsed = parse_dhcp_packet(full_packet, size, &ctx->dhcp_state);
                pthread_mutex_unlock(&ctx->dhcp_mutex);
                
                if (parsed && ctx->dhcp_state.valid) {
                    uint32_t your_ip = ctx->dhcp_state.client_ip;
                    
                    // Configure TapTun with our IP address
                    taptun_translator_set_our_ip(ctx->translator, your_ip);
                    
                    LOG_INFO("IOS_ADAPTER", "PutPacket: ✅ DHCP configuration obtained:");
                    LOG_INFO("IOS_ADAPTER", "  IP: %u.%u.%u.%u",
                             (your_ip >> 24) & 0xFF, (your_ip >> 16) & 0xFF, 
                             (your_ip >> 8) & 0xFF, your_ip & 0xFF);
                    LOG_INFO("IOS_ADAPTER", "  Mask: %u.%u.%u.%u",
                             (ctx->dhcp_state.subnet_mask >> 24) & 0xFF, 
                             (ctx->dhcp_state.subnet_mask >> 16) & 0xFF,
                             (ctx->dhcp_state.subnet_mask >> 8) & 0xFF, 
                             ctx->dhcp_state.subnet_mask & 0xFF);
                    LOG_INFO("IOS_ADAPTER", "  Gateway: %u.%u.%u.%u",
                             (ctx->dhcp_state.gateway >> 24) & 0xFF, 
                             (ctx->dhcp_state.gateway >> 16) & 0xFF,
                             (ctx->dhcp_state.gateway >> 8) & 0xFF, 
                             ctx->dhcp_state.gateway & 0xFF);
                }
                
                // ✅ CRITICAL: Do NOT enqueue DHCP packets - they're handled by state machine in GetNextPacket
                LOG_INFO("IOS_ADAPTER", "PutPacket: 🔄 DHCP packet handled by state machine, not enqueued");
                return true;  // Success, but don't enqueue
            }
        }
    }
    
    // Enqueue IP packet (non-blocking to avoid stalling SoftEther thread)
    int ret = packet_queue_enqueue(ctx->outgoing_queue, ip_packet_buf, ip_len, false);
    
    if (ret != 0) {
        ctx->queue_drops_out++;
        LOG_ERROR("IOS_ADAPTER", "PutPacket: OUTGOING QUEUE FULL! Dropped packet #%llu (%d bytes)", put_count, ip_len);
        return false;
    }
    
    LOG_INFO("IOS_ADAPTER", "PutPacket: ✅ Packet #%llu enqueued successfully (IP packet ready for iOS)", put_count);
    return true;
}

/**
 * Free iOS adapter
 */
static void IosAdapterFree(SESSION *s) {
    PACKET_ADAPTER *pa = s->PacketAdapter;
    if (!s || !pa) return;
    
    printf("[IosAdapterFree] Freeing iOS adapter\n");
    
    IOS_ADAPTER_CONTEXT* ctx = (IOS_ADAPTER_CONTEXT*)pa->Param;
    if (ctx) {
        ctx->initialized = false;
        
        // Print statistics
        printf("[IosAdapterFree] Statistics:\n");
        printf("[IosAdapterFree]   RX: %llu packets (%llu bytes)\n", ctx->packets_received, ctx->bytes_received);
        printf("[IosAdapterFree]   TX: %llu packets (%llu bytes)\n", ctx->packets_sent, ctx->bytes_sent);
        printf("[IosAdapterFree]   Drops: %llu in, %llu out\n", ctx->queue_drops_in, ctx->queue_drops_out);
        printf("[IosAdapterFree]   TapTun L2→L3: %llu, L3→L2: %llu, ARP: %llu\n",
               ctx->l2_to_l3_translated, ctx->l3_to_l2_translated, ctx->arp_packets_handled);
        
        // Release resources
        if (ctx->translator) {
            taptun_translator_destroy(ctx->translator);
            ctx->translator = NULL;
        }
        
        if (ctx->cancel) {
            ReleaseCancel(ctx->cancel);
        }
        
        if (ctx->incoming_queue) {
            packet_queue_destroy(ctx->incoming_queue);
        }
        
        if (ctx->outgoing_queue) {
            packet_queue_destroy(ctx->outgoing_queue);
        }
        
        // Destroy DHCP mutex
        pthread_mutex_destroy(&ctx->dhcp_mutex);
        
        // Clear global context
        if (global_ios_adapter_ctx == ctx) {
            global_ios_adapter_ctx = NULL;
        }
        
        free(ctx);
    }
    
    Free(pa);
    printf("[IosAdapterFree] ✓ iOS adapter freed\n");
}

// ============================================================================
// Public Constructor
// ============================================================================

/**
 * Create new iOS packet adapter
 * Called by zig_packet_adapter.c on iOS builds
 */
PACKET_ADAPTER* NewIosPacketAdapter(void) {
    LOG_INFO("IOS_ADAPTER", "Creating iOS Network Extension packet adapter");
    
    PACKET_ADAPTER* pa = ZeroMalloc(sizeof(PACKET_ADAPTER));
    if (!pa) {
        LOG_ERROR("IOS_ADAPTER", "Failed to allocate PACKET_ADAPTER");
        return NULL;
    }
    
    // Allocate and initialize context IMMEDIATELY (don't wait for Init callback)
    IOS_ADAPTER_CONTEXT* ctx = (IOS_ADAPTER_CONTEXT*)calloc(1, sizeof(IOS_ADAPTER_CONTEXT));
    if (!ctx) {
        LOG_ERROR("IOS_ADAPTER", "Failed to allocate adapter context");
        Free(pa);
        return NULL;
    }
    
    // Create packet queues now (not in Init callback)
    ctx->cancel = NewCancel();
    ctx->incoming_queue = packet_queue_create();
    ctx->outgoing_queue = packet_queue_create();
    pthread_mutex_init(&ctx->dhcp_mutex, NULL);
    memset(&ctx->dhcp_state, 0, sizeof(DHCPState));
    
    if (!ctx->incoming_queue || !ctx->outgoing_queue || !ctx->cancel) {
        LOG_ERROR("IOS_ADAPTER", "Failed to create packet queues or cancel handle");
        if (ctx->incoming_queue) packet_queue_destroy(ctx->incoming_queue);
        if (ctx->outgoing_queue) packet_queue_destroy(ctx->outgoing_queue);
        if (ctx->cancel) ReleaseCancel(ctx->cancel);
        pthread_mutex_destroy(&ctx->dhcp_mutex);
        free(ctx);
        Free(pa);
        return NULL;
    }
    
    ctx->initialized = true;
    global_ios_adapter_ctx = ctx;
    
    // Generate and store MAC address for TapTun translator
    uint8_t our_mac[6];
    our_mac[0] = 0x02; // Locally administered unicast
    srand((unsigned int)time(NULL));
    for (int i = 1; i < 6; i++) {
        our_mac[i] = (uint8_t)(rand() % 256);
    }
    memcpy(ctx->dhcp_state.client_mac, our_mac, 6);
    
    // Initialize TapTun L2↔L3 translator
    ctx->translator = taptun_translator_create(our_mac);
    if (!ctx->translator) {
        LOG_ERROR("IOS_ADAPTER", "Failed to create TapTun translator");
        if (ctx->incoming_queue) packet_queue_destroy(ctx->incoming_queue);
        if (ctx->outgoing_queue) packet_queue_destroy(ctx->outgoing_queue);
        if (ctx->cancel) ReleaseCancel(ctx->cancel);
        pthread_mutex_destroy(&ctx->dhcp_mutex);
        free(ctx);
        Free(pa);
        return NULL;
    }
    
    LOG_INFO("IOS_ADAPTER", "✅ TapTun translator initialized (MAC=%02X:%02X:%02X:%02X:%02X:%02X)",
             our_mac[0], our_mac[1], our_mac[2], our_mac[3], our_mac[4], our_mac[5]);
    
    // Set callbacks
    pa->Init = IosAdapterInit;
    pa->GetCancel = IosAdapterGetCancel;
    pa->GetNextPacket = IosAdapterGetNextPacket;
    pa->PutPacket = IosAdapterPutPacket;
    pa->Free = IosAdapterFree;
    pa->Param = ctx;  // Context is ready NOW
    
    // Use VLAN adapter ID (required by server for some protocols)
    pa->Id = PACKET_ADAPTER_ID_VLAN_WIN32;
    
    LOG_INFO("IOS_ADAPTER", "✓ iOS adapter initialized IMMEDIATELY");
    LOG_INFO("IOS_ADAPTER", "  - Incoming queue: %d packets capacity", MAX_PACKET_QUEUE_SIZE);
    LOG_INFO("IOS_ADAPTER", "  - Outgoing queue: %d packets capacity", MAX_PACKET_QUEUE_SIZE);
    
    // NOTE: Do NOT send DHCP DISCOVER here!
    // SoftEther VPN protocol handles IP assignment automatically after session authentication.
    // Sending DHCP before the session is established causes the server to ignore it.
    // The server will push IP configuration once the secure session is authenticated.
    
    printf("[NewIosPacketAdapter] ✓ iOS packet adapter created\n");
    
    return pa;
}
