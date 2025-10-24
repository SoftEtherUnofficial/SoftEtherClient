// SoftEther VPN - Zig Packet Adapter Bridge
// Integrates high-performance Zig adapter with C SoftEther VPN

#include <GlobalConst.h>

#ifdef BRIDGE_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Mayaqua/Mayaqua.h>
#include <Cedar/Cedar.h>

// Forward declarations for Zig adapter (defined in adapter.zig)
typedef struct ZigPacketAdapter ZigPacketAdapter;

typedef struct {
    size_t recv_queue_size;
    size_t send_queue_size;
    size_t packet_pool_size;
    size_t batch_size;
    const char *device_name;
} ZigAdapterConfig;

// External Zig functions
extern ZigPacketAdapter* zig_adapter_create(const ZigAdapterConfig *config);
extern void zig_adapter_destroy(ZigPacketAdapter *adapter);
extern bool zig_adapter_open(ZigPacketAdapter *adapter);
extern bool zig_adapter_start(ZigPacketAdapter *adapter);
extern void zig_adapter_stop(ZigPacketAdapter *adapter);
extern bool zig_adapter_get_packet(ZigPacketAdapter *adapter, unsigned char **out_data, size_t *out_len);
extern bool zig_adapter_put_packet(ZigPacketAdapter *adapter, const unsigned char *data, size_t len);
extern void zig_adapter_print_stats(ZigPacketAdapter *adapter);
extern long zig_adapter_read_sync(ZigPacketAdapter *adapter, unsigned char *buffer, size_t buffer_len);
extern long zig_adapter_write_sync(ZigPacketAdapter *adapter);

// DHCP building function from protocol.zig
extern bool zig_build_dhcp_discover(const uint8_t* mac, uint32_t xid, uint8_t* buffer, size_t buffer_len, size_t* out_size);

// Helper: Get TUN device name (returns pointer to internal buffer)
extern const char* zig_adapter_get_device_name_ptr(ZigPacketAdapter *adapter);

// Helper: Parse DHCP OFFER and extract IP configuration
static bool ParseDHCPOffer(const unsigned char *pkt, size_t len, uint32_t *out_ip, uint32_t *out_mask, uint32_t *out_gateway)
{
    // Ethernet (14) + IP (20) + UDP (8) + BOOTP (236) = min 278 bytes
    if (len < 278) return false;
    
    // Skip Ethernet header (14 bytes)
    const unsigned char *ip_pkt = pkt + 14;
    
    // Verify it's UDP port 68 (DHCP client)
    if (ip_pkt[9] != 17) return false; // Not UDP
    uint16_t dst_port = (ip_pkt[22] << 8) | ip_pkt[23];
    if (dst_port != 68) return false; // Not DHCP client port
    
    // DHCP starts after Ethernet + IP + UDP = 14 + 20 + 8 = 42 bytes
    const unsigned char *dhcp = pkt + 42;
    
    // Check DHCP magic cookie (0x63825363)
    if (dhcp[236] != 0x63 || dhcp[237] != 0x82 || 
        dhcp[238] != 0x53 || dhcp[239] != 0x63) {
        return false;
    }
    
    // Extract Your IP (yiaddr) - offset 16-19 in BOOTP
    *out_ip = (dhcp[16] << 24) | (dhcp[17] << 16) | (dhcp[18] << 8) | dhcp[19];
    
    // Extract Server IP (siaddr) as potential gateway - offset 20-23
    uint32_t siaddr = (dhcp[20] << 24) | (dhcp[21] << 16) | (dhcp[22] << 8) | dhcp[23];
    
    // DEBUG: Print DHCP header fields
    printf("[ZigBridge] 🔍 DHCP Header: yiaddr=%u.%u.%u.%u, siaddr=%u.%u.%u.%u\n",
           dhcp[16], dhcp[17], dhcp[18], dhcp[19],
           dhcp[20], dhcp[21], dhcp[22], dhcp[23]);
    fflush(stdout);
    
    // Parse DHCP options for subnet mask and router
    *out_mask = 0xFFFF0000; // Default /16
    *out_gateway = siaddr;
    
    const unsigned char *opt = dhcp + 240; // Options start after magic cookie
    size_t opt_len = len - 42 - 240;
    size_t i = 0;
    
    while (i < opt_len) {
        uint8_t opt_type = opt[i++];
        if (opt_type == 255) break; // End marker
        if (opt_type == 0) continue; // Padding
        
        if (i >= opt_len) break;
        uint8_t opt_size = opt[i++];
        if (i + opt_size > opt_len) break;
        
        if (opt_type == 1 && opt_size == 4) {
            // Subnet mask
            *out_mask = (opt[i] << 24) | (opt[i+1] << 16) | (opt[i+2] << 8) | opt[i+3];
            printf("[ZigBridge] 🔍 DHCP Option 1 (Subnet Mask): %u.%u.%u.%u\n",
                   opt[i], opt[i+1], opt[i+2], opt[i+3]);
            fflush(stdout);
        } else if (opt_type == 3 && opt_size >= 4) {
            // Router (gateway)
            *out_gateway = (opt[i] << 24) | (opt[i+1] << 16) | (opt[i+2] << 8) | opt[i+3];
            printf("[ZigBridge] 🔍 DHCP Option 3 (Router): %u.%u.%u.%u\n",
                   opt[i], opt[i+1], opt[i+2], opt[i+3]);
            fflush(stdout);
        }
        
        i += opt_size;
    }
    
    return *out_ip != 0;
}

// Helper: Configure TUN interface with IP
static bool ConfigureTUNInterface(const char *device, uint32_t ip, uint32_t mask, uint32_t gateway)
{
    char cmd[512];
    char ip_str[32], mask_str[32], gw_str[32];
    
    // Format IP addresses
    snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
    snprintf(mask_str, sizeof(mask_str), "%u.%u.%u.%u",
             (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF);
    snprintf(gw_str, sizeof(gw_str), "%u.%u.%u.%u",
             (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF, (gateway >> 8) & 0xFF, gateway & 0xFF);
    
    printf("[ZigBridge] 🌐 Configuring %s: IP=%s, Mask=%s, Gateway=%s\n", 
           device, ip_str, mask_str, gw_str);
    fflush(stdout);
    
    // Step 1: Configure interface with ifconfig
    // macOS TUN ifconfig format: ifconfig DEVICE LOCAL_IP PEER_IP netmask NETMASK up
    snprintf(cmd, sizeof(cmd), "ifconfig %s %s %s netmask %s up", 
             device, ip_str, gw_str, mask_str);
    
    int ret = system(cmd);
    if (ret != 0) {
        printf("[ZigBridge] ❌ Failed to configure interface (exit code: %d)\n", ret);
        return false;
    }
    
    printf("[ZigBridge] ✅ Interface configured successfully!\n");
    fflush(stdout);
    
    // Step 2: Add route to VPN network
    // Calculate network address: ip & mask
    uint32_t network = ip & mask;
    char net_str[32];
    snprintf(net_str, sizeof(net_str), "%u.%u.%u.%u",
             (network >> 24) & 0xFF, (network >> 16) & 0xFF, 
             (network >> 8) & 0xFF, network & 0xFF);
    
    // Calculate CIDR prefix length from netmask
    int prefix = 0;
    uint32_t temp_mask = mask;
    while (temp_mask) {
        prefix += (temp_mask & 1);
        temp_mask >>= 1;
    }
    
    printf("[ZigBridge] 🛣️  Adding route: %s/%d via %s\n", net_str, prefix, gw_str);
    fflush(stdout);
    
    // Add route: route add -net NETWORK/PREFIX GATEWAY
    snprintf(cmd, sizeof(cmd), "route add -net %s/%d %s 2>/dev/null", 
             net_str, prefix, gw_str);
    
    ret = system(cmd);
    if (ret != 0) {
        printf("[ZigBridge] ⚠️  Failed to add route (may already exist): exit code %d\n", ret);
        fflush(stdout);
        // Don't return false - route may already exist, interface is still configured
    } else {
        printf("[ZigBridge] ✅ Route added successfully!\n");
        fflush(stdout);
    }
    
    return true;
}

// Wrapper structure for SoftEther integration
typedef struct ZIG_BRIDGE_SESSION {
    ZigPacketAdapter *adapter;
    CANCEL *cancel;
    volatile bool running;
    
    // Pre-queued packets (like old packet_adapter_macos.c)
    bool dhcp_discover_sent;
    uint8_t *dhcp_discover_packet;
    size_t dhcp_discover_size;
    
    // Auto-configuration
    bool ip_configured;
    char device_name[32];
    
    // MAC address caching
    uint8_t cached_mac[6];
    bool mac_initialized;
} ZIG_BRIDGE_SESSION;

// Global MAC address cache (persistent across connections)
static uint8_t g_cached_mac[6] = {0};
static bool g_mac_cached = false;

// Generate or retrieve MAC address based on config
static void GetOrGenerateMAC(SESSION *s, uint8_t *mac_out)
{
    // Check config for mac_address setting
    // TODO: Parse from config when config system is integrated
    bool randomize_mac = false; // From config: "randomize_mac"
    const char *mac_address = NULL; // From config: "mac_address"
    
    // Priority 1: If randomize_mac is true, always generate new random MAC
    if (randomize_mac) {
        mac_out[0] = 0x00;
        mac_out[1] = 0xAC; // Locally administered
        Rand(mac_out + 2, 4);
        printf("[ZigBridge] 🎲 Randomized MAC: %02X:%02X:%02X:%02X:%02X:%02X (randomize_mac=true)\n",
               mac_out[0], mac_out[1], mac_out[2], mac_out[3], mac_out[4], mac_out[5]);
        return;
    }
    
    // Priority 2: If mac_address is set in config, use it
    if (mac_address != NULL && StrCmp(mac_address, "random") == 0) {
        // "random" keyword - generate new random MAC
        mac_out[0] = 0x00;
        mac_out[1] = 0xAC;
        Rand(mac_out + 2, 4);
        printf("[ZigBridge] 🎲 Random MAC: %02X:%02X:%02X:%02X:%02X:%02X (mac_address=random)\n",
               mac_out[0], mac_out[1], mac_out[2], mac_out[3], mac_out[4], mac_out[5]);
        return;
    } else if (mac_address != NULL) {
        // Parse MAC address from config (format: "00:AC:11:22:33:44")
        // TODO: Add MAC parsing when config system is ready
        printf("[ZigBridge] ⚙️  Using configured MAC: %s\n", mac_address);
    }
    
    // Priority 3: Use cached MAC address (default behavior)
    if (g_mac_cached) {
        Copy(mac_out, g_cached_mac, 6);
        printf("[ZigBridge] 📌 Using cached MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               mac_out[0], mac_out[1], mac_out[2], mac_out[3], mac_out[4], mac_out[5]);
        return;
    }
    
    // Priority 4: Generate new random MAC and cache it
    mac_out[0] = 0x00;
    mac_out[1] = 0xAC; // Locally administered
    Rand(mac_out + 2, 4);
    
    // Cache for future connections
    Copy(g_cached_mac, mac_out, 6);
    g_mac_cached = true;
    
    printf("[ZigBridge] ✨ Generated and cached new MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac_out[0], mac_out[1], mac_out[2], mac_out[3], mac_out[4], mac_out[5]);
}

// PA_INIT callback - Initialize the adapter
// Signature: typedef bool (PA_INIT)(SESSION *s);
static bool ZigBridgeInit(SESSION *s)
{
    ZIG_BRIDGE_SESSION *zbs = NULL;
    ZigAdapterConfig config;
    
    printf("[ZigBridge] Initializing Zig packet adapter for session %s\n", 
           s->Name ? s->Name : "unknown");
    
    // Allocate session structure
    zbs = ZeroMalloc(sizeof(ZIG_BRIDGE_SESSION));
    if (zbs == NULL) {
        printf("[ZigBridge] ERROR: Failed to allocate session structure\n");
        return false;
    }
    
    // Configure Zig adapter with optimized settings
    config.recv_queue_size = 65536;  // 64K starting (scales to 128K)
    config.send_queue_size = 32768;  // 32K starting (scales to 128K)
    config.packet_pool_size = 131072; // 128K pre-allocated
    config.batch_size = 256;
    config.device_name = "utun";
    
    // Create Zig adapter
    printf("[ZigBridge] Creating Zig adapter with dynamic adaptive scaling...\n");
    zbs->adapter = zig_adapter_create(&config);
    if (zbs->adapter == NULL) {
        printf("[ZigBridge] ERROR: Failed to create Zig adapter\n");
        Free(zbs);
        return false;
    }
    
    // Open TUN device
    printf("[ZigBridge] Opening TUN device...\n");
    if (!zig_adapter_open(zbs->adapter)) {
        printf("[ZigBridge] ERROR: Failed to open TUN device\n");
        zig_adapter_destroy(zbs->adapter);
        Free(zbs);
        return false;
    }
    
    // Start I/O threads (including adaptive monitor thread)
    printf("[ZigBridge] Starting I/O threads...\n");
    if (!zig_adapter_start(zbs->adapter)) {
        printf("[ZigBridge] ERROR: Failed to start I/O threads\n");
        zig_adapter_destroy(zbs->adapter);
        Free(zbs);
        return false;
    }
    
    // Create cancel event
    zbs->cancel = NewCancel();
    zbs->running = true;
    zbs->dhcp_discover_sent = false;
    zbs->dhcp_discover_packet = NULL;
    zbs->dhcp_discover_size = 0;
    zbs->ip_configured = false;
    
    // Get and store device name
    const char *dev_name = zig_adapter_get_device_name_ptr(zbs->adapter);
    if (dev_name) {
        StrCpy(zbs->device_name, sizeof(zbs->device_name), (char*)dev_name);
        printf("[ZigBridge] 📱 Device: %s\n", zbs->device_name);
    } else {
        zbs->device_name[0] = '\0';
    }
    fflush(stdout);
    
    // Store in session
    s->PacketAdapter->Param = zbs;
    
    printf("[ZigBridge] ✅ Zig adapter initialized successfully\n");
    printf("[ZigBridge] 🚀 Dynamic adaptive buffer scaling: 1K→128K\n");
    printf("[ZigBridge] 📊 Monitor thread active (1ms polling)\n");
    printf("[ZigBridge] 🔥 Performance optimizations enabled\n");
    printf("[ZigBridge] ✅ Returning TRUE from ZigBridgeInit\n");
    fflush(stdout);
    
    // Build initial DHCP DISCOVER (matching old packet_adapter_macos.c behavior)
    // DON'T send it yet - pre-queue it for GetNextPacket to return
    printf("[ZigBridge] Building DHCP DISCOVER packet...\n");
    uint8_t *dhcp_buffer = Malloc(1024);
    size_t dhcp_size = 0;
    
    // Get or generate MAC address (cached across connections by default)
    uint8_t client_mac[6];
    GetOrGenerateMAC(s, client_mac);
    fflush(stdout);
    
    uint32_t xid = (uint32_t)Tick64(); // Transaction ID from current time
    
    if (zig_build_dhcp_discover(client_mac, xid, dhcp_buffer, 1024, &dhcp_size)) {
        zbs->dhcp_discover_packet = dhcp_buffer;
        zbs->dhcp_discover_size = dhcp_size;
        printf("[ZigBridge] ✅ DHCP DISCOVER built (%zu bytes, xid=0x%08x) - will send on first GetNextPacket\n", 
               dhcp_size, xid);
    } else {
        Free(dhcp_buffer);
        printf("[ZigBridge] ⚠️  Failed to build DHCP DISCOVER\n");
    }
    fflush(stdout);
    
    return true;
}

// PA_GETCANCEL callback - Get cancel event
// Signature: typedef CANCEL *(PA_GETCANCEL)(SESSION *s);
static CANCEL* ZigBridgeGetCancel(SESSION *s)
{
    printf("[ZigBridge] 🔔 GetCancel called\n");
    fflush(stdout);
    
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    if (zbs == NULL) {
        printf("[ZigBridge] ❌ GetCancel: zbs is NULL!\n");
        return NULL;
    }
    if (zbs->cancel == NULL) {
        printf("[ZigBridge] ❌ GetCancel: cancel is NULL!\n");
        return NULL;
    }
    if (zbs->cancel->ref == NULL) {
        printf("[ZigBridge] ❌ GetCancel: cancel->ref is NULL!\n");
        return NULL;
    }
    
    printf("[ZigBridge] GetCancel: Adding ref...\n");
    fflush(stdout);
    
    // IMPORTANT: AddRef because session will ReleaseCancel (session owns Cancel2)
    AddRef(zbs->cancel->ref);
    
    printf("[ZigBridge] ✅ GetCancel returning cancel=%p\n", zbs->cancel);
    fflush(stdout);
    
    return zbs->cancel;
}

// PA_GETNEXTPACKET callback - Get next packet from adapter
// Signature: typedef UINT (PA_GETNEXTPACKET)(SESSION *s, void **data);
static UINT ZigBridgeGetNextPacket(SESSION *s, void **data)
{
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    
    if (zbs == NULL) {
        printf("[ZigBridge] ❌ GetNextPacket: zbs is NULL\n");
        fflush(stdout);
        return INFINITE;
    }
    
    if (!zbs->running) {
        printf("[ZigBridge] ⚠️  GetNextPacket: not running anymore\n");
        fflush(stdout);
        return INFINITE;
    }
    
    // PRIORITY 1: Return pre-queued DHCP DISCOVER first (like old packet_adapter_macos.c)
    if (!zbs->dhcp_discover_sent && zbs->dhcp_discover_packet != NULL) {
        printf("[ZigBridge] 📤 Returning pre-queued DHCP DISCOVER (%zu bytes)\n", zbs->dhcp_discover_size);
        fflush(stdout);
        
        *data = zbs->dhcp_discover_packet; // Session will free this
        zbs->dhcp_discover_sent = true;
        zbs->dhcp_discover_packet = NULL; // Transfer ownership to session
        
        return (UINT)zbs->dhcp_discover_size;
    }
    
    // PRIORITY 2: Read from TUN device synchronously
    // Allocate buffer for Ethernet frame (TUN returns IP, adapter adds Ethernet header)
    unsigned char *buffer = Malloc(2048);
    if (buffer == NULL) {
        printf("[ZigBridge] ❌ GetNextPacket: Malloc failed!\n");
        fflush(stdout);
        return INFINITE;
    }
    
    // Read from TUN device (blocking with 1ms timeout)
    long bytes_read = zig_adapter_read_sync(zbs->adapter, buffer, 2048);
    
    if (bytes_read < 0) {
        // Error reading
        Free(buffer);
        printf("[ZigBridge] ❌ GetNextPacket: Read error\n");
        fflush(stdout);
        return INFINITE;
    }
    
    if (bytes_read == 0) {
        // No data available (timeout) - this is normal
        Free(buffer);
        static uint64_t no_packet_count = 0;
        no_packet_count++;
        if (no_packet_count <= 100 || (no_packet_count % 100) == 0) {
            printf("[ZigBridge] 🔍 GetNextPacket: No packet available (count=%llu)\n", no_packet_count);
            fflush(stdout);
        }
        return 0; // Tell session to poll again
    }
    
    // Got a packet!
    printf("[ZigBridge] 📬 GetNextPacket: Read %ld bytes from TUN device\n", bytes_read);
    fflush(stdout);
    
    *data = buffer; // Transfer ownership to session (will free it)
    return (UINT)bytes_read;
}

// PA_PUTPACKET callback - Put packet to adapter for transmission
// Signature: typedef bool (PA_PUTPACKET)(SESSION *s, void *data, UINT size);
static bool ZigBridgePutPacket(SESSION *s, void *data, UINT size)
{
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    
    if (zbs == NULL || !zbs->running) {
        printf("[ZigBridge] ⚠️  PutPacket: adapter not ready\n");
        fflush(stdout);
        return false;
    }
    
    // NULL packet is a finalization signal from SoftEther - acknowledge it
    if (data == NULL || size == 0) {
        printf("[ZigBridge] ℹ️  PutPacket: NULL packet (finalization)\n");
        fflush(stdout);
        return true;
    }
    
    // Debug: Log packet type for first few packets
    static uint32_t put_count = 0;
    put_count++;
    
    // **AUTO-CONFIGURE FROM DHCP OFFER**
    if (!zbs->ip_configured && size >= 278) {
        unsigned char *pkt = (unsigned char*)data;
        uint16_t ethertype = (pkt[12] << 8) | pkt[13];
        
        if (ethertype == 0x0800) { // IPv4
            unsigned char protocol = pkt[23];
            if (protocol == 17) { // UDP
                uint16_t dst_port = (pkt[36] << 8) | pkt[37];
                if (dst_port == 68) { // DHCP client port
                    printf("[ZigBridge] 🎯 Detected DHCP packet - attempting auto-configuration...\n");
                    fflush(stdout);
                    
                    uint32_t ip, mask, gateway;
                    if (ParseDHCPOffer(pkt, size, &ip, &mask, &gateway)) {
                        printf("[ZigBridge] ✅ Parsed DHCP OFFER successfully\n");
                        fflush(stdout);
                        
                        if (zbs->device_name[0] != '\0') {
                            if (ConfigureTUNInterface(zbs->device_name, ip, mask, gateway)) {
                                zbs->ip_configured = true;
                                printf("[ZigBridge] 🎉 VPN IP configured via DHCP!\n");
                            }
                        } else {
                            printf("[ZigBridge] ⚠️  Cannot configure - device name unknown\n");
                        }
                        fflush(stdout);
                    }
                }
            }
        }
    }
    
    if (put_count <= 10) {
        unsigned char *pkt = (unsigned char*)data;
        if (size >= 14) {
            uint16_t ethertype = (pkt[12] << 8) | pkt[13];
            printf("[ZigBridge] 📨 PutPacket #%u: %u bytes, EtherType=0x%04x", put_count, size, ethertype);
            
            // Check if it's IPv4 (0x0800)
            if (ethertype == 0x0800 && size >= 34) {
                unsigned char protocol = pkt[23]; // IP protocol field
                if (protocol == 17) { // UDP
                    uint16_t dst_port = (pkt[36] << 8) | pkt[37];
                    printf(" (UDP dst_port=%u", dst_port);
                    if (dst_port == 68) printf(" - DHCP client)");
                    else printf(")");
                }
            }
            printf("\n");
        } else {
            printf("[ZigBridge] 📨 PutPacket #%u: %u bytes (too small)\n", put_count, size);
        }
        fflush(stdout);
    }
    
    // Queue packet for writing
    if (!zig_adapter_put_packet(zbs->adapter, (const unsigned char*)data, size)) {
        printf("[ZigBridge] ❌ PutPacket: Failed to queue packet\n");
        fflush(stdout);
        return false;
    }
    
    // Immediately drain queue and write to TUN device
    long packets_written = zig_adapter_write_sync(zbs->adapter);
    
    if (packets_written <= 0) {
        printf("[ZigBridge] ❌ PutPacket: Write failed (wrote %ld packets)\n", packets_written);
        fflush(stdout);
        return false;
    }
    
    printf("[ZigBridge] ✅ PutPacket: Wrote %ld packet(s) to TUN\n", packets_written);
    fflush(stdout);
    
    return true;
}

// PA_FREE callback - Cleanup
// Signature: typedef void (PA_FREE)(SESSION *s);
static void ZigBridgeFree(SESSION *s)
{
    ZIG_BRIDGE_SESSION *zbs = (ZIG_BRIDGE_SESSION*)s->PacketAdapter->Param;
    
    if (zbs == NULL) {
        return;
    }
    
    printf("[ZigBridge] Cleaning up Zig adapter for session %s\n", 
           s->Name ? s->Name : "unknown");
    
    zbs->running = false;
    
    // Free pre-queued DHCP packet if not sent
    if (zbs->dhcp_discover_packet != NULL) {
        Free(zbs->dhcp_discover_packet);
        zbs->dhcp_discover_packet = NULL;
    }
    
    // Print final statistics
    printf("[ZigBridge] Final statistics:\n");
    zig_adapter_print_stats(zbs->adapter);
    
    // Stop threads
    zig_adapter_stop(zbs->adapter);
    
    // Destroy adapter
    zig_adapter_destroy(zbs->adapter);
    
    // NOTE: Don't free cancel here - session already released it via ReleaseCancel(s->Cancel2)
    // The cancel object is owned by the session, we just provided a reference
    
    // Free session structure
    Free(zbs);
    
    printf("[ZigBridge] ✅ Cleanup complete\n");
}

// Create Zig-based packet adapter for SoftEther
PACKET_ADAPTER* NewZigPacketAdapter()
{
    PACKET_ADAPTER *pa;
    
    printf("[ZigBridge] Creating Zig packet adapter (with adaptive scaling)...\n");
    
    pa = NewPacketAdapter(
        ZigBridgeInit,
        ZigBridgeGetCancel,
        ZigBridgeGetNextPacket,
        ZigBridgePutPacket,
        ZigBridgeFree
    );
    
    if (pa != NULL) {
        printf("[ZigBridge] ✅ Packet adapter created successfully\n");
    } else {
        printf("[ZigBridge] ❌ Failed to create packet adapter\n");
    }
    
    return pa;
}

#endif // BRIDGE_C
