// FFI bridge for Zig packet adapter
// Provides C-compatible interface for SoftEther integration

#ifndef ZIG_PACKET_ADAPTER_H
#define ZIG_PACKET_ADAPTER_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// Note: We don't include stdbool.h because SoftEther defines bool as UINT
#ifndef bool
typedef unsigned int bool;
#define true 1
#define false 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Opaque adapter handle
typedef struct ZigPacketAdapter ZigPacketAdapter;

// Configuration structure (matches Zig Config)
typedef struct {
    size_t recv_queue_size;    // 8192 default
    size_t send_queue_size;    // 4096 default
    size_t packet_pool_size;   // 16384 default
    size_t batch_size;         // 32 default
    const char *device_name;   // "utun" default
    size_t device_name_len;
} ZigAdapterConfig;

// Packet buffer structure
typedef struct {
    uint8_t *data;
    size_t len;
    int64_t timestamp;
} ZigPacketBuffer;

// Default configuration
// ZIGSE-25: Optimized for high-throughput bidirectional traffic
static inline ZigAdapterConfig zig_adapter_default_config(void) {
    ZigAdapterConfig config = {
        .recv_queue_size = 128,  // Balanced for downloads
        .send_queue_size = 128,  // Balanced for uploads
        .packet_pool_size = 256, // CRITICAL: Must be >= recv+send
        .batch_size = 128,       // Match queue size for throughput
        .device_name = "utun",
        .device_name_len = 4
    };
    return config;
}

// Lifecycle functions
ZigPacketAdapter* zig_adapter_create(const ZigAdapterConfig *config);
void zig_adapter_destroy(ZigPacketAdapter *adapter);
bool zig_adapter_open(ZigPacketAdapter *adapter);
bool zig_adapter_start(ZigPacketAdapter *adapter);
void zig_adapter_stop(ZigPacketAdapter *adapter);

// Packet I/O
bool zig_adapter_get_packet(ZigPacketAdapter *adapter, uint8_t **out_data, size_t *out_len);
void zig_adapter_release_packet(ZigPacketAdapter *adapter, uint8_t *data);
size_t zig_adapter_get_packet_batch(ZigPacketAdapter *adapter, ZigPacketBuffer *out_array, size_t max_count);
bool zig_adapter_put_packet(ZigPacketAdapter *adapter, const uint8_t *data, size_t len);

// Statistics
void zig_adapter_print_stats(ZigPacketAdapter *adapter);

// Gateway configuration (for MAC learning from ARP)
void zig_adapter_set_gateway(ZigPacketAdapter *adapter, uint32_t ip_network_order);
void zig_adapter_set_gateway_mac(ZigPacketAdapter *adapter, const uint8_t mac[6]);

// VPN routing configuration
bool zig_adapter_configure_routing(ZigPacketAdapter *adapter, uint32_t vpn_gateway, uint32_t vpn_server);
bool zig_adapter_configure_routes(ZigPacketAdapter *adapter, uint32_t vpn_gateway_ip, uint32_t vpn_network, uint32_t vpn_netmask);

// Synchronous I/O (for non-async operation)
ssize_t zig_adapter_read_sync(ZigPacketAdapter *adapter, uint8_t *buffer, size_t buffer_len);
ssize_t zig_adapter_write_sync(ZigPacketAdapter *adapter);

// LATENCY FIX: Get TUN device FD for select()/poll() integration
int zig_adapter_get_fd(ZigPacketAdapter *adapter);

// Helper functions for Zig FFI
size_t sizeof_CLIENT_OPTION(void);
size_t sizeof_CLIENT_AUTH(void);
void set_client_option_hostname(void *opt, const char *hostname);
void set_client_option_hubname(void *opt, const char *hubname);
void set_client_option_devicename(void *opt, const char *devicename);
void set_client_auth_username(void *auth, const char *username);

#ifdef __cplusplus
}
#endif

#endif // ZIG_PACKET_ADAPTER_H
