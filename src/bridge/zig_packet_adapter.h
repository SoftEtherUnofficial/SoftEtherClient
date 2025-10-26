// Zig Packet Adapter - C FFI Header
// Provides C-compatible interface to Zig packet adapter

#ifndef ZIG_PACKET_ADAPTER_H
#define ZIG_PACKET_ADAPTER_H

#ifdef __cplusplus
extern "C" {
#endif

// Include SoftEther headers first (they define bool and other types)
#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"

// Standard headers (after SoftEther to avoid bool conflicts)
#include <stdint.h>

// Opaque handle to Zig adapter
typedef struct ZigPacketAdapter ZigPacketAdapter;

// Configuration for Zig adapter
typedef struct {
    uint64_t recv_queue_size;
    uint64_t send_queue_size;
    uint64_t packet_pool_size;
    uint64_t batch_size;
    const char* device_name;
    uint64_t device_name_len;  // Length of device_name string
} ZigAdapterConfig;

// Packet buffer structure (matches Zig side)
typedef struct {
    uint8_t* data;
    uint64_t len;
    int64_t timestamp;
} ZigPacketBuffer;

// Zig adapter FFI functions (exported from adapter.zig)
extern ZigPacketAdapter* zig_adapter_create(const ZigAdapterConfig* config);
extern void zig_adapter_destroy(ZigPacketAdapter* adapter);
extern bool zig_adapter_open(ZigPacketAdapter* adapter);
extern bool zig_adapter_start(ZigPacketAdapter* adapter);
extern void zig_adapter_stop(ZigPacketAdapter* adapter);
extern bool zig_adapter_get_packet(ZigPacketAdapter* adapter, uint8_t** out_data, uint64_t* out_len);
extern void zig_adapter_release_packet(ZigPacketAdapter* adapter, uint8_t* data);
extern uint64_t zig_adapter_get_packet_batch(ZigPacketAdapter* adapter, ZigPacketBuffer* out_array, uint64_t max_count);
extern bool zig_adapter_put_packet(ZigPacketAdapter* adapter, const uint8_t* data, uint64_t len);
extern void zig_adapter_print_stats(ZigPacketAdapter* adapter);
extern uint64_t zig_adapter_get_device_name(ZigPacketAdapter* adapter, uint8_t* out_buffer, uint64_t buffer_len);
extern bool zig_adapter_configure_interface(ZigPacketAdapter* adapter, uint32_t local_ip, uint32_t peer_ip, uint32_t netmask);

// Create SoftEther PACKET_ADAPTER that wraps Zig adapter
PACKET_ADAPTER* NewZigPacketAdapter(void);

// TapTun Translator C FFI (from TapTun/src/c_ffi.zig)
typedef struct TapTunTranslator TapTunTranslator;
extern TapTunTranslator* taptun_translator_create(const uint8_t* our_mac);
extern void taptun_translator_destroy(TapTunTranslator* handle);
extern int taptun_ethernet_to_ip(TapTunTranslator* handle, const uint8_t* eth_frame, size_t frame_len, uint8_t* out_ip_packet, size_t out_buffer_size);
extern int taptun_ip_to_ethernet(TapTunTranslator* handle, const uint8_t* ip_packet, size_t packet_len, uint8_t* out_eth_frame, size_t out_buffer_size);
extern void taptun_translator_set_our_ip(TapTunTranslator* handle, uint32_t ip);
extern void taptun_translator_set_gateway_mac(TapTunTranslator* handle, const uint8_t* mac);

// Context for Zig adapter wrapper
typedef struct {
    SESSION* session;
    ZigPacketAdapter* zig_adapter;     // NULL on iOS (uses mobile FFI)
    TapTunTranslator* taptun_translator; // iOS: TapTun translator for L2↔L3 + DHCP
    CANCEL* cancel;
    bool halt;
    
    // DHCP state machine (moved from globals for thread safety)
    int dhcp_state;  // DHCP_STATE enum
    uint32_t dhcp_xid;
    uint8_t my_mac[6];
    uint64_t connection_start_time;
    uint64_t last_dhcp_send_time;
    uint32_t dhcp_retry_count;
    bool dhcp_initialized;
    uint32_t offered_ip;
    uint32_t offered_gw;
    uint32_t offered_mask;
    uint32_t dhcp_server_ip;
    uint32_t our_ip;
    
    // ARP state
    bool need_gateway_arp;
    bool need_gratuitous_arp_configured;
    bool need_arp_reply;
    uint8_t arp_reply_to_mac[6];
    uint32_t arp_reply_to_ip;
    uint64_t last_keepalive_time;
    uint8_t gateway_mac[6];
    bool need_reactive_garp;
    
    // Packet counters
    uint64_t put_arp_count;
    uint64_t put_dhcp_count;
    uint64_t put_icmp_count;
    uint64_t put_tcp_count;
    uint64_t put_udp_count;
    uint64_t put_other_count;
} ZIG_ADAPTER_CONTEXT;

#ifdef __cplusplus
}
#endif

#endif // ZIG_PACKET_ADAPTER_H
