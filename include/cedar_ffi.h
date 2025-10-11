#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CONNECTING_TIMEOUT_MS 15000

#define CONNECTING_TIMEOUT_AZURE_MS 8000

#define CONNECTING_POOLING_SPAN_MS 3000

#define MIN_RETRY_INTERVAL_MS 5000

#define MAX_RETRY_INTERVAL_MS 300000

#define MAX_ADDITIONAL_CONNECTION_FAILED_COUNTER 16

#define ADDITIONAL_CONNECTION_FAILED_COUNTER_RESET_MS 60000

/**
 * UDP Acceleration and NAT-T related constants (from UdpAccel.h)
 */
#define UDP_ACCELERATION_WINDOW_SIZE_MSEC 30000

#define UDP_ACCELERATION_KEEPALIVE_TIMEOUT 9000

#define UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN 1000

#define UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX 3000

#define UDP_ACCELERATION_KEEPALIVE_INTERVAL_MIN_FAST 500

#define UDP_ACCELERATION_KEEPALIVE_INTERVAL_MAX_FAST 1000

#define UDP_ACCELERATION_KEEPALIVE_TIMEOUT_FAST 2100

#define UDP_ACCELERATION_COMMON_KEY_SIZE_V1 20

#define UDP_ACCELERATION_COMMON_KEY_SIZE_V2 128

#define UDP_ACCELERATION_MAX_PAYLOAD_SIZE 1600

#define HELLO 1

#define HELLO_RESPONSE 2

#define AUTH_REQUEST 16

#define AUTH_RESPONSE 17

#define KEEP_ALIVE 32

#define KEEP_ALIVE_RESPONSE 33

#define DATA 48

#define DISCONNECT 64

/**
 * Protocol version - SoftEther 4.44 (same as working implementations)
 */
#define PROTOCOL_VERSION 444

/**
 * Maximum packet size (16MB)
 */
#define MAX_PACKET_SIZE ((16 * 1024) * 1024)

#define DHCP_DISCOVER 1

#define DHCP_OFFER 2

#define DHCP_REQUEST 3

#define DHCP_DECLINE 4

#define DHCP_ACK 5

#define DHCP_NAK 6

#define DHCP_RELEASE 7

#define DHCP_INFORM 8

#define DHCP_OPT_PAD 0

#define DHCP_OPT_SUBNET_MASK 1

#define DHCP_OPT_ROUTER 3

#define DHCP_OPT_DNS 6

#define DHCP_OPT_REQUESTED_IP 50

#define DHCP_OPT_LEASE_TIME 51

#define DHCP_OPT_MSG_TYPE 53

#define DHCP_OPT_SERVER_ID 54

#define DHCP_OPT_PARAM_REQUEST 55

#define DHCP_OPT_RENEWAL_TIME 58

#define DHCP_OPT_REBINDING_TIME 59

#define DHCP_OPT_CLIENT_ID 61

#define DHCP_OPT_END 255

#define ETH_TYPE_IPV4 2048

#define ETH_TYPE_ARP 2054

#define IP_PROTO_UDP 17

#define DHCP_CLIENT_PORT 68

#define DHCP_SERVER_PORT 67

#define ARP_REQUEST 1

#define ARP_REPLY 2

#define DHCP_MAGIC_COOKIE 1669485411

#define DHCP_INITIAL_DELAY_MS 2000

#define DHCP_RETRY_INTERVAL_MS 3000

#define DHCP_REQUEST_DELAY_MS 500

#define DHCP_MAX_RETRIES 5

#define KEEPALIVE_INTERVAL_MS 10000

/**
 * Compression algorithm for FFI
 */
typedef enum CedarCompressionAlgorithm {
  CompressionNone = 0,
  Deflate = 1,
  Gzip = 2,
  Lz4 = 3,
} CedarCompressionAlgorithm;

/**
 * FFI error codes
 */
typedef enum CedarErrorCode {
  Success = 0,
  InternalError = 1,
  InvalidParameter = 2,
  NotConnected = 3,
  InvalidState = 4,
  BufferTooSmall = 5,
  PacketTooLarge = 6,
  AuthenticationFailed = 7,
  NotImplemented = 8,
  TimeOut = 9,
  IoError = 10,
} CedarErrorCode;

/**
 * NAT type for FFI
 */
typedef enum CedarNatType {
  NatNone = 0,
  FullCone = 1,
  RestrictedCone = 2,
  PortRestrictedCone = 3,
  Symmetric = 4,
  Unknown = 5,
} CedarNatType;

/**
 * Session status for FFI
 */
typedef enum CedarSessionStatus {
  Init = 0,
  Connecting = 1,
  Authenticating = 2,
  Established = 3,
  Reconnecting = 4,
  Closing = 5,
  Terminated = 6,
} CedarSessionStatus;

/**
 * TLS state for FFI
 */
typedef enum CedarTlsState {
  Disconnected = 0,
  Handshaking = 1,
  Connected = 2,
  Error = 3,
} CedarTlsState;

/**
 * UDP acceleration mode for FFI
 */
typedef enum CedarUdpAccelMode {
  Disabled = 0,
  Hybrid = 1,
  UdpOnly = 2,
} CedarUdpAccelMode;

/**
 * Opaque session handle
 */
typedef void *CedarSessionHandle;

/**
 * Session statistics for FFI
 */
typedef struct CedarSessionStats {
  uint64_t bytes_sent;
  uint64_t bytes_received;
  uint64_t packets_sent;
  uint64_t packets_received;
  uint64_t duration_secs;
  uint64_t idle_time_secs;
} CedarSessionStats;

/**
 * Opaque packet handle
 */
typedef void *CedarPacketHandle;

/**
 * Opaque TLS connection handle
 */
typedef void *CedarTlsHandle;

/**
 * Opaque compressor handle
 */
typedef void *CedarCompressorHandle;

/**
 * Opaque UDP accelerator handle
 */
typedef void *CedarUdpAccelHandle;

/**
 * Opaque NAT traversal handle
 */
typedef void *CedarNatTraversalHandle;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Create new session
 */
CedarSessionHandle cedar_session_new(const char *server, uint16_t port, const char *hub);

/**
 * Create new session with authentication (wrapper for backward compatibility)
 */
CedarSessionHandle cedar_session_new_with_auth(const char *server, uint16_t port, const char *hub, const char *username, const char *password);

/**
 * Create new session with authentication and encryption control
 * use_encrypt: 0 = no encryption, 1 = use RC4 encryption (default)
 */
CedarSessionHandle cedar_session_new_with_auth_ex(const char *server, uint16_t port, const char *hub, const char *username, const char *password, uint8_t use_encrypt);

/**
 * Free session
 */
void cedar_session_free(CedarSessionHandle handle);

/**
 * Get session status
 */
enum CedarSessionStatus cedar_session_get_status(CedarSessionHandle handle);

/**
 * Get session statistics
 */
enum CedarErrorCode cedar_session_get_stats(CedarSessionHandle handle, struct CedarSessionStats *stats);

/**
 * Create new packet
 */
CedarPacketHandle cedar_packet_new(const char *command);

/**
 * Free packet
 */
void cedar_packet_free(CedarPacketHandle handle);

/**
 * Add integer parameter to packet
 */
enum CedarErrorCode cedar_packet_add_int(CedarPacketHandle handle, const char *key, uint32_t value);

/**
 * Add string parameter to packet
 */
enum CedarErrorCode cedar_packet_add_string(CedarPacketHandle handle, const char *key, const char *value);

/**
 * Get integer parameter from packet
 */
enum CedarErrorCode cedar_packet_get_int(CedarPacketHandle handle, const char *key, uint32_t *value);

/**
 * Get string parameter from packet (copies to buffer)
 */
enum CedarErrorCode cedar_packet_get_string(CedarPacketHandle handle, const char *key, char *buffer, uintptr_t buffer_len);

/**
 * Create new TLS connection
 */
CedarTlsHandle cedar_tls_new(void);

/**
 * Free TLS connection
 */
void cedar_tls_free(CedarTlsHandle handle);

/**
 * Get TLS state
 */
enum CedarTlsState cedar_tls_get_state(CedarTlsHandle handle);

/**
 * Encrypt data
 */
enum CedarErrorCode cedar_tls_encrypt(CedarTlsHandle handle, const uint8_t *plaintext, uintptr_t plaintext_len, uint8_t *ciphertext, uintptr_t ciphertext_len, uintptr_t *bytes_written);

/**
 * Create new compressor
 */
CedarCompressorHandle cedar_compressor_new(enum CedarCompressionAlgorithm algorithm);

/**
 * Free compressor
 */
void cedar_compressor_free(CedarCompressorHandle handle);

/**
 * Compress data
 */
enum CedarErrorCode cedar_compressor_compress(CedarCompressorHandle handle, const uint8_t *input, uintptr_t input_len, uint8_t *output, uintptr_t output_len, uintptr_t *bytes_written);

/**
 * Decompress data
 */
enum CedarErrorCode cedar_compressor_decompress(CedarCompressorHandle handle, const uint8_t *input, uintptr_t input_len, uint8_t *output, uintptr_t output_len, uintptr_t *bytes_written);

/**
 * Create new UDP accelerator
 */
CedarUdpAccelHandle cedar_udp_accel_new(enum CedarUdpAccelMode mode);

/**
 * Free UDP accelerator
 */
void cedar_udp_accel_free(CedarUdpAccelHandle handle);

/**
 * Check if UDP acceleration is healthy
 */
int cedar_udp_accel_is_healthy(CedarUdpAccelHandle handle);

/**
 * Create new NAT traversal engine
 */
CedarNatTraversalHandle cedar_nat_traversal_new(void);

/**
 * Free NAT traversal engine
 */
void cedar_nat_traversal_free(CedarNatTraversalHandle handle);

/**
 * Detect NAT type
 */
enum CedarNatType cedar_nat_traversal_detect(CedarNatTraversalHandle handle);

/**
 * Check if NAT traversal is supported
 */
int cedar_nat_traversal_is_supported(CedarNatTraversalHandle handle);

/**
 * Get Cedar version string
 */
const char *cedar_version(void);

/**
 * Get Cedar protocol version
 */
uint32_t cedar_protocol_version(void);

/**
 * Connect TLS connection to server
 * Returns Success on successful connection, error code otherwise
 */
enum CedarErrorCode cedar_tls_connect(CedarTlsHandle handle, const char *host, uint16_t port);

/**
 * Send data over TLS connection
 * Returns number of bytes sent, or -1 on error
 */
int cedar_tls_send(CedarTlsHandle handle, const uint8_t *data, uintptr_t len);

/**
 * Receive data from TLS connection
 * Returns number of bytes received, 0 on EOF, or -1 on error
 */
int cedar_tls_receive(CedarTlsHandle handle, uint8_t *buffer, uintptr_t buffer_size);

/**
 * Connect session to server (TLS + initial handshake)
 * This performs the full connection sequence:
 * 1. TLS connection
 * 2. Protocol hello exchange
 */
enum CedarErrorCode cedar_session_connect(CedarSessionHandle handle);

/**
 * Send packet over session
 */
enum CedarErrorCode cedar_session_send_packet(CedarSessionHandle handle, CedarPacketHandle packet);

/**
 * Receive packet from session
 * On success, writes packet handle to out_packet
 * Caller must free the returned packet with cedar_packet_free()
 */
enum CedarErrorCode cedar_session_receive_packet(CedarSessionHandle handle, CedarPacketHandle *out_packet);

/**
 * Send data packet to VPN server (for TUN device integration)
 * data should point to raw packet bytes (e.g., IP packet from TUN device)
 */
enum CedarErrorCode cedar_session_send_data_packet(CedarSessionHandle handle, const uint8_t *data, uintptr_t data_len);

/**
 * Try to receive data packet from VPN server (non-blocking)
 * Returns Success and writes packet data if available
 * Returns TimeOut if no packet available
 * buffer should be at least 65536 bytes for typical packets
 */
enum CedarErrorCode cedar_session_try_receive_data_packet(CedarSessionHandle handle, uint8_t *buffer, uintptr_t buffer_size, uintptr_t *out_size);

/**
 * Poll session for keep-alive (call periodically from forwarding loop)
 * interval_secs: Seconds between keep-alive packets (e.g., 30)
 */
enum CedarErrorCode cedar_session_poll_keepalive(CedarSessionHandle handle, uint64_t interval_secs);

/**
 * Authenticate with the server
 * password_hash should be SHA-1 hash of password (20 bytes)
 */
enum CedarErrorCode cedar_session_authenticate(CedarSessionHandle handle, const char *username, const uint8_t *password_hash, uintptr_t hash_len);

/**
 * Poll received packets from background receive thread
 * Returns number of packets retrieved (0 if none available)
 * Each packet is written to buffers[i] with length in lengths[i]
 * max_packets specifies array size
 */
uintptr_t cedar_session_poll_packets(CedarSessionHandle handle, uint8_t **buffers, uintptr_t *lengths, uintptr_t max_packets);

/**
 * Free packet buffer allocated by cedar_session_poll_packets
 */
void cedar_free_packet_buffer(uint8_t *buffer, uintptr_t length);

/**
 * Queue an outbound packet to send to server (upstream: client → server)
 * This is called by Zig when it reads a packet from TUN that needs to be sent to VPN server
 */
enum CedarErrorCode cedar_session_queue_outbound_packet(CedarSessionHandle handle, const uint8_t *data, uintptr_t length);

/**
 * Stop background receive thread (called during disconnect)
 */
void cedar_session_stop_background_thread(CedarSessionHandle handle);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
