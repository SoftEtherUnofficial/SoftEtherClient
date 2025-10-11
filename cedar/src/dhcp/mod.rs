// DHCP Client Module for Cedar FFI
// Provides Layer 2/3 translation and DHCP client functionality

// Module declarations
mod client;
mod packets;
mod parser;

// Re-exports
pub use client::{DhcpClient, DhcpState};
pub use packets::{
    build_dhcp_discover, build_dhcp_request, build_gratuitous_arp,
    build_arp_request, build_arp_reply,
};
pub use parser::{parse_dhcp_packet, parse_arp_packet, DhcpMessage, ArpMessage};

// DHCP Message Types (RFC 2131)
pub const DHCP_DISCOVER: u8 = 1;
pub const DHCP_OFFER: u8 = 2;
pub const DHCP_REQUEST: u8 = 3;
pub const DHCP_DECLINE: u8 = 4;
pub const DHCP_ACK: u8 = 5;
pub const DHCP_NAK: u8 = 6;
pub const DHCP_RELEASE: u8 = 7;
pub const DHCP_INFORM: u8 = 8;

// DHCP Options (RFC 2132)
pub const DHCP_OPT_PAD: u8 = 0;
pub const DHCP_OPT_SUBNET_MASK: u8 = 1;
pub const DHCP_OPT_ROUTER: u8 = 3;
pub const DHCP_OPT_DNS: u8 = 6;
pub const DHCP_OPT_REQUESTED_IP: u8 = 50;
pub const DHCP_OPT_LEASE_TIME: u8 = 51;
pub const DHCP_OPT_MSG_TYPE: u8 = 53;
pub const DHCP_OPT_SERVER_ID: u8 = 54;
pub const DHCP_OPT_PARAM_REQUEST: u8 = 55;
pub const DHCP_OPT_RENEWAL_TIME: u8 = 58;
pub const DHCP_OPT_REBINDING_TIME: u8 = 59;
pub const DHCP_OPT_CLIENT_ID: u8 = 61;
pub const DHCP_OPT_END: u8 = 255;

// Protocol Numbers
pub const ETH_TYPE_IPV4: u16 = 0x0800;
pub const ETH_TYPE_ARP: u16 = 0x0806;
pub const IP_PROTO_UDP: u8 = 17;

// Port Numbers
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;

// ARP Operations
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

// DHCP Magic Cookie
pub const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

// Timing constants
pub const DHCP_INITIAL_DELAY_MS: u64 = 2000;      // Wait 2s before first GARP
pub const DHCP_RETRY_INTERVAL_MS: u64 = 3000;     // Retry DISCOVER every 3s
pub const DHCP_REQUEST_DELAY_MS: u64 = 500;       // Wait 500ms before REQUEST
pub const DHCP_MAX_RETRIES: u32 = 5;              // Max 5 retries
pub const KEEPALIVE_INTERVAL_MS: u64 = 10000;     // Send keep-alive GARP every 10s
