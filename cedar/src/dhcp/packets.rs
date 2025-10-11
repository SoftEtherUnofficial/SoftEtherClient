// DHCP Packet Structures and Builders
// Implements RFC 2131 (DHCP), RFC 826 (ARP), RFC 791 (IP), RFC 768 (UDP)

use std::net::Ipv4Addr;

// Ethernet Frame Header (14 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,  // Network byte order (big-endian)
}

// IPv4 Header (20 bytes, no options)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version_ihl: u8,        // Version (4 bits) + IHL (4 bits)
    pub tos: u8,                 // Type of Service
    pub total_length: u16,       // Total length (header + data)
    pub identification: u16,     // Identification
    pub flags_fragment: u16,     // Flags (3 bits) + Fragment offset (13 bits)
    pub ttl: u8,                 // Time to Live
    pub protocol: u8,            // Protocol (17 = UDP)
    pub checksum: u16,           // Header checksum
    pub src_ip: u32,             // Source IP (network byte order)
    pub dst_ip: u32,             // Destination IP (network byte order)
}

// UDP Header (8 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,           // Source port
    pub dst_port: u16,           // Destination port
    pub length: u16,             // Length (header + data)
    pub checksum: u16,           // Checksum
}

// BOOTP/DHCP Header (236 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DhcpHeader {
    pub op: u8,                  // Message op code (1 = BOOTREQUEST, 2 = BOOTREPLY)
    pub htype: u8,               // Hardware address type (1 = Ethernet)
    pub hlen: u8,                // Hardware address length (6 for Ethernet)
    pub hops: u8,                // Hops (0 for client)
    pub xid: u32,                // Transaction ID (random)
    pub secs: u16,               // Seconds elapsed since client started
    pub flags: u16,              // Flags (0x8000 = broadcast)
    pub ciaddr: u32,             // Client IP address
    pub yiaddr: u32,             // Your (client) IP address
    pub siaddr: u32,             // Next server IP address
    pub giaddr: u32,             // Relay agent IP address
    pub chaddr: [u8; 16],        // Client hardware address (MAC + padding)
    pub sname: [u8; 64],         // Server host name
    pub file: [u8; 128],         // Boot file name
    pub magic: u32,              // Magic cookie (0x63825363)
}

// ARP Header (28 bytes for Ethernet/IPv4)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ArpHeader {
    pub hw_type: u16,            // Hardware type (1 = Ethernet)
    pub proto_type: u16,         // Protocol type (0x0800 = IPv4)
    pub hw_len: u8,              // Hardware address length (6)
    pub proto_len: u8,           // Protocol address length (4)
    pub operation: u16,          // Operation (1 = request, 2 = reply)
    pub sender_mac: [u8; 6],     // Sender hardware address
    pub sender_ip: u32,          // Sender protocol address
    pub target_mac: [u8; 6],     // Target hardware address
    pub target_ip: u32,          // Target protocol address
}

impl EthernetHeader {
    pub fn new(dst_mac: [u8; 6], src_mac: [u8; 6], ether_type: u16) -> Self {
        Self {
            dst_mac,
            src_mac,
            ether_type: ether_type.to_be(),
        }
    }
}

impl Ipv4Header {
    pub fn new(src_ip: u32, dst_ip: u32, protocol: u8, payload_len: u16) -> Self {
        let total_len = 20 + payload_len; // IP header + payload
        let mut header = Self {
            version_ihl: 0x45,  // Version 4, IHL 5 (20 bytes)
            tos: 0,
            total_length: total_len.to_be(),
            identification: 0,
            flags_fragment: 0,
            ttl: 64,
            protocol,
            checksum: 0,
            src_ip: src_ip.to_be(),
            dst_ip: dst_ip.to_be(),
        };
        header.checksum = header.calculate_checksum();
        header
    }

    fn calculate_checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        let bytes = unsafe {
            std::slice::from_raw_parts(self as *const Self as *const u8, 20)
        };
        
        for i in (0..20).step_by(2) {
            if i == 10 {
                // Skip checksum field itself
                continue;
            }
            let word = ((bytes[i] as u32) << 8) | (bytes[i + 1] as u32);
            sum += word;
        }
        
        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        (!sum as u16).to_be()
    }
}

impl UdpHeader {
    pub fn new(src_port: u16, dst_port: u16, payload_len: u16) -> Self {
        let total_len = 8 + payload_len; // UDP header + payload
        Self {
            src_port: src_port.to_be(),
            dst_port: dst_port.to_be(),
            length: total_len.to_be(),
            checksum: 0, // Optional for IPv4
        }
    }
}

impl DhcpHeader {
    pub fn new_request(xid: u32, client_mac: [u8; 6]) -> Self {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&client_mac);
        
        Self {
            op: 1,          // BOOTREQUEST
            htype: 1,       // Ethernet
            hlen: 6,        // MAC address length
            hops: 0,
            xid: xid.to_be(),
            secs: 0,
            flags: 0x8000u16.to_be(), // Broadcast flag
            ciaddr: 0,
            yiaddr: 0,
            siaddr: 0,
            giaddr: 0,
            chaddr,
            sname: [0; 64],
            file: [0; 128],
            magic: super::DHCP_MAGIC_COOKIE.to_be(),
        }
    }
}

impl ArpHeader {
    pub fn new_request(sender_mac: [u8; 6], sender_ip: u32, target_ip: u32) -> Self {
        Self {
            hw_type: 1u16.to_be(),           // Ethernet
            proto_type: 0x0800u16.to_be(),   // IPv4
            hw_len: 6,
            proto_len: 4,
            operation: super::ARP_REQUEST.to_be(),
            sender_mac,
            sender_ip: sender_ip.to_be(),
            target_mac: [0; 6],  // Unknown (what we're asking for)
            target_ip: target_ip.to_be(),
        }
    }

    pub fn new_reply(sender_mac: [u8; 6], sender_ip: u32, target_mac: [u8; 6], target_ip: u32) -> Self {
        Self {
            hw_type: 1u16.to_be(),
            proto_type: 0x0800u16.to_be(),
            hw_len: 6,
            proto_len: 4,
            operation: super::ARP_REPLY.to_be(),
            sender_mac,
            sender_ip: sender_ip.to_be(),
            target_mac,
            target_ip: target_ip.to_be(),
        }
    }
}

// Helper to convert bytes to struct (unsafe, but necessary for network packets)
pub unsafe fn bytes_to_struct<T: Copy>(bytes: &[u8]) -> Option<T> {
    if bytes.len() < std::mem::size_of::<T>() {
        return None;
    }
    Some(std::ptr::read_unaligned(bytes.as_ptr() as *const T))
}

// Helper to convert struct to bytes
pub fn struct_to_bytes<T: Copy>(s: &T) -> Vec<u8> {
    let bytes = unsafe {
        std::slice::from_raw_parts(s as *const T as *const u8, std::mem::size_of::<T>())
    };
    bytes.to_vec()
}

/// Build a DHCP DISCOVER packet
/// Returns Ethernet frame containing: Ethernet + IP + UDP + DHCP DISCOVER
pub fn build_dhcp_discover(client_mac: &[u8; 6], xid: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(342);
    
    // Ethernet header (broadcast)
    let eth = EthernetHeader::new(
        [0xFF; 6],      // Broadcast MAC
        *client_mac,
        super::ETH_TYPE_IPV4,
    );
    packet.extend_from_slice(&struct_to_bytes(&eth));
    
    // DHCP options (will be appended after BOOTP header)
    let mut options = Vec::new();
    
    // Option 53: DHCP Message Type = DISCOVER
    options.push(super::DHCP_OPT_MSG_TYPE);
    options.push(1);
    options.push(super::DHCP_DISCOVER);
    
    // Option 61: Client Identifier (hardware type + MAC)
    options.push(super::DHCP_OPT_CLIENT_ID);
    options.push(7);  // Length: 1 (type) + 6 (MAC)
    options.push(1);  // Hardware type: Ethernet
    options.extend_from_slice(client_mac);
    
    // Option 55: Parameter Request List
    options.push(super::DHCP_OPT_PARAM_REQUEST);
    options.push(4);  // Request 4 parameters
    options.push(super::DHCP_OPT_SUBNET_MASK);
    options.push(super::DHCP_OPT_ROUTER);
    options.push(super::DHCP_OPT_DNS);
    options.push(super::DHCP_OPT_LEASE_TIME);
    
    // Option 255: End
    options.push(super::DHCP_OPT_END);
    
    // Pad to align
    while options.len() % 4 != 0 {
        options.push(super::DHCP_OPT_PAD);
    }
    
    let dhcp_payload_len = 236 + 4 + options.len() as u16; // BOOTP + magic + options
    
    // IP header (broadcast)
    let ip = Ipv4Header::new(
        0x00000000,     // 0.0.0.0 (we don't have IP yet)
        0xFFFFFFFF,     // 255.255.255.255 (broadcast)
        super::IP_PROTO_UDP,
        8 + dhcp_payload_len, // UDP header + DHCP
    );
    packet.extend_from_slice(&struct_to_bytes(&ip));
    
    // UDP header
    let udp = UdpHeader::new(
        super::DHCP_CLIENT_PORT,
        super::DHCP_SERVER_PORT,
        dhcp_payload_len,
    );
    packet.extend_from_slice(&struct_to_bytes(&udp));
    
    // DHCP header
    let dhcp = DhcpHeader::new_request(xid, *client_mac);
    packet.extend_from_slice(&struct_to_bytes(&dhcp));
    
    // DHCP options
    packet.extend_from_slice(&options);
    
    packet
}

/// Build a DHCP REQUEST packet
/// Returns Ethernet frame containing: Ethernet + IP + UDP + DHCP REQUEST
pub fn build_dhcp_request(
    client_mac: &[u8; 6],
    xid: u32,
    requested_ip: u32,
    server_ip: u32,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(342);
    
    // Ethernet header (broadcast)
    let eth = EthernetHeader::new(
        [0xFF; 6],
        *client_mac,
        super::ETH_TYPE_IPV4,
    );
    packet.extend_from_slice(&struct_to_bytes(&eth));
    
    // DHCP options
    let mut options = Vec::new();
    
    // Option 53: DHCP Message Type = REQUEST
    options.push(super::DHCP_OPT_MSG_TYPE);
    options.push(1);
    options.push(super::DHCP_REQUEST);
    
    // Option 50: Requested IP Address
    options.push(super::DHCP_OPT_REQUESTED_IP);
    options.push(4);
    options.extend_from_slice(&requested_ip.to_be_bytes());
    
    // Option 54: DHCP Server Identifier
    options.push(super::DHCP_OPT_SERVER_ID);
    options.push(4);
    options.extend_from_slice(&server_ip.to_be_bytes());
    
    // Option 61: Client Identifier
    options.push(super::DHCP_OPT_CLIENT_ID);
    options.push(7);
    options.push(1);  // Ethernet
    options.extend_from_slice(client_mac);
    
    // Option 55: Parameter Request List
    options.push(super::DHCP_OPT_PARAM_REQUEST);
    options.push(4);
    options.push(super::DHCP_OPT_SUBNET_MASK);
    options.push(super::DHCP_OPT_ROUTER);
    options.push(super::DHCP_OPT_DNS);
    options.push(super::DHCP_OPT_LEASE_TIME);
    
    // Option 255: End
    options.push(super::DHCP_OPT_END);
    
    while options.len() % 4 != 0 {
        options.push(super::DHCP_OPT_PAD);
    }
    
    let dhcp_payload_len = 236 + 4 + options.len() as u16;
    
    // IP header (broadcast)
    let ip = Ipv4Header::new(
        0x00000000,
        0xFFFFFFFF,
        super::IP_PROTO_UDP,
        8 + dhcp_payload_len,
    );
    packet.extend_from_slice(&struct_to_bytes(&ip));
    
    // UDP header
    let udp = UdpHeader::new(
        super::DHCP_CLIENT_PORT,
        super::DHCP_SERVER_PORT,
        dhcp_payload_len,
    );
    packet.extend_from_slice(&struct_to_bytes(&udp));
    
    // DHCP header
    let dhcp = DhcpHeader::new_request(xid, *client_mac);
    packet.extend_from_slice(&struct_to_bytes(&dhcp));
    
    // Options
    packet.extend_from_slice(&options);
    
    packet
}

/// Build a Gratuitous ARP packet (announces our IP to the network)
/// Returns Ethernet frame containing: Ethernet + ARP
pub fn build_gratuitous_arp(client_mac: &[u8; 6], client_ip: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);
    
    // Ethernet header (broadcast)
    let eth = EthernetHeader::new(
        [0xFF; 6],
        *client_mac,
        super::ETH_TYPE_ARP,
    );
    packet.extend_from_slice(&struct_to_bytes(&eth));
    
    // ARP header (gratuitous - sender and target are same)
    let arp = ArpHeader::new_reply(
        *client_mac,
        client_ip,
        [0xFF; 6],  // Broadcast
        client_ip,  // Target is ourselves (gratuitous)
    );
    packet.extend_from_slice(&struct_to_bytes(&arp));
    
    packet
}

/// Build an ARP Request packet (asks for MAC address of target IP)
/// Returns Ethernet frame containing: Ethernet + ARP Request
pub fn build_arp_request(
    client_mac: &[u8; 6],
    client_ip: u32,
    target_ip: u32,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);
    
    // Ethernet header (broadcast)
    let eth = EthernetHeader::new(
        [0xFF; 6],
        *client_mac,
        super::ETH_TYPE_ARP,
    );
    packet.extend_from_slice(&struct_to_bytes(&eth));
    
    // ARP Request
    let arp = ArpHeader::new_request(*client_mac, client_ip, target_ip);
    packet.extend_from_slice(&struct_to_bytes(&arp));
    
    packet
}

/// Build an ARP Reply packet (responds with our MAC address)
/// Returns Ethernet frame containing: Ethernet + ARP Reply
pub fn build_arp_reply(
    client_mac: &[u8; 6],
    client_ip: u32,
    target_mac: &[u8; 6],
    target_ip: u32,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(42);
    
    // Ethernet header (unicast to requester)
    let eth = EthernetHeader::new(
        *target_mac,
        *client_mac,
        super::ETH_TYPE_ARP,
    );
    packet.extend_from_slice(&struct_to_bytes(&eth));
    
    // ARP Reply
    let arp = ArpHeader::new_reply(*client_mac, client_ip, *target_mac, target_ip);
    packet.extend_from_slice(&struct_to_bytes(&arp));
    
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_discover_size() {
        let mac = [0x02, 0x00, 0x5E, 0xAA, 0xBB, 0xCC];
        let xid = 0x12345678;
        let packet = build_dhcp_discover(&mac, xid);
        
        // Ethernet(14) + IP(20) + UDP(8) + DHCP(236) + Magic(4) + Options(~60) = 342
        assert!(packet.len() >= 300 && packet.len() <= 400);
    }

    #[test]
    fn test_gratuitous_arp_size() {
        let mac = [0x02, 0x00, 0x5E, 0xAA, 0xBB, 0xCC];
        let ip = 0x0A15FDB6; // 10.21.253.182
        let packet = build_gratuitous_arp(&mac, ip);
        
        // Ethernet(14) + ARP(28) = 42
        assert_eq!(packet.len(), 42);
    }

    #[test]
    fn test_arp_request_size() {
        let mac = [0x02, 0x00, 0x5E, 0xAA, 0xBB, 0xCC];
        let my_ip = 0x0A15FDB6;
        let gateway_ip = 0x0A150001;
        let packet = build_arp_request(&mac, my_ip, gateway_ip);
        
        assert_eq!(packet.len(), 42);
    }
}
