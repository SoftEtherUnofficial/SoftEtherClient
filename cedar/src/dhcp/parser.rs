// DHCP Packet Parser
// Parses DHCP OFFER, ACK and ARP packets from server

use mayaqua::error::{Error, Result};

/// Parsed DHCP message (OFFER or ACK)
#[derive(Debug, Clone)]
pub struct DhcpMessage {
    pub msg_type: u8,        // 2 = OFFER, 5 = ACK
    pub xid: u32,            // Transaction ID
    pub your_ip: u32,        // Offered/assigned IP address
    pub server_ip: u32,      // DHCP server IP
    pub gateway: u32,        // Default gateway (router)
    pub netmask: u32,        // Subnet mask
    pub dns1: u32,           // Primary DNS server
    pub dns2: u32,           // Secondary DNS server
    pub lease_time: u32,     // Lease time in seconds
}

/// Parsed ARP message (Request or Reply)
#[derive(Debug, Clone)]
pub struct ArpMessage {
    pub operation: u16,      // 1 = Request, 2 = Reply
    pub sender_mac: [u8; 6], // Sender hardware address
    pub sender_ip: u32,      // Sender protocol address
    pub target_mac: [u8; 6], // Target hardware address
    pub target_ip: u32,      // Target protocol address
}

/// Parse a DHCP packet (OFFER or ACK)
/// Expects Ethernet + IP + UDP + DHCP format
pub fn parse_dhcp_packet(data: &[u8]) -> Result<DhcpMessage> {
    // Minimum size: Ethernet(14) + IP(20) + UDP(8) + BOOTP(236) + Magic(4) = 282
    if data.len() < 282 {
        return Err(Error::InvalidResponse);
    }
    
    // Skip Ethernet(14) + IP(20) + UDP(8) = 42 bytes to get to BOOTP header
    let bootp_start = 42;
    
    // Extract XID at offset 4 in BOOTP
    let xid = u32::from_be_bytes([
        data[bootp_start + 4],
        data[bootp_start + 5],
        data[bootp_start + 6],
        data[bootp_start + 7],
    ]);
    
    // Extract yiaddr (your IP address) at offset 16 in BOOTP
    let your_ip = u32::from_be_bytes([
        data[bootp_start + 16],
        data[bootp_start + 17],
        data[bootp_start + 18],
        data[bootp_start + 19],
    ]);
    
    // Verify DHCP magic cookie at offset 236 in BOOTP (= byte 278 in packet)
    let magic_offset = bootp_start + 236;
    let magic = u32::from_be_bytes([
        data[magic_offset],
        data[magic_offset + 1],
        data[magic_offset + 2],
        data[magic_offset + 3],
    ]);
    
    if magic != super::DHCP_MAGIC_COOKIE {
        eprintln!("[DHCP Parser] ⚠️  Invalid DHCP magic cookie: 0x{:08x} (expected 0x{:08x})",
                  magic, super::DHCP_MAGIC_COOKIE);
        return Err(Error::InvalidResponse);
    }
    
    // Parse DHCP options (start at offset 240 in BOOTP, byte 282 in packet)
    let options_start = magic_offset + 4;
    let options = &data[options_start..];
    
    let mut msg = DhcpMessage {
        msg_type: 0,
        xid,
        your_ip,
        server_ip: 0,
        gateway: 0,
        netmask: 0,
        dns1: 0,
        dns2: 0,
        lease_time: 0,
    };
    
    let mut i = 0;
    while i < options.len() {
        let option_type = options[i];
        i += 1;
        
        if option_type == super::DHCP_OPT_END {
            break;
        }
        
        if option_type == super::DHCP_OPT_PAD {
            continue;
        }
        
        if i >= options.len() {
            break;
        }
        
        let option_len = options[i] as usize;
        i += 1;
        
        if i + option_len > options.len() {
            break;
        }
        
        match option_type {
            // Option 53: DHCP Message Type
            super::DHCP_OPT_MSG_TYPE => {
                if option_len >= 1 {
                    msg.msg_type = options[i];
                }
            }
            // Option 1: Subnet Mask
            super::DHCP_OPT_SUBNET_MASK => {
                if option_len >= 4 {
                    msg.netmask = u32::from_be_bytes([
                        options[i],
                        options[i + 1],
                        options[i + 2],
                        options[i + 3],
                    ]);
                }
            }
            // Option 3: Router (Gateway)
            super::DHCP_OPT_ROUTER => {
                if option_len >= 4 {
                    msg.gateway = u32::from_be_bytes([
                        options[i],
                        options[i + 1],
                        options[i + 2],
                        options[i + 3],
                    ]);
                }
            }
            // Option 6: DNS Servers
            super::DHCP_OPT_DNS => {
                if option_len >= 4 {
                    msg.dns1 = u32::from_be_bytes([
                        options[i],
                        options[i + 1],
                        options[i + 2],
                        options[i + 3],
                    ]);
                }
                if option_len >= 8 {
                    msg.dns2 = u32::from_be_bytes([
                        options[i + 4],
                        options[i + 5],
                        options[i + 6],
                        options[i + 7],
                    ]);
                }
            }
            // Option 51: IP Address Lease Time
            super::DHCP_OPT_LEASE_TIME => {
                if option_len >= 4 {
                    msg.lease_time = u32::from_be_bytes([
                        options[i],
                        options[i + 1],
                        options[i + 2],
                        options[i + 3],
                    ]);
                }
            }
            // Option 54: DHCP Server Identifier
            super::DHCP_OPT_SERVER_ID => {
                if option_len >= 4 {
                    msg.server_ip = u32::from_be_bytes([
                        options[i],
                        options[i + 1],
                        options[i + 2],
                        options[i + 3],
                    ]);
                }
            }
            _ => {
                // Unknown option, skip
            }
        }
        
        i += option_len;
    }
    
    Ok(msg)
}

/// Parse an ARP packet (Request or Reply)
/// Expects Ethernet + ARP format
pub fn parse_arp_packet(data: &[u8]) -> Result<ArpMessage> {
    // Minimum size: Ethernet(14) + ARP(28) = 42
    if data.len() < 42 {
        return Err(Error::InvalidResponse);
    }
    
    // Skip Ethernet header (14 bytes) to get to ARP
    let arp_start = 14;
    
    // Check hardware type (should be 1 = Ethernet)
    let hw_type = u16::from_be_bytes([data[arp_start], data[arp_start + 1]]);
    if hw_type != 1 {
        return Err(Error::InvalidResponse);
    }
    
    // Check protocol type (should be 0x0800 = IPv4)
    let proto_type = u16::from_be_bytes([data[arp_start + 2], data[arp_start + 3]]);
    if proto_type != 0x0800 {
        return Err(Error::InvalidResponse);
    }
    
    // Extract operation (1 = Request, 2 = Reply)
    let operation = u16::from_be_bytes([data[arp_start + 6], data[arp_start + 7]]);
    
    // Extract sender MAC (6 bytes at offset 8)
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&data[arp_start + 8..arp_start + 14]);
    
    // Extract sender IP (4 bytes at offset 14)
    let sender_ip = u32::from_be_bytes([
        data[arp_start + 14],
        data[arp_start + 15],
        data[arp_start + 16],
        data[arp_start + 17],
    ]);
    
    // Extract target MAC (6 bytes at offset 18)
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&data[arp_start + 18..arp_start + 24]);
    
    // Extract target IP (4 bytes at offset 24)
    let target_ip = u32::from_be_bytes([
        data[arp_start + 24],
        data[arp_start + 25],
        data[arp_start + 26],
        data[arp_start + 27],
    ]);
    
    Ok(ArpMessage {
        operation,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    })
}

/// Helper to format IP address as string
pub fn format_ip(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

/// Helper to format MAC address as string
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ip() {
        let ip = 0x0A15FDB6; // 10.21.253.182
        assert_eq!(format_ip(ip), "10.21.253.182");
    }

    #[test]
    fn test_format_mac() {
        let mac = [0x02, 0x00, 0x5E, 0xAA, 0xBB, 0xCC];
        assert_eq!(format_mac(&mac), "02:00:5e:aa:bb:cc");
    }
}
