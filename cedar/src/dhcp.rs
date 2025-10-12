//! DHCP Client Implementation
//! 
//! Implements RFC 2131 DHCP client state machine for automatic IP configuration.
//! States: Init → Selecting → Requesting → Bound

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use mayaqua::error::{Error, Result};

/// DHCP Client State
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DhcpState {
    /// Initial state - need to send DISCOVER
    Init,
    /// Waiting for OFFER from server
    Selecting,
    /// Sending REQUEST for offered IP
    Requesting,
    /// IP configured and bound
    Bound,
}

/// DHCP Client
pub struct DhcpClient {
    /// Current state
    state: DhcpState,
    
    /// Transaction ID (random)
    xid: u32,
    
    /// Client MAC address
    mac: [u8; 6],
    
    /// Offered IP address from server
    offered_ip: Option<Ipv4Addr>,
    
    /// DHCP server IP
    server_ip: Option<Ipv4Addr>,
    
    /// Assigned IP address (after ACK)
    pub assigned_ip: Option<Ipv4Addr>,
    
    /// Gateway IP
    pub gateway: Option<Ipv4Addr>,
    
    /// Subnet mask
    pub netmask: Option<Ipv4Addr>,
    
    /// DNS servers
    pub dns_servers: Vec<Ipv4Addr>,
    
    /// Lease time (seconds)
    pub lease_time: Option<u32>,
    
    /// Last packet sent time
    last_send: Instant,
    
    /// Retry interval
    retry_interval: Duration,
    
    /// Number of retries
    retry_count: u32,
}

impl DhcpClient {
    /// Create new DHCP client
    pub fn new(mac: [u8; 6]) -> Self {
        use rand::Rng;
        let xid = rand::thread_rng().gen::<u32>();
        
        Self {
            state: DhcpState::Init,
            xid,
            mac,
            offered_ip: None,
            server_ip: None,
            assigned_ip: None,
            gateway: None,
            netmask: None,
            dns_servers: Vec::new(),
            lease_time: None,
            last_send: Instant::now(),
            retry_interval: Duration::from_secs(5),
            retry_count: 0,
        }
    }
    
    /// Check if IP is configured
    pub fn is_configured(&self) -> bool {
        self.state == DhcpState::Bound && self.assigned_ip.is_some()
    }
    
    /// Get current state
    pub fn state(&self) -> DhcpState {
        self.state
    }
    
    /// Tick - generate next packet if needed
    /// Returns Some(packet) if a packet should be sent
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_send);
        
        match self.state {
            DhcpState::Init => {
                // Send DISCOVER immediately
                self.last_send = now;
                self.retry_count = 0;
                self.state = DhcpState::Selecting;
                Some(self.build_discover())
            }
            DhcpState::Selecting => {
                // Retry DISCOVER if no OFFER received
                if elapsed >= self.retry_interval && self.retry_count < 3 {
                    self.last_send = now;
                    self.retry_count += 1;
                    eprintln!("[DHCP] Retrying DISCOVER (attempt {})", self.retry_count + 1);
                    Some(self.build_discover())
                } else {
                    None
                }
            }
            DhcpState::Requesting => {
                // REQUEST should be sent immediately after OFFER
                // If we're still in this state, retry
                if elapsed >= Duration::from_secs(2) && self.retry_count < 3 {
                    self.last_send = now;
                    self.retry_count += 1;
                    eprintln!("[DHCP] Retrying REQUEST (attempt {})", self.retry_count + 1);
                    if let Some(ip) = self.offered_ip {
                        Some(self.build_request(ip))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            DhcpState::Bound => {
                // No packets needed when bound
                None
            }
        }
    }
    
    /// Process incoming DHCP packet
    pub fn put_packet(&mut self, packet: &[u8]) -> Result<()> {
        // Parse Ethernet + IP + UDP + DHCP
        if packet.len() < 282 {  // Min DHCP packet size
            return Ok(()); // Not a DHCP packet
        }
        
        // Check if it's a DHCP packet (UDP port 68)
        let eth_type = u16::from_be_bytes([packet[12], packet[13]]);
        if eth_type != 0x0800 {
            return Ok(()); // Not IPv4
        }
        
        let ip_proto = packet[23];
        if ip_proto != 17 {
            return Ok(()); // Not UDP
        }
        
        let udp_dst_port = u16::from_be_bytes([packet[36], packet[37]]);
        if udp_dst_port != 68 {
            return Ok(()); // Not DHCP client port
        }
        
        // Extract DHCP payload (skip Ethernet + IP + UDP headers)
        let dhcp_offset = 42; // 14 (Eth) + 20 (IP) + 8 (UDP)
        if packet.len() < dhcp_offset + 240 {
            return Ok(());
        }
        
        let dhcp = &packet[dhcp_offset..];
        
        // Verify DHCP magic cookie
        if dhcp.len() < 240 || &dhcp[236..240] != &[0x63, 0x82, 0x53, 0x63] {
            return Ok(());
        }
        
        // Check transaction ID
        let pkt_xid = u32::from_be_bytes([dhcp[4], dhcp[5], dhcp[6], dhcp[7]]);
        if pkt_xid != self.xid {
            return Ok(()); // Not our transaction
        }
        
        // Parse DHCP options to get message type
        let mut msg_type = None;
        let mut server_id = None;
        let mut yiaddr = Ipv4Addr::new(dhcp[16], dhcp[17], dhcp[18], dhcp[19]);
        
        let mut i = 240;
        while i < dhcp.len() {
            let option = dhcp[i];
            if option == 255 {
                break; // End option
            }
            if option == 0 {
                i += 1; // Pad option
                continue;
            }
            
            if i + 1 >= dhcp.len() {
                break;
            }
            let len = dhcp[i + 1] as usize;
            if i + 2 + len > dhcp.len() {
                break;
            }
            
            match option {
                53 => {
                    // DHCP Message Type
                    if len >= 1 {
                        msg_type = Some(dhcp[i + 2]);
                    }
                }
                54 => {
                    // Server Identifier
                    if len >= 4 {
                        server_id = Some(Ipv4Addr::new(
                            dhcp[i + 2], dhcp[i + 3], dhcp[i + 4], dhcp[i + 5]
                        ));
                    }
                }
                1 => {
                    // Subnet Mask
                    if len >= 4 {
                        self.netmask = Some(Ipv4Addr::new(
                            dhcp[i + 2], dhcp[i + 3], dhcp[i + 4], dhcp[i + 5]
                        ));
                    }
                }
                3 => {
                    // Router (Gateway)
                    if len >= 4 {
                        self.gateway = Some(Ipv4Addr::new(
                            dhcp[i + 2], dhcp[i + 3], dhcp[i + 4], dhcp[i + 5]
                        ));
                    }
                }
                6 => {
                    // DNS Servers
                    self.dns_servers.clear();
                    for j in (0..len).step_by(4) {
                        if j + 4 <= len {
                            self.dns_servers.push(Ipv4Addr::new(
                                dhcp[i + 2 + j], dhcp[i + 3 + j],
                                dhcp[i + 4 + j], dhcp[i + 5 + j]
                            ));
                        }
                    }
                }
                51 => {
                    // Lease Time
                    if len >= 4 {
                        self.lease_time = Some(u32::from_be_bytes([
                            dhcp[i + 2], dhcp[i + 3], dhcp[i + 4], dhcp[i + 5]
                        ]));
                    }
                }
                _ => {}
            }
            
            i += 2 + len;
        }
        
        // Handle message based on current state
        match (self.state, msg_type) {
            (DhcpState::Selecting, Some(2)) => {
                // DHCP OFFER received
                self.offered_ip = Some(yiaddr);
                self.server_ip = server_id;
                eprintln!("[DHCP] ✅ OFFER received: IP={}, Server={:?}", 
                    yiaddr, server_id);
                
                // Transition to Requesting state
                self.state = DhcpState::Requesting;
                self.retry_count = 0;
                
                // Immediately request the offered IP (don't wait for next tick)
                // Caller should check for pending packets
            }
            (DhcpState::Requesting, Some(5)) => {
                // DHCP ACK received
                self.assigned_ip = Some(yiaddr);
                self.state = DhcpState::Bound;
                eprintln!("[DHCP] ✅ ACK received! IP={}, Gateway={:?}, Lease={}s",
                    yiaddr, self.gateway, self.lease_time.unwrap_or(0));
            }
            (DhcpState::Requesting, Some(6)) => {
                // DHCP NAK received - restart
                eprintln!("[DHCP] ❌ NAK received, restarting...");
                self.state = DhcpState::Init;
                self.offered_ip = None;
                self.server_ip = None;
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Get next packet to send (if any)
    /// Call this after put_packet() to get immediate REQUEST
    pub fn get_pending_packet(&mut self) -> Option<Vec<u8>> {
        match self.state {
            DhcpState::Requesting if self.retry_count == 0 => {
                // Just transitioned to Requesting, send REQUEST immediately
                self.last_send = Instant::now();
                self.retry_count = 1;
                if let Some(ip) = self.offered_ip {
                    Some(self.build_request(ip))
                } else {
                    None
                }
            }
            _ => None
        }
    }
    
    /// Build DHCP DISCOVER packet
    fn build_discover(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(342);
        
        // Ethernet header (14 bytes)
        packet.extend_from_slice(&self.mac);           // Src MAC
        packet.extend_from_slice(&[0xff; 6]);          // Dst MAC (broadcast)
        packet.extend_from_slice(&[0x08, 0x00]);       // EtherType: IPv4
        
        // IPv4 header (20 bytes)
        packet.push(0x45);                              // Version + IHL
        packet.push(0x00);                              // DSCP + ECN
        let ip_len = 328u16;                            // Total length
        packet.extend_from_slice(&ip_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);       // Identification
        packet.extend_from_slice(&[0x00, 0x00]);       // Flags + Fragment
        packet.push(0x80);                              // TTL
        packet.push(0x11);                              // Protocol: UDP
        packet.extend_from_slice(&[0x00, 0x00]);       // Checksum (calculated later)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Src IP: 0.0.0.0
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Dst IP: broadcast
        
        // Calculate IP checksum
        let ip_checksum = Self::calculate_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xff) as u8;
        
        // UDP header (8 bytes)
        packet.extend_from_slice(&[0x00, 0x44]);       // Src port: 68
        packet.extend_from_slice(&[0x00, 0x43]);       // Dst port: 67
        let udp_len = 308u16;                           // UDP length
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);       // Checksum (optional for IPv4)
        
        // DHCP packet (300 bytes minimum)
        packet.push(0x01);                              // op: BOOTREQUEST
        packet.push(0x01);                              // htype: Ethernet
        packet.push(0x06);                              // hlen: 6
        packet.push(0x00);                              // hops: 0
        packet.extend_from_slice(&self.xid.to_be_bytes()); // xid
        packet.extend_from_slice(&[0x00, 0x00]);       // secs: 0
        packet.extend_from_slice(&[0x00, 0x00]);       // flags: 0
        packet.extend_from_slice(&[0x00; 4]);          // ciaddr: 0.0.0.0
        packet.extend_from_slice(&[0x00; 4]);          // yiaddr: 0.0.0.0
        packet.extend_from_slice(&[0x00; 4]);          // siaddr: 0.0.0.0
        packet.extend_from_slice(&[0x00; 4]);          // giaddr: 0.0.0.0
        packet.extend_from_slice(&self.mac);           // chaddr
        packet.extend_from_slice(&[0x00; 10]);         // chaddr padding
        packet.extend_from_slice(&[0x00; 64]);         // sname (server name)
        packet.extend_from_slice(&[0x00; 128]);        // file (boot filename)
        
        // DHCP options
        packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // Magic cookie
        
        // Option 53: DHCP Message Type (DISCOVER = 1)
        packet.extend_from_slice(&[53, 1, 1]);
        
        // Option 55: Parameter Request List
        packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]); // Subnet, Router, DNS, Domain
        
        // Option 255: End
        packet.push(255);
        
        // Pad to minimum size
        while packet.len() < 342 {
            packet.push(0);
        }
        
        packet
    }
    
    /// Build DHCP REQUEST packet
    fn build_request(&self, requested_ip: Ipv4Addr) -> Vec<u8> {
        let mut packet = Vec::with_capacity(342);
        
        // Ethernet header
        packet.extend_from_slice(&self.mac);
        packet.extend_from_slice(&[0xff; 6]);
        packet.extend_from_slice(&[0x08, 0x00]);
        
        // IPv4 header
        packet.push(0x45);
        packet.push(0x00);
        let ip_len = 328u16;
        packet.extend_from_slice(&ip_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.push(0x80);
        packet.push(0x11);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        
        let ip_checksum = Self::calculate_checksum(&packet[14..34]);
        packet[24] = (ip_checksum >> 8) as u8;
        packet[25] = (ip_checksum & 0xff) as u8;
        
        // UDP header
        packet.extend_from_slice(&[0x00, 0x44]);
        packet.extend_from_slice(&[0x00, 0x43]);
        let udp_len = 308u16;
        packet.extend_from_slice(&udp_len.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        
        // DHCP packet
        packet.push(0x01);
        packet.push(0x01);
        packet.push(0x06);
        packet.push(0x00);
        packet.extend_from_slice(&self.xid.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0x00; 4]);          // ciaddr
        packet.extend_from_slice(&[0x00; 4]);          // yiaddr
        packet.extend_from_slice(&[0x00; 4]);          // siaddr
        packet.extend_from_slice(&[0x00; 4]);          // giaddr
        packet.extend_from_slice(&self.mac);
        packet.extend_from_slice(&[0x00; 10]);
        packet.extend_from_slice(&[0x00; 64]);
        packet.extend_from_slice(&[0x00; 128]);
        
        // DHCP options
        packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        
        // Option 53: DHCP Message Type (REQUEST = 3)
        packet.extend_from_slice(&[53, 1, 3]);
        
        // Option 50: Requested IP Address
        packet.push(50);
        packet.push(4);
        packet.extend_from_slice(&requested_ip.octets());
        
        // Option 54: Server Identifier
        if let Some(server) = self.server_ip {
            packet.push(54);
            packet.push(4);
            packet.extend_from_slice(&server.octets());
        }
        
        // Option 55: Parameter Request List
        packet.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
        
        // Option 255: End
        packet.push(255);
        
        while packet.len() < 342 {
            packet.push(0);
        }
        
        packet
    }
    
    /// Calculate IP/UDP checksum
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        
        !sum as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dhcp_client_creation() {
        let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x00];
        let client = DhcpClient::new(mac);
        
        assert_eq!(client.state(), DhcpState::Init);
        assert!(!client.is_configured());
    }
    
    #[test]
    fn test_dhcp_discover_packet() {
        let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x00];
        let mut client = DhcpClient::new(mac);
        
        let packet = client.tick();
        assert!(packet.is_some());
        
        let pkt = packet.unwrap();
        assert_eq!(pkt.len(), 342);
        
        // Check Ethernet header
        assert_eq!(&pkt[0..6], &mac);
        assert_eq!(&pkt[6..12], &[0xff; 6]);
        
        // Check DHCP operation
        assert_eq!(pkt[42], 0x01); // BOOTREQUEST
    }
}
