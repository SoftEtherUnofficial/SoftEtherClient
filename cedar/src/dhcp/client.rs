// DHCP Client State Machine
// Implements RFC 2131 DHCP client behavior

use mayaqua::error::{Error, Result};
use std::time::{Duration, Instant};
use super::parser::{parse_dhcp_packet, parse_arp_packet, format_ip, format_mac, DhcpMessage, ArpMessage};
use super::packets::{
    build_dhcp_discover, build_dhcp_request, build_gratuitous_arp,
    build_arp_request, build_arp_reply,
};

/// DHCP Client State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    Init,                // Initial state
    ArpAnnounceSent,     // Sent gratuitous ARP (0.0.0.0)
    DiscoverSent,        // Sent DHCP DISCOVER
    OfferReceived,       // Received DHCP OFFER
    RequestSent,         // Sent DHCP REQUEST
    Configured,          // Received DHCP ACK, interface configured
}

/// DHCP Client
pub struct DhcpClient {
    // State
    state: DhcpState,
    
    // Identity
    my_mac: [u8; 6],
    xid: u32,
    
    // Offered/Assigned configuration
    our_ip: u32,
    offered_ip: u32,
    offered_gw: u32,
    offered_mask: u32,
    offered_dns1: u32,
    offered_dns2: u32,
    dhcp_server_ip: u32,
    
    // Gateway MAC learning
    gateway_mac: [u8; 6],
    need_gateway_arp: bool,
    
    // Timing
    connection_start: Instant,
    last_send: Instant,
    retry_count: u32,
    
    // Flags
    need_arp_reply: bool,
    arp_reply_to_mac: [u8; 6],
    arp_reply_to_ip: u32,
    need_gratuitous_arp_configured: bool,
    last_keepalive: Instant,
}

impl DhcpClient {
    /// Create a new DHCP client with generated MAC address
    pub fn new() -> Self {
        // Generate MAC address: 02:00:5E:XX:XX:XX (locally administered, SoftEther prefix)
        let mut my_mac = [0u8; 6];
        my_mac[0] = 0x02; // Locally administered
        my_mac[1] = 0x00;
        my_mac[2] = 0x5E; // SoftEther prefix
        
        // Random last 3 bytes
        use std::time::SystemTime;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        my_mac[3] = ((timestamp >> 16) & 0xFF) as u8;
        my_mac[4] = ((timestamp >> 8) & 0xFF) as u8;
        my_mac[5] = (timestamp & 0xFF) as u8;
        
        // Generate transaction ID from timestamp
        let xid = timestamp as u32;
        
        let now = Instant::now();
        
        Self {
            state: DhcpState::Init,
            my_mac,
            xid,
            our_ip: 0,
            offered_ip: 0,
            offered_gw: 0,
            offered_mask: 0,
            offered_dns1: 0,
            offered_dns2: 0,
            dhcp_server_ip: 0,
            gateway_mac: [0; 6],
            need_gateway_arp: false,
            connection_start: now,
            last_send: now,
            retry_count: 0,
            need_arp_reply: false,
            arp_reply_to_mac: [0; 6],
            arp_reply_to_ip: 0,
            need_gratuitous_arp_configured: false,
            last_keepalive: now,
        }
    }
    
    /// Get MAC address
    pub fn mac(&self) -> &[u8; 6] {
        &self.my_mac
    }
    
    /// Get current state
    pub fn state(&self) -> DhcpState {
        self.state
    }
    
    /// Get assigned IP address (0 if not configured yet)
    pub fn ip(&self) -> u32 {
        self.our_ip
    }
    
    /// Get gateway IP
    pub fn gateway_ip(&self) -> u32 {
        self.offered_gw
    }
    
    /// Get gateway MAC
    pub fn gateway_mac(&self) -> &[u8; 6] {
        &self.gateway_mac
    }
    
    /// Get netmask
    pub fn netmask(&self) -> u32 {
        self.offered_mask
    }
    
    /// Check if DHCP is fully configured
    pub fn is_configured(&self) -> bool {
        self.state == DhcpState::Configured && self.our_ip != 0
    }
    
    /// Get next packet to send (returns None if nothing to send)
    pub fn tick(&mut self) -> Option<Vec<u8>> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.connection_start);
        let since_last_send = now.duration_since(self.last_send);
        
        // Priority 1: Send ARP reply if needed
        if self.need_arp_reply && self.our_ip != 0 {
            self.need_arp_reply = false;
            eprintln!("[DHCP] 📤 Sending ARP Reply to {} ({})",
                     format_ip(self.arp_reply_to_ip),
                     format_mac(&self.arp_reply_to_mac));
            return Some(build_arp_reply(
                &self.my_mac,
                self.our_ip,
                &self.arp_reply_to_mac,
                self.arp_reply_to_ip,
            ));
        }
        
        match self.state {
            DhcpState::Init => {
                // Wait 2 seconds before sending first GARP
                if elapsed >= Duration::from_millis(super::DHCP_INITIAL_DELAY_MS) {
                    eprintln!("[DHCP] 📡 Sending Gratuitous ARP (0.0.0.0) to announce MAC");
                    self.state = DhcpState::ArpAnnounceSent;
                    self.last_send = now;
                    return Some(build_gratuitous_arp(&self.my_mac, 0));
                }
            }
            
            DhcpState::ArpAnnounceSent => {
                // Wait 300ms after GARP before sending DISCOVER
                if since_last_send >= Duration::from_millis(300) {
                    eprintln!("[DHCP] 📡 Sending DHCP DISCOVER #1 (xid=0x{:08x})", self.xid);
                    self.state = DhcpState::DiscoverSent;
                    self.last_send = now;
                    self.retry_count = 0;
                    return Some(build_dhcp_discover(&self.my_mac, self.xid));
                }
            }
            
            DhcpState::DiscoverSent => {
                // Retry DISCOVER every 3 seconds, up to 5 attempts
                if self.retry_count < super::DHCP_MAX_RETRIES &&
                   since_last_send >= Duration::from_millis(super::DHCP_RETRY_INTERVAL_MS) {
                    self.retry_count += 1;
                    self.last_send = now;
                    eprintln!("[DHCP] 🔄 Retrying DHCP DISCOVER #{} (xid=0x{:08x})",
                             self.retry_count + 1, self.xid);
                    return Some(build_dhcp_discover(&self.my_mac, self.xid));
                }
            }
            
            DhcpState::OfferReceived => {
                // Wait 500ms after receiving OFFER before sending REQUEST
                if since_last_send >= Duration::from_millis(super::DHCP_REQUEST_DELAY_MS) {
                    eprintln!("[DHCP] 📡 Sending DHCP REQUEST for IP {} (server {})",
                             format_ip(self.offered_ip),
                             format_ip(self.dhcp_server_ip));
                    self.state = DhcpState::RequestSent;
                    self.last_send = now;
                    return Some(build_dhcp_request(
                        &self.my_mac,
                        self.xid,
                        self.offered_ip,
                        self.dhcp_server_ip,
                    ));
                }
            }
            
            DhcpState::RequestSent => {
                // Waiting for ACK (handled in put_packet)
            }
            
            DhcpState::Configured => {
                // Priority 2: Send gratuitous ARP after configuration
                if self.need_gratuitous_arp_configured {
                    self.need_gratuitous_arp_configured = false;
                    eprintln!("[DHCP] 📡 Sending Gratuitous ARP ({}) to announce IP",
                             format_ip(self.our_ip));
                    return Some(build_gratuitous_arp(&self.my_mac, self.our_ip));
                }
                
                // Priority 3: Send gateway ARP request
                if self.need_gateway_arp && self.our_ip != 0 && self.offered_gw != 0 {
                    self.need_gateway_arp = false;
                    eprintln!("[DHCP] 🔍 Sending ARP Request to resolve gateway MAC {}",
                             format_ip(self.offered_gw));
                    eprintln!("[DHCP]    This populates SoftEther's MAC/IP table!");
                    return Some(build_arp_request(&self.my_mac, self.our_ip, self.offered_gw));
                }
                
                // Priority 4: Send keep-alive GARP every 10 seconds
                if now.duration_since(self.last_keepalive) >= Duration::from_millis(super::KEEPALIVE_INTERVAL_MS) {
                    self.last_keepalive = now;
                    eprintln!("[DHCP] 💓 Sending keep-alive Gratuitous ARP");
                    return Some(build_gratuitous_arp(&self.my_mac, self.our_ip));
                }
            }
        }
        
        None
    }
    
    /// Process received packet from server
    pub fn put_packet(&mut self, data: &[u8]) -> Result<()> {
        // Check if this is a DHCP packet (UDP port 68)
        if data.len() >= 42 {
            // Check Ethernet type (IPv4 = 0x0800)
            let eth_type = u16::from_be_bytes([data[12], data[13]]);
            
            if eth_type == super::ETH_TYPE_IPV4 {
                // Check IP protocol (UDP = 17)
                if data.len() >= 34 && data[23] == super::IP_PROTO_UDP {
                    // Check UDP destination port (68 = DHCP client)
                    if data.len() >= 36 {
                        let dst_port = u16::from_be_bytes([data[36], data[37]]);
                        if dst_port == super::DHCP_CLIENT_PORT {
                            return self.handle_dhcp_packet(data);
                        }
                    }
                }
            } else if eth_type == super::ETH_TYPE_ARP {
                // ARP packet
                return self.handle_arp_packet(data);
            }
        }
        
        Ok(())
    }
    
    fn handle_dhcp_packet(&mut self, data: &[u8]) -> Result<()> {
        let msg = parse_dhcp_packet(data)?;
        
        // Verify XID matches
        if msg.xid != self.xid {
            eprintln!("[DHCP] ⚠️  Ignoring DHCP packet with wrong XID: 0x{:08x} (expected 0x{:08x})",
                     msg.xid, self.xid);
            return Ok(());
        }
        
        match msg.msg_type {
            super::DHCP_OFFER => {
                if self.state == DhcpState::DiscoverSent {
                    eprintln!("[DHCP] ✅ Received DHCP OFFER:");
                    eprintln!("[DHCP]    IP:      {}", format_ip(msg.your_ip));
                    eprintln!("[DHCP]    Gateway: {}", format_ip(msg.gateway));
                    eprintln!("[DHCP]    Netmask: {}", format_ip(msg.netmask));
                    eprintln!("[DHCP]    DNS1:    {}", format_ip(msg.dns1));
                    eprintln!("[DHCP]    Server:  {}", format_ip(msg.server_ip));
                    
                    self.offered_ip = msg.your_ip;
                    self.offered_gw = msg.gateway;
                    self.offered_mask = msg.netmask;
                    self.offered_dns1 = msg.dns1;
                    self.offered_dns2 = msg.dns2;
                    self.dhcp_server_ip = msg.server_ip;
                    
                    self.state = DhcpState::OfferReceived;
                    self.last_send = Instant::now();
                }
            }
            
            super::DHCP_ACK => {
                if self.state == DhcpState::RequestSent {
                    eprintln!("[DHCP] ✅ Received DHCP ACK! Configuration complete:");
                    eprintln!("[DHCP]    IP:      {}", format_ip(msg.your_ip));
                    eprintln!("[DHCP]    Gateway: {}", format_ip(msg.gateway));
                    eprintln!("[DHCP]    Netmask: {}", format_ip(msg.netmask));
                    eprintln!("[DHCP]    Lease:   {} seconds", msg.lease_time);
                    
                    self.our_ip = msg.your_ip;
                    self.offered_gw = msg.gateway;
                    self.offered_mask = msg.netmask;
                    
                    self.state = DhcpState::Configured;
                    
                    // Schedule post-configuration tasks
                    self.need_gratuitous_arp_configured = true;
                    self.need_gateway_arp = true;
                    self.last_keepalive = Instant::now();
                    
                    // TODO: Configure interface (will be done by caller)
                    eprintln!("[DHCP] 📋 Ready to configure interface");
                }
            }
            
            super::DHCP_NAK => {
                eprintln!("[DHCP] ❌ Received DHCP NAK - request rejected!");
                // Reset to DISCOVER state
                self.state = DhcpState::DiscoverSent;
                self.retry_count = 0;
            }
            
            _ => {
                eprintln!("[DHCP] ⚠️  Received unknown DHCP message type: {}", msg.msg_type);
            }
        }
        
        Ok(())
    }
    
    fn handle_arp_packet(&mut self, data: &[u8]) -> Result<()> {
        let arp = parse_arp_packet(data)?;
        
        match arp.operation {
            super::ARP_REQUEST => {
                // Someone is asking for our IP - send reply
                if arp.target_ip == self.our_ip && self.our_ip != 0 {
                    eprintln!("[DHCP] 📬 Received ARP Request for our IP {} from {}",
                             format_ip(arp.target_ip),
                             format_mac(&arp.sender_mac));
                    
                    self.need_arp_reply = true;
                    self.arp_reply_to_mac = arp.sender_mac;
                    self.arp_reply_to_ip = arp.sender_ip;
                }
            }
            
            super::ARP_REPLY => {
                // ARP Reply - learn gateway MAC if this is from gateway
                if arp.sender_ip == self.offered_gw && self.offered_gw != 0 {
                    eprintln!("[DHCP] 🎯 Learned gateway MAC: {} (IP: {})",
                             format_mac(&arp.sender_mac),
                             format_ip(arp.sender_ip));
                    eprintln!("[DHCP]    This enables bidirectional routing!");
                    
                    self.gateway_mac = arp.sender_mac;
                }
            }
            
            _ => {}
        }
        
        Ok(())
    }
}

impl Default for DhcpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_client_creation() {
        let client = DhcpClient::new();
        assert_eq!(client.state(), DhcpState::Init);
        assert_eq!(client.ip(), 0);
        assert!(!client.is_configured());
    }

    #[test]
    fn test_mac_address_generation() {
        let client = DhcpClient::new();
        let mac = client.mac();
        
        // Check prefix
        assert_eq!(mac[0], 0x02); // Locally administered
        assert_eq!(mac[1], 0x00);
        assert_eq!(mac[2], 0x5E); // SoftEther prefix
    }
}
