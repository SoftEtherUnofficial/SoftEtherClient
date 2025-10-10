//! NAT Traversal Module
//!
//! NAT traversal support for establishing VPN connections through NATs.
//! Implements STUN-like protocol and UDP hole punching.

use mayaqua::error::{Error, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// NAT type detected
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatType {
    /// No NAT detected (direct internet)
    None,
    /// Full cone NAT (easiest to traverse)
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port restricted cone NAT
    PortRestrictedCone,
    /// Symmetric NAT (hardest to traverse)
    Symmetric,
    /// Unknown/couldn't detect
    Unknown,
}

/// NAT traversal method
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TraversalMethod {
    /// Direct connection (no NAT)
    Direct,
    /// UDP hole punching
    HolePunching,
    /// TCP with port forwarding
    PortForward,
    /// Relay server
    Relay,
}

/// NAT traversal configuration
#[derive(Debug, Clone)]
pub struct NatTraversalConfig {
    /// Enable NAT traversal
    pub enabled: bool,
    /// STUN server address
    pub stun_server: Option<String>,
    /// STUN server port
    pub stun_port: u16,
    /// Enable UDP hole punching
    pub hole_punching: bool,
    /// Keep-alive interval (seconds)
    pub keepalive_interval: u32,
    /// Detection timeout (seconds)
    pub detection_timeout: u32,
    /// Relay server address (fallback)
    pub relay_server: Option<String>,
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stun_server: Some("stun.softether.net".to_string()),
            stun_port: 3478,
            hole_punching: true,
            keepalive_interval: 30,
            detection_timeout: 5,
            relay_server: None,
        }
    }
}

/// NAT traversal engine
pub struct NatTraversal {
    /// Configuration
    config: NatTraversalConfig,
    /// Detected NAT type
    nat_type: NatType,
    /// Public IP address
    public_addr: Option<SocketAddr>,
    /// Local IP address
    local_addr: Option<SocketAddr>,
    /// Current traversal method
    method: TraversalMethod,
    /// Last keep-alive sent
    last_keepalive: Instant,
    /// Statistics
    stats: NatTraversalStats,
}

/// NAT traversal statistics
#[derive(Debug, Clone, Default)]
pub struct NatTraversalStats {
    /// Number of hole punching attempts
    pub hole_punch_attempts: u64,
    /// Number of successful hole punches
    pub hole_punch_success: u64,
    /// Number of keep-alives sent
    pub keepalives_sent: u64,
    /// Number of detections performed
    pub detections: u64,
}

impl NatTraversal {
    /// Create new NAT traversal engine
    pub fn new(config: NatTraversalConfig) -> Self {
        Self {
            config,
            nat_type: NatType::Unknown,
            public_addr: None,
            local_addr: None,
            method: TraversalMethod::Direct,
            last_keepalive: Instant::now(),
            stats: NatTraversalStats::default(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(NatTraversalConfig::default())
    }

    /// Detect NAT type using STUN
    pub fn detect_nat_type(&mut self) -> Result<NatType> {
        if !self.config.enabled {
            return Ok(NatType::None);
        }

        self.stats.detections += 1;

        // TODO: Implement actual STUN protocol
        // This is a placeholder implementation

        // For now, assume port restricted cone NAT
        self.nat_type = NatType::PortRestrictedCone;
        Ok(self.nat_type)
    }

    /// Get public IP address via STUN
    pub fn get_public_address(&mut self) -> Result<SocketAddr> {
        if let Some(addr) = self.public_addr {
            return Ok(addr);
        }

        // TODO: Implement STUN request
        // Placeholder: return error
        Err(Error::NotImplemented)
    }

    /// Perform UDP hole punching
    pub fn hole_punch(
        &mut self,
        local_socket: &UdpSocket,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        if !self.config.hole_punching {
            return Err(Error::NotSupported);
        }

        self.stats.hole_punch_attempts += 1;

        // Send multiple packets to punch hole
        for i in 0..5 {
            let packet = format!("HOLE_PUNCH:{}", i);
            local_socket
                .send_to(packet.as_bytes(), remote_addr)
                .map_err(|e| Error::IoError(e.to_string()))?;

            std::thread::sleep(Duration::from_millis(100));
        }

        self.stats.hole_punch_success += 1;
        Ok(())
    }

    /// Send NAT keep-alive packet
    pub fn send_keepalive(&mut self, socket: &UdpSocket, remote_addr: SocketAddr) -> Result<()> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_keepalive);

        if elapsed.as_secs() >= self.config.keepalive_interval as u64 {
            socket
                .send_to(b"KEEPALIVE", remote_addr)
                .map_err(|e| Error::IoError(e.to_string()))?;

            self.last_keepalive = now;
            self.stats.keepalives_sent += 1;
        }

        Ok(())
    }

    /// Determine best traversal method
    pub fn determine_method(&mut self) -> TraversalMethod {
        match self.nat_type {
            NatType::None => TraversalMethod::Direct,
            NatType::FullCone | NatType::RestrictedCone | NatType::PortRestrictedCone => {
                if self.config.hole_punching {
                    TraversalMethod::HolePunching
                } else {
                    TraversalMethod::PortForward
                }
            }
            NatType::Symmetric => {
                if self.config.relay_server.is_some() {
                    TraversalMethod::Relay
                } else {
                    TraversalMethod::PortForward
                }
            }
            NatType::Unknown => TraversalMethod::Direct,
        }
    }

    /// Get detected NAT type
    pub fn nat_type(&self) -> NatType {
        self.nat_type
    }

    /// Get current traversal method
    pub fn method(&self) -> TraversalMethod {
        self.method
    }

    /// Get public address
    pub fn public_address(&self) -> Option<SocketAddr> {
        self.public_addr
    }

    /// Set local address
    pub fn set_local_address(&mut self, addr: SocketAddr) {
        self.local_addr = Some(addr);
    }

    /// Get statistics
    pub fn stats(&self) -> &NatTraversalStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = NatTraversalStats::default();
    }

    /// Check if NAT traversal is supported for current NAT type
    pub fn is_supported(&self) -> bool {
        matches!(
            self.nat_type,
            NatType::None
                | NatType::FullCone
                | NatType::RestrictedCone
                | NatType::PortRestrictedCone
        )
    }
}

/// STUN message for NAT detection
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message type
    pub message_type: StunMessageType,
    /// Transaction ID
    pub transaction_id: [u8; 12],
    /// Attributes
    pub attributes: Vec<StunAttribute>,
}

/// STUN message type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StunMessageType {
    /// Binding request
    BindingRequest,
    /// Binding response
    BindingResponse,
    /// Binding error
    BindingError,
}

/// STUN attribute
#[derive(Debug, Clone)]
pub struct StunAttribute {
    /// Attribute type
    pub attr_type: u16,
    /// Attribute value
    pub value: Vec<u8>,
}

impl StunMessage {
    /// Create new binding request
    pub fn new_binding_request() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut transaction_id = [0u8; 12];
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        // Use timestamp for transaction ID (not cryptographically secure)
        transaction_id[..8].copy_from_slice(&timestamp.to_be_bytes());

        Self {
            message_type: StunMessageType::BindingRequest,
            transaction_id,
            attributes: Vec::new(),
        }
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        // TODO: Implement STUN message serialization
        // Placeholder: return empty vec
        Vec::new()
    }

    /// Deserialize from bytes
    pub fn deserialize(_data: &[u8]) -> Result<Self> {
        // TODO: Implement STUN message deserialization
        Err(Error::NotImplemented)
    }
}

/// Port mapping for UPnP/NAT-PMP
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// External port
    pub external_port: u16,
    /// Internal port
    pub internal_port: u16,
    /// Protocol (TCP/UDP)
    pub protocol: String,
    /// Description
    pub description: String,
    /// Lease duration (seconds, 0 = permanent)
    pub lease_duration: u32,
}

impl PortMapping {
    /// Create new port mapping
    pub fn new(external_port: u16, internal_port: u16, protocol: String) -> Self {
        Self {
            external_port,
            internal_port,
            protocol,
            description: "SoftEther VPN".to_string(),
            lease_duration: 0,
        }
    }

    /// Request port mapping via UPnP
    pub fn request(&self) -> Result<()> {
        // TODO: Implement UPnP port mapping
        Err(Error::NotImplemented)
    }

    /// Delete port mapping
    pub fn delete(&self) -> Result<()> {
        // TODO: Implement UPnP port deletion
        Err(Error::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_traversal_config_default() {
        let config = NatTraversalConfig::default();
        assert!(config.enabled);
        assert!(config.hole_punching);
        assert_eq!(config.stun_port, 3478);
    }

    #[test]
    fn test_nat_traversal_creation() {
        let nat = NatTraversal::with_defaults();
        assert_eq!(nat.nat_type(), NatType::Unknown);
        assert_eq!(nat.method(), TraversalMethod::Direct);
    }

    #[test]
    fn test_nat_types() {
        assert_ne!(NatType::None, NatType::FullCone);
        assert_ne!(NatType::Symmetric, NatType::RestrictedCone);
    }

    #[test]
    fn test_traversal_methods() {
        assert_ne!(TraversalMethod::Direct, TraversalMethod::HolePunching);
        assert_ne!(TraversalMethod::Relay, TraversalMethod::PortForward);
    }

    #[test]
    fn test_determine_method_no_nat() {
        let mut nat = NatTraversal::with_defaults();
        nat.nat_type = NatType::None;

        let method = nat.determine_method();
        assert_eq!(method, TraversalMethod::Direct);
    }

    #[test]
    fn test_determine_method_cone_nat() {
        let mut nat = NatTraversal::with_defaults();
        nat.nat_type = NatType::FullCone;

        let method = nat.determine_method();
        assert_eq!(method, TraversalMethod::HolePunching);
    }

    #[test]
    fn test_is_supported() {
        let mut nat = NatTraversal::with_defaults();

        nat.nat_type = NatType::None;
        assert!(nat.is_supported());

        nat.nat_type = NatType::FullCone;
        assert!(nat.is_supported());

        nat.nat_type = NatType::Symmetric;
        assert!(!nat.is_supported());
    }

    #[test]
    fn test_stats_default() {
        let stats = NatTraversalStats::default();
        assert_eq!(stats.hole_punch_attempts, 0);
        assert_eq!(stats.keepalives_sent, 0);
    }

    #[test]
    fn test_set_local_address() {
        let mut nat = NatTraversal::with_defaults();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        nat.set_local_address(addr);
        assert_eq!(nat.local_addr, Some(addr));
    }

    #[test]
    fn test_stun_message_creation() {
        let msg = StunMessage::new_binding_request();
        assert_eq!(msg.message_type, StunMessageType::BindingRequest);
        assert_eq!(msg.transaction_id.len(), 12);
    }

    #[test]
    fn test_port_mapping_creation() {
        let mapping = PortMapping::new(8080, 8080, "UDP".to_string());
        assert_eq!(mapping.external_port, 8080);
        assert_eq!(mapping.internal_port, 8080);
        assert_eq!(mapping.protocol, "UDP");
    }

    #[test]
    fn test_stats_reset() {
        let mut nat = NatTraversal::with_defaults();
        nat.stats.hole_punch_attempts = 10;

        nat.reset_stats();
        assert_eq!(nat.stats().hole_punch_attempts, 0);
    }
}
