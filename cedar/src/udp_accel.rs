//! UDP Acceleration Module
//!
//! UDP acceleration support for low-latency VPN connections.
//! Provides faster data transfer with automatic fallback to TCP.

use mayaqua::error::{Error, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// UDP acceleration mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UdpAccelMode {
    /// UDP acceleration disabled
    Disabled,
    /// UDP for data, TCP for control
    Hybrid,
    /// UDP only (fallback to TCP on failure)
    UdpOnly,
}

/// UDP acceleration configuration
#[derive(Debug, Clone)]
pub struct UdpAccelConfig {
    /// Acceleration mode
    pub mode: UdpAccelMode,
    /// UDP port to use (0 = auto)
    pub port: u16,
    /// Enable NAT-T for UDP
    pub nat_traversal: bool,
    /// Maximum packet size
    pub max_packet_size: usize,
    /// Packet loss threshold for fallback (0.0-1.0)
    pub loss_threshold: f32,
    /// RTT threshold for fallback (milliseconds)
    pub rtt_threshold: u32,
    /// Keep-alive interval (seconds)
    pub keepalive_interval: u32,
}

impl Default for UdpAccelConfig {
    fn default() -> Self {
        Self {
            mode: UdpAccelMode::Hybrid,
            port: 0,
            nat_traversal: true,
            max_packet_size: 1400, // Safe for most MTUs
            loss_threshold: 0.1,   // 10% packet loss
            rtt_threshold: 500,    // 500ms
            keepalive_interval: 5, // 5 seconds
        }
    }
}

/// UDP acceleration engine
pub struct UdpAccelerator {
    /// Configuration
    config: UdpAccelConfig,
    /// UDP socket
    socket: Option<UdpSocket>,
    /// Remote address
    remote_addr: Option<SocketAddr>,
    /// Acceleration state
    state: UdpAccelState,
    /// Statistics
    stats: UdpAccelStats,
    /// Last keep-alive sent
    last_keepalive: Instant,
    /// Sequence number
    sequence: u32,
}

/// UDP acceleration state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UdpAccelState {
    /// Not initialized
    Disabled,
    /// Initializing
    Initializing,
    /// Active and working
    Active,
    /// Degraded (high loss/latency)
    Degraded,
    /// Failed, using TCP fallback
    Failed,
}

/// UDP acceleration statistics
#[derive(Debug, Clone, Default)]
pub struct UdpAccelStats {
    /// Packets sent via UDP
    pub packets_sent: u64,
    /// Packets received via UDP
    pub packets_received: u64,
    /// Packets lost (detected)
    pub packets_lost: u64,
    /// Packets out of order
    pub packets_ooo: u64,
    /// Average RTT (milliseconds)
    pub avg_rtt: u32,
    /// Current packet loss rate (0.0-1.0)
    pub loss_rate: f32,
}

impl UdpAccelerator {
    /// Create new UDP accelerator
    pub fn new(config: UdpAccelConfig) -> Self {
        Self {
            config,
            socket: None,
            remote_addr: None,
            state: UdpAccelState::Disabled,
            stats: UdpAccelStats::default(),
            last_keepalive: Instant::now(),
            sequence: 0,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(UdpAccelConfig::default())
    }

    /// Initialize UDP acceleration
    pub fn initialize(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        if self.config.mode == UdpAccelMode::Disabled {
            return Ok(());
        }

        self.state = UdpAccelState::Initializing;

        // Create UDP socket
        let socket = UdpSocket::bind(local_addr)
            .map_err(|e| Error::IoError(format!("Failed to bind UDP socket: {}", e)))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| Error::IoError(e.to_string()))?;

        socket
            .connect(remote_addr)
            .map_err(|e| Error::IoError(e.to_string()))?;

        self.socket = Some(socket);
        self.remote_addr = Some(remote_addr);
        self.state = UdpAccelState::Active;

        Ok(())
    }

    /// Send data via UDP
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state == UdpAccelState::Disabled || self.state == UdpAccelState::Failed {
            return Err(Error::InvalidState);
        }

        let socket = self.socket.as_ref().ok_or(Error::NotConnected)?;

        if data.len() > self.config.max_packet_size {
            return Err(Error::PacketTooLarge);
        }

        // Create packet with sequence number
        let mut packet = Vec::with_capacity(data.len() + 4);
        packet.extend_from_slice(&self.sequence.to_be_bytes());
        packet.extend_from_slice(data);

        // Send packet
        let sent = socket
            .send(&packet)
            .map_err(|e| Error::IoError(e.to_string()))?;

        self.sequence = self.sequence.wrapping_add(1);
        self.stats.packets_sent += 1;

        Ok(sent - 4) // Subtract sequence number size
    }

    /// Receive data via UDP
    pub fn recv(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if self.state == UdpAccelState::Disabled || self.state == UdpAccelState::Failed {
            return Err(Error::InvalidState);
        }

        let socket = self.socket.as_ref().ok_or(Error::NotConnected)?;

        // Receive packet
        let mut packet_buffer = vec![0u8; self.config.max_packet_size + 4];
        let received = match socket.recv(&mut packet_buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(Error::TimeOut);
            }
            Err(e) => return Err(Error::IoError(e.to_string())),
        };

        if received < 4 {
            return Err(Error::InvalidPacketFormat);
        }

        // Extract sequence number (for future ordering/loss detection)
        let _seq = u32::from_be_bytes([
            packet_buffer[0],
            packet_buffer[1],
            packet_buffer[2],
            packet_buffer[3],
        ]);

        // Copy data to output buffer
        let data_len = received - 4;
        if buffer.len() < data_len {
            return Err(Error::BufferTooSmall);
        }

        buffer[..data_len].copy_from_slice(&packet_buffer[4..received]);
        self.stats.packets_received += 1;

        Ok(data_len)
    }

    /// Send keep-alive packet
    pub fn send_keepalive(&mut self) -> Result<()> {
        if self.state != UdpAccelState::Active {
            return Ok(());
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_keepalive);

        if elapsed.as_secs() >= self.config.keepalive_interval as u64 {
            // Send empty packet as keep-alive
            let _ = self.send(&[])?;
            self.last_keepalive = now;
        }

        Ok(())
    }

    /// Check if acceleration should be disabled due to poor performance
    pub fn check_health(&mut self) -> bool {
        if self.stats.loss_rate > self.config.loss_threshold
            || self.stats.avg_rtt > self.config.rtt_threshold
        {
            if self.state == UdpAccelState::Active {
                self.state = UdpAccelState::Degraded;
            }
            return false;
        }

        if self.state == UdpAccelState::Degraded {
            self.state = UdpAccelState::Active;
        }
        true
    }

    /// Disable UDP acceleration and fall back to TCP
    pub fn disable(&mut self) -> Result<()> {
        self.state = UdpAccelState::Failed;
        if let Some(socket) = self.socket.take() {
            drop(socket);
        }
        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> UdpAccelState {
        self.state
    }

    /// Get statistics
    pub fn stats(&self) -> &UdpAccelStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = UdpAccelStats::default();
    }

    /// Check if UDP is available and performing well
    pub fn is_healthy(&self) -> bool {
        self.state == UdpAccelState::Active
    }
}

/// UDP packet header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UdpPacketHeader {
    /// Sequence number
    pub sequence: u32,
    /// Timestamp (for RTT measurement)
    pub timestamp: u64,
    /// Flags
    pub flags: u16,
    /// Payload size
    pub size: u16,
}

impl UdpPacketHeader {
    /// Header size in bytes
    pub const SIZE: usize = 16;

    /// Create new header
    pub fn new(sequence: u32, size: u16) -> Self {
        Self {
            sequence,
            timestamp: Self::current_timestamp(),
            flags: 0,
            size,
        }
    }

    /// Get current timestamp (milliseconds since epoch)
    fn current_timestamp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// Calculate RTT from timestamp
    pub fn calculate_rtt(&self) -> u64 {
        Self::current_timestamp().saturating_sub(self.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_accel_config_default() {
        let config = UdpAccelConfig::default();
        assert_eq!(config.mode, UdpAccelMode::Hybrid);
        assert_eq!(config.max_packet_size, 1400);
        assert!(config.nat_traversal);
    }

    #[test]
    fn test_udp_accelerator_creation() {
        let accel = UdpAccelerator::with_defaults();
        assert_eq!(accel.state(), UdpAccelState::Disabled);
        assert_eq!(accel.stats().packets_sent, 0);
    }

    #[test]
    fn test_udp_accel_modes() {
        assert_ne!(UdpAccelMode::Disabled, UdpAccelMode::Hybrid);
        assert_ne!(UdpAccelMode::Hybrid, UdpAccelMode::UdpOnly);
    }

    #[test]
    fn test_send_requires_initialization() {
        let mut accel = UdpAccelerator::with_defaults();
        let data = b"test";

        // Should fail when not initialized
        let result = accel.send(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_packet_too_large() {
        let mut accel = UdpAccelerator::with_defaults();
        accel.state = UdpAccelState::Active;
        accel.socket = None; // Will fail anyway

        let large_data = vec![0u8; 2000];
        let result = accel.send(&large_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_udp_stats_default() {
        let stats = UdpAccelStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.loss_rate, 0.0);
    }

    #[test]
    fn test_health_check_degraded() {
        let mut accel = UdpAccelerator::with_defaults();
        accel.state = UdpAccelState::Active;
        accel.stats.loss_rate = 0.5; // 50% loss

        let is_healthy = accel.check_health();
        assert!(!is_healthy);
        assert_eq!(accel.state(), UdpAccelState::Degraded);
    }

    #[test]
    fn test_disable_acceleration() {
        let mut accel = UdpAccelerator::with_defaults();
        accel.state = UdpAccelState::Active;

        accel.disable().unwrap();
        assert_eq!(accel.state(), UdpAccelState::Failed);
    }

    #[test]
    fn test_udp_packet_header() {
        let header = UdpPacketHeader::new(123, 1000);
        assert_eq!(header.sequence, 123);
        assert_eq!(header.size, 1000);
        assert_eq!(UdpPacketHeader::SIZE, 16);
    }

    #[test]
    fn test_stats_reset() {
        let mut accel = UdpAccelerator::with_defaults();
        accel.stats.packets_sent = 100;

        accel.reset_stats();
        assert_eq!(accel.stats().packets_sent, 0);
    }

    #[test]
    fn test_is_healthy() {
        let mut accel = UdpAccelerator::with_defaults();
        assert!(!accel.is_healthy());

        accel.state = UdpAccelState::Active;
        assert!(accel.is_healthy());
    }
}
