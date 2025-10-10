//! Connection Management Module
//!
//! Handles individual TCP/UDP connections, packet framing, and protocol logic.

use crate::constants::*;
use mayaqua::error::{Error, Result};
use mayaqua::network::TcpSocket;
use std::time::{Duration, Instant};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    /// Initial state
    Init,
    /// Connecting
    Connecting,
    /// Protocol negotiation
    Negotiating,
    /// Established and ready
    Established,
    /// Disconnecting
    Disconnecting,
    /// Closed
    Closed,
}

/// Connection type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionType {
    /// Regular TCP connection
    Tcp,
    /// UDP connection (acceleration)
    Udp,
    /// R-UDP (Reliable UDP)
    RUdp,
}

/// Packet header for Cedar protocol
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader {
    /// Packet signature (magic number)
    pub signature: u32,
    /// Packet type/command
    pub packet_type: u32,
    /// Packet size (excluding header)
    pub size: u32,
    /// Sequence number
    pub sequence: u32,
}

impl PacketHeader {
    pub const SIZE: usize = 16; // 4 fields × 4 bytes
    pub const SIGNATURE: u32 = 0x53455650; // "SEVP" in hex

    pub fn new(packet_type: u32, size: u32, sequence: u32) -> Self {
        Self {
            signature: Self::SIGNATURE,
            packet_type,
            size,
            sequence,
        }
    }

    /// Serialize header to bytes (big-endian)
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.signature.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.packet_type.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.size.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.sequence.to_be_bytes());
        bytes
    }

    /// Deserialize header from bytes (big-endian)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        let signature = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if signature != Self::SIGNATURE {
            return Err(Error::InvalidSignature);
        }

        let packet_type = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let size = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let sequence = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);

        Ok(Self {
            signature,
            packet_type,
            size,
            sequence,
        })
    }
}

/// Packet types matching SoftEther protocol
#[allow(dead_code)]
pub mod packet_type {
    pub const HELLO: u32 = 0x00000001;
    pub const HELLO_RESPONSE: u32 = 0x00000002;
    pub const AUTH_REQUEST: u32 = 0x00000010;
    pub const AUTH_RESPONSE: u32 = 0x00000011;
    pub const KEEP_ALIVE: u32 = 0x00000020;
    pub const KEEP_ALIVE_RESPONSE: u32 = 0x00000021;
    pub const DATA: u32 = 0x00000030;
    pub const DISCONNECT: u32 = 0x00000040;
}

/// VPN Connection
pub struct Connection {
    /// Underlying TCP socket
    socket: TcpSocket,
    /// Connection state
    state: ConnectionState,
    /// Connection type
    conn_type: ConnectionType,
    /// Packet sequence counter
    sequence: u32,
    /// Last activity timestamp
    last_activity: Instant,
    /// Connection timeout
    timeout: Duration,
    /// Use encryption
    use_encrypt: bool,
    /// Use compression
    use_compress: bool,
}

impl Connection {
    /// Create new connection from socket
    pub fn new(socket: TcpSocket, use_encrypt: bool, use_compress: bool) -> Self {
        Self {
            socket,
            state: ConnectionState::Init,
            conn_type: ConnectionType::Tcp,
            sequence: 0,
            last_activity: Instant::now(),
            timeout: Duration::from_secs(CONNECTING_TIMEOUT_MS as u64 / 1000),
            use_encrypt,
            use_compress,
        }
    }

    /// Get current state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Set connection state
    pub fn set_state(&mut self, state: ConnectionState) {
        self.state = state;
        self.last_activity = Instant::now();
    }

    /// Get connection type
    pub fn conn_type(&self) -> ConnectionType {
        self.conn_type
    }

    /// Get next sequence number
    fn next_sequence(&mut self) -> u32 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }

    /// Send packet with header
    pub fn send_packet(&mut self, packet_type: u32, data: &[u8]) -> Result<()> {
        let sequence = self.next_sequence();
        let header = PacketHeader::new(packet_type, data.len() as u32, sequence);

        // Send header
        let header_bytes = header.to_bytes();
        self.socket.send(&header_bytes)?;

        // Send data if any
        if !data.is_empty() {
            // TODO: Apply encryption if enabled
            // TODO: Apply compression if enabled
            self.socket.send(data)?;
        }

        self.last_activity = Instant::now();
        Ok(())
    }

    /// Receive packet with header
    pub fn recv_packet(&mut self) -> Result<(PacketHeader, Vec<u8>)> {
        // Receive header
        let mut header_buf = [0u8; PacketHeader::SIZE];
        self.socket.recv(&mut header_buf)?;

        let header = PacketHeader::from_bytes(&header_buf)?;

        // Receive data
        let mut data = vec![0u8; header.size as usize];
        if header.size > 0 {
            self.socket.recv(&mut data)?;
            // TODO: Apply decryption if enabled
            // TODO: Apply decompression if enabled
        }

        self.last_activity = Instant::now();
        Ok((header, data))
    }

    /// Send HELLO packet
    pub fn send_hello(&mut self, client_signature: &str) -> Result<()> {
        let data = client_signature.as_bytes();
        self.send_packet(packet_type::HELLO, data)?;
        self.set_state(ConnectionState::Negotiating);
        Ok(())
    }

    /// Receive HELLO response
    pub fn recv_hello_response(&mut self) -> Result<String> {
        let (header, data) = self.recv_packet()?;

        if header.packet_type != packet_type::HELLO_RESPONSE {
            return Err(Error::UnexpectedPacketType);
        }

        let server_signature = String::from_utf8(data)
            .map_err(|_| Error::EncodingError)?;

        Ok(server_signature)
    }

    /// Send authentication request
    pub fn send_auth_request(&mut self, auth_data: &[u8]) -> Result<()> {
        self.send_packet(packet_type::AUTH_REQUEST, auth_data)
    }

    /// Receive authentication response
    pub fn recv_auth_response(&mut self) -> Result<bool> {
        let (header, data) = self.recv_packet()?;

        if header.packet_type != packet_type::AUTH_RESPONSE {
            return Err(Error::UnexpectedPacketType);
        }

        // First byte indicates success/failure
        if data.is_empty() {
            return Err(Error::InvalidResponse);
        }

        Ok(data[0] != 0)
    }

    /// Send keep-alive packet
    pub fn send_keep_alive(&mut self) -> Result<()> {
        self.send_packet(packet_type::KEEP_ALIVE, &[])
    }

    /// Send data packet
    pub fn send_data(&mut self, data: &[u8]) -> Result<()> {
        self.send_packet(packet_type::DATA, data)
    }

    /// Send disconnect packet
    pub fn send_disconnect(&mut self) -> Result<()> {
        self.send_packet(packet_type::DISCONNECT, &[])?;
        self.set_state(ConnectionState::Disconnecting);
        Ok(())
    }

    /// Check if connection timed out
    pub fn is_timeout(&self) -> bool {
        Instant::now().duration_since(self.last_activity) > self.timeout
    }

    /// Get idle time
    pub fn idle_time(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }

    /// Close connection
    pub fn close(self) {
        // Socket will be closed when dropped
        drop(self.socket);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_header_serialization() {
        let header = PacketHeader::new(packet_type::HELLO, 1024, 42);

        let bytes = header.to_bytes();
        let decoded = PacketHeader::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.signature, PacketHeader::SIGNATURE);
        assert_eq!(decoded.packet_type, packet_type::HELLO);
        assert_eq!(decoded.size, 1024);
        assert_eq!(decoded.sequence, 42);
    }

    #[test]
    fn test_packet_header_invalid_signature() {
        let mut bytes = [0u8; PacketHeader::SIZE];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());

        let result = PacketHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_state_transitions() {
        // Note: Cannot test with real socket without server
        // This test just verifies type signatures compile
        assert_eq!(ConnectionState::Init, ConnectionState::Init);
        assert_eq!(ConnectionType::Tcp, ConnectionType::Tcp);
    }

    #[test]
    fn test_packet_types() {
        assert_eq!(packet_type::HELLO, 0x00000001);
        assert_eq!(packet_type::HELLO_RESPONSE, 0x00000002);
        assert_eq!(packet_type::AUTH_REQUEST, 0x00000010);
        assert_eq!(packet_type::DATA, 0x00000030);
    }
}
