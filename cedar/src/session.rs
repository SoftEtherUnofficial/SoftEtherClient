//! Session Management Module
//!
//! Handles VPN session lifecycle, state management, and connection coordination.

use crate::constants::*;
use mayaqua::error::{Error, Result};
use mayaqua::network::{TcpSocket, UdpSocketWrapper};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Session status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionStatus {
    /// Initial state
    Init,
    /// Connecting to server
    Connecting,
    /// Performing authentication
    Authenticating,
    /// Fully established and ready
    Established,
    /// Reconnecting after disconnect
    Reconnecting,
    /// Gracefully closing
    Closing,
    /// Terminated
    Terminated,
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_received: u64,
    /// Session start time
    pub start_time: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Number of reconnections
    pub reconnect_count: u32,
}

impl SessionStats {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            start_time: now,
            last_activity: now,
            reconnect_count: 0,
        }
    }

    pub fn update_send(&mut self, bytes: usize, packets: usize) {
        self.bytes_sent += bytes as u64;
        self.packets_sent += packets as u64;
        self.last_activity = Instant::now();
    }

    pub fn update_recv(&mut self, bytes: usize, packets: usize) {
        self.bytes_received += bytes as u64;
        self.packets_received += packets as u64;
        self.last_activity = Instant::now();
    }

    pub fn duration(&self) -> Duration {
        Instant::now().duration_since(self.start_time)
    }

    pub fn idle_time(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session name/identifier
    pub name: String,
    /// Server hostname
    pub server: String,
    /// Server port
    pub port: u16,
    /// Virtual Hub name
    pub hub: String,
    /// Authentication credentials
    pub auth: AuthConfig,
    /// Use encryption
    pub use_encrypt: bool,
    /// Use compression
    pub use_compress: bool,
    /// Maximum number of TCP connections
    pub max_connection: u32,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Connection timeout
    pub timeout: Duration,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub enum AuthConfig {
    Anonymous,
    Password { username: String, password: String },
    Certificate { username: String, cert_data: Vec<u8> },
}

/// VPN Session
pub struct Session {
    /// Session configuration
    config: SessionConfig,
    /// Current status
    status: Arc<Mutex<SessionStatus>>,
    /// Session statistics
    stats: Arc<Mutex<SessionStats>>,
    /// TCP connections (multi-connection support)
    tcp_connections: Arc<Mutex<Vec<TcpSocket>>>,
    /// UDP socket (for UDP acceleration)
    udp_socket: Arc<Mutex<Option<UdpSocketWrapper>>>,
    /// Session flags
    flags: SessionFlags,
}

impl Session {
    /// Create new session
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            status: Arc::new(Mutex::new(SessionStatus::Init)),
            stats: Arc::new(Mutex::new(SessionStats::new())),
            tcp_connections: Arc::new(Mutex::new(Vec::new())),
            udp_socket: Arc::new(Mutex::new(None)),
            flags: SessionFlags::default(),
        }
    }

    /// Get current session status
    pub fn status(&self) -> SessionStatus {
        *self.status.lock().unwrap()
    }

    /// Set session status
    fn set_status(&self, new_status: SessionStatus) {
        let mut status = self.status.lock().unwrap();
        *status = new_status;
    }

    /// Get session statistics
    pub fn stats(&self) -> SessionStats {
        self.stats.lock().unwrap().clone()
    }

    /// Connect to VPN server
    pub fn connect(&self) -> Result<()> {
        self.set_status(SessionStatus::Connecting);

        // Establish initial TCP connection
        let socket = TcpSocket::connect(&self.config.server, self.config.port)?;

        let mut connections = self.tcp_connections.lock().unwrap();
        connections.push(socket);

        // Send initial handshake
        self.send_handshake()?;

        // Authenticate
        self.set_status(SessionStatus::Authenticating);
        self.authenticate()?;

        // Session established
        self.set_status(SessionStatus::Established);

        Ok(())
    }

    /// Send initial handshake
    fn send_handshake(&self) -> Result<()> {
        // TODO: Implement SoftEther handshake protocol
        // This would include:
        // - Send Cedar signature
        // - Protocol version negotiation
        // - Capability exchange
        Ok(())
    }

    /// Authenticate with server
    fn authenticate(&self) -> Result<()> {
        // TODO: Implement authentication based on AuthConfig
        match &self.config.auth {
            AuthConfig::Anonymous => {
                // Anonymous authentication
                Ok(())
            }
            AuthConfig::Password { username, password } => {
                // Password-based authentication
                let _hash = mayaqua::crypto::softether_password_hash(password, username);
                // TODO: Send authentication packet
                Ok(())
            }
            AuthConfig::Certificate { .. } => {
                // Certificate-based authentication
                // TODO: Implement certificate auth
                Err(Error::NotImplemented)
            }
        }
    }

    /// Send data through session
    pub fn send(&self, data: &[u8]) -> Result<usize> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.is_empty() {
            return Err(Error::NotConnected);
        }

        // Send through first connection
        // TODO: Implement load balancing across multiple connections
        let sent = connections[0].send(data)?;

        // Update statistics
        let mut stats = self.stats.lock().unwrap();
        stats.update_send(sent, 1);

        Ok(sent)
    }

    /// Receive data from session
    pub fn recv(&self, buffer: &mut [u8]) -> Result<usize> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.is_empty() {
            return Err(Error::NotConnected);
        }

        // Receive from first connection
        let received = connections[0].recv(buffer)?;

        // Update statistics
        let mut stats = self.stats.lock().unwrap();
        stats.update_recv(received, 1);

        Ok(received)
    }

    /// Add additional TCP connection (for multi-connection)
    pub fn add_connection(&self) -> Result<()> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        let socket = TcpSocket::connect(&self.config.server, self.config.port)?;

        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.len() >= self.config.max_connection as usize {
            return Err(Error::TooManyConnections);
        }

        connections.push(socket);
        Ok(())
    }

    /// Enable UDP acceleration
    pub fn enable_udp_acceleration(&self, port: u16) -> Result<()> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        let socket = UdpSocketWrapper::new(port)?;
        let mut udp_socket = self.udp_socket.lock().unwrap();
        *udp_socket = Some(socket);

        Ok(())
    }

    /// Close session gracefully
    pub fn close(&self) -> Result<()> {
        self.set_status(SessionStatus::Closing);

        // Close all TCP connections
        let mut connections = self.tcp_connections.lock().unwrap();
        connections.clear();

        // Close UDP socket if active
        let mut udp_socket = self.udp_socket.lock().unwrap();
        *udp_socket = None;

        self.set_status(SessionStatus::Terminated);
        Ok(())
    }

    /// Get session configuration
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Check if session is alive
    pub fn is_alive(&self) -> bool {
        matches!(
            self.status(),
            SessionStatus::Established | SessionStatus::Connecting | SessionStatus::Authenticating
        )
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        self.tcp_connections.lock().unwrap().len()
    }

    /// Check if UDP acceleration is active
    pub fn is_udp_accelerated(&self) -> bool {
        self.udp_socket.lock().unwrap().is_some()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let config = SessionConfig {
            name: "test_session".to_string(),
            server: "example.com".to_string(),
            port: 443,
            hub: "DEFAULT".to_string(),
            auth: AuthConfig::Anonymous,
            use_encrypt: true,
            use_compress: false,
            max_connection: 8,
            keep_alive_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(15),
        };

        let session = Session::new(config);
        assert_eq!(session.status(), SessionStatus::Init);
        assert_eq!(session.connection_count(), 0);
        assert!(!session.is_udp_accelerated());
    }

    #[test]
    fn test_session_stats() {
        let mut stats = SessionStats::new();

        stats.update_send(1024, 10);
        assert_eq!(stats.bytes_sent, 1024);
        assert_eq!(stats.packets_sent, 10);

        stats.update_recv(2048, 20);
        assert_eq!(stats.bytes_received, 2048);
        assert_eq!(stats.packets_received, 20);
    }

    #[test]
    fn test_session_status_transitions() {
        let config = SessionConfig {
            name: "test".to_string(),
            server: "localhost".to_string(),
            port: 443,
            hub: "DEFAULT".to_string(),
            auth: AuthConfig::Anonymous,
            use_encrypt: true,
            use_compress: false,
            max_connection: 4,
            keep_alive_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(15),
        };

        let session = Session::new(config);
        assert_eq!(session.status(), SessionStatus::Init);

        session.set_status(SessionStatus::Connecting);
        assert_eq!(session.status(), SessionStatus::Connecting);

        session.set_status(SessionStatus::Established);
        assert_eq!(session.status(), SessionStatus::Established);
        assert!(session.is_alive());
    }
}
