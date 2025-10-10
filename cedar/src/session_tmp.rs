//! Session Management Module
//!
//! Handles VPN session lifecycle, state management, and connection coordination.

use crate::constants::*;
use crate::protocol::Packet;
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

        // Establish TLS connection for secure VPN (port 443)
        let socket = TcpSocket::connect_tls(&self.config.server, self.config.port)?;

        let mut connections = self.tcp_connections.lock().unwrap();
        connections.push(socket);

        // Send initial handshake
        self.send_handshake()?;

        // Authenticate
        self.set_status(SessionStatus::Authenticating);
        self.authenticate_from_config()?;

        // Session established
        self.set_status(SessionStatus::Established);

        Ok(())
    }

    /// Send initial handshake
    fn send_handshake(&self) -> Result<()> {
        use crate::protocol::{Packet, PROTOCOL_VERSION, CEDAR_SIGNATURE};

    /// Send initial handshake
    fn send_handshake(&self) -> Result<()> {
        use crate::protocol::{Packet, PROTOCOL_VERSION, CEDAR_SIGNATURE};

        eprintln!("[DEBUG] Sending protocol signature: {}", CEDAR_SIGNATURE);
        
        // Step 1: Send protocol signature (does NOT need newline for SoftEther)
        let bytes_sent = self.send_raw(CEDAR_SIGNATURE.as_bytes())?;
        eprintln!("[DEBUG] Sent {} bytes", bytes_sent);
        
        //  Flush to ensure signature is sent immediately
        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
            }
        }
        eprintln!("[DEBUG] Flushed TCP buffer");

        eprintln!("[DEBUG] Creating hello packet...");
