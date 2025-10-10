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

        eprintln!("[CONNECT] Establishing TLS connection to {}:{}", self.config.server, self.config.port);
        
        // Establish TLS connection
        let socket = TcpSocket::connect_tls(&self.config.server, self.config.port)?;
        
        eprintln!("[CONNECT] TLS connection established");

        let mut connections = self.tcp_connections.lock().unwrap();
        connections.push(socket);
        drop(connections); // Release lock before handshake

        eprintln!("[CONNECT] Starting handshake...");
        
        // Send initial handshake
        self.send_handshake()?;

        eprintln!("[CONNECT] Handshake complete, authenticating...");

        // Authenticate
        self.set_status(SessionStatus::Authenticating);
        self.authenticate_from_config()?;

        eprintln!("[CONNECT] Authentication complete");

        // Session established
        self.set_status(SessionStatus::Established);

        Ok(())
    }

    /// Send initial handshake
    fn send_handshake(&self) -> Result<()> {
        use crate::protocol::{Packet, PROTOCOL_VERSION, WATERMARK};
        use mayaqua::HttpRequest;

        // NOTE: Protocol signature is NOT sent in HTTP mode!
        // In HTTP mode, we wrap everything in HTTP POST request.
        // The signature is only sent in raw TCP mode.
        eprintln!("[HANDSHAKE] Creating hello packet (HTTP mode - no signature)");
        
        // Step 2: Create hello packet with client information
        let hello_packet = Packet::new("hello")
            .add_string("client_str", "Cedar-Zig-Client/1.0")
            .add_int("version", PROTOCOL_VERSION)
            .add_int("build", 9999)
            .add_bool("use_encrypt", self.config.use_encrypt)
            .add_bool("use_compress", self.config.use_compress)
            .add_int("max_connection", self.config.max_connection);

        // Step 3: Serialize packet to binary PACK format
        let pack_data = hello_packet.to_bytes()?;
        eprintln!("[HANDSHAKE] Serialized PACK data: {} bytes", pack_data.len());

        // Step 4: Prepend watermark to PACK data
        // Server expects: WATERMARK + PACK (not just PACK alone)
        let mut body = Vec::with_capacity(WATERMARK.len() + pack_data.len());
        body.extend_from_slice(WATERMARK);
        body.extend_from_slice(&pack_data);
        eprintln!("[HANDSHAKE] Total body with watermark: {} bytes (watermark: {} + pack: {})", 
                 body.len(), WATERMARK.len(), pack_data.len());

        // Step 5: Wrap in HTTP POST request
        let http_request = HttpRequest::new_vpn_post(
            &self.config.server,
            self.config.port,
            body
        );
        
        eprintln!("[HANDSHAKE] Sending HTTP POST to /vpnsvc/vpn.cgi");
        eprintln!("[HTTP] Content-Type: application/octet-stream");
        eprintln!("[HTTP] Content-Length: {} bytes", http_request.body.len());
        
        // Debug: Print actual HTTP headers being sent
        eprintln!("[HTTP] Headers being sent:");
        for (name, value) in &http_request.headers {
            eprintln!("[HTTP]   {}: {}", name, value);
        }
        
        // Step 5: Send HTTP request (headers + binary body)
        let http_bytes = http_request.to_bytes();
        self.send_raw(&http_bytes)?;
        
        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
                eprintln!("[HANDSHAKE] HTTP request sent and flushed");
            }
        }

        eprintln!("[HANDSHAKE] Waiting for HTTP response from server...");
        
        // Step 6: Receive HTTP response
        let response = self.receive_http_response()?;

        eprintln!("[HTTP] Response: {} {}", response.status_code, 
                 response.headers.get("content-type").unwrap_or(&"unknown".to_string()));
        eprintln!("[HTTP] Body: {} bytes", response.body.len());

        // Debug: Print error body if not 200 OK
        if response.status_code != 200 {
            eprintln!("[HTTP] Error response body:");
            if let Ok(body_str) = String::from_utf8(response.body.clone()) {
                eprintln!("{}", body_str);
            }
            return Err(Error::InvalidResponse);
        }

        // Step 7: Parse PACK from HTTP response body
        let server_hello = Packet::from_bytes(&response.body)?;

        eprintln!("[HANDSHAKE] Received server hello packet");
        
        // Step 8: Extract and validate server information
        let server_str = server_hello
            .get_string("server_str")
            .ok_or(Error::InvalidResponse)?;
        
        let server_version = server_hello
            .get_int("version")
            .ok_or(Error::InvalidResponse)?;

        eprintln!("[HANDSHAKE] Server: {} (version: {})", server_str, server_version);

        // Validate protocol version compatibility
        if server_version != PROTOCOL_VERSION {
            eprintln!("[HANDSHAKE] WARNING: Version mismatch - Client: {}, Server: {}",
                    PROTOCOL_VERSION, server_version);
        }

        Ok(())
    }

    /// Internal authentication helper using config
    fn authenticate_from_config(&self) -> Result<()> {
        // TODO: Implement authentication based on AuthConfig
        match &self.config.auth {
            AuthConfig::Anonymous => {
                // Anonymous authentication
                Ok(())
            }
            AuthConfig::Password { username, password } => {
                // Password-based authentication
                let hash = mayaqua::crypto::softether_password_hash(password, username);
                // Call public authenticate with username and hash
                self.authenticate(username, &hash)
            }
            AuthConfig::Certificate { .. } => {
                // Certificate-based authentication
                // TODO: Implement certificate auth
                Err(Error::NotImplemented)
            }
        }
    }

    /// Internal method: Send raw data without status check (for handshake)
    fn send_raw(&self, data: &[u8]) -> Result<usize> {
        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.is_empty() {
            return Err(Error::NotConnected);
        }

        // Send through first connection
        let sent = connections[0].send(data)?;

        // Update statistics
        let mut stats = self.stats.lock().unwrap();
        stats.update_send(sent, 1);

        Ok(sent)
    }

    /// Internal method: Receive raw data without status check (for handshake)
    fn recv_raw(&self, buffer: &mut [u8]) -> Result<usize> {
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

    /// Internal method: Send packet without status check (for handshake)
    fn send_packet_raw(&self, packet: &Packet) -> Result<()> {
        let data = packet.to_bytes()?;

        // Send packet size first (4 bytes, big-endian)
        let size_bytes = (data.len() as u32).to_be_bytes();
        self.send_raw(&size_bytes)?;

        // Then send packet data
        self.send_raw(&data)?;

        Ok(())
    }

    /// Internal method: Receive packet without status check (for handshake)
    fn receive_packet_raw(&self) -> Result<Packet> {
        // Read packet size first (4 bytes)
        let mut size_buf = [0u8; 4];
        self.recv_raw(&mut size_buf)?;
        let packet_size = u32::from_be_bytes(size_buf) as usize;

        // Validate packet size
        if packet_size == 0 || packet_size > 16 * 1024 * 1024 {
            // Max 16MB
            return Err(Error::InvalidPacketSize);
        }

        // Read packet data
        let mut packet_data = vec![0u8; packet_size];
        let mut total_received = 0;
        while total_received < packet_size {
            let received = self.recv_raw(&mut packet_data[total_received..])?;
            if received == 0 {
                return Err(Error::DisconnectedError);
            }
            total_received += received;
        }

        // Parse packet
        Packet::from_bytes(&packet_data)
    }

    /// Internal method: Receive HTTP response (for handshake)
    fn receive_http_response(&self) -> Result<mayaqua::HttpResponse> {
        use std::io::BufRead;
        
        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.is_empty() {
            return Err(Error::NotConnected);
        }

        // Read HTTP response line by line
        let mut response_data = Vec::new();
        let mut buffer = [0u8; 1];
        let mut line = Vec::new();
        let mut headers_done = false;
        let mut content_length = 0;

        // Read status line and headers
        while !headers_done {
            let n = connections[0].recv(&mut buffer)?;
            if n == 0 {
                return Err(Error::DisconnectedError);
            }
            
            response_data.push(buffer[0]);
            line.push(buffer[0]);
            
            // Check for end of line
            if line.len() >= 2 && line[line.len()-2] == b'\r' && line[line.len()-1] == b'\n' {
                let line_str = String::from_utf8_lossy(&line[..line.len()-2]);
                
                // Check for end of headers (empty line)
                if line_str.is_empty() {
                    headers_done = true;
                } else if line_str.to_lowercase().starts_with("content-length:") {
                    // Extract content length
                    if let Some(len_str) = line_str.split(':').nth(1) {
                        content_length = len_str.trim().parse().unwrap_or(0);
                    }
                }
                
                line.clear();
            }
        }

        // Read body based on content-length
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            let mut total_read = 0;
            while total_read < content_length {
                let n = connections[0].recv(&mut body[total_read..])?;
                if n == 0 {
                    return Err(Error::DisconnectedError);
                }
                total_read += n;
            }
            response_data.extend_from_slice(&body);
        }

        // Parse HTTP response from the collected data
        let mut cursor = std::io::Cursor::new(response_data);
        mayaqua::HttpResponse::from_stream(&mut cursor)
            .map_err(|e| Error::InvalidResponse)
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

    /// Send protocol packet over session
    pub fn send_packet(&self, packet: &Packet) -> Result<()> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        // Serialize packet to bytes
        let data = packet.to_bytes()?;

        // Send packet size first (4 bytes, big-endian)
        let size_bytes = (data.len() as u32).to_be_bytes();
        self.send(&size_bytes)?;

        // Then send packet data
        self.send(&data)?;

        Ok(())
    }

    /// Receive protocol packet from session
    pub fn receive_packet(&self) -> Result<Packet> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        // Read packet size first (4 bytes)
        let mut size_buf = [0u8; 4];
        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.is_empty() {
            return Err(Error::NotConnected);
        }

        connections[0].recv(&mut size_buf)?;
        let packet_size = u32::from_be_bytes(size_buf) as usize;

        // Validate packet size
        if packet_size == 0 || packet_size > 16 * 1024 * 1024 {
            // Max 16MB
            return Err(Error::InvalidPacketSize);
        }

        // Read packet data
        let mut packet_data = vec![0u8; packet_size];
        connections[0].recv(&mut packet_data)?;

        // Deserialize packet
        Packet::from_bytes(&packet_data)
    }

    /// Authenticate with server using username and password hash
    /// hash should be SHA-1 hash of the password (20 bytes)
    pub fn authenticate(&self, username: &str, hash: &[u8]) -> Result<()> {
        if hash.len() != 20 {
            return Err(Error::InvalidParameter);
        }

        // Create authentication packet (using builder pattern)
        let auth_packet = Packet::new("auth")
            .add_string("username", username)
            .add_data("password_hash", hash.to_vec());

        // Send authentication packet
        self.send_packet(&auth_packet)?;

        // Receive authentication response
        let response = self.receive_packet()?;

        // Check if authentication succeeded
        let success = response.get_bool("authenticated").unwrap_or(false);
        if success {
            Ok(())
        } else {
            Err(Error::AuthenticationFailed)
        }
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
