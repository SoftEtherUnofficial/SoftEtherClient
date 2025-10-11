//! Session Management Module
//!
//! Handles VPN session lifecycle, state management, and connection coordination.

use crate::constants::*;
use crate::protocol::{Packet, PROTOCOL_VERSION};
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
    /// Server random challenge (20 bytes from handshake)
    server_random: Arc<Mutex<Option<Vec<u8>>>>,
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
            server_random: Arc::new(Mutex::new(None)),
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

        eprintln!("[CONNECT] ✅ Connection established! Status: {:?}", self.status());
        eprintln!("[CONNECT] Ready to start session loop");

        // Start session loop (packet forwarding + keep-alive)
        eprintln!("[CONNECT] Starting session loop...");
        self.run_session()?;

        Ok(())
    }

    /// Send initial handshake
    fn send_handshake(&self) -> Result<()> {
        use crate::protocol::WATERMARK;
        use mayaqua::HttpRequest;
        use std::time::SystemTime;

        // CRITICAL FIX: Based on SoftEtherRust working implementation
        // Send ONLY watermark + random padding (no PACK!) with Content-Type: image/jpeg
        // Server will respond with hello PACK containing server_random
        // Add random padding (up to 2000 bytes) like Go and SoftEtherRust clients
        const HTTP_PACK_RAND_SIZE_MAX: usize = 1000;
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as usize;
        let rand_size = timestamp % (HTTP_PACK_RAND_SIZE_MAX * 2);
        
        let mut body = Vec::with_capacity(WATERMARK.len() + rand_size);
        body.extend_from_slice(WATERMARK);
        if rand_size > 0 {
            body.extend(std::iter::repeat(0u8).take(rand_size));
        }

        let http_request = HttpRequest::new_handshake_post(
            &self.config.server,
            self.config.port,
            body
        );
        
        let http_bytes = http_request.to_bytes();
        self.send_raw(&http_bytes)?;
        
        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
            }
        }
        
        let response = self.receive_http_response()?;

        if response.status_code != 200 {
            eprintln!("[HANDSHAKE] ❌ Server returned HTTP {}", response.status_code);
            return Err(Error::InvalidResponse);
        }

        let pack_data = if response.body.len() > WATERMARK.len() && 
                          &response.body[0..6] == &WATERMARK[0..6] {
            &response.body[WATERMARK.len()..]
        } else {
            &response.body[..]
        };

        let server_hello = Packet::from_bytes(pack_data)?;

        eprintln!("[HANDSHAKE] Received server hello packet");
        
        let server_str = server_hello
            .get_string("hello")
            .ok_or(Error::InvalidResponse)?;
        
        let server_version = server_hello
            .get_int("version")
            .ok_or(Error::InvalidResponse)?;
        
        let server_build = server_hello
            .get_int("build")
            .unwrap_or(0);

        // Store server random challenge for authentication
        if let Some(random_data) = server_hello.get_data("random") {
            *self.server_random.lock().unwrap() = Some(random_data.to_vec());
        }

        eprintln!("[HANDSHAKE] ✅ Server: {} (v{}, build {})", 
                 server_str, server_version, server_build);

        Ok(())
    }

    fn authenticate_from_config(&self) -> Result<()> {
        use crate::protocol::{Packet, WATERMARK};
        use mayaqua::HttpRequest;

        const CLIENT_AUTHTYPE_ANONYMOUS: u32 = 0;
        const CLIENT_AUTHTYPE_PASSWORD: u32 = 1;
        let auth_packet = match &self.config.auth {
            AuthConfig::Anonymous => {
                Packet::new("auth")
                    .add_string("method", "login")
                    .add_string("hubname", &self.config.hub)
                    .add_string("username", "")
                    .add_int("authtype", CLIENT_AUTHTYPE_ANONYMOUS)
            }
            AuthConfig::Password { username, password } => {
                // Get password hash
                let password_hash: Vec<u8> = if password.starts_with("SHA:") || password.contains("=") {
                    let hash_b64 = password.trim_start_matches("SHA:");
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.decode(hash_b64)
                        .map_err(|_| Error::InvalidParameter)?
                } else {
                    mayaqua::crypto::softether_password_hash(password, username).to_vec()
                };

                // Get server random challenge
                let server_random = self.server_random.lock().unwrap()
                    .clone()
                    .ok_or(Error::InvalidResponse)?;
                
                // Compute secure_password = SHA-0(password_hash || server_random)
                let mut combined = Vec::with_capacity(password_hash.len() + server_random.len());
                combined.extend_from_slice(&password_hash);
                combined.extend_from_slice(&server_random);
                let secure_token = mayaqua::crypto::sha0(&combined).to_vec();
                
                let client_str = "SoftEther VPN Client";
                let protocol_ver = 444;
                let client_build = 9807;
                
                // Get hostname for environment fields
                let hostname = hostname::get()
                    .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
                    .to_string_lossy()
                    .to_string();
                
                let os_name = std::env::consts::OS;
                
                // Unique ID (20 random bytes)
                let unique_id = Self::generate_unique_id();
                
                // Build minimal auth packet matching softether-rust
                let packet = Packet::new("auth")
                    // Core auth fields
                    .add_string("method", "login")
                    .add_int("version", protocol_ver)  // 444
                    .add_int("build", client_build)    // 9807
                    .add_string("client_str", client_str)
                    .add_string("hubname", &self.config.hub)
                    .add_string("username", username)
                    .add_string("protocol", "SE-VPN4-PROTOCOL")
                    .add_int("max_connection", self.config.max_connection)
                    .add_int("use_encrypt", if self.config.use_encrypt { 1 } else { 0 })
                    .add_int("use_compress", if self.config.use_compress { 1 } else { 0 })
                    .add_int("half_connection", 0)
                    .add_int("authtype", CLIENT_AUTHTYPE_PASSWORD)  // 1 = password
                    .add_data("secure_password", secure_token)
                    .add_int("client_id", 123)  // Match softether-rust
                    .add_data("unique_id", unique_id)
                    // Environment info (lowercase versions)
                    .add_string("client_os_name", os_name)
                    .add_string("client_hostname", &hostname)
                    .add_string("client_product_name", client_str)
                    .add_int("client_product_ver", protocol_ver)
                    .add_int("client_product_build", client_build)
                    // Capitalized versions (softether-rust sends both)
                    .add_string("ClientOsName", os_name)
                    .add_string("ClientHostname", &hostname)
                    .add_string("ClientProductName", client_str)
                    .add_int("ClientProductVer", protocol_ver)
                    .add_int("ClientProductBuild", client_build)
                    // Branding field
                    .add_string("branded_ctos", "");
                
                eprintln!("[AUTH] ✅ Created MINIMAL auth pack (25 fields, matching softether-rust)");
                packet
            }
            AuthConfig::Certificate { username, cert_data } => {
                eprintln!("[AUTH] Using certificate authentication");
                Packet::new("auth")
                    .add_string("method", "cert")
                    .add_string("hubname", &self.config.hub)
                    .add_string("username", username)
                    .add_data("cert_data", cert_data.clone())
            }
        };

        let pack_data = auth_packet.to_bytes()?;

        // Send via HTTP POST
        let http_request = HttpRequest::new_vpn_post(
            &self.config.server,
            self.config.port,
            pack_data
        );

        let http_bytes = http_request.to_bytes();
        self.send_raw(&http_bytes)?;

        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
            }
        }
        
        // Receive HTTP response
        let response = self.receive_http_response()?;

        if response.status_code != 200 {
            eprintln!("[AUTH] ❌ Authentication failed: HTTP {}", response.status_code);
            return Err(Error::AuthenticationFailed);
        }

        // Strip watermark if present
        let pack_data = if response.body.len() > WATERMARK.len() && 
                          &response.body[0..6] == &WATERMARK[0..6] {
            &response.body[WATERMARK.len()..]
        } else {
            &response.body[..]
        };

        // Parse response packet
        let auth_response = Packet::from_bytes(pack_data)?;

        // Check authentication result
        if let Some(error_code) = auth_response.get_int("error") {
            if error_code != 0 {
                eprintln!("[AUTH] ❌ Authentication failed - error code: {}", error_code);
                return Err(Error::AuthenticationFailed);
            }
        }

        eprintln!("[AUTH] ✅ Authentication successful");

        eprintln!("[AUTH] 🎉 Authentication phase complete!");

        Ok(())
    }

    /// Run session loop (packet forwarding + keep-alive)
    pub fn run_session(&self) -> Result<()> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        eprintln!("[SESSION] Starting session loop");
        eprintln!("[SESSION] Session established - ready for packet forwarding");
        eprintln!("[SESSION] Keep-alive interval: {:?}", self.config.keep_alive_interval);
        eprintln!();
        eprintln!("[SESSION] \u{1f4a1} TUN/TAP Integration Ready!");
        eprintln!("[SESSION] To enable full VPN tunnel:");
        eprintln!("[SESSION]   1. Run as root/sudo for TUN device permissions");
        eprintln!("[SESSION]   2. Uncomment TUN/TAP code in client.zig");
        eprintln!("[SESSION]   3. Forward packets through tunnel");
        eprintln!();

        let mut last_keepalive = Instant::now();
        let mut packet_count = 0u64;
        let start_time = Instant::now();

        loop {
            // Check connection status
            if !self.is_alive() {
                eprintln!("[SESSION] Connection lost, exiting session loop");
                break;
            }

            // Send keep-alive if needed
            if last_keepalive.elapsed() >= self.config.keep_alive_interval {
                let elapsed = start_time.elapsed();
                eprintln!("[SESSION] \u{1f493} Keep-alive (session uptime: {:?})", elapsed);
                if let Err(e) = self.send_keepalive() {
                    eprintln!("[SESSION] \u{26a0}\u{fe0f}  Keep-alive failed: {:?}", e);
                    break;
                }
                last_keepalive = Instant::now();
            }

            // Try to receive data packets from server
            // This would normally forward to TUN device
            match self.try_receive_data_packet() {
                Ok(Some((packet_type, size))) => {
                    eprintln!("[SESSION] \u{1f4e6} Received {} bytes (type: {})", size, packet_type);
                    packet_count += 1;
                }
                Ok(None) => {
                    // No packet available (normal)
                }
                Err(e) => {
                    eprintln!("[SESSION] \u{26a0}\u{fe0f}  Receive error: {:?}", e);
                    // Don't break on receive errors - might be transient
                }
            }

            // Statistics every 30 seconds
            if packet_count > 0 && packet_count % 100 == 0 {
                let elapsed = start_time.elapsed();
                let stats = self.stats();
                eprintln!("[SESSION] \u{1f4ca} Statistics:");
                eprintln!("[SESSION]   Uptime:     {:?}", elapsed);
                eprintln!("[SESSION]   Packets RX: {}", stats.packets_received);
                eprintln!("[SESSION]   Packets TX: {}", stats.packets_sent);
                eprintln!("[SESSION]   Bytes RX:   {}", stats.bytes_received);
                eprintln!("[SESSION]   Bytes TX:   {}", stats.bytes_sent);
            }

            // Small delay to prevent CPU spinning
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let elapsed = start_time.elapsed();
        eprintln!("[SESSION] Session ended after {:?}", elapsed);
        Ok(())
    }

    /// Try to receive a data packet from server (non-blocking)
    /// Returns Some((packet_type, size)) if packet received, None if no packet available
    fn try_receive_data_packet(&self) -> Result<Option<(String, usize)>> {
        // For now, just return None since we don't have non-blocking receive implemented
        // This will be replaced with proper TUN/TAP integration
        // TODO: Implement non-blocking packet receive from server
        Ok(None)
    }

    /// Send keep-alive packet to maintain connection
    fn send_keepalive(&self) -> Result<()> {
        use mayaqua::HttpRequest;

        eprintln!("[KEEPALIVE] Creating keep-alive packet");

        // Create keep-alive PACK
        let keepalive_packet = Packet::new("keep_alive")
            .add_string("method", "keepalive")
            .add_int("timestamp", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32);

        let pack_data = keepalive_packet.to_bytes()?;
        eprintln!("[KEEPALIVE] PACK data: {} bytes", pack_data.len());

        // Send via HTTP POST
        let http_request = HttpRequest::new_vpn_post(
            &self.config.server,
            self.config.port,
            pack_data,
        );

        let http_bytes = http_request.to_bytes();
        self.send_raw(&http_bytes)?;

        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
            }
        }

        eprintln!("[KEEPALIVE] ✅ Keep-alive sent");

        // Receive keep-alive response
        let response = self.receive_http_response()?;
        if response.status_code != 200 {
            eprintln!("[KEEPALIVE] ❌ Server returned HTTP {}", response.status_code);
            return Err(Error::InvalidResponse);
        }

        eprintln!("[KEEPALIVE] ✅ Keep-alive acknowledged by server");
        Ok(())
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

    // ========================================================================
    // Helper methods for NodeInfo and WinVer
    // ========================================================================

    /// Generate OS version string
    fn get_os_version() -> String {
        #[cfg(target_os = "macos")]
        {
            // Try to get macOS version
            use std::process::Command;
            if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    return format!("macOS {}", version.trim());
                }
            }
            "macOS Unknown".to_string()
        }
        #[cfg(target_os = "linux")]
        {
            // Try to read /etc/os-release
            if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
                for line in contents.lines() {
                    if line.starts_with("PRETTY_NAME=") {
                        let name = line.trim_start_matches("PRETTY_NAME=").trim_matches('"');
                        return name.to_string();
                    }
                }
            }
            "Linux Unknown".to_string()
        }
        #[cfg(target_os = "windows")]
        {
            "Windows".to_string()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            "Unknown OS".to_string()
        }
    }

    /// Generate unique machine ID (20 bytes) matching C Bridge algorithm
    /// 
    /// CRITICAL: Must match GenerateMachineUniqueHash() from Protocol.c exactly:
    /// - Input components: hostname + IP hash + OS type + kernel info + OS details
    /// - Hash algorithm: SHA-1 (20 bytes)
    /// 
    /// C Bridge algorithm (Protocol.c:1555-1595):
    /// 1. Get IP address list hash (8 bytes)
    /// 2. Get machine name
    /// 3. Get OS info (type, kernel, version, product, service pack, system, vendor)
    /// 4. Hash all components together with SHA-1
    fn generate_unique_id() -> Vec<u8> {
        use sha1::{Sha1, Digest};
        let mut hasher = Sha1::new();
        
        // 1. Machine name (matches GetMachineName())
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.as_encoded_bytes());
        } else {
            hasher.update(b"unknown");
        }
        
        // 2. IP address list hash (matches GetHostIPAddressListHash())
        // C Bridge hashes all local IP addresses together
        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            // Simplified version: hash primary interface IPs
            // TODO: Implement full GetHostIPAddressListHash() equivalent
            use std::net::{UdpSocket, IpAddr};
            
            // Get local IP by connecting to 8.8.8.8:80 (doesn't actually send data)
            if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                if let Ok(_) = socket.connect("8.8.8.8:80") {
                    if let Ok(local_addr) = socket.local_addr() {
                        match local_addr.ip() {
                            IpAddr::V4(ipv4) => {
                                hasher.update(&ipv4.octets());
                            }
                            IpAddr::V6(ipv6) => {
                                hasher.update(&ipv6.octets());
                            }
                        }
                    }
                }
            }
        }
        
        // 3. OS type (matches osinfo->OsType)
        #[cfg(target_os = "macos")]
        {
            hasher.update(&3u32.to_le_bytes());  // OSTYPE_MACOS_X = 3
            hasher.update(b"Darwin");  // Kernel name
            
            // Get macOS version for kernel version
            use std::process::Command;
            if let Ok(output) = Command::new("uname").arg("-r").output() {
                if let Ok(kernel_ver) = String::from_utf8(output.stdout) {
                    hasher.update(kernel_ver.trim().as_bytes());
                }
            } else {
                hasher.update(b"unknown");
            }
            
            // OS product name
            if let Ok(output) = Command::new("sw_vers").arg("-productName").output() {
                if let Ok(product) = String::from_utf8(output.stdout) {
                    hasher.update(product.trim().as_bytes());
                }
            }
            
            // Service pack (0 for macOS)
            hasher.update(&0u32.to_le_bytes());
            
            // OS system name (same as product)
            hasher.update(b"macOS");
            
            // OS vendor
            hasher.update(b"Apple Inc.");
            
            // OS version
            if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    hasher.update(version.trim().as_bytes());
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            hasher.update(&1u32.to_le_bytes());  // OSTYPE_LINUX = 1
            hasher.update(b"Linux");  // Kernel name
            
            // Get kernel version
            use std::process::Command;
            if let Ok(output) = Command::new("uname").arg("-r").output() {
                if let Ok(kernel_ver) = String::from_utf8(output.stdout) {
                    hasher.update(kernel_ver.trim().as_bytes());
                }
            } else {
                hasher.update(b"unknown");
            }
            
            // Try to get distro info from /etc/os-release
            if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
                for line in contents.lines() {
                    if line.starts_with("NAME=") {
                        let name = line.trim_start_matches("NAME=").trim_matches('"');
                        hasher.update(name.as_bytes());
                        break;
                    }
                }
            } else {
                hasher.update(b"Linux");
            }
            
            hasher.update(&0u32.to_le_bytes());  // Service pack = 0
            hasher.update(b"Linux");  // System name
            hasher.update(b"Linux");  // Vendor
            
            // Version from /etc/os-release
            if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
                for line in contents.lines() {
                    if line.starts_with("VERSION_ID=") {
                        let version = line.trim_start_matches("VERSION_ID=").trim_matches('"');
                        hasher.update(version.as_bytes());
                        break;
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            hasher.update(&2u32.to_le_bytes());  // OSTYPE_WINDOWS_NT = 2
            hasher.update(b"Windows NT");  // Kernel name
            // TODO: Get actual Windows version info
            hasher.update(b"10.0");  // Kernel version
            hasher.update(b"Windows");  // Product
            hasher.update(&0u32.to_le_bytes());  // Service pack
            hasher.update(b"Windows");  // System
            hasher.update(b"Microsoft Corporation");  // Vendor
            hasher.update(b"10");  // Version
        }
        
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            // Fallback for unsupported OS
            hasher.update(&0u32.to_le_bytes());  // OSTYPE_UNKNOWN = 0
            hasher.update(b"Unknown");
            hasher.update(b"Unknown");
            hasher.update(b"Unknown");
            hasher.update(&0u32.to_le_bytes());
            hasher.update(b"Unknown");
            hasher.update(b"Unknown");
            hasher.update(b"Unknown");
        }
        
        hasher.finalize().to_vec()
    }

    /// Get local address from socket
    fn get_local_address(stream: &TcpSocket) -> ([u8; 4], u32) {
        if let Ok(addr) = stream.local_addr() {
            match addr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    return (ipv4.octets(), addr.port() as u32);
                }
                _ => {}
            }
        }
        ([0, 0, 0, 0], 0)
    }

    /// Get peer address from socket
    fn get_peer_address(stream: &TcpSocket) -> ([u8; 4], u32) {
        if let Ok(addr) = stream.peer_addr() {
            match addr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    return (ipv4.octets(), addr.port() as u32);
                }
                _ => {}
            }
        }
        ([0, 0, 0, 0], 0)
    }

    /// Get Windows version info (adapted for cross-platform)
    /// Returns: (os_type, service_pack, build, system_name, product_name)
    fn get_win_ver_info() -> (u32, u32, u32, String, String) {
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    let v = version.trim();
                    let parts: Vec<&str> = v.split('.').collect();
                    let major = parts.get(0).and_then(|s| s.parse::<u32>().ok()).unwrap_or(10);
                    let build = parts.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
                    return (major, 0, build, format!("macOS {}", v), "macOS".to_string());
                }
            }
            (10, 0, 0, "macOS".to_string(), "macOS".to_string())
        }
        #[cfg(target_os = "linux")]
        {
            (0, 0, 0, "Linux".to_string(), "Linux".to_string())
        }
        #[cfg(target_os = "windows")]
        {
            (10, 0, 0, "Windows".to_string(), "Windows".to_string())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            (0, 0, 0, "Unknown".to_string(), "Unknown".to_string())
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
