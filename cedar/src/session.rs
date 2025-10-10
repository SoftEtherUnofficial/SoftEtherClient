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
        
        eprintln!("[HANDSHAKE] Sending HTTP POST to /vpnsvc/connect.cgi");
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

        // Debug: Show response body (first 100 bytes)
        eprintln!("[HTTP] Response body (first 100 bytes): {:02X?}", 
                 &response.body[..response.body.len().min(100)]);

        // Step 7: Handle watermark in response (may or may not be present)
        // Server sends watermark (1411 bytes) + PACK in initial handshake
        // But may send PACK directly in subsequent responses
        let pack_data = if response.body.len() > WATERMARK.len() && 
                          &response.body[0..6] == &WATERMARK[0..6] {
            eprintln!("[HANDSHAKE] Detected watermark, stripping {} bytes", WATERMARK.len());
            &response.body[WATERMARK.len()..]
        } else {
            eprintln!("[HANDSHAKE] No watermark detected, parsing {} bytes of PACK data directly", response.body.len());
            &response.body[..]
        };

        // Step 8: Parse PACK from HTTP response body
        eprintln!("[HANDSHAKE] Attempting to parse PACK from {} bytes", pack_data.len());
        eprintln!("[HANDSHAKE] First 50 bytes: {:02X?}", &pack_data[..pack_data.len().min(50)]);
        
        let server_hello = match Packet::from_bytes(pack_data) {
            Ok(packet) => {
                eprintln!("[HANDSHAKE] ✅ PACK parsed successfully");
                packet
            },
            Err(e) => {
                eprintln!("[HANDSHAKE] ❌ PACK parsing failed: {:?}", e);
                return Err(e);
            }
        };

        eprintln!("[HANDSHAKE] Received server hello packet");
        
        // Step 9: Extract and validate server information
        let server_str = server_hello
            .get_string("hello")
            .ok_or(Error::InvalidResponse)?;
        
        let server_version = server_hello
            .get_int("version")
            .ok_or(Error::InvalidResponse)?;
        
        let server_build = server_hello
            .get_int("build")
            .unwrap_or(0);

        // CRITICAL: Extract server random challenge for authentication
        if let Some(random_data) = server_hello.get_data("random") {
            eprintln!("[HANDSHAKE] Received server random: {} bytes", random_data.len());
            *self.server_random.lock().unwrap() = Some(random_data.to_vec());
        } else {
            eprintln!("[HANDSHAKE] WARNING: No random challenge received from server");
        }

        eprintln!("[HANDSHAKE] ✅ Server: {} (version: {}, build: {})", 
                 server_str, server_version, server_build);
        eprintln!("[HANDSHAKE] Protocol handshake completed successfully!");

        // Validate protocol version compatibility
        if server_version != PROTOCOL_VERSION {
            eprintln!("[HANDSHAKE] WARNING: Version mismatch - Client: {}, Server: {}",
                    PROTOCOL_VERSION, server_version);
        }

        Ok(())
    }

    /// Internal authentication helper using config
    fn authenticate_from_config(&self) -> Result<()> {
        use crate::protocol::{Packet, WATERMARK};
        use mayaqua::HttpRequest;

        eprintln!("[AUTH] Starting authentication phase");

        // Create authentication packet based on config
        const CLIENT_AUTHTYPE_ANONYMOUS: u32 = 0;
        const CLIENT_AUTHTYPE_PASSWORD: u32 = 1;
        
        let auth_packet = match &self.config.auth {
            AuthConfig::Anonymous => {
                eprintln!("[AUTH] Using anonymous authentication");
                Packet::new("auth")
                    .add_string("method", "login")
                    .add_string("hubname", &self.config.hub)
                    .add_string("username", "")
                    .add_int("authtype", CLIENT_AUTHTYPE_ANONYMOUS)
            }
            AuthConfig::Password { username, password } => {
                eprintln!("[AUTH] Using password authentication for user: {}", username);
                
                // Get password hash (SHA-0)
                let password_hash: Vec<u8> = if password.starts_with("SHA:") || password.contains("=") {
                    // Already a base64-encoded hash
                    eprintln!("[AUTH] Using pre-hashed password");
                    let hash_b64 = password.trim_start_matches("SHA:");
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.decode(hash_b64)
                        .map_err(|_| Error::InvalidParameter)?
                } else {
                    // Hash the password (SHA-0 with username as salt)
                    eprintln!("[AUTH] Hashing password");
                    mayaqua::crypto::softether_password_hash(password, username).to_vec()
                };

                eprintln!("[AUTH] Password hash length: {} bytes", password_hash.len());
                eprintln!("[AUTH] Password hash (hex): {}", password_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>());

                // Get server random challenge (CRITICAL for authentication)
                let server_random = self.server_random.lock().unwrap()
                    .clone()
                    .ok_or(Error::InvalidResponse)?;
                
                eprintln!("[AUTH] Using server random: {} bytes", server_random.len());
                eprintln!("[AUTH] Server random (hex): {}", server_random.iter().map(|b| format!("{:02x}", b)).collect::<String>());

                // Compute secure_password = SHA-0(password_hash || server_random)
                // This is the SecurePassword() function from Sam.c
                // CRITICAL: SoftEther uses SHA-0 (not SHA-1!) for authentication!
                let mut combined = Vec::with_capacity(password_hash.len() + server_random.len());
                combined.extend_from_slice(&password_hash);
                combined.extend_from_slice(&server_random);
                let secure_token = mayaqua::crypto::sha0(&combined).to_vec();

                eprintln!("[AUTH] Secure token computed: {} bytes", secure_token.len());
                eprintln!("[AUTH] Secure token (hex): {}", secure_token.iter().map(|b| format!("{:02x}", b)).collect::<String>());

                // Build auth packet with correct SoftEther format:
                // method="login", authtype=1 (CLIENT_AUTHTYPE_PASSWORD)
                // CRITICAL: Must include all fields that C client sends
                
                let packet = Packet::new("auth")
                    .add_string("method", "login")
                    .add_string("hubname", &self.config.hub)
                    .add_string("username", username)
                    .add_int("authtype", CLIENT_AUTHTYPE_PASSWORD)
                    .add_data("secure_password", secure_token);
                
                // Add client version info (PackAddClientVersion)
                let packet = packet
                    .add_string("client_str", "SoftEther VPN Client")
                    .add_int("client_ver", 444)  // Match C client version
                    .add_int("client_build", 9807); // Match C client build
                
                // Add protocol and hello (required fields)
                let packet = packet
                    .add_int("protocol", 0)
                    .add_string("hello", "SoftEther VPN Client")
                    .add_int("version", 444)
                    .add_int("build", 9807)
                    .add_int("client_id", 0);
                
                // Add connection options that C client sends
                // NOTE: use_encrypt, use_compress, half_connection are Int (0/1), not Bool!
                let packet = packet
                    .add_int("max_connection", self.config.max_connection)
                    .add_int("use_encrypt", if self.config.use_encrypt { 1 } else { 0 })
                    .add_int("use_compress", if self.config.use_compress { 1 } else { 0 })
                    .add_int("half_connection", 0)
                    .add_bool("require_bridge_routing_mode", false)  // Normal VPN client = false
                    .add_bool("require_monitor_mode", false)
                    .add_bool("qos", true)  // Match C: !DisableQoS = true
                    .add_bool("support_bulk_on_rudp", true)
                    .add_bool("support_hmac_on_bulk_of_rudp", true)
                    .add_bool("support_udp_recovery", true);

                // Unique ID (MUST come before NodeInfo)
                let unique_id = Self::generate_unique_id();
                let packet = packet.add_data("unique_id", unique_id);

                // RUDP bulk max version (after unique_id, before NodeInfo)
                let packet = packet.add_int("rudp_bulk_max_version", 2);

                // Generate NodeInfo fields (OutRpcNodeInfo equivalent)
                let hostname = hostname::get()
                    .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
                    .to_string_lossy()
                    .to_string();
                
                // TEMPORARY: Use empty strings to match C client behavior
                // C client sends empty ClientOsName/ClientOsVer on macOS
                let os_name = "";  // was: std::env::consts::OS;
                let os_ver = "";   // was: Self::get_os_version();
                
                let (client_ip, client_port) = {
                    let connections = self.tcp_connections.lock().unwrap();
                    if !connections.is_empty() {
                        Self::get_local_address(&connections[0])
                    } else {
                        ([0, 0, 0, 0], 0)
                    }
                };
                
                let (server_ip, server_port) = {
                    let connections = self.tcp_connections.lock().unwrap();
                    if !connections.is_empty() {
                        Self::get_peer_address(&connections[0])
                    } else {
                        ([0, 0, 0, 0], 0)
                    }
                };

                // Add NodeInfo fields in same order as C bridge
                let packet = packet
                    .add_string("ClientProductName", "SoftEther VPN Client")
                    .add_string("ServerProductName", "")
                    .add_string("ClientOsName", os_name)
                    .add_string("ClientOsVer", os_ver)
                    .add_string("ClientOsProductId", "")
                    .add_string("ClientHostname", &hostname)
                    .add_string("ServerHostname", &self.config.server)
                    .add_string("ProxyHostname", "")
                    .add_string("HubName", &self.config.hub)
                    // UniqueId is the same as unique_id from earlier, not duplicated
                    .add_int("ClientProductVer", 444)
                    .add_int("ClientProductBuild", 9807)
                    .add_int("ServerProductVer", 0)
                    .add_int("ServerProductBuild", 0)
                    // ClientIpAddress with IPv6 variants (PackAddIp adds 3 fields automatically)
                    .add_ip32("ClientIpAddress", client_ip)
                    .add_bool("ClientIpAddress@ipv6_bool", false) // IPv4
                    .add_data("ClientIpAddress@ipv6_array", vec![0u8; 16])
                    .add_int("ClientIpAddress@ipv6_scope_id", 0)
                    .add_data("ClientIpAddress6", vec![0u8; 16])
                    .add_int("ClientPort", client_port)
                    // ServerIpAddress with IPv6 variants
                    .add_ip32("ServerIpAddress", server_ip)
                    .add_bool("ServerIpAddress@ipv6_bool", false) // IPv4
                    .add_data("ServerIpAddress@ipv6_array", vec![0u8; 16])
                    .add_int("ServerIpAddress@ipv6_scope_id", 0)
                    .add_data("ServerIpAddress6", vec![0u8; 16])
                    .add_int("ServerPort2", server_port) // Note: it's "ServerPort2" not "ServerPort"!
                    // ProxyIpAddress with IPv6 variants
                    .add_ip32("ProxyIpAddress", [0, 0, 0, 0])
                    .add_bool("ProxyIpAddress@ipv6_bool", false) // IPv4
                    .add_data("ProxyIpAddress@ipv6_array", vec![0u8; 16])
                    .add_int("ProxyIpAddress@ipv6_scope_id", 0)
                    .add_data("ProxyIpAddress6", vec![0u8; 16])
                    .add_int("ProxyPort", 0);

                // Add WinVer fields (OutRpcWinVer equivalent)
                // CRITICAL: All WinVer fields MUST have "V_" prefix to match C client!
                let (os_type, os_service_pack, os_build, os_system_name, _os_product_name) = Self::get_win_ver_info();
                let packet = packet
                    .add_bool("V_IsWindows", cfg!(target_os = "windows"))
                    .add_bool("V_IsNT", cfg!(target_os = "windows"))
                    .add_bool("V_IsServer", false)
                    .add_bool("V_IsBeta", false)
                    .add_int("V_VerMajor", os_type)
                    .add_int("V_VerMinor", 0)
                    .add_int("V_Build", os_build)
                    .add_int("V_ServicePack", os_service_pack)
                    .add_string("V_Title", &os_system_name);
                
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

        eprintln!("[AUTH] Serializing authentication packet");
        let pack_data = auth_packet.to_bytes()?;
        eprintln!("[AUTH] PACK data: {} bytes", pack_data.len());
        
        // Debug: dump first 512 bytes to compare with C client
        eprintln!("[AUTH] === PACK DATA HEX DUMP (first {} bytes) ===", std::cmp::min(512, pack_data.len()));
        for chunk_start in (0..std::cmp::min(512, pack_data.len())).step_by(16) {
            eprint!("[AUTH]   {:04x}: ", chunk_start);
            for i in 0..16 {
                if chunk_start + i < pack_data.len() {
                    eprint!("{:02X} ", pack_data[chunk_start + i]);
                }
            }
            eprintln!();
        }
        eprintln!("[AUTH] === END PACK DATA HEX DUMP ===");
        
        // Hex dump of PACK data for debugging
        eprintln!("[AUTH] === PACK DATA HEX DUMP (first 512 bytes) ===");
        let dump_len = pack_data.len().min(512);
        for (i, chunk) in pack_data[..dump_len].chunks(16).enumerate() {
            eprint!("[AUTH]   {:04x}:", i * 16);
            for byte in chunk {
                eprint!(" {:02x}", byte);
            }
            eprintln!();
        }
        if pack_data.len() > 512 {
            eprintln!("[AUTH]   ... ({} more bytes)", pack_data.len() - 512);
        }
        eprintln!("[AUTH] === END PACK DATA HEX DUMP ===");

        // Wrap with watermark (like handshake)
        let mut body = Vec::with_capacity(WATERMARK.len() + pack_data.len());
        body.extend_from_slice(WATERMARK);
        body.extend_from_slice(&pack_data);
        eprintln!("[AUTH] Total body with watermark: {} bytes", body.len());

        // Send via HTTP POST
        let http_request = HttpRequest::new_vpn_post(
            &self.config.server,
            self.config.port,
            body
        );

        eprintln!("[AUTH] Sending HTTP POST for authentication");
        let http_bytes = http_request.to_bytes();
        
        // Hex dump of HTTP headers (first 512 bytes)
        eprintln!("[AUTH] === HTTP REQUEST HEX DUMP (first 512 bytes) ===");
        let http_dump_len = http_bytes.len().min(512);
        for (i, chunk) in http_bytes[..http_dump_len].chunks(16).enumerate() {
            eprint!("[AUTH]   {:04x}:", i * 16);
            for byte in chunk {
                eprint!(" {:02x}", byte);
            }
            eprintln!();
        }
        if http_bytes.len() > 512 {
            eprintln!("[AUTH]   ... ({} more bytes)", http_bytes.len() - 512);
        }
        eprintln!("[AUTH] === END HTTP REQUEST HEX DUMP ===");
        
        self.send_raw(&http_bytes)?;

        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
                eprintln!("[AUTH] Authentication request sent and flushed");
            }
        }

        eprintln!("[AUTH] Waiting for authentication response...");
        
        // Receive HTTP response
        let response = self.receive_http_response()?;

        if response.status_code != 200 {
            eprintln!("[AUTH] ❌ Authentication failed: HTTP {}", response.status_code);
            if let Ok(body_str) = String::from_utf8(response.body.clone()) {
                eprintln!("[AUTH] Server response: {}", body_str);
            }
            return Err(Error::AuthenticationFailed);
        }

        eprintln!("[AUTH] HTTP 200 OK - parsing response");

        // Strip watermark if present
        let pack_data = if response.body.len() > WATERMARK.len() && 
                          &response.body[0..6] == &WATERMARK[0..6] {
            eprintln!("[AUTH] Stripping watermark");
            &response.body[WATERMARK.len()..]
        } else {
            &response.body[..]
        };

        // Parse response packet
        eprintln!("[AUTH] Parsing PACK response ({} bytes)", pack_data.len());
        let auth_response = Packet::from_bytes(pack_data)?;

        // Debug: Print ALL fields in the response
        eprintln!("[AUTH] === Response fields ===");
        for (key, value) in &auth_response.params {
            match value {
                crate::protocol::PacketValue::Int(v) => eprintln!("[AUTH]   {} = {} (int)", key, v),
                crate::protocol::PacketValue::String(s) => eprintln!("[AUTH]   {} = {:?} (string)", key, s),
                crate::protocol::PacketValue::Data(d) => eprintln!("[AUTH]   {} = <{} bytes> (data)", key, d.len()),
                crate::protocol::PacketValue::Bool(b) => eprintln!("[AUTH]   {} = {} (bool)", key, b),
                _ => eprintln!("[AUTH]   {} = <other>", key),
            }
        }
        eprintln!("[AUTH] === End response fields ===");

        // Check authentication result
        // Server sends "auth" response with status
        if let Some(error_code) = auth_response.get_int("error") {
            eprintln!("[AUTH] ❌ Authentication failed with error code: {}", error_code);
            if let Some(error_msg) = auth_response.get_string("error_str") {
                eprintln!("[AUTH] Error message: {}", error_msg);
            }
            return Err(Error::AuthenticationFailed);
        }

        // Check for success indicator
        let authenticated = auth_response.get_int("authok").unwrap_or(0) != 0;
        if !authenticated {
            eprintln!("[AUTH] ❌ Authentication rejected by server");
            return Err(Error::AuthenticationFailed);
        }

        eprintln!("[AUTH] ✅ Authentication successful!");

        // Extract session information if provided
        if let Some(session_key) = auth_response.get_data("session_key") {
            eprintln!("[AUTH] Received session key: {} bytes", session_key.len());
        }

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

    /// Generate unique machine ID (20 bytes)
    fn generate_unique_id() -> Vec<u8> {
        use sha1::{Sha1, Digest};
        let mut hasher = Sha1::new();
        
        // Use hostname as base
        if let Ok(hostname) = hostname::get() {
            hasher.update(hostname.as_encoded_bytes());
        }
        
        // Add some system-specific data
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            if let Ok(output) = Command::new("ioreg").args(&["-rd1", "-c", "IOPlatformExpertDevice"]).output() {
                hasher.update(&output.stdout);
            }
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
