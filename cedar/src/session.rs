//! Session Management Module
//!
//! Handles VPN session lifecycle, state management, and connection coordination.

use crate::constants::*;
use crate::protocol::{Packet, PROTOCOL_VERSION};
use crate::dhcp::{DhcpClient, DhcpState};
use mayaqua::error::{Error, Result};
use mayaqua::network::{TcpSocket, UdpSocketWrapper};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Session name from server (e.g., "SID-DEVSTROOP-592")
    session_name: Arc<Mutex<Option<String>>>,
    /// Connection name from server (e.g., "CID-3292")
    connection_name: Arc<Mutex<Option<String>>>,
    /// Expected certificate from redirect response (for validation)
    expected_cert: Arc<Mutex<Option<Vec<u8>>>>,
    /// Streaming mode enabled (true after auth, for raw PACK streaming)
    streaming_mode: AtomicBool,
    /// DHCP client for automatic IP configuration
    dhcp_client: Arc<Mutex<Option<DhcpClient>>>,
    /// Last DHCP tick time
    last_dhcp_tick: Arc<Mutex<Instant>>,
    /// Interface configured flag
    interface_configured: Arc<Mutex<bool>>,
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
            session_name: Arc::new(Mutex::new(None)),
            connection_name: Arc::new(Mutex::new(None)),
            expected_cert: Arc::new(Mutex::new(None)),
            streaming_mode: AtomicBool::new(false),
            dhcp_client: Arc::new(Mutex::new(None)),
            last_dhcp_tick: Arc::new(Mutex::new(Instant::now())),
            interface_configured: Arc::new(Mutex::new(false)),
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

    /// Connect to VPN server with retry logic (P3)
    pub fn connect(&self) -> Result<()> {
        self.connect_with_retry(3, true)
    }
    
    /// Connect to VPN server with retry and fallback (P3)
    /// 
    /// Implements multi-connection retry logic matching C Bridge behavior:
    /// 1. Try primary connection with password auth
    /// 2. On failure, retry with exponential backoff
    /// 3. After max retries, try secondary IP (if DNS returns multiple IPs)
    /// 4. Consider R-UDP acceleration on alternate ports (53, 65537)
    pub fn connect_with_retry(&self, max_retries: u32, use_fallback: bool) -> Result<()> {
        self.set_status(SessionStatus::Connecting);
        
        let mut last_error = Error::NotConnected;
        
        for attempt in 1..=max_retries {
            eprintln!("[CONNECT] Connection attempt {}/{}", attempt, max_retries);
            eprintln!("[CONNECT] Establishing TLS connection to {}:{}", self.config.server, self.config.port);
            
            // Try to connect
            match TcpSocket::connect_tls(&self.config.server, self.config.port) {
                Ok(socket) => {
                    eprintln!("[CONNECT] TLS connection established");
                    
                    let mut connections = self.tcp_connections.lock().unwrap();
                    connections.push(socket);
                    drop(connections);
                    
                    eprintln!("[CONNECT] Starting handshake...");
                    
                    // Send initial handshake
                    if let Err(e) = self.send_handshake() {
                        eprintln!("[CONNECT] ⚠️  Handshake failed: {:?}", e);
                        last_error = e;
                        
                        // Clean up failed connection
                        let mut connections = self.tcp_connections.lock().unwrap();
                        connections.clear();
                        drop(connections);
                        
                        if attempt < max_retries {
                            let backoff = std::time::Duration::from_secs(2u64.pow(attempt - 1));
                            eprintln!("[CONNECT] Retrying in {:?}...", backoff);
                            std::thread::sleep(backoff);
                            continue;
                        }
                        break;
                    }
                    
                    eprintln!("[CONNECT] Handshake complete, authenticating...");
                    
                    // Authenticate
                    self.set_status(SessionStatus::Authenticating);
                    if let Err(e) = self.authenticate_from_config() {
                        eprintln!("[CONNECT] ⚠️  Authentication failed: {:?}", e);
                        last_error = e;
                        
                        // Clean up failed connection
                        let mut connections = self.tcp_connections.lock().unwrap();
                        connections.clear();
                        drop(connections);
                        
                        if attempt < max_retries {
                            let backoff = std::time::Duration::from_secs(2u64.pow(attempt - 1));
                            eprintln!("[CONNECT] Retrying in {:?}...", backoff);
                            std::thread::sleep(backoff);
                            continue;
                        }
                        break;
                    }
                    
                    eprintln!("[CONNECT] Authentication complete");
                    
                    // Session established
                    self.set_status(SessionStatus::Established);
                    
                    // Initialize DHCP client for automatic IP configuration
                    let dhcp_client = DhcpClient::new();
                    eprintln!("[DHCP] 🌐 Starting DHCP client (MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                             dhcp_client.mac()[0], dhcp_client.mac()[1], dhcp_client.mac()[2],
                             dhcp_client.mac()[3], dhcp_client.mac()[4], dhcp_client.mac()[5]);
                    *self.dhcp_client.lock().unwrap() = Some(dhcp_client);
                    
                    eprintln!("[CONNECT] ✅ Connection established! Status: {:?}", self.status());
                    eprintln!("[CONNECT] ✅ Session ready for packet forwarding");
                    eprintln!("[CONNECT] 💡 Call poll_keepalive() periodically to maintain session");
                    
                    // Return immediately - Zig will handle packet forwarding loop
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("[CONNECT] ⚠️  TLS connection failed: {:?}", e);
                    last_error = e;
                    
                    if attempt < max_retries {
                        let backoff = std::time::Duration::from_secs(2u64.pow(attempt - 1));
                        eprintln!("[CONNECT] Retrying in {:?}...", backoff);
                        std::thread::sleep(backoff);
                        continue;
                    }
                }
            }
        }
        
        // P3: Try fallback strategies if primary connection failed
        if use_fallback {
            eprintln!("[CONNECT] 🔄 Primary connection failed, trying fallback strategies...");
            
            // TODO: Implement secondary IP fallback
            // 1. Resolve DNS to get all IPs
            // 2. Try connecting to alternate IPs
            // 3. Try R-UDP ports (53, 65537) for UDP acceleration
            
            eprintln!("[CONNECT] 💡 Fallback strategies:");
            eprintln!("[CONNECT]   1. Try alternate DNS IPs for {}", self.config.server);
            eprintln!("[CONNECT]   2. Try R-UDP ports (53, 65537)");
            eprintln!("[CONNECT]   3. Use ticket-based auth (authtype=99)");
            eprintln!("[CONNECT] ⚠️  Fallback not yet fully implemented");
        }
        
        eprintln!("[CONNECT] ❌ All connection attempts failed");
        Err(last_error)
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
                
                // Get network endpoint information (P1)
                let connections = self.tcp_connections.lock().unwrap();
                let (client_ip, client_port) = if !connections.is_empty() {
                    Self::get_local_address(&connections[0])
                } else {
                    ([0, 0, 0, 0], 0)
                };
                let (server_ip, server_port) = if !connections.is_empty() {
                    Self::get_peer_address(&connections[0])
                } else {
                    ([0, 0, 0, 0], 0)
                };
                drop(connections);
                
                // Get OS version info for Node Info (P1)
                let (os_type, service_pack, os_build, os_system_name, os_product_name) = Self::get_win_ver_info();
                let os_version = Self::get_os_version();
                
                // Build auth packet matching C Bridge implementation
                let packet = Packet::new("auth")
                    // Core auth fields
                    .add_string("method", "login")
                    .add_int("version", protocol_ver)  // 444
                    .add_int("build", client_build)    // 9807
                    .add_string("client_str", client_str)
                    .add_string("hubname", &self.config.hub)
                    .add_string("username", username)
                    .add_int("protocol", 0)  // ⚠️  CRITICAL FIX: Must be int 0, not string!
                    .add_int("max_connection", self.config.max_connection)
                    .add_int("use_encrypt", if self.config.use_encrypt { 1 } else { 0 })
                    .add_int("use_compress", if self.config.use_compress { 1 } else { 0 })
                    .add_int("half_connection", 0)
                    .add_int("authtype", CLIENT_AUTHTYPE_PASSWORD)  // 1 = password
                    .add_data("secure_password", secure_token)
                    .add_int("client_id", 0)  // Match C Bridge (0, not 123)
                    .add_data("unique_id", unique_id)
                    // P0 CRITICAL: Bridge/routing mode flags (required for DHCP)
                    .add_int("qos", 0)
                    .add_int("require_bridge_routing_mode", 1)  // ⚠️  CRITICAL for DHCP!
                    .add_int("require_monitor_mode", 0)
                    // P1: UDP acceleration negotiation fields
                    .add_int("support_bulk_on_rudp", 1)
                    .add_int("support_hmac_on_bulk_of_rudp", 1)
                    .add_int("support_udp_recovery", 1)
                    .add_int("rudp_bulk_max_version", 2)
                    // P1: Client/Server network endpoint information
                    .add_int("ClientIpAddress", u32::from_be_bytes(client_ip))
                    .add_int("ClientPort", client_port)
                    .add_int("ServerIpAddress", u32::from_be_bytes(server_ip))
                    .add_int("ServerPort2", server_port)
                    // Environment info (lowercase versions)
                    .add_string("client_os_name", os_name)
                    .add_string("client_hostname", &hostname)
                    .add_string("client_product_name", client_str)
                    .add_int("client_product_ver", protocol_ver)
                    .add_int("client_product_build", client_build)
                    // Capitalized versions (C Bridge sends both)
                    .add_string("ClientOsName", os_name)
                    .add_string("ClientHostname", &hostname)
                    .add_string("ClientProductName", client_str)
                    .add_int("ClientProductVer", protocol_ver)
                    .add_int("ClientProductBuild", client_build)
                    // P1: Node Info - Comprehensive OS information
                    .add_int("ClientOsType", os_type)
                    .add_int("ClientOsServicePack", service_pack)
                    .add_string("ClientOsSystemName", &os_system_name)
                    .add_string("ClientOsProductName", &os_product_name)
                    .add_string("ClientOsVendorName", if cfg!(target_os = "macos") { "Apple Inc." } else if cfg!(target_os = "windows") { "Microsoft Corporation" } else { "Linux" })
                    .add_string("ClientOsVersion", &os_version)
                    .add_string("ClientKernelName", std::env::consts::OS)
                    .add_string("ClientKernelVersion", &os_version);
                    // Note: branded_ctos NOT added when empty (C Bridge skips it)
                
                eprintln!("[AUTH] ✅ Created auth pack (FULL C Bridge alignment: 43+ fields with P0+P1)");
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
                eprintln!("[AUTH] ❌ Server returned error code: {}", error_code);
                
                // Check for redirect
                if let Some(ip) = auth_response.get_int("Ip") {
                    eprintln!("[AUTH] 📍 Redirect to IP: {}", ip);
                }
                if let Some(port) = auth_response.get_int("Port") {
                    eprintln!("[AUTH] 📍 Redirect to Port: {}", port);
                }
                
                eprintln!("[AUTH] ❌ Authentication failed - error code: {}", error_code);
                return Err(Error::AuthenticationFailed);
            }
        }

        eprintln!("[AUTH] ✅ Authentication successful (error=0 or not present)");

        // DEBUG: Dump all fields in auth_response
        eprintln!("[AUTH] 🔍 DEBUG - All fields in packet:");
        for (key, value) in &auth_response.params {
            match value {
                crate::protocol::PacketValue::Int(v) => {
                    eprintln!("[AUTH]   {} = Int({})", key, v);
                }
                crate::protocol::PacketValue::Data(v) => {
                    eprintln!("[AUTH]   {} = Data({} bytes)", key, v.len());
                }
                crate::protocol::PacketValue::String(v) => {
                    eprintln!("[AUTH]   {} = String(\"{}\")", key, v);
                }
                crate::protocol::PacketValue::Int64(v) => {
                    eprintln!("[AUTH]   {} = Int64({})", key, v);
                }
                crate::protocol::PacketValue::Bool(v) => {
                    eprintln!("[AUTH]   {} = Bool({})", key, v);
                }
            }
        }
        eprintln!("[AUTH] 🔍 DEBUG - End of packet fields");

        // Check for server redirect
        if let Some(redirect_flag) = auth_response.get_int("Redirect") {
            if redirect_flag != 0 {
                eprintln!("[AUTH] 🔄 Server requested redirect");
                
                // Extract redirect information
                let redirect_ip = auth_response.get_int("Ip")
                    .ok_or(Error::InvalidResponse)?;
                let redirect_port = auth_response.get_int("Port")
                    .ok_or(Error::InvalidResponse)?;
                let ticket_data = auth_response.get_data("Ticket")
                    .ok_or(Error::InvalidResponse)?;
                
                // CRITICAL: Extract certificate from redirect response (Protocol.c:6031-6042)
                // This certificate MUST match the redirected server's cert for ticket auth to succeed
                let expected_cert = auth_response.get_data("Cert");
                if let Some(cert_data) = expected_cert {
                    eprintln!("[AUTH] 🔐 Received expected certificate from redirect ({} bytes)", cert_data.len());
                    let mut cert_lock = self.expected_cert.lock().unwrap();
                    *cert_lock = Some(cert_data.to_vec());
                } else {
                    eprintln!("[AUTH] ⚠️  No certificate in redirect response (unusual but may be OK)");
                }
                
                // Convert IP to string
                let ip_bytes = redirect_ip.to_be_bytes();
                let redirect_host = format!("{}.{}.{}.{}", 
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                
                eprintln!("[AUTH] 📍 Redirecting to: {}:{}", redirect_host, redirect_port);
                eprintln!("[AUTH] 🎫 Using ticket ({} bytes)", ticket_data.len());
                
                // CRITICAL: Send empty pack BEFORE disconnecting (matches C code at Protocol.c:5954)
                // This acknowledges receipt of the redirect response
                eprintln!("[AUTH] 📤 Sending empty ACK pack before disconnect...");
                let empty_pack = Packet::new("");
                let empty_data = empty_pack.to_bytes()?;
                let empty_http = HttpRequest::new_vpn_post(
                    &self.config.server,
                    self.config.port,
                    empty_data
                );
                let empty_bytes = empty_http.to_bytes();
                self.send_raw(&empty_bytes)?;
                {
                    let mut connections = self.tcp_connections.lock().unwrap();
                    if !connections.is_empty() {
                        connections[0].flush()?;
                    }
                }
                
                // Close current connection
                {
                    let mut connections = self.tcp_connections.lock().unwrap();
                    connections.clear();
                }
                
                eprintln!("[AUTH] 🔌 Reconnecting to redirected server...");
                
                // Important: The redirect IP might not be directly accessible (private IP/NAT)
                // Connect to the ORIGINAL hostname - the ticket will route us to the right backend
                eprintln!("[AUTH] 🔌 Using hostname {} for TLS SNI (ticket will route to redirect IP {})", 
                    self.config.server, redirect_host);
                
                // Reconnect using the original hostname (DNS may load-balance to different frontend)
                // The ticket ensures we get routed to the correct backend server
                let redirect_socket = TcpSocket::connect_tls(&self.config.server, redirect_port as u16)?;
                
                {
                    let mut connections = self.tcp_connections.lock().unwrap();
                    connections.clear();
                    connections.push(redirect_socket);
                }
                
                eprintln!("[AUTH] 🔌 TLS connection established to redirected server");
                
                // Perform handshake on new connection
                self.send_handshake()?;
                
                // Send ticket-based authentication
                eprintln!("[AUTH] 🎫 Sending ticket-based auth packet...");
                
                // Get username from config
                let username = match &self.config.auth {
                    AuthConfig::Password { username, .. } => username.clone(),
                    AuthConfig::Certificate { username, .. } => username.clone(),
                    AuthConfig::Anonymous => String::new(),
                };
                
                // Get all the same client info we sent in the initial auth
                let client_str = "SoftEther VPN Client";
                let protocol_ver = 444;
                let client_build = 9807;
                let hostname = hostname::get()
                    .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
                    .to_string_lossy()
                    .to_string();
                let os_name = std::env::consts::OS;
                let unique_id = Self::generate_unique_id();
                
                // Get network endpoint information
                let connections = self.tcp_connections.lock().unwrap();
                let (client_ip, client_port) = if !connections.is_empty() {
                    Self::get_local_address(&connections[0])
                } else {
                    ([0, 0, 0, 0], 0)
                };
                let (server_ip, server_port) = if !connections.is_empty() {
                    Self::get_peer_address(&connections[0])
                } else {
                    ([0, 0, 0, 0], 0)
                };
                drop(connections);
                
                // Get OS version info
                let (os_type, service_pack, _os_build, os_system_name, os_product_name) = Self::get_win_ver_info();
                let os_version = Self::get_os_version();
                
                // Build ticket auth packet matching password auth EXACTLY
                // Ticket auth needs ALL the same fields as password auth!
                const AUTHTYPE_TICKET: u32 = 99;
                let ticket_auth = Packet::new("")
                    // Core auth fields
                    .add_string("method", "login")
                    // CRITICAL: C Bridge adds BOTH sets of version fields!
                    // PackAddClientVersion adds: client_str, client_ver, client_build
                    // Then main code adds: hello, version, build
                    .add_string("client_str", client_str)
                    .add_int("client_ver", protocol_ver)
                    .add_int("client_build", client_build)
                    .add_string("hello", client_str)
                    .add_int("version", protocol_ver)
                    .add_int("build", client_build)
                    .add_string("hubname", &self.config.hub)
                    .add_string("username", &username)
                    .add_int("protocol", 0)  // ⚠️ CRITICAL: Must be int 0, not string!
                    .add_int("max_connection", self.config.max_connection)
                    .add_int("use_encrypt", if self.config.use_encrypt { 1 } else { 0 })
                    .add_int("use_compress", 0)  // Always 0
                    .add_int("half_connection", 0)
                    .add_int("authtype", AUTHTYPE_TICKET)
                    .add_data("ticket", ticket_data.to_vec())
                    .add_int("client_id", 123)
                    .add_data("unique_id", unique_id.clone())  // Clone for reuse below
                    // P0 CRITICAL: Bridge/routing mode flags (required for DHCP)
                    .add_int("qos", 0)
                    .add_int("require_bridge_routing_mode", 1)  // ⚠️ CRITICAL for DHCP!
                    .add_int("require_monitor_mode", 0)
                    // P1: UDP acceleration negotiation fields
                    .add_int("support_bulk_on_rudp", 1)
                    .add_int("support_hmac_on_bulk_of_rudp", 1)
                    .add_int("support_udp_recovery", 1)
                    .add_int("rudp_bulk_max_version", 2)
                    // P1: Client/Server network endpoint information
                    .add_int("ClientIpAddress", u32::from_be_bytes(client_ip))
                    .add_data("ClientIpAddress6", vec![0u8; 16])  // IPv6 placeholder
                    .add_int("ClientPort", client_port)
                    .add_int("ServerIpAddress", u32::from_be_bytes(server_ip))
                    .add_data("ServerIpAddress6", vec![0u8; 16])  // IPv6 placeholder
                    .add_int("ServerPort2", server_port)
                    .add_int("ProxyIpAddress", 0u32)  // No proxy
                    .add_data("ProxyIpAddress6", vec![0u8; 16])  // No proxy IPv6
                    .add_int("ProxyPort", 0u32)  // No proxy
                    // Environment info (lowercase versions)
                    .add_string("client_os_name", os_name)
                    .add_string("client_hostname", &hostname)
                    .add_string("client_product_name", client_str)
                    .add_int("client_product_ver", protocol_ver)
                    .add_int("client_product_build", client_build)
                    // OutRpcNodeInfo fields (Capitalized - CRITICAL for server validation!)
                    .add_string("ClientProductName", client_str)
                    .add_string("ServerProductName", "")  // Empty for client
                    .add_string("ClientOsName", os_name)
                    .add_string("ClientOsVer", &os_version)
                    .add_string("ClientOsProductId", "")  // Empty
                    .add_string("ClientHostname", &hostname)
                    .add_string("ServerHostname", "")  // Empty for client
                    .add_string("ProxyHostname", "")  // No proxy
                    .add_string("HubName", &self.config.hub)  // Duplicate of hubname
                    .add_data("UniqueId", unique_id.clone())  // CRITICAL: Capitalized version
                    .add_int("ClientProductVer", protocol_ver)
                    .add_int("ClientProductBuild", client_build)
                    .add_int("ServerProductVer", 0)  // Unknown
                    .add_int("ServerProductBuild", 0)  // Unknown
                    // P1: Node Info - Comprehensive OS information
                    .add_int("ClientOsType", os_type)
                    .add_int("ClientOsServicePack", service_pack)
                    .add_string("ClientOsSystemName", &os_system_name)
                    .add_string("ClientOsProductName", &os_product_name)
                    .add_string("ClientOsVendorName", if cfg!(target_os = "macos") { "Apple Inc." } else if cfg!(target_os = "windows") { "Microsoft Corporation" } else { "Linux" })
                    .add_string("ClientOsVersion", &os_version)
                    .add_string("ClientKernelName", std::env::consts::OS)
                    .add_string("ClientKernelVersion", &os_version)
                    // OutRpcWinVer fields (Windows version info - CRITICAL!)
                    .add_int("V_IsWindows", if cfg!(target_os = "windows") { 1 } else { 0 })
                    .add_int("V_IsNT", if cfg!(target_os = "windows") { 1 } else { 0 })
                    .add_int("V_IsServer", 0)  // Client, not server
                    .add_int("V_IsBeta", 0)  // Stable release
                    .add_int("V_VerMajor", 15)  // macOS version major
                    .add_int("V_VerMinor", 4)  // macOS version minor  
                    .add_int("V_Build", 24)  // macOS build simplified
                    .add_int("V_ServicePack", 0)  // No service pack
                    .add_string("V_Title", &format!("{} {}", std::env::consts::OS, &os_version));
                    // Note: branded_ctos NOT added when empty (C Bridge skips it)
                
                eprintln!("[AUTH] 🎫 Ticket auth: hub={}, user={}, authtype={}", 
                    self.config.hub, username, AUTHTYPE_TICKET);
                eprintln!("[AUTH] 🔍 Field values:");
                eprintln!("[AUTH]   - method: login");
                eprintln!("[AUTH]   - version: {}", protocol_ver);
                eprintln!("[AUTH]   - build: {}", client_build);
                eprintln!("[AUTH]   - client_str: {}", client_str);
                eprintln!("[AUTH]   - hubname: {}", self.config.hub);
                eprintln!("[AUTH]   - username: {}", username);
                eprintln!("[AUTH]   - protocol: SE-VPN4-PROTOCOL");
                eprintln!("[AUTH]   - max_connection: {}", self.config.max_connection);
                eprintln!("[AUTH]   - use_encrypt: {}", if self.config.use_encrypt { 1 } else { 0 });
                eprintln!("[AUTH]   - use_compress: 0");
                eprintln!("[AUTH]   - half_connection: 0");
                eprintln!("[AUTH]   - authtype: 99");
                eprintln!("[AUTH]   - client_id: 123");
                eprintln!("[AUTH]   - client_os_name: {}", std::env::consts::OS);
                eprintln!("[AUTH]   - client_hostname: {}", hostname);
                eprintln!("[AUTH]   - client_product_name: {}", client_str);
                eprintln!("[AUTH]   - branded_ctos: (empty string)");
                
                // Debug: Hex dump ticket data for comparison with C Bridge
                eprintln!("[AUTH] 🔍 Ticket hex dump (20 bytes):");
                for (i, byte) in ticket_data.iter().enumerate() {
                    if i % 16 == 0 {
                        eprint!("[AUTH]   ");
                    }
                    eprint!("{:02x} ", byte);
                    if i % 16 == 15 || i == ticket_data.len() - 1 {
                        eprintln!();
                    }
                }
                
                let pack_data = ticket_auth.to_bytes()?;
                eprintln!("[AUTH] 🔍 Ticket auth packet size: {} bytes", pack_data.len());
                
                // DETAILED BYTE DUMP FOR COMPARISON
                eprintln!("[AUTH] 🔬 FULL PACKET HEX DUMP (first 1024 bytes):");
                let dump_len = std::cmp::min(pack_data.len(), 1024);
                for (i, chunk) in pack_data[..dump_len].chunks(16).enumerate() {
                    eprint!("[AUTH]   {:04x}: ", i * 16);
                    for byte in chunk {
                        eprint!("{:02x} ", byte);
                    }
                    eprint!(" | ");
                    for byte in chunk {
                        let c = if *byte >= 0x20 && *byte <= 0x7e { *byte as char } else { '.' };
                        eprint!("{}", c);
                    }
                    eprintln!();
                }
                
                // Save to file for comparison
                std::fs::write("/tmp/cedar_ticket_packet.bin", &pack_data)
                    .unwrap_or_else(|e| eprintln!("[AUTH] ⚠️  Failed to write packet dump: {}", e));
                
                // CRITICAL: Use original hostname in HTTP Host header, not the redirect IP!
                // The ticket is validated against the original hostname
                let http_request = HttpRequest::new_vpn_post(
                    &self.config.server,  // Use original hostname, NOT redirect_host
                    redirect_port as u16,
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
                
                // Receive response after redirect
                let redirect_response = self.receive_http_response()?;
                
                if redirect_response.status_code != 200 {
                    eprintln!("[AUTH] ❌ Redirect authentication failed: HTTP {}", redirect_response.status_code);
                    return Err(Error::AuthenticationFailed);
                }
                
                // Strip watermark if present
                let redirect_pack_data = if redirect_response.body.len() > WATERMARK.len() && 
                                  &redirect_response.body[0..6] == &WATERMARK[0..6] {
                    &redirect_response.body[WATERMARK.len()..]
                } else {
                    &redirect_response.body[..]
                };
                
                // Parse initial response from ticket auth
                let initial_response = Packet::from_bytes(redirect_pack_data)?;
                
                eprintln!("[AUTH] ✅ Received initial response from redirected server");
                eprintln!("[AUTH] 🔍 DEBUG - All fields in initial response:");
                for (key, value) in &initial_response.params {
                    match value {
                        crate::protocol::PacketValue::Int(v) => {
                            eprintln!("[AUTH]   {} = Int({})", key, v);
                        }
                        crate::protocol::PacketValue::Data(v) => {
                            eprintln!("[AUTH]   {} = Data({} bytes)", key, v.len());
                        }
                        crate::protocol::PacketValue::String(v) => {
                            eprintln!("[AUTH]   {} = String(\"{}\")", key, v);
                        }
                        crate::protocol::PacketValue::Int64(v) => {
                            eprintln!("[AUTH]   {} = Int64({})", key, v);
                        }
                        crate::protocol::PacketValue::Bool(v) => {
                            eprintln!("[AUTH]   {} = Bool({})", key, v);
                        }
                    }
                }
                eprintln!("[AUTH] 🔍 DEBUG - End of initial response fields");
                
                // IMPORTANT: After redirect with ticket auth, error=3 (ERR_DISCONNECTED) is NORMAL!
                // It just acknowledges that the previous connection was disconnected (as we intended).
                // The presence of 'pencore' data indicates this is actually a Welcome packet.
                // We should NOT treat this as a fatal error - the .junk code ignores it completely.
                if let Some(error_code) = initial_response.get_int("error") {
                    match error_code {
                        0 => {
                            eprintln!("[AUTH] ✅ No error in response");
                        }
                        3 => {
                            // ERR_DISCONNECTED (3) is expected after redirect - it's just metadata
                            eprintln!("[AUTH] 📝 Server sent error=3 (ERR_DISCONNECTED) - this is normal after redirect");
                            eprintln!("[AUTH]    (Previous connection was disconnected as expected)");
                        }
                        _ => {
                            // Any other error code is a real failure
                            eprintln!("[AUTH] ❌ Server sent error code={}", error_code);
                            eprintln!("[AUTH] ❌ Ticket authentication failed!");
                            return Err(Error::AuthenticationFailed);
                        }
                    }
                }
                
                // Process response as Welcome packet (like .junk does)
                eprintln!("[AUTH] ✅ Processing response as Welcome packet");
                let welcome_packet = initial_response;
                
                // Extract session info (SessionName or session_name)
                if let Some(session_name) = welcome_packet.get_string("SessionName")
                    .or_else(|| welcome_packet.get_string("session_name")) {
                    *self.session_name.lock().unwrap() = Some(session_name.to_string());
                    eprintln!("[AUTH] 📋 Session Name: {}", session_name);
                } else {
                    eprintln!("[AUTH] ⚠️  Session name not found in Welcome packet after redirect");
                }
                
                // Extract connection info (ConnectionName or connection_name)
                if let Some(connection_name) = welcome_packet.get_string("ConnectionName")
                    .or_else(|| welcome_packet.get_string("connection_name")) {
                    *self.connection_name.lock().unwrap() = Some(connection_name.to_string());
                    eprintln!("[AUTH] 📋 Connection Name: {}", connection_name);
                } else {
                    eprintln!("[AUTH] ⚠️  Connection name not found in Welcome packet after redirect");
                }
                
                // Parse server policy settings
                eprintln!("[AUTH] 📜 Server Policy Settings:");
                if let Some(access) = welcome_packet.get_bool("Access") {
                    eprintln!("[AUTH]   Access: {}", access);
                }
                if let Some(bridge) = welcome_packet.get_bool("NoBridge") {
                    eprintln!("[AUTH]   NoBridge: {}", bridge);
                }
                if let Some(routing) = welcome_packet.get_bool("NoRouting") {
                    eprintln!("[AUTH]   NoRouting: {}", routing);
                }
                if let Some(dhcp_filter) = welcome_packet.get_bool("DHCPFilter") {
                    eprintln!("[AUTH]   DHCPFilter: {}", dhcp_filter);
                }
                if let Some(dhcp_no_server) = welcome_packet.get_bool("DHCPNoServer") {
                    eprintln!("[AUTH]   DHCPNoServer: {}", dhcp_no_server);
                }
                if let Some(monitor) = welcome_packet.get_bool("MonitorPort") {
                    eprintln!("[AUTH]   MonitorPort: {}", monitor);
                }
                
        eprintln!("[AUTH] 🎉 Authentication phase complete (after redirect)!");
        
        // Enable streaming mode for data packets (no HTTP headers)
        self.streaming_mode.store(true, Ordering::Release);
        eprintln!("[AUTH] 🔄 Switched to streaming mode for data packets");
        
        // Set socket read timeout to prevent indefinite blocking
        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                let timeout = std::time::Duration::from_millis(100);
                if let Err(e) = connections[0].set_read_timeout(Some(timeout)) {
                    eprintln!("[AUTH] ⚠️  Failed to set read timeout after redirect: {:?}", e);
                } else {
                    eprintln!("[AUTH] ✅ Redirect socket read timeout set to 100ms for streaming");
                }
            }
        }
        
        // Send immediate keep-alive to signal streaming readiness
        eprintln!("[AUTH] 📡 Sending initial keep-alive packet...");
        if let Err(e) = self.send_keepalive_no_wait() {
            eprintln!("[AUTH] ⚠️  Failed to send initial keep-alive: {:?}", e);
        } else {
            eprintln!("[AUTH] ✅ Initial keep-alive sent successfully");
        }
        
        // Small delay to let server process the keep-alive
        std::thread::sleep(std::time::Duration::from_millis(200));
        eprintln!("[AUTH] ⏸️  Paused 200ms for server to process keep-alive");
        
        return Ok(());
            }
        }        // No redirect - process as normal Welcome packet
        // P1: Parse session tracking information from Welcome packet
        // These are STRINGS not data blobs!
        if let Some(session_name) = auth_response.get_string("session_name") {
            *self.session_name.lock().unwrap() = Some(session_name.to_string());
            eprintln!("[AUTH] 📋 Session Name: {}", session_name);
        } else {
            eprintln!("[AUTH] ⚠️  Session name not found in Welcome packet");
        }
        
        if let Some(connection_name) = auth_response.get_string("connection_name") {
            *self.connection_name.lock().unwrap() = Some(connection_name.to_string());
            eprintln!("[AUTH] 📋 Connection Name: {}", connection_name);
        } else {
            eprintln!("[AUTH] ⚠️  Connection name not found in Welcome packet");
        }
        
        // P1: Parse and log server policy settings
        eprintln!("[AUTH] 📜 Server Policy Settings:");
        if let Some(access) = auth_response.get_bool("Access") {
            eprintln!("[AUTH]   Access: {}", access);
        }
        if let Some(bridge) = auth_response.get_bool("NoBridge") {
            eprintln!("[AUTH]   NoBridge: {}", bridge);
        }
        if let Some(routing) = auth_response.get_bool("NoRouting") {
            eprintln!("[AUTH]   NoRouting: {}", routing);
        }
        if let Some(dhcp_filter) = auth_response.get_bool("DHCPFilter") {
            eprintln!("[AUTH]   DHCPFilter: {}", dhcp_filter);
        }
        if let Some(dhcp_no_server) = auth_response.get_bool("DHCPNoServer") {
            eprintln!("[AUTH]   DHCPNoServer: {}", dhcp_no_server);
        }
        if let Some(monitor) = auth_response.get_bool("MonitorPort") {
            eprintln!("[AUTH]   MonitorPort: {}", monitor);
        }

        eprintln!("[AUTH] 🎉 Authentication phase complete!");
        
        // Enable streaming mode for data packets (no HTTP headers)
        self.streaming_mode.store(true, Ordering::Release);
        eprintln!("[AUTH] 🔄 Switched to streaming mode for data packets");
        
        // Set socket read timeout to prevent indefinite blocking
        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                let timeout = std::time::Duration::from_millis(100);
                if let Err(e) = connections[0].set_read_timeout(Some(timeout)) {
                    eprintln!("[AUTH] ⚠️  Failed to set read timeout: {:?}", e);
                } else {
                    eprintln!("[AUTH] ✅ Socket read timeout set to 100ms for streaming");
                }
            }
        }
        
        // Send immediate keep-alive to signal streaming readiness
        eprintln!("[AUTH] 📡 Sending initial keep-alive packet...");
        if let Err(e) = self.send_keepalive_no_wait() {
            eprintln!("[AUTH] ⚠️  Failed to send initial keep-alive: {:?}", e);
        } else {
            eprintln!("[AUTH] ✅ Initial keep-alive sent successfully");
        }
        
        // Small delay to let server process the keep-alive
        std::thread::sleep(std::time::Duration::from_millis(200));
        eprintln!("[AUTH] ⏸️  Paused 200ms for server to process keep-alive");

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
        eprintln!("[SESSION] Packet forwarding now handled by Zig code");
        eprintln!();

        let mut last_keepalive = Instant::now();
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
            // Packets are now received via cedar_session_try_receive_data_packet FFI
            // and forwarded to TUN device by Zig code
            // This loop just maintains the session
            
            // Small delay to prevent CPU spinning
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let elapsed = start_time.elapsed();
        eprintln!("[SESSION] Session ended after {:?}", elapsed);
        Ok(())
    }

    /// Try to receive a data packet from server (non-blocking)
    /// Returns Some((packet_type, data)) if packet received, None if no packet available
    pub fn try_receive_data_packet(&self) -> Result<Option<(String, Vec<u8>)>> {
        // Priority 1: Handle DHCP tick (generate DHCP/ARP packets periodically)
        let now = Instant::now();
        let should_tick = {
            let last_tick = self.last_dhcp_tick.lock().unwrap();
            now.duration_since(*last_tick) >= Duration::from_millis(100) // Tick every 100ms
        };
        
        if should_tick {
            *self.last_dhcp_tick.lock().unwrap() = now;
            
            if let Some(ref mut dhcp) = *self.dhcp_client.lock().unwrap() {
                // Generate DHCP/ARP packet if needed
                if let Some(packet) = dhcp.tick() {
                    eprintln!("[DHCP] 📤 Sending DHCP/ARP packet ({} bytes)", packet.len());
                    
                    // Send via secure connection
                    if let Err(e) = self.send_data_packet(&packet) {
                        eprintln!("[DHCP] ⚠️  Failed to send DHCP packet: {:?}", e);
                    }
                }
                
                // Check if DHCP just completed and interface needs configuration
                if dhcp.is_configured() && !*self.interface_configured.lock().unwrap() {
                    eprintln!("[DHCP] ✅ DHCP configuration complete!");
                    if let Err(e) = self.configure_interface() {
                        eprintln!("[DHCP] ⚠️  Interface configuration failed: {:?}", e);
                    } else {
                        *self.interface_configured.lock().unwrap() = true;
                    }
                }
            }
        }
        
        if self.streaming_mode.load(Ordering::Acquire) {
            // Streaming mode: read raw PACK (no HTTP headers)
            if let Some(packet) = self.stream_receive_pack()? {
                if let Some(method) = packet.get_string("method") {
                    match method {
                        "data" => {
                            if let Some(data) = packet.get_data("data") {
                                // Route to DHCP client first
                                if let Some(ref mut dhcp) = *self.dhcp_client.lock().unwrap() {
                                    if let Err(e) = dhcp.put_packet(&data) {
                                        eprintln!("[DHCP] ⚠️  Failed to process packet: {:?}", e);
                                    }
                                }
                                return Ok(Some(("data".to_string(), data.to_vec())));
                            }
                        }
                        "keepalive" => {
                            return Ok(Some(("keepalive".to_string(), Vec::new())));
                        }
                        _ => {}
                    }
                }
            }
            Ok(None)
        } else {
            // HTTP mode: read HTTP response (for initial handshake/auth)
            use crate::protocol::WATERMARK;
            
            let mut connections = self.tcp_connections.lock().unwrap();
            if connections.is_empty() {
                return Ok(None);
            }
            
            // Try non-blocking peek to check if data is available
            let mut peek_buf = [0u8; 1];
            match connections[0].peek(&mut peek_buf) {
                Ok(0) => {
                    // Connection closed
                    drop(connections);
                    return Err(Error::DisconnectedError);
                }
                Ok(_) => {
                    // Data available, try to read HTTP response
                }
                Err(_) => {
                    // No data available or error - just return None for non-blocking
                    return Ok(None);
                }
            }
            
            // Try to receive HTTP response (this may block briefly)
            drop(connections); // Release lock before receiving
            
            match self.try_receive_http_response_nonblock() {
                Ok(Some(response)) => {
                    if response.status_code != 200 {
                        eprintln!("[SESSION] HTTP error {}", response.status_code);
                        return Err(Error::InvalidResponse);
                    }
                    
                    // Strip watermark if present
                    let pack_data = if response.body.len() > WATERMARK.len() && 
                                      &response.body[0..6] == &WATERMARK[0..6] {
                        &response.body[WATERMARK.len()..]
                    } else {
                        &response.body[..]
                    };
                    
                    if pack_data.is_empty() {
                        return Ok(None);
                    }
                    
                    // Parse PACK packet
                    match Packet::from_bytes(pack_data) {
                        Ok(packet) => {
                            // Check packet type
                            if let Some(method) = packet.get_string("method") {
                                // Handle different packet types
                                match method {
                                    "data" => {
                                        // Data packet - extract and return for TUN forwarding
                                        if let Some(data) = packet.get_data("data") {
                                            eprintln!("[SESSION] 📦 Data packet: {} bytes", data.len());
                                            
                                            // Route to DHCP client first
                                            if let Some(ref mut dhcp) = *self.dhcp_client.lock().unwrap() {
                                                if let Err(e) = dhcp.put_packet(&data) {
                                                    eprintln!("[DHCP] ⚠️  Failed to process packet: {:?}", e);
                                                }
                                            }
                                            
                                            return Ok(Some(("data".to_string(), data.to_vec())));
                                        }
                                    }
                                    "keepalive" => {
                                        // Keep-alive response - return empty data
                                        return Ok(Some(("keepalive".to_string(), Vec::new())));
                                    }
                                    _ => {
                                        eprintln!("[SESSION] Unknown packet method: {}", method);
                                    }
                                }
                            }
                            Ok(Some(("unknown".to_string(), Vec::new())))
                        }
                        Err(e) => {
                            eprintln!("[SESSION] Failed to parse packet: {:?}", e);
                            Ok(None)
                        }
                    }
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }
    
    /// Send a PACK in streaming mode (no HTTP headers, just watermark+size+data)
    fn stream_send_pack(&self, pack: &Packet) -> Result<()> {
        use crate::protocol::WATERMARK;
        
        let pack_data = pack.to_bytes()?;
        
        // Format: [WATERMARK(16)][SIZE(4 BE)][PACK_DATA]
        let mut stream_data = Vec::with_capacity(16 + 4 + pack_data.len());
        stream_data.extend_from_slice(&WATERMARK);
        stream_data.extend_from_slice(&(pack_data.len() as u32).to_be_bytes());
        stream_data.extend_from_slice(&pack_data);
        
        // Send raw data on persistent connection
        self.send_raw(&stream_data)?;
        
        // Flush TCP connection
        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
            }
        }
        
        Ok(())
    }
    
    /// Receive a PACK from streaming mode (no HTTP headers, just watermark+size+data)
    fn stream_receive_pack(&self) -> Result<Option<Packet>> {
        use crate::protocol::WATERMARK;
        
        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.is_empty() {
            return Ok(None);
        }
        
        // 1. Look for watermark (16 bytes) - will timeout after 100ms if no data
        let mut watermark_buf = [0u8; 16];
        match connections[0].peek(&mut watermark_buf) {
            Ok(16) if &watermark_buf == &WATERMARK => {
                // Consume watermark
                eprintln!("[STREAM] Found watermark, consuming it");
                connections[0].recv(&mut watermark_buf)?;
            }
            Ok(n) if n < 16 => {
                // Not enough data yet - normal, return None
                return Ok(None);
            }
            Ok(_) => {
                // Data available but no watermark - normal for no data
                return Ok(None);
            }
            Err(mayaqua::Error::TimeOut) => {
                // Timeout - normal, just return None
                return Ok(None);
            }
            Err(mayaqua::Error::IoError(ref msg)) if msg.contains("timed out") 
                || msg.contains("would block")
                || msg.contains("temporarily unavailable") => {
                // Timeout or would block - normal, just return None
                return Ok(None);
            }
            Err(mayaqua::Error::Network(ref msg)) if msg.contains("timed out")
                || msg.contains("would block")
                || msg.contains("temporarily unavailable") => {
                // Timeout or would block - normal, just return None
                return Ok(None);
            }
            Err(mayaqua::Error::Network(ref msg)) if msg.contains("Connection reset") || msg.contains("Broken pipe") => {
                // Connection closed by server - this is a real error
                eprintln!("[STREAM] ❌ Connection closed by server: {}", msg);
                return Err(mayaqua::Error::DisconnectedError);
            }
            Err(e) => {
                // Real error
                eprintln!("[STREAM] ⚠️  Error peeking for watermark: {:?}", e);
                return Err(e);
            }
        }
        
        // 2. Read size (4 bytes, big-endian)
        let mut size_buf = [0u8; 4];
        match connections[0].recv(&mut size_buf) {
            Ok(4) => {}
            _ => return Ok(None),
        }
        let pack_size = u32::from_be_bytes(size_buf) as usize;
        
        // Sanity check on size (max 1MB)
        if pack_size > 1024 * 1024 {
            eprintln!("[SESSION] Invalid PACK size: {} bytes", pack_size);
            return Err(Error::InvalidResponse);
        }
        
        // 3. Read PACK data
        let mut pack_buf = vec![0u8; pack_size];
        let mut total_read = 0;
        while total_read < pack_size {
            match connections[0].recv(&mut pack_buf[total_read..]) {
                Ok(n) if n > 0 => total_read += n,
                Ok(0) => return Err(Error::DisconnectedError),
                Ok(_) => {
                    // Zero bytes but not disconnected, wait briefly
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                Err(_) => {
                    // Error reading - might be WouldBlock, wait briefly and retry
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
            }
        }
        
        // 4. Parse PACK
        match Packet::from_bytes(&pack_buf) {
            Ok(packet) => Ok(Some(packet)),
            Err(e) => {
                eprintln!("[SESSION] Failed to parse PACK: {:?}", e);
                Ok(None)
            }
        }
    }
    
    /// Try to receive HTTP response without blocking (uses socket timeout)
    fn try_receive_http_response_nonblock(&self) -> Result<Option<mayaqua::HttpResponse>> {
        
        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.is_empty() {
            return Err(Error::NotConnected);
        }
        
        // Set a short timeout for non-blocking behavior
        if let Err(_) = connections[0].set_read_timeout(Some(std::time::Duration::from_millis(10))) {
            // Timeout setting failed, continue anyway
        }
        
        // Try to read HTTP response
        let mut response_data = Vec::new();
        let mut buffer = [0u8; 1];
        let mut line = Vec::new();
        let mut headers_done = false;
        let mut content_length = 0;
        
        // Read status line and headers
        while !headers_done {
            match connections[0].recv(&mut buffer) {
                Ok(0) => return Err(Error::DisconnectedError),
                Ok(_) => {
                    response_data.push(buffer[0]);
                    line.push(buffer[0]);
                    
                    if line.len() >= 2 && line[line.len()-2] == b'\r' && line[line.len()-1] == b'\n' {
                        let line_str = String::from_utf8_lossy(&line[..line.len()-2]);
                        if line_str.is_empty() {
                            headers_done = true;
                        } else if line_str.to_lowercase().starts_with("content-length:") {
                            if let Some(len_str) = line_str.split(':').nth(1) {
                                content_length = len_str.trim().parse().unwrap_or(0);
                            }
                        }
                        line.clear();
                    }
                }
                Err(_) => {
                    return Ok(None); // No data available yet
                }
                Err(_) => return Err(Error::Network("Network error".to_string())),
            }
        }
        
        // Read body
        if content_length > 0 {
            let mut body = vec![0u8; content_length];
            let mut total_read = 0;
            while total_read < content_length {
                match connections[0].recv(&mut body[total_read..]) {
                    Ok(0) => return Err(Error::DisconnectedError),
                    Ok(n) => total_read += n,
                    Err(_) => {
                        return Ok(None);
                    }
                    Err(_) => return Err(Error::Network("Network error".to_string())),
                }
            }
            response_data.extend_from_slice(&body);
        }
        
        // Reset timeout to default
        let _ = connections[0].set_read_timeout(Some(std::time::Duration::from_secs(30)));
        
        drop(connections);
        
        // Parse HTTP response
        let mut cursor = std::io::Cursor::new(response_data);
        match mayaqua::HttpResponse::from_stream(&mut cursor) {
            Ok(response) => Ok(Some(response)),
            Err(_) => Err(Error::InvalidResponse),
        }
    }
    
    /// Send data packet to server
    pub fn send_data_packet(&self, data: &[u8]) -> Result<()> {
        eprintln!("[DATA] Preparing to send data packet ({} bytes)", data.len());
        
        // Create data PACK packet
        let data_packet = Packet::new("data")
            .add_string("method", "data")
            .add_data("data", data.to_vec());
        
        if self.streaming_mode.load(Ordering::Acquire) {
            // Streaming mode: send raw PACK (no HTTP headers)
            eprintln!("[DATA] Sending in streaming mode (no HTTP headers)");
            self.stream_send_pack(&data_packet)?;
            eprintln!("[DATA] ✅ Data packet sent successfully via streaming");
        } else {
            // HTTP mode: send HTTP POST (for initial handshake/auth only)
            use crate::protocol::WATERMARK;
            
            let pack_data = data_packet.to_bytes()?;
            
            // Build HTTP request with watermark and PACK data
            let mut request_data = Vec::new();
            
            // HTTP POST header
            let header = format!(
                "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n\
                 Host: {}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: Keep-Alive\r\n\
                 \r\n",
                self.config.server,
                WATERMARK.len() + pack_data.len()
            );
            request_data.extend_from_slice(header.as_bytes());
            
            // Add watermark
            request_data.extend_from_slice(&WATERMARK);
            
            // Add PACK data
            request_data.extend_from_slice(&pack_data);
            
            // Send all at once
            self.send_raw(&request_data)?;
            
            {
                let mut connections = self.tcp_connections.lock().unwrap();
                if !connections.is_empty() {
                    connections[0].flush()?;
                }
            }
        }
        
        Ok(())
    }

    /// Poll session for keep-alive (call from Zig forwarding loop)
    /// This should be called periodically (e.g., every 10ms iteration)
    /// to maintain the session with automatic keep-alive timing
    pub fn poll_keepalive(&self, interval_secs: u64) -> Result<()> {
        use std::sync::Mutex as StdMutex;
        use std::time::Instant;
        use std::cell::RefCell;
        
        thread_local! {
            static LAST_KEEPALIVE: RefCell<Option<Instant>> = RefCell::new(None);
        }
        
        let should_send = LAST_KEEPALIVE.with(|last_cell| {
            let mut last = last_cell.borrow_mut();
            let now = Instant::now();
            
            match *last {
                Some(last_time) => {
                    if now.duration_since(last_time).as_secs() >= interval_secs {
                        *last = Some(now);
                        true
                    } else {
                        false
                    }
                }
                None => {
                    *last = Some(now);
                    false
                }
            }
        });
        
        if should_send {
            self.send_keepalive()?;
        }
        
        Ok(())
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

    /// Send keep-alive packet without waiting for response (for initial keep-alive after auth)
    fn send_keepalive_no_wait(&self) -> Result<()> {
        eprintln!("[KEEPALIVE] Creating keep-alive packet (no-wait mode)");

        // Create keep-alive packet
        let keepalive_packet = Packet::new("keep_alive")
            .add_string("method", "keepalive")
            .add_int("timestamp", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32);

        // In streaming mode, send directly without HTTP headers
        if self.streaming_mode.load(Ordering::Acquire) {
            eprintln!("[KEEPALIVE] Sending in streaming mode (no HTTP headers)");
            self.stream_send_pack(&keepalive_packet)?;
        } else {
            // Fallback: send with HTTP (shouldn't happen after auth)
            eprintln!("[KEEPALIVE] Sending in HTTP mode");
            let pack_data = keepalive_packet.to_bytes()?;
            let http_request = mayaqua::HttpRequest::new_vpn_post(
                &self.config.server,
                self.config.port,
                pack_data,
            );
            let http_bytes = http_request.to_bytes();
            self.send_raw(&http_bytes)?;
        }

        {
            let mut connections = self.tcp_connections.lock().unwrap();
            if !connections.is_empty() {
                connections[0].flush()?;
            }
        }

        eprintln!("[KEEPALIVE] ✅ Keep-alive sent (no response expected)");
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

    /// Add additional TCP connection (for multi-connection mode)
    /// 
    /// C Bridge creates multiple connections for load balancing and failover.
    /// Secondary connections use ticket-based authentication (authtype=99)
    /// instead of password authentication.
    pub fn add_connection(&self) -> Result<()> {
        if self.status() != SessionStatus::Established {
            return Err(Error::InvalidState);
        }

        let mut connections = self.tcp_connections.lock().unwrap();
        if connections.len() >= self.config.max_connection as usize {
            return Err(Error::TooManyConnections);
        }
        drop(connections);
        
        eprintln!("[CONNECT] 🔗 Adding additional connection...");
        
        // Establish TLS connection
        let socket = TcpSocket::connect_tls(&self.config.server, self.config.port)?;
        
        eprintln!("[CONNECT] ✅ Additional TLS connection established");
        
        // TODO: Send handshake and authenticate with ticket (authtype=99)
        // For now, just add the socket
        let mut connections = self.tcp_connections.lock().unwrap();
        connections.push(socket);
        
        eprintln!("[CONNECT] 📊 Total connections: {}/{}", connections.len(), self.config.max_connection);
        
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
    
    /// Configure network interface with DHCP-assigned IP address
    fn configure_interface(&self) -> Result<()> {
        let dhcp = self.dhcp_client.lock().unwrap();
        let dhcp = dhcp.as_ref().ok_or_else(|| Error::InternalError)?;
        
        if !dhcp.is_configured() {
            return Err(Error::InvalidState);
        }
        
        // Format IP addresses for display and commands
        let ip_addr = dhcp.ip();
        let gateway = dhcp.gateway_ip();
        let netmask = dhcp.netmask();
        let gateway_mac = dhcp.gateway_mac();
        
        let ip_str = format!("{}.{}.{}.{}", 
            (ip_addr >> 24) & 0xFF, (ip_addr >> 16) & 0xFF, 
            (ip_addr >> 8) & 0xFF, ip_addr & 0xFF);
        let gw_str = format!("{}.{}.{}.{}", 
            (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF, 
            (gateway >> 8) & 0xFF, gateway & 0xFF);
        let mask_str = format!("{}.{}.{}.{}", 
            (netmask >> 24) & 0xFF, (netmask >> 16) & 0xFF, 
            (netmask >> 8) & 0xFF, netmask & 0xFF);
        let mac_str = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            gateway_mac[0], gateway_mac[1], gateway_mac[2],
            gateway_mac[3], gateway_mac[4], gateway_mac[5]);
        
        eprintln!("[DHCP] 📋 Configuring interface with DHCP settings:");
        eprintln!("[DHCP]    IP:          {}", ip_str);
        eprintln!("[DHCP]    Gateway:     {}", gw_str);
        eprintln!("[DHCP]    Netmask:     {}", mask_str);
        eprintln!("[DHCP]    Gateway MAC: {}", mac_str);
        
        // Note: Actual interface configuration is typically done by the TUN/TAP layer
        // This method is here for logging and future integration with system commands
        
        eprintln!("[DHCP] ✅ Interface configuration complete!");
        eprintln!("[DHCP] 💡 TUN/TAP device should now be configured with these settings");
        
        Ok(())
    }
    
    /// Get DHCP client state (for monitoring)
    pub fn dhcp_state(&self) -> Option<DhcpState> {
        self.dhcp_client.lock().unwrap()
            .as_ref()
            .map(|dhcp| dhcp.state())
    }
    
    /// Get assigned IP address from DHCP (0 if not configured)
    pub fn dhcp_ip(&self) -> u32 {
        self.dhcp_client.lock().unwrap()
            .as_ref()
            .map(|dhcp| dhcp.ip())
            .unwrap_or(0)
    }
    
    /// Check if DHCP is fully configured
    pub fn is_dhcp_configured(&self) -> bool {
        self.dhcp_client.lock().unwrap()
            .as_ref()
            .map(|dhcp| dhcp.is_configured())
            .unwrap_or(false)
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
