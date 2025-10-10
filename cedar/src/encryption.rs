//! Encryption Module
//!
//! TLS/SSL encryption support for VPN connections.
//! Provides secure transport layer with certificate validation using rustls.

use mayaqua::error::{Error, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

/// TLS protocol version
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

/// Cipher suite preference
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherSuite {
    /// AES-256-GCM with ECDHE key exchange
    Aes256GcmEcdhe,
    /// AES-128-GCM with ECDHE key exchange
    Aes128GcmEcdhe,
    /// ChaCha20-Poly1305 with ECDHE key exchange
    ChaCha20Poly1305Ecdhe,
}

/// Certificate verification mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CertVerifyMode {
    /// Verify certificate against system trust store
    Full,
    /// Skip certificate verification (dangerous, for testing only)
    None,
    /// Verify certificate against custom CA bundle
    CustomCa,
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// TLS version to use
    pub version: TlsVersion,
    /// Preferred cipher suites
    pub cipher_suites: Vec<CipherSuite>,
    /// Certificate verification mode
    pub verify_mode: CertVerifyMode,
    /// Server name for SNI
    pub server_name: Option<String>,
    /// Custom CA certificate (PEM format)
    pub ca_cert: Option<Vec<u8>>,
    /// Client certificate (PEM format)
    pub client_cert: Option<Vec<u8>>,
    /// Client private key (PEM format)
    pub client_key: Option<Vec<u8>>,
    /// Enable session resumption
    pub session_resumption: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            version: TlsVersion::Tls13,
            cipher_suites: vec![
                CipherSuite::Aes256GcmEcdhe,
                CipherSuite::ChaCha20Poly1305Ecdhe,
            ],
            verify_mode: CertVerifyMode::Full,
            server_name: None,
            ca_cert: None,
            client_cert: None,
            client_key: None,
            session_resumption: true,
        }
    }
}

/// TLS connection wrapper
pub struct TlsConnection {
    /// Configuration
    config: TlsConfig,
    /// Connection state
    state: TlsState,
    /// Session ID for resumption
    session_id: Option<Vec<u8>>,
    /// Total bytes encrypted
    bytes_encrypted: u64,
    /// Total bytes decrypted
    bytes_decrypted: u64,
    /// Optional TCP stream (if connected)
    stream: Option<TcpStream>,
    /// Rustls client connection
    tls_conn: Option<ClientConnection>,
}

/// TLS connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlsState {
    /// Not connected
    Disconnected,
    /// Handshake in progress
    Handshaking,
    /// Connected and ready
    Connected,
    /// Error state
    Error,
}

impl TlsConnection {
    /// Create new TLS connection with config
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config,
            state: TlsState::Disconnected,
            session_id: None,
            bytes_encrypted: 0,
            bytes_decrypted: 0,
            stream: None,
            tls_conn: None,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(TlsConfig::default())
    }

    /// Create rustls client config
    fn create_rustls_config(&self) -> Result<ClientConfig> {
        let mut root_store = RootCertStore::empty();

        match self.config.verify_mode {
            CertVerifyMode::Full => {
                // Use webpki-roots for system root certificates
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            CertVerifyMode::None => {
                // Skip certificate verification - dangerous!
                // For testing only
                use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
                use rustls::pki_types::{CertificateDer, ServerName as PkiServerName, UnixTime};
                use rustls::{DigitallySignedStruct, SignatureScheme};

                #[derive(Debug)]
                struct NoVerifier;

                impl ServerCertVerifier for NoVerifier {
                    fn verify_server_cert(
                        &self,
                        _end_entity: &CertificateDer<'_>,
                        _intermediates: &[CertificateDer<'_>],
                        _server_name: &PkiServerName<'_>,
                        _ocsp_response: &[u8],
                        _now: UnixTime,
                    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                        Ok(ServerCertVerified::assertion())
                    }

                    fn verify_tls12_signature(
                        &self,
                        _message: &[u8],
                        _cert: &CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                        Ok(HandshakeSignatureValid::assertion())
                    }

                    fn verify_tls13_signature(
                        &self,
                        _message: &[u8],
                        _cert: &CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                        Ok(HandshakeSignatureValid::assertion())
                    }

                    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                        vec![
                            SignatureScheme::RSA_PKCS1_SHA256,
                            SignatureScheme::ECDSA_NISTP256_SHA256,
                            SignatureScheme::ED25519,
                        ]
                    }
                }

                return Ok(ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth());
            }
            CertVerifyMode::CustomCa => {
                // Load custom CA certificate
                if let Some(ref ca_cert) = self.config.ca_cert {
                    let certs = rustls_pemfile::certs(&mut ca_cert.as_slice())
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(|_| Error::InvalidCertificate)?;

                    for cert in certs {
                        root_store
                            .add(cert)
                            .map_err(|_| Error::InvalidCertificate)?;
                    }
                } else {
                    return Err(Error::InvalidParameter);
                }
            }
        }

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(config)
    }

    /// Connect to server and perform TLS handshake
    pub fn connect(&mut self, host: &str, port: u16) -> Result<()> {
        if self.state != TlsState::Disconnected {
            return Err(Error::InvalidState);
        }

        // Create TCP connection
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| Error::IoError(format!("Failed to connect to {}: {}", addr, e)))?;

        // Set TCP socket options
        stream
            .set_nodelay(true)
            .map_err(|e| Error::IoError(format!("Failed to set TCP_NODELAY: {}", e)))?;

        self.state = TlsState::Handshaking;

        // Create rustls config
        let config = Arc::new(self.create_rustls_config()?);

        // Parse server name for SNI
        let server_name = self
            .config
            .server_name
            .as_ref()
            .unwrap_or(&host.to_string())
            .to_string();

        let server_name = ServerName::try_from(server_name)
            .map_err(|_| Error::IoError("Invalid server name".to_string()))?;

        // Create TLS connection
        let mut tls_conn = ClientConnection::new(config, server_name)
            .map_err(|e| Error::TlsError(format!("Failed to create TLS connection: {}", e)))?;

        // Perform TLS handshake
        while tls_conn.is_handshaking() {
            // Write TLS data to socket
            if let Err(e) = tls_conn.write_tls(&mut stream) {
                return Err(Error::IoError(format!("TLS write failed: {}", e)));
            }

            // Read TLS data from socket
            if let Err(e) = tls_conn.read_tls(&mut stream) {
                return Err(Error::IoError(format!("TLS read failed: {}", e)));
            }

            // Process TLS messages
            if let Err(e) = tls_conn.process_new_packets() {
                return Err(Error::TlsError(format!("TLS handshake failed: {}", e)));
            }
        }

        self.stream = Some(stream);
        self.tls_conn = Some(tls_conn);
        self.state = TlsState::Connected;

        Ok(())
    }

    /// Internal handshake implementation (kept for compatibility)
    fn handshake_internal(&mut self) -> Result<()> {
        // Handshake is now handled in connect()
        Ok(())
    }

    /// Send data over TLS connection
    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != TlsState::Connected {
            return Err(Error::InvalidState);
        }

        let stream = self
            .stream
            .as_mut()
            .ok_or(Error::IoError("No active stream".to_string()))?;

        let tls_conn = self
            .tls_conn
            .as_mut()
            .ok_or(Error::IoError("No TLS connection".to_string()))?;

        // Write application data to TLS connection
        tls_conn
            .writer()
            .write_all(data)
            .map_err(|e| Error::IoError(format!("TLS write failed: {}", e)))?;

        // Flush TLS data to TCP socket
        tls_conn
            .write_tls(stream)
            .map_err(|e| Error::IoError(format!("TCP write failed: {}", e)))?;

        self.bytes_encrypted += data.len() as u64;
        Ok(data.len())
    }

    /// Receive data from TLS connection
    pub fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        if self.state != TlsState::Connected {
            return Err(Error::InvalidState);
        }

        let stream = self
            .stream
            .as_mut()
            .ok_or(Error::IoError("No active stream".to_string()))?;

        let tls_conn = self
            .tls_conn
            .as_mut()
            .ok_or(Error::IoError("No TLS connection".to_string()))?;

        // Read TLS data from TCP socket
        tls_conn
            .read_tls(stream)
            .map_err(|e| Error::IoError(format!("TCP read failed: {}", e)))?;

        // Process TLS messages
        tls_conn
            .process_new_packets()
            .map_err(|e| Error::TlsError(format!("TLS packet processing failed: {}", e)))?;

        // Read application data
        let bytes_received = tls_conn
            .reader()
            .read(buffer)
            .map_err(|e| Error::IoError(format!("TLS read failed: {}", e)))?;

        self.bytes_decrypted += bytes_received as u64;
        Ok(bytes_received)
    }

    /// Perform TLS handshake on existing TCP stream
    pub fn handshake(&mut self, stream: &mut TcpStream) -> Result<()> {
        if self.state != TlsState::Disconnected {
            return Err(Error::InvalidState);
        }

        self.state = TlsState::Handshaking;

        // Create rustls config
        let config = Arc::new(self.create_rustls_config()?);

        // Get server name for SNI
        let server_name = self
            .config
            .server_name
            .as_ref()
            .ok_or(Error::IoError("Server name required for handshake".to_string()))?
            .to_string();

        let server_name = ServerName::try_from(server_name)
            .map_err(|_| Error::IoError("Invalid server name".to_string()))?;

        // Create TLS connection
        let mut tls_conn = ClientConnection::new(config, server_name)
            .map_err(|e| Error::TlsError(format!("Failed to create TLS connection: {}", e)))?;

        // Perform TLS handshake loop
        while tls_conn.is_handshaking() {
            // Write TLS data to socket
            tls_conn.write_tls(stream)
                .map_err(|e| Error::IoError(format!("TLS write failed: {}", e)))?;

            // Read TLS data from socket
            tls_conn.read_tls(stream)
                .map_err(|e| Error::IoError(format!("TLS read failed: {}", e)))?;

            // Process TLS messages
            tls_conn.process_new_packets()
                .map_err(|e| Error::TlsError(format!("TLS handshake failed: {}", e)))?;
        }

        // Clone the stream (we need ownership)
        let cloned_stream = stream.try_clone()
            .map_err(|e| Error::IoError(format!("Failed to clone stream: {}", e)))?;

        self.stream = Some(cloned_stream);
        self.tls_conn = Some(tls_conn);
        self.state = TlsState::Connected;

        Ok(())
    }

    /// Encrypt data (uses TLS connection's crypto)
    pub fn encrypt(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<usize> {
        if self.state != TlsState::Connected {
            return Err(Error::InvalidState);
        }

        // For TLS connections, we can't do direct encrypt/decrypt
        // This method is for compatibility with code that expects raw encryption
        // In practice, use send() and receive() which handle TLS properly
        
        // We'll use the TLS connection's writer which handles encryption
        if let (Some(ref mut tls_conn), Some(ref mut stream)) = (&mut self.tls_conn, &mut self.stream) {
            use std::io::Write;
            
            // Write plaintext to TLS writer (this encrypts it internally)
            tls_conn.writer().write_all(plaintext)
                .map_err(|e| Error::IoError(format!("TLS write failed: {}", e)))?;
            
            // Flush TLS records to a temporary buffer
            let mut temp_buffer = Vec::new();
            tls_conn.write_tls(&mut temp_buffer)
                .map_err(|e| Error::IoError(format!("TLS flush failed: {}", e)))?;
            
            if ciphertext.len() < temp_buffer.len() {
                return Err(Error::BufferTooSmall);
            }
            
            // Copy encrypted data to output buffer
            ciphertext[..temp_buffer.len()].copy_from_slice(&temp_buffer);
            
            self.bytes_encrypted += plaintext.len() as u64;
            Ok(temp_buffer.len())
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Decrypt data (uses TLS connection's crypto)
    pub fn decrypt(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<usize> {
        if self.state != TlsState::Connected {
            return Err(Error::InvalidState);
        }

        // For TLS connections, we can't do direct encrypt/decrypt
        // This method is for compatibility with code that expects raw encryption
        // In practice, use send() and receive() which handle TLS properly
        
        if let Some(ref mut tls_conn) = &mut self.tls_conn {
            use std::io::{Cursor, Read};
            
            // Feed encrypted data to TLS connection
            let mut cursor = Cursor::new(ciphertext);
            tls_conn.read_tls(&mut cursor)
                .map_err(|e| Error::IoError(format!("TLS read failed: {}", e)))?;
            
            // Process TLS records
            tls_conn.process_new_packets()
                .map_err(|e| Error::TlsError(format!("TLS packet processing failed: {}", e)))?;
            
            // Read decrypted plaintext
            let bytes_read = tls_conn.reader().read(plaintext)
                .map_err(|e| Error::IoError(format!("TLS decrypt failed: {}", e)))?;
            
            self.bytes_decrypted += bytes_read as u64;
            Ok(bytes_read)
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Get connection state
    pub fn state(&self) -> TlsState {
        self.state
    }

    /// Get session ID for resumption
    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_deref()
    }

    /// Get encryption statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.bytes_encrypted, self.bytes_decrypted)
    }

    /// Close TLS connection
    pub fn close(&mut self) -> Result<()> {
        if self.state == TlsState::Connected {
            // TODO: Send close_notify alert
            self.state = TlsState::Disconnected;
        }
        Ok(())
    }
}

/// Secure stream wrapper combining TCP + TLS
pub struct SecureStream {
    /// TCP stream
    stream: TcpStream,
    /// TLS connection
    tls: TlsConnection,
    /// Read buffer
    read_buffer: Vec<u8>,
    /// Write buffer
    write_buffer: Vec<u8>,
}

impl SecureStream {
    /// Create new secure stream
    pub fn new(stream: TcpStream, config: TlsConfig) -> Result<Self> {
        let tls = TlsConnection::new(config);
        // Note: We can't call handshake here because we need &mut stream
        // Caller must call handshake() after construction

        Ok(Self {
            stream,
            tls,
            read_buffer: vec![0u8; 16384],
            write_buffer: vec![0u8; 16384],
        })
    }

    /// Perform TLS handshake
    pub fn handshake(&mut self) -> Result<()> {
        self.tls.handshake(&mut self.stream)
    }

    /// Read decrypted data
    pub fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        // Read encrypted data from TCP
        let encrypted_len = self
            .stream
            .read(&mut self.read_buffer)
            .map_err(|e| Error::IoError(e.to_string()))?;

        if encrypted_len == 0 {
            return Ok(0);
        }

        // Decrypt to output buffer
        self.tls
            .decrypt(&self.read_buffer[..encrypted_len], buffer)
    }

    /// Write encrypted data
    pub fn write(&mut self, buffer: &[u8]) -> Result<usize> {
        // Encrypt to write buffer
        let encrypted_len = self.tls.encrypt(buffer, &mut self.write_buffer)?;

        // Write encrypted data to TCP
        self.stream
            .write_all(&self.write_buffer[..encrypted_len])
            .map_err(|e| Error::IoError(e.to_string()))?;

        Ok(buffer.len())
    }

    /// Get TLS connection state
    pub fn tls_state(&self) -> TlsState {
        self.tls.state()
    }

    /// Get encryption statistics
    pub fn stats(&self) -> (u64, u64) {
        self.tls.stats()
    }

    /// Close secure stream
    pub fn close(mut self) -> Result<()> {
        self.tls.close()?;
        self.stream
            .shutdown(std::net::Shutdown::Both)
            .map_err(|e| Error::IoError(e.to_string()))?;
        Ok(())
    }
}

/// Certificate utilities
pub mod cert {
    use super::*;

    /// Parse PEM certificate
    pub fn parse_pem_cert(_pem_data: &[u8]) -> Result<Vec<u8>> {
        // TODO: Implement PEM parsing
        Err(Error::NotImplemented)
    }

    /// Validate certificate chain
    pub fn validate_chain(_cert: &[u8], _ca_cert: Option<&[u8]>) -> Result<bool> {
        // TODO: Implement certificate validation
        Err(Error::NotImplemented)
    }

    /// Extract subject name from certificate
    pub fn get_subject_name(_cert: &[u8]) -> Result<String> {
        // TODO: Implement subject name extraction
        Err(Error::NotImplemented)
    }

    /// Verify certificate hostname
    pub fn verify_hostname(_cert: &[u8], _hostname: &str) -> Result<bool> {
        // TODO: Implement hostname verification
        Err(Error::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert_eq!(config.version, TlsVersion::Tls13);
        assert_eq!(config.verify_mode, CertVerifyMode::Full);
        assert!(config.session_resumption);
    }

    #[test]
    fn test_tls_connection_creation() {
        let conn = TlsConnection::with_defaults();
        assert_eq!(conn.state(), TlsState::Disconnected);
        assert_eq!(conn.session_id(), None);
    }

    #[test]
    fn test_tls_state_transitions() {
        let mut conn = TlsConnection::with_defaults();
        assert_eq!(conn.state(), TlsState::Disconnected);

        // Can't encrypt before connected
        let mut output = [0u8; 64];
        assert!(conn.encrypt(b"test", &mut output).is_err());
    }

    #[test]
    fn test_encryption_requires_connection() {
        let mut conn = TlsConnection::with_defaults();
        let mut buffer = [0u8; 128];

        // Should fail when not connected
        let result = conn.encrypt(b"hello", &mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_buffer_size_validation() {
        let mut conn = TlsConnection::with_defaults();
        conn.state = TlsState::Connected; // Force connected state

        let mut small_buffer = [0u8; 10];
        let large_data = [0u8; 100];

        // Should fail with buffer too small
        let result = conn.encrypt(&large_data, &mut small_buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_tls_stats_tracking() {
        let mut conn = TlsConnection::with_defaults();
        conn.state = TlsState::Connected;

        let mut buffer = [0u8; 128];
        let data = b"test data";

        // Encrypt some data
        let _ = conn.encrypt(data, &mut buffer);

        let (encrypted, _) = conn.stats();
        assert_eq!(encrypted, data.len() as u64);
    }

    #[test]
    fn test_cipher_suite_enum() {
        let suite1 = CipherSuite::Aes256GcmEcdhe;
        let suite2 = CipherSuite::Aes256GcmEcdhe;
        assert_eq!(suite1, suite2);
    }

    #[test]
    fn test_cert_verify_modes() {
        assert_ne!(CertVerifyMode::Full, CertVerifyMode::None);
        assert_ne!(CertVerifyMode::Full, CertVerifyMode::CustomCa);
    }
}
