//! TLS support using rustls
//!
//! Provides TLS/SSL encryption for TCP connections using the rustls library.

use crate::error::{Error, Result};
use crate::tls_verifier::DangerAcceptAnyCertVerifier;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerName, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

/// TLS-wrapped TCP stream
pub struct TlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
}

impl TlsStream {
    /// Connect with TLS using system root certificates
    pub fn connect(stream: TcpStream, hostname: &str) -> Result<Self> {
        // Load system root certificates
        let mut root_store = RootCertStore::empty();
        
        match rustls_native_certs::load_native_certs() {
            Ok(certs) => {
                let mut cert_count = 0;
                for cert in certs {
                    if root_store.add(&rustls::Certificate(cert.0)).is_ok() {
                        cert_count += 1;
                    }
                }
                if cert_count == 0 {
                    eprintln!("Warning: No valid native certificates found, using webpki-roots");
                    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject,
                            ta.spki,
                            ta.name_constraints,
                        )
                    }));
                }
            }
            Err(e) => {
                // Fallback to webpki-roots if system certs fail
                eprintln!("Warning: Failed to load native certs: {}, using webpki-roots", e);
                root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }));
            }
        }

        // Ensure we have at least some root certificates
        if root_store.is_empty() {
            return Err(Error::TlsError("No root certificates available".to_string()));
        }

        // Create TLS config with safe defaults but INSECURE cert verification
        // TODO: Add proper certificate validation for production
        eprintln!("⚠️  Using insecure certificate verification for testing");
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(DangerAcceptAnyCertVerifier))
            .with_no_client_auth();

        // Create server name
        let server_name = ServerName::try_from(hostname)
            .map_err(|e| Error::TlsError(format!("Invalid hostname '{}': {}", hostname, e)))?;

        // Create TLS connection
        let conn = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| Error::TlsError(format!("Failed to create TLS connection: {}", e)))?;

        let tls_stream = StreamOwned::new(conn, stream);

        Ok(Self { inner: tls_stream })
    }

    /// Read from TLS stream
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner
            .read(buf)
            .map_err(|e| Error::IoError(format!("TLS read failed: {}", e)))
    }

    /// Write to TLS stream
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner
            .write(buf)
            .map_err(|e| Error::IoError(format!("TLS write failed: {}", e)))
    }

    /// Flush write buffer
    pub fn flush(&mut self) -> Result<()> {
        self.inner
            .flush()
            .map_err(|e| Error::IoError(format!("TLS flush failed: {}", e)))
    }

    /// Get access to the underlying TCP stream (for socket options)
    pub fn get_ref(&self) -> &TcpStream {
        self.inner.get_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    #[ignore] // Requires network access
    fn test_tls_connection() {
        // Test connection to a known HTTPS server
        let stream = TcpStream::connect_timeout(
            &"www.google.com:443".parse().unwrap(),
            Duration::from_secs(5),
        )
        .expect("Failed to connect");

        let mut tls = TlsStream::connect(stream, "www.google.com").expect("Failed TLS handshake");

        // Send a simple HTTP request
        let request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
        tls.write(request).expect("Failed to write");
        tls.flush().expect("Failed to flush");

        // Read response
        let mut buf = [0u8; 1024];
        let n = tls.read(&mut buf).expect("Failed to read");
        assert!(n > 0);

        // Check for HTTP response
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.starts_with("HTTP/"));
    }
}
