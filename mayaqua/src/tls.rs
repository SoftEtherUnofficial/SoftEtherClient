//! TLS support using native-tls
//!
//! Provides TLS/SSL encryption for TCP connections using the native-tls library (OpenSSL on macOS/Linux).

use crate::error::{Error, Result};
use native_tls::{TlsConnector, TlsStream as NativeTlsStream};
use std::io::{Read, Write};
use std::net::TcpStream;

/// TLS-wrapped TCP stream
pub struct TlsStream {
    inner: NativeTlsStream<TcpStream>,
}

impl TlsStream {
    /// Connect with TLS using native-tls (OpenSSL on macOS/Linux)
    pub fn connect(stream: TcpStream, hostname: &str) -> Result<Self> {
        eprintln!("[TLS-CEDAR] ========================================");
        eprintln!("[TLS-CEDAR] Creating TLS connection using native-tls (OpenSSL)");
        eprintln!("[TLS-CEDAR] Target hostname: {}", hostname);
        eprintln!("[TLS-CEDAR] ========================================");
        
        // Build TLS connector with insecure cert verification for testing
        // TODO: Add proper certificate validation for production
        eprintln!("⚠️  Using insecure certificate verification for testing");
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .map_err(|e| Error::TlsError(format!("Failed to build TLS connector: {}", e)))?;

        // Perform TLS handshake
        eprintln!("[TLS-CEDAR] Performing TLS handshake...");
        let tls_stream = connector
            .connect(hostname, stream)
            .map_err(|e| Error::TlsError(format!("TLS handshake failed: {}", e)))?;

        eprintln!("[TLS-CEDAR] ✅ TLS handshake completed successfully");
        eprintln!("[TLS-CEDAR] Using native-tls (OpenSSL backend)");
        
        // Log certificate info if available
        if let Ok(Some(cert)) = tls_stream.peer_certificate() {
            if let Ok(der) = cert.to_der() {
                eprintln!("[TLS-CEDAR] Server certificate received ({} bytes)", der.len());
            }
        }
        
        eprintln!("[TLS-CEDAR] ========================================");

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
