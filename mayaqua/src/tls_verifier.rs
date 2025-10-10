//! Permissive TLS certificate verifier for testing with self-signed certificates
//!
//! ⚠️  WARNING: This bypasses certificate validation and should ONLY be used for testing!

use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, Error, ServerName};
use std::time::SystemTime;

/// Permissive certificate verifier that accepts any certificate
/// 
/// ⚠️  SECURITY WARNING: This accepts ALL certificates without validation!
/// Only use for testing with known self-signed certificates.
pub struct DangerAcceptAnyCertVerifier;

impl ServerCertVerifier for DangerAcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, Error> {
        eprintln!("⚠️  WARNING: Accepting certificate without verification!");
        Ok(ServerCertVerified::assertion())
    }
}
