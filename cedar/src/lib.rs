//! Cedar VPN Protocol Layer
//!
//! This crate implements the Cedar VPN protocol layer, built on top of Mayaqua.
//! Cedar handles the VPN session management, authentication, and protocol logic.
//!
//! ## Current Status
//! - constants: Protocol constants and version information
//! - types: Core protocol data structures
//! - session: Session management and lifecycle
//! - connection: Connection handling and packet framing
//! - auth: Authentication strategies and credential management
//! - protocol: Wire protocol implementation
//!
//! ## Future Modules (Planned)
//! - encryption: TLS/SSL wrapper and cipher management
//! - compression: Data compression support
//! - udp_accel: UDP acceleration implementation
//! - nat_traversal: NAT-T and hole punching

// Extracted from softether-rust (Tier 1)
pub mod constants;
pub mod types;

// Phase 3.2 modules
pub mod session;
pub mod connection;
pub mod auth;
pub mod protocol;

// Re-export commonly used items
pub use constants::*;
pub use types::*;

// Re-export key types from modules
pub use session::{Session, SessionConfig, SessionStats, SessionStatus};
pub use connection::{Connection, ConnectionState, ConnectionType, PacketHeader};
pub use auth::{AuthManager, Credentials, AuthRequest, AuthResponse};
pub use protocol::{Packet, PacketValue, PROTOCOL_VERSION, CEDAR_SIGNATURE};

#[cfg(test)]
mod tests {
    use mayaqua::SHA1_SIZE;

    #[test]
    fn test_constants() {
        // Verify SHA1_SIZE from mayaqua
        assert_eq!(SHA1_SIZE, 20);
        
        // Verify basic protocol constants
        assert_eq!(super::CONNECTING_TIMEOUT_MS, 15_000);
        assert_eq!(super::MIN_RETRY_INTERVAL_MS, 5_000);
    }
}
