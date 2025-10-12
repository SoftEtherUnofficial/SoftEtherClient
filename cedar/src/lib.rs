//! Cedar - VPN Protocol Layer
//!
//! Cedar implements the SoftEther VPN protocol layer, providing:
//! - Session management
//! - Connection handling
//! - Authentication
//! - Protocol serialization
//! - Encryption (TLS/SSL)
//! - Compression
//! - UDP acceleration
//! - NAT traversal
//!
//! ## Complete Modules
//! - `session` - VPN session lifecycle management
//! - `connection` - TCP connection and packet framing
//! - `auth` - Authentication system
//! - `protocol` - Wire protocol format
//! - `encryption` - TLS/SSL support
//! - `compression` - Data compression
//! - `udp_accel` - UDP acceleration
//! - `nat_traversal` - NAT traversal

// Extracted from softether-rust (Tier 1)
pub mod constants;
pub mod types;

// Phase 3.2 modules
pub mod session;
pub mod connection;
pub mod auth;
pub mod protocol;
pub mod encryption;
pub mod compression;
pub mod udp_accel;
pub mod nat_traversal;

// DHCP client for automatic IP configuration
pub mod dhcp;

// ZigTapTun adapter FFI bindings
pub mod adapter_ffi;

// FFI exports for C/Zig integration
pub mod ffi;

// Re-export commonly used items
pub use constants::*;
pub use types::*;

// Re-export key types from modules
pub use session::{Session, SessionConfig, SessionStats, SessionStatus};
pub use connection::{Connection, ConnectionState, ConnectionType, PacketHeader};
pub use auth::{AuthManager, Credentials, AuthRequest, AuthResponse};
pub use protocol::{Packet, PacketValue, PROTOCOL_VERSION, CEDAR_SIGNATURE};
pub use encryption::{TlsConnection, TlsConfig, TlsState};
pub use compression::{Compressor, CompressionConfig, CompressionAlgorithm};
pub use udp_accel::{UdpAccelerator, UdpAccelConfig, UdpAccelMode};
pub use nat_traversal::{NatTraversal, NatTraversalConfig, NatType};
pub use dhcp::{DhcpClient, DhcpState};

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
