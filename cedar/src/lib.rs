//! Cedar VPN Protocol Layer
//!
//! This crate implements the Cedar VPN protocol layer, built on top of Mayaqua.
//! Cedar handles the VPN session management, authentication, and protocol logic.
//!
//! ## Current Status
//! - constants: Protocol constants and version information
//! - types: Core protocol data structures
//!
//! ## Future Modules (Planned)
//! - session: Session management
//! - connection: Connection handling
//! - auth: Authentication strategies
//! - protocol: Wire protocol implementation

// Extracted from softether-rust (Tier 1)
pub mod constants;
pub mod types;

// Re-export commonly used items
pub use constants::*;
pub use types::*;

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
