//! Cedar Layer Module Index
//!
//! High-level VPN protocol engine components for SoftEther protocol.
//! Ties together authentication, connections, protocol handling, and cryptography.
//!
//! ## Modules
//! - **auth**: Authentication methods (anonymous, password, cert, secure device, ticket)
//! - **connection**: TCP connection lifecycle and block queue management
//! - **protocol**: VPN protocol packet creation and statistics
//! - **crypto**: Session encryption with multiple cipher support
//!
//! ## Usage Example
//! ```zig
//! const cedar = @import("cedar/mod.zig");
//! const allocator = std.heap.page_allocator;
//!
//! // Create authentication context
//! var auth_ctx = try cedar.createPasswordAuth(allocator, "username", "password");
//! defer auth_ctx.deinit();
//!
//! // Establish connection
//! var conn = try cedar.Connection.init(allocator, "vpn.example.com", 443, "HUB");
//! defer conn.deinit();
//!
//! // Initialize protocol handler
//! var proto = cedar.ProtocolHandler.init(allocator);
//!
//! // Setup session encryption
//! var crypto_ctx = try cedar.SessionCrypto.init(allocator, .aes_256_gcm);
//! defer crypto_ctx.deinit();
//!
//! // Authenticate and establish session
//! const auth_result = try auth_ctx.authenticate(&conn);
//! if (auth_result.authenticated) {
//!     try crypto_ctx.deriveSessionKey(password, &auth_result.random);
//!     // Ready for encrypted communication
//! }
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================================================
// Module Exports
// ============================================================================

/// Authentication module - Methods and credential management
pub const auth = @import("auth.zig");

/// Connection module - TCP lifecycle and block queue
pub const connection = @import("connection.zig");

/// Protocol module - Packet creation and statistics
pub const protocol = @import("protocol.zig");

/// Crypto module - Session encryption
pub const crypto = @import("crypto.zig");

// ============================================================================
// Type Re-exports for Convenience
// ============================================================================

// Authentication types
pub const AuthType = auth.AuthType;
pub const ClientAuth = auth.ClientAuth;

// Connection types
pub const Connection = connection.Connection;
pub const ConnectionState = connection.ConnectionState;
pub const BlockQueue = connection.BlockQueue;
pub const Block = connection.Block;

// Protocol types
pub const ProtocolHandler = protocol.ProtocolHandler;
pub const ProtocolStats = protocol.ProtocolStats;

// Crypto types
pub const SessionCrypto = crypto.SessionCrypto;
pub const EncryptionAlgorithm = @import("../protocol/crypto.zig").EncryptionAlgorithm;

// ============================================================================
// Simplified Client Configuration
// ============================================================================

/// Simple configuration for establishing a VPN connection
/// For more advanced options, use individual module configurations
pub const ClientConfig = struct {
    /// VPN server hostname or IP address
    server_name: []const u8,

    /// VPN server port (typically 443 or 5555)
    server_port: u16,

    /// Virtual HUB name to connect to
    hub_name: []const u8,

    /// Authentication type to use
    auth_type: AuthType,

    /// Username for authentication (required for password/cert/secure device)
    username: []const u8,

    /// Password for password authentication (or empty for other methods)
    password: []const u8,

    /// Memory allocator
    allocator: Allocator,

    /// Preferred encryption algorithm (default: AES-256-GCM)
    encryption: EncryptionAlgorithm = .aes_256_gcm,

    /// Maximum TCP connections (default: 1)
    max_connections: u32 = 1,

    /// Connection timeout in milliseconds (default: 15000)
    timeout_ms: u32 = 15000,

    /// Keepalive interval in milliseconds (default: 5000)
    keepalive_interval_ms: u32 = 5000,

    pub fn validate(self: *const ClientConfig) !void {
        if (self.server_name.len == 0) {
            return error.InvalidServerName;
        }
        if (self.server_port == 0) {
            return error.InvalidServerPort;
        }
        if (self.hub_name.len == 0) {
            return error.InvalidHubName;
        }
        if (self.auth_type != .anonymous and self.username.len == 0) {
            return error.InvalidUsername;
        }
        if (self.auth_type == .password and self.password.len == 0) {
            return error.InvalidPassword;
        }
    }
};

// ============================================================================
// Helper Functions - Re-export from auth module
// ============================================================================

/// Helper functions are now directly available from the auth module.
/// Use ClientAuth.initAnonymous, ClientAuth.initPassword, etc.

// ============================================================================
// Module Information
// ============================================================================

/// Cedar layer version information
pub const VERSION = struct {
    pub const MAJOR: u32 = 1;
    pub const MINOR: u32 = 0;
    pub const PATCH: u32 = 0;
    pub const STRING = "1.0.0";
};

/// Get module statistics
pub const ModuleStats = struct {
    auth_lines: usize = 254,
    connection_lines: usize = 359,
    protocol_lines: usize = 332,
    crypto_lines: usize = 270,
    total_lines: usize = 1215,
    total_tests: usize = 44,
};

pub fn getModuleStats() ModuleStats {
    return .{};
}

// ============================================================================
// Tests
// ============================================================================

test "cedar module exports" {
    // Verify all modules are accessible
    _ = auth;
    _ = connection;
    _ = protocol;
    _ = crypto;
}

test "cedar type re-exports" {
    // Verify re-exported types are accessible
    _ = AuthType;
    _ = ClientAuth;
    _ = Connection;
    _ = ProtocolHandler;
    _ = SessionCrypto;
}

test "cedar config validation" {
    const allocator = std.testing.allocator;

    // Valid config
    var config = ClientConfig{
        .server_name = "vpn.example.com",
        .server_port = 443,
        .hub_name = "DEFAULT",
        .auth_type = .password,
        .username = "testuser",
        .password = "testpass",
        .allocator = allocator,
    };
    try config.validate();

    // Invalid: empty server name
    config.server_name = "";
    try std.testing.expectError(error.InvalidServerName, config.validate());
}
test "cedar helper functions" {
    const allocator = std.testing.allocator;

    // Anonymous auth
    const anon_auth = try ClientAuth.initAnonymous(allocator);
    defer anon_auth.deinit();
    try std.testing.expectEqual(AuthType.anonymous, anon_auth.auth_type);

    // Password auth
    const pass_auth = try ClientAuth.initPassword(allocator, "user", "pass");
    defer pass_auth.deinit();
    try std.testing.expectEqual(AuthType.password, pass_auth.auth_type);
}

test "cedar module integration" {
    const allocator = std.testing.allocator;

    // Test that all 4 modules can be instantiated together

    // Auth
    const auth_obj = try ClientAuth.initPassword(allocator, "testuser", "testpass");
    defer auth_obj.deinit();

    // Connection
    var conn = try Connection.init(allocator, "example.com", 443, "HUB");
    defer conn.deinit();

    // Protocol
    const proto = ProtocolHandler.init(allocator);
    _ = proto;

    // Crypto
    var crypto_ctx = try SessionCrypto.init(allocator, .rc4);
    defer crypto_ctx.deinit();

    // All modules instantiated successfully
    try std.testing.expect(true);
}
