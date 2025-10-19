//! Cedar Crypto Integration Module
//!
//! High-level cryptographic interface for VPN session encryption.
//! Wraps protocol/crypto.zig primitives for Cedar layer usage.
//!
//! Components:
//! - SessionCrypto: Main encryption/decryption context for VPN sessions
//! - Key management: Session key derivation and storage
//! - Algorithm selection: RC4, AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//!
//! Usage:
//! ```zig
//! // Initialize crypto context with RC4
//! var crypto_ctx = try SessionCrypto.init(allocator, .rc4);
//! defer crypto_ctx.deinit();
//!
//! // Set session key (derived from authentication)
//! try crypto_ctx.setSessionKey(&session_key);
//!
//! // Encrypt data
//! const encrypted = try crypto_ctx.encrypt(plaintext_data);
//! defer encrypted.deinit();
//!
//! // Decrypt data
//! const plaintext = try crypto_ctx.decrypt(&encrypted_packet);
//! defer allocator.free(plaintext);
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import protocol crypto primitives
const protocol_crypto = @import("../protocol/crypto.zig");
const CryptoEngine = protocol_crypto.CryptoEngine;
const EncryptionAlgorithm = protocol_crypto.EncryptionAlgorithm;
const EncryptedPacket = protocol_crypto.EncryptedPacket;
const Rc4Cipher = protocol_crypto.Rc4Cipher;

// Import mayaqua crypto for key derivation
const mayaqua_crypto = @import("../mayaqua/crypto.zig");

// ============================================================================
// Session Crypto Context
// ============================================================================

/// High-level crypto context for VPN session encryption
pub const SessionCrypto = struct {
    engine: ?CryptoEngine,
    algorithm: EncryptionAlgorithm,
    session_key: [32]u8, // Maximum key size (256-bit)
    key_size: usize,
    has_key: bool,
    allocator: Allocator,

    const Self = @This();

    /// Initialize crypto context with specified algorithm
    pub fn init(allocator: Allocator, algorithm: EncryptionAlgorithm) !Self {
        return .{
            .engine = null,
            .algorithm = algorithm,
            .session_key = [_]u8{0} ** 32,
            .key_size = algorithm.getKeySize(),
            .has_key = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.engine) |*engine| {
            engine.deinit();
        }
        // Zero out session key for security
        mayaqua_crypto.secureZero(&self.session_key);
    }

    /// Set session key and initialize crypto engine
    pub fn setSessionKey(self: *Self, key: []const u8) !void {
        if (key.len < self.key_size) {
            return error.KeyTooShort;
        }

        // Copy key to internal storage
        @memcpy(self.session_key[0..self.key_size], key[0..self.key_size]);
        self.has_key = true;

        // Initialize crypto engine with the key
        if (self.engine) |*engine| {
            engine.deinit();
        }
        self.engine = try CryptoEngine.init(self.allocator, self.algorithm);

        // Set the key in the engine's contexts
        if (self.engine) |*engine| {
            @memcpy(engine.encrypt_ctx.key[0..self.key_size], self.session_key[0..self.key_size]);
            @memcpy(engine.decrypt_ctx.key[0..self.key_size], self.session_key[0..self.key_size]);
        }
    }

    /// Derive session key from password and random challenge (SoftEther method)
    pub fn deriveSessionKey(self: *Self, password: []const u8, random: []const u8) !void {
        if (random.len < 20) {
            return error.InvalidRandomSize;
        }

        // SoftEther key derivation: SHA-0(SHA-0(password) + random)
        var key: [20]u8 = undefined;
        const random_bytes: *const [20]u8 = random[0..20];
        protocol_crypto.KeyDerivation.deriveAuthKey(password, random_bytes, &key);

        // Set the derived key (use first key_size bytes)
        try self.setSessionKey(&key);

        // Zero out temporary key
        mayaqua_crypto.secureZero(&key);
    }

    /// Generate random session key (for key exchange scenarios)
    pub fn generateSessionKey(self: *Self) !void {
        var key: [32]u8 = undefined;
        mayaqua_crypto.randomBytes(&key);
        try self.setSessionKey(&key);
        mayaqua_crypto.secureZero(&key);
    }

    /// Encrypt plaintext data
    pub fn encrypt(self: *Self, plaintext: []const u8) !EncryptedPacket {
        if (!self.has_key) {
            return error.NoSessionKey;
        }

        var engine = self.engine orelse return error.EngineNotInitialized;
        return try engine.encrypt(plaintext);
    }

    /// Decrypt encrypted packet
    pub fn decrypt(self: *Self, encrypted: *const EncryptedPacket) ![]u8 {
        if (!self.has_key) {
            return error.NoSessionKey;
        }

        var engine = self.engine orelse return error.EngineNotInitialized;
        return try engine.decrypt(encrypted);
    }

    /// Get current encryption algorithm
    pub fn getAlgorithm(self: *const Self) EncryptionAlgorithm {
        return self.algorithm;
    }

    /// Check if session key is set
    pub fn hasKey(self: *const Self) bool {
        return self.has_key;
    }

    /// Get required key size for current algorithm
    pub fn getKeySize(self: *const Self) usize {
        return self.key_size;
    }

    /// Clear session key (for rekeying scenarios)
    pub fn clearKey(self: *Self) void {
        mayaqua_crypto.secureZero(&self.session_key);
        self.has_key = false;

        if (self.engine) |*engine| {
            engine.deinit();
            self.engine = null;
        }
    }
};

// ============================================================================
// Cipher Selection Helpers
// ============================================================================

/// Select cipher algorithm based on server capabilities
pub fn selectCipherAlgorithm(
    server_supports_aead: bool,
    prefer_chacha: bool,
) EncryptionAlgorithm {
    if (server_supports_aead) {
        // Modern server: prefer AEAD ciphers
        if (prefer_chacha) {
            return .chacha20_poly1305;
        } else {
            return .aes_256_gcm;
        }
    } else {
        // Legacy server: fallback to RC4
        return .rc4;
    }
}

/// Get cipher name string for protocol negotiation
pub fn getCipherName(algorithm: EncryptionAlgorithm) []const u8 {
    return switch (algorithm) {
        .rc4 => "RC4",
        .aes_128_gcm => "AES-128-GCM",
        .aes_256_gcm => "AES-256-GCM",
        .chacha20_poly1305 => "ChaCha20-Poly1305",
    };
}

/// Parse cipher name from server response
pub fn parseCipherName(name: []const u8) ?EncryptionAlgorithm {
    if (std.mem.eql(u8, name, "RC4")) {
        return .rc4;
    } else if (std.mem.eql(u8, name, "AES-128-GCM")) {
        return .aes_128_gcm;
    } else if (std.mem.eql(u8, name, "AES-256-GCM")) {
        return .aes_256_gcm;
    } else if (std.mem.eql(u8, name, "ChaCha20-Poly1305")) {
        return .chacha20_poly1305;
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "SessionCrypto initialization" {
    const allocator = std.testing.allocator;

    var crypto = try SessionCrypto.init(allocator, .rc4);
    defer crypto.deinit();

    try std.testing.expectEqual(EncryptionAlgorithm.rc4, crypto.getAlgorithm());
    try std.testing.expect(!crypto.hasKey());
    try std.testing.expectEqual(@as(usize, 16), crypto.getKeySize());
}

test "SessionCrypto set session key" {
    const allocator = std.testing.allocator;

    var crypto = try SessionCrypto.init(allocator, .rc4);
    defer crypto.deinit();

    const key = "0123456789abcdef"; // 16 bytes
    try crypto.setSessionKey(key);

    try std.testing.expect(crypto.hasKey());
}

test "SessionCrypto derive session key from password" {
    const allocator = std.testing.allocator;

    var crypto = try SessionCrypto.init(allocator, .rc4);
    defer crypto.deinit();

    const password = "test_password";
    var random: [20]u8 = undefined;
    mayaqua_crypto.randomBytes(&random);

    try crypto.deriveSessionKey(password, &random);
    try std.testing.expect(crypto.hasKey());
}

test "SessionCrypto generate random session key" {
    const allocator = std.testing.allocator;

    var crypto = try SessionCrypto.init(allocator, .aes_256_gcm);
    defer crypto.deinit();

    try crypto.generateSessionKey();
    try std.testing.expect(crypto.hasKey());
    try std.testing.expectEqual(@as(usize, 32), crypto.getKeySize());
}

test "SessionCrypto clear key" {
    const allocator = std.testing.allocator;

    var crypto = try SessionCrypto.init(allocator, .rc4);
    defer crypto.deinit();

    const key = "0123456789abcdef";
    try crypto.setSessionKey(key);
    try std.testing.expect(crypto.hasKey());

    crypto.clearKey();
    try std.testing.expect(!crypto.hasKey());
}

test "Cipher algorithm selection" {
    // Modern server with AEAD support
    const cipher1 = selectCipherAlgorithm(true, false);
    try std.testing.expectEqual(EncryptionAlgorithm.aes_256_gcm, cipher1);

    const cipher2 = selectCipherAlgorithm(true, true);
    try std.testing.expectEqual(EncryptionAlgorithm.chacha20_poly1305, cipher2);

    // Legacy server without AEAD
    const cipher3 = selectCipherAlgorithm(false, false);
    try std.testing.expectEqual(EncryptionAlgorithm.rc4, cipher3);
}

test "Cipher name conversion" {
    try std.testing.expectEqualStrings("RC4", getCipherName(.rc4));
    try std.testing.expectEqualStrings("AES-256-GCM", getCipherName(.aes_256_gcm));
    try std.testing.expectEqualStrings("ChaCha20-Poly1305", getCipherName(.chacha20_poly1305));

    const alg1 = parseCipherName("RC4");
    try std.testing.expectEqual(EncryptionAlgorithm.rc4, alg1.?);

    const alg2 = parseCipherName("AES-128-GCM");
    try std.testing.expectEqual(EncryptionAlgorithm.aes_128_gcm, alg2.?);

    const alg3 = parseCipherName("Invalid");
    try std.testing.expectEqual(@as(?EncryptionAlgorithm, null), alg3);
}
