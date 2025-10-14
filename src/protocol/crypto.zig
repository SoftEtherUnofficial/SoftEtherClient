// Cryptography and Encryption Module
// Provides TLS/SSL integration, cipher suite management, and encrypted packet handling
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

// ============================================================================
// Constants
// ============================================================================

pub const MAX_KEY_SIZE: usize = 256; // 2048-bit keys
pub const MAX_IV_SIZE: usize = 16; // 128-bit IVs
pub const MIN_TLS_VERSION: u16 = 0x0303; // TLS 1.2
pub const PREFERRED_TLS_VERSION: u16 = 0x0304; // TLS 1.3

// ============================================================================
// TLS Version
// ============================================================================

pub const TlsVersion = enum(u16) {
    tls_1_0 = 0x0301,
    tls_1_1 = 0x0302,
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,

    pub fn toString(self: TlsVersion) []const u8 {
        return switch (self) {
            .tls_1_0 => "TLS 1.0",
            .tls_1_1 => "TLS 1.1",
            .tls_1_2 => "TLS 1.2",
            .tls_1_3 => "TLS 1.3",
        };
    }

    pub fn isSupported(self: TlsVersion) bool {
        return @intFromEnum(self) >= MIN_TLS_VERSION;
    }

    pub fn fromU16(value: u16) ?TlsVersion {
        return switch (value) {
            0x0301 => .tls_1_0,
            0x0302 => .tls_1_1,
            0x0303 => .tls_1_2,
            0x0304 => .tls_1_3,
            else => null,
        };
    }
};

// ============================================================================
// Cipher Suites
// ============================================================================

pub const CipherSuite = enum(u16) {
    // TLS 1.3 cipher suites (recommended)
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,

    // TLS 1.2 cipher suites (legacy support)
    tls_ecdhe_rsa_aes_128_gcm_sha256 = 0xC02F,
    tls_ecdhe_rsa_aes_256_gcm_sha384 = 0xC030,
    tls_ecdhe_ecdsa_aes_128_gcm_sha256 = 0xC02B,
    tls_ecdhe_ecdsa_aes_256_gcm_sha384 = 0xC02C,

    pub fn toString(self: CipherSuite) []const u8 {
        return switch (self) {
            .tls_aes_128_gcm_sha256 => "TLS_AES_128_GCM_SHA256",
            .tls_aes_256_gcm_sha384 => "TLS_AES_256_GCM_SHA384",
            .tls_chacha20_poly1305_sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            .tls_ecdhe_rsa_aes_128_gcm_sha256 => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            .tls_ecdhe_rsa_aes_256_gcm_sha384 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            .tls_ecdhe_ecdsa_aes_128_gcm_sha256 => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            .tls_ecdhe_ecdsa_aes_256_gcm_sha384 => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        };
    }

    pub fn getKeySize(self: CipherSuite) usize {
        return switch (self) {
            .tls_aes_128_gcm_sha256,
            .tls_ecdhe_rsa_aes_128_gcm_sha256,
            .tls_ecdhe_ecdsa_aes_128_gcm_sha256,
            => 16, // 128-bit

            .tls_aes_256_gcm_sha384,
            .tls_chacha20_poly1305_sha256,
            .tls_ecdhe_rsa_aes_256_gcm_sha384,
            .tls_ecdhe_ecdsa_aes_256_gcm_sha384,
            => 32, // 256-bit
        };
    }

    pub fn isAead(self: CipherSuite) bool {
        _ = self;
        return true; // All modern suites use AEAD
    }
};

// ============================================================================
// Certificate Information
// ============================================================================

pub const CertificateInfo = struct {
    subject: []const u8,
    issuer: []const u8,
    valid_from: i64, // Unix timestamp
    valid_until: i64, // Unix timestamp
    serial_number: []const u8,
    fingerprint: []const u8,
    allocator: Allocator,

    pub fn init(
        allocator: Allocator,
        subject: []const u8,
        issuer: []const u8,
        valid_from: i64,
        valid_until: i64,
        serial: []const u8,
        fingerprint: []const u8,
    ) !CertificateInfo {
        return .{
            .subject = try allocator.dupe(u8, subject),
            .issuer = try allocator.dupe(u8, issuer),
            .valid_from = valid_from,
            .valid_until = valid_until,
            .serial_number = try allocator.dupe(u8, serial),
            .fingerprint = try allocator.dupe(u8, fingerprint),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CertificateInfo) void {
        self.allocator.free(self.subject);
        self.allocator.free(self.issuer);
        self.allocator.free(self.serial_number);
        self.allocator.free(self.fingerprint);
    }

    pub fn isValid(self: *const CertificateInfo) bool {
        const now = std.time.timestamp();
        return now >= self.valid_from and now <= self.valid_until;
    }

    pub fn daysUntilExpiry(self: *const CertificateInfo) i64 {
        const now = std.time.timestamp();
        const remaining = self.valid_until - now;
        return @divFloor(remaining, 86400); // seconds per day
    }
};

// ============================================================================
// TLS Configuration
// ============================================================================

pub const TlsConfig = struct {
    min_version: TlsVersion,
    preferred_version: TlsVersion,
    cipher_suites: ArrayList(CipherSuite),
    verify_peer: bool,
    verify_hostname: bool,
    ca_cert_path: ?[]const u8,
    client_cert_path: ?[]const u8,
    client_key_path: ?[]const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator) TlsConfig {
        return .{
            .min_version = .tls_1_2,
            .preferred_version = .tls_1_3,
            .cipher_suites = ArrayList(CipherSuite){},
            .verify_peer = true,
            .verify_hostname = true,
            .ca_cert_path = null,
            .client_cert_path = null,
            .client_key_path = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TlsConfig) void {
        self.cipher_suites.deinit(self.allocator);
        if (self.ca_cert_path) |path| self.allocator.free(path);
        if (self.client_cert_path) |path| self.allocator.free(path);
        if (self.client_key_path) |path| self.allocator.free(path);
    }

    pub fn addCipherSuite(self: *TlsConfig, suite: CipherSuite) !void {
        try self.cipher_suites.append(self.allocator, suite);
    }

    pub fn setDefaultCipherSuites(self: *TlsConfig) !void {
        // TLS 1.3 suites (preferred)
        try self.addCipherSuite(.tls_aes_256_gcm_sha384);
        try self.addCipherSuite(.tls_chacha20_poly1305_sha256);
        try self.addCipherSuite(.tls_aes_128_gcm_sha256);

        // TLS 1.2 suites (fallback)
        try self.addCipherSuite(.tls_ecdhe_rsa_aes_256_gcm_sha384);
        try self.addCipherSuite(.tls_ecdhe_rsa_aes_128_gcm_sha256);
    }

    pub fn setCaCertPath(self: *TlsConfig, path: []const u8) !void {
        if (self.ca_cert_path) |old_path| {
            self.allocator.free(old_path);
        }
        self.ca_cert_path = try self.allocator.dupe(u8, path);
    }
};

// ============================================================================
// Encryption Context
// ============================================================================

pub const EncryptionAlgorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn getKeySize(self: EncryptionAlgorithm) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    pub fn getIvSize(self: EncryptionAlgorithm) usize {
        return switch (self) {
            .aes_128_gcm, .aes_256_gcm => 12, // GCM uses 96-bit IVs
            .chacha20_poly1305 => 12,
        };
    }

    pub fn getTagSize(self: EncryptionAlgorithm) usize {
        _ = self;
        return 16; // All AEAD algorithms use 128-bit tags
    }
};

pub const EncryptionContext = struct {
    algorithm: EncryptionAlgorithm,
    key: []u8,
    iv: []u8,
    sequence: u64,
    allocator: Allocator,

    pub fn init(allocator: Allocator, algorithm: EncryptionAlgorithm) !EncryptionContext {
        const key = try allocator.alloc(u8, algorithm.getKeySize());
        const iv = try allocator.alloc(u8, algorithm.getIvSize());

        // Initialize with random data
        std.crypto.random.bytes(key);
        std.crypto.random.bytes(iv);

        return .{
            .algorithm = algorithm,
            .key = key,
            .iv = iv,
            .sequence = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EncryptionContext) void {
        // Zero out sensitive data
        @memset(self.key, 0);
        @memset(self.iv, 0);

        self.allocator.free(self.key);
        self.allocator.free(self.iv);
    }

    pub fn setKey(self: *EncryptionContext, key: []const u8) !void {
        if (key.len != self.algorithm.getKeySize()) {
            return error.InvalidKeySize;
        }
        @memcpy(self.key, key);
    }

    pub fn setIv(self: *EncryptionContext, iv: []const u8) !void {
        if (iv.len != self.algorithm.getIvSize()) {
            return error.InvalidIvSize;
        }
        @memcpy(self.iv, iv);
    }

    pub fn incrementSequence(self: *EncryptionContext) void {
        self.sequence +%= 1;
    }

    pub fn deriveNonce(self: *const EncryptionContext, allocator: Allocator) ![]u8 {
        // Derive nonce from IV and sequence number
        const nonce = try allocator.alloc(u8, self.algorithm.getIvSize());
        @memcpy(nonce, self.iv);

        // XOR sequence number into nonce
        const seq_bytes = std.mem.asBytes(&self.sequence);
        const xor_len = @min(seq_bytes.len, nonce.len);
        for (0..xor_len) |i| {
            nonce[nonce.len - xor_len + i] ^= seq_bytes[i];
        }

        return nonce;
    }
};

// ============================================================================
// Encrypted Packet
// ============================================================================

pub const EncryptedPacket = struct {
    ciphertext: []u8,
    tag: []u8,
    sequence: u64,
    allocator: Allocator,

    pub fn deinit(self: *EncryptedPacket) void {
        self.allocator.free(self.ciphertext);
        self.allocator.free(self.tag);
    }

    pub fn serialize(self: *const EncryptedPacket, allocator: Allocator) ![]u8 {
        // Format: [sequence:8][tag_len:2][tag:n][ciphertext_len:4][ciphertext:n]
        const total_size = 8 + 2 + self.tag.len + 4 + self.ciphertext.len;
        var buffer = try allocator.alloc(u8, total_size);

        var offset: usize = 0;

        // Sequence number
        std.mem.writeInt(u64, buffer[offset..][0..8], self.sequence, .little);
        offset += 8;

        // Tag length and data
        std.mem.writeInt(u16, buffer[offset..][0..2], @intCast(self.tag.len), .little);
        offset += 2;
        @memcpy(buffer[offset..][0..self.tag.len], self.tag);
        offset += self.tag.len;

        // Ciphertext length and data
        std.mem.writeInt(u32, buffer[offset..][0..4], @intCast(self.ciphertext.len), .little);
        offset += 4;
        @memcpy(buffer[offset..][0..self.ciphertext.len], self.ciphertext);

        return buffer;
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !EncryptedPacket {
        if (data.len < 14) return error.PacketTooSmall; // min: 8+2+0+4+0

        var offset: usize = 0;

        // Read sequence
        const sequence = std.mem.readInt(u64, data[offset..][0..8], .little);
        offset += 8;

        // Read tag
        const tag_len = std.mem.readInt(u16, data[offset..][0..2], .little);
        offset += 2;
        if (offset + tag_len > data.len) return error.InvalidPacket;
        const tag = try allocator.dupe(u8, data[offset..][0..tag_len]);
        offset += tag_len;

        // Read ciphertext
        const ciphertext_len = std.mem.readInt(u32, data[offset..][0..4], .little);
        offset += 4;
        if (offset + ciphertext_len != data.len) return error.InvalidPacket;
        const ciphertext = try allocator.dupe(u8, data[offset..][0..ciphertext_len]);

        return .{
            .ciphertext = ciphertext,
            .tag = tag,
            .sequence = sequence,
            .allocator = allocator,
        };
    }
};

// ============================================================================
// Crypto Engine
// ============================================================================

pub const CryptoEngine = struct {
    encrypt_ctx: EncryptionContext,
    decrypt_ctx: EncryptionContext,
    allocator: Allocator,

    pub fn init(allocator: Allocator, algorithm: EncryptionAlgorithm) !CryptoEngine {
        var encrypt_ctx = try EncryptionContext.init(allocator, algorithm);
        errdefer encrypt_ctx.deinit();

        const decrypt_ctx = try EncryptionContext.init(allocator, algorithm);

        return .{
            .encrypt_ctx = encrypt_ctx,
            .decrypt_ctx = decrypt_ctx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *CryptoEngine) void {
        self.encrypt_ctx.deinit();
        self.decrypt_ctx.deinit();
    }

    pub fn encrypt(self: *CryptoEngine, plaintext: []const u8) !EncryptedPacket {
        const algorithm = self.encrypt_ctx.algorithm;
        const tag_size = algorithm.getTagSize();

        // Allocate buffers
        const ciphertext = try self.allocator.alloc(u8, plaintext.len);
        errdefer self.allocator.free(ciphertext);

        const tag = try self.allocator.alloc(u8, tag_size);
        errdefer self.allocator.free(tag);

        // Derive nonce
        const nonce = try self.encrypt_ctx.deriveNonce(self.allocator);
        defer self.allocator.free(nonce);

        // Perform real encryption using std.crypto.aead
        switch (algorithm) {
            .aes_128_gcm => {
                const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                const key_bytes: *const [16]u8 = self.encrypt_ctx.key[0..16];
                const nonce_bytes: *const [12]u8 = nonce[0..12];
                const tag_bytes: *[16]u8 = tag[0..16];

                Aes128Gcm.encrypt(
                    ciphertext,
                    tag_bytes,
                    plaintext,
                    &[_]u8{}, // No additional data
                    nonce_bytes.*,
                    key_bytes.*,
                );
            },
            .aes_256_gcm => {
                const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                const key_bytes: *const [32]u8 = self.encrypt_ctx.key[0..32];
                const nonce_bytes: *const [12]u8 = nonce[0..12];
                const tag_bytes: *[16]u8 = tag[0..16];

                Aes256Gcm.encrypt(
                    ciphertext,
                    tag_bytes,
                    plaintext,
                    &[_]u8{}, // No additional data
                    nonce_bytes.*,
                    key_bytes.*,
                );
            },
            .chacha20_poly1305 => {
                const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
                const key_bytes: *const [32]u8 = self.encrypt_ctx.key[0..32];
                const nonce_bytes: *const [12]u8 = nonce[0..12];
                const tag_bytes: *[16]u8 = tag[0..16];

                ChaCha20Poly1305.encrypt(
                    ciphertext,
                    tag_bytes,
                    plaintext,
                    &[_]u8{}, // No additional data
                    nonce_bytes.*,
                    key_bytes.*,
                );
            },
        }

        const sequence = self.encrypt_ctx.sequence;
        self.encrypt_ctx.incrementSequence();

        return .{
            .ciphertext = ciphertext,
            .tag = tag,
            .sequence = sequence,
            .allocator = self.allocator,
        };
    }

    pub fn decrypt(self: *CryptoEngine, encrypted: *const EncryptedPacket) ![]u8 {
        const algorithm = self.decrypt_ctx.algorithm;

        // Allocate plaintext buffer
        const plaintext = try self.allocator.alloc(u8, encrypted.ciphertext.len);
        errdefer self.allocator.free(plaintext);

        // Derive nonce
        const nonce = try self.decrypt_ctx.deriveNonce(self.allocator);
        defer self.allocator.free(nonce);

        // Perform real decryption using std.crypto.aead
        switch (algorithm) {
            .aes_128_gcm => {
                const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
                const key_bytes: *const [16]u8 = self.decrypt_ctx.key[0..16];
                const nonce_bytes: *const [12]u8 = nonce[0..12];
                const tag_bytes: *const [16]u8 = encrypted.tag[0..16];

                Aes128Gcm.decrypt(
                    plaintext,
                    encrypted.ciphertext,
                    tag_bytes.*,
                    &[_]u8{}, // No additional data
                    nonce_bytes.*,
                    key_bytes.*,
                ) catch {
                    self.allocator.free(plaintext);
                    return error.AuthenticationFailed;
                };
            },
            .aes_256_gcm => {
                const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
                const key_bytes: *const [32]u8 = self.decrypt_ctx.key[0..32];
                const nonce_bytes: *const [12]u8 = nonce[0..12];
                const tag_bytes: *const [16]u8 = encrypted.tag[0..16];

                Aes256Gcm.decrypt(
                    plaintext,
                    encrypted.ciphertext,
                    tag_bytes.*,
                    &[_]u8{}, // No additional data
                    nonce_bytes.*,
                    key_bytes.*,
                ) catch {
                    self.allocator.free(plaintext);
                    return error.AuthenticationFailed;
                };
            },
            .chacha20_poly1305 => {
                const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
                const key_bytes: *const [32]u8 = self.decrypt_ctx.key[0..32];
                const nonce_bytes: *const [12]u8 = nonce[0..12];
                const tag_bytes: *const [16]u8 = encrypted.tag[0..16];

                ChaCha20Poly1305.decrypt(
                    plaintext,
                    encrypted.ciphertext,
                    tag_bytes.*,
                    &[_]u8{}, // No additional data
                    nonce_bytes.*,
                    key_bytes.*,
                ) catch {
                    self.allocator.free(plaintext);
                    return error.AuthenticationFailed;
                };
            },
        }

        self.decrypt_ctx.incrementSequence();

        return plaintext;
    }
};

// ============================================================================
// Session Key Exchange
// ============================================================================

pub const KeyExchangeMethod = enum {
    dhe, // Diffie-Hellman Ephemeral
    ecdhe, // Elliptic Curve Diffie-Hellman Ephemeral

    pub fn toString(self: KeyExchangeMethod) []const u8 {
        return switch (self) {
            .dhe => "DHE",
            .ecdhe => "ECDHE",
        };
    }
};

pub const SessionKeys = struct {
    client_write_key: []u8,
    server_write_key: []u8,
    client_write_iv: []u8,
    server_write_iv: []u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, key_size: usize, iv_size: usize) !SessionKeys {
        return .{
            .client_write_key = try allocator.alloc(u8, key_size),
            .server_write_key = try allocator.alloc(u8, key_size),
            .client_write_iv = try allocator.alloc(u8, iv_size),
            .server_write_iv = try allocator.alloc(u8, iv_size),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionKeys) void {
        // Zero out sensitive data
        @memset(self.client_write_key, 0);
        @memset(self.server_write_key, 0);
        @memset(self.client_write_iv, 0);
        @memset(self.server_write_iv, 0);

        self.allocator.free(self.client_write_key);
        self.allocator.free(self.server_write_key);
        self.allocator.free(self.client_write_iv);
        self.allocator.free(self.server_write_iv);
    }

    pub fn generateRandom(self: *SessionKeys) void {
        std.crypto.random.bytes(self.client_write_key);
        std.crypto.random.bytes(self.server_write_key);
        std.crypto.random.bytes(self.client_write_iv);
        std.crypto.random.bytes(self.server_write_iv);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "TLS version support" {
    try std.testing.expect(TlsVersion.tls_1_2.isSupported());
    try std.testing.expect(TlsVersion.tls_1_3.isSupported());
    try std.testing.expect(!TlsVersion.tls_1_0.isSupported());
    try std.testing.expect(!TlsVersion.tls_1_1.isSupported());
}

test "TLS version to string" {
    try std.testing.expectEqualStrings("TLS 1.2", TlsVersion.tls_1_2.toString());
    try std.testing.expectEqualStrings("TLS 1.3", TlsVersion.tls_1_3.toString());
}

test "TLS version from u16" {
    const v12 = TlsVersion.fromU16(0x0303);
    try std.testing.expect(v12 != null);
    try std.testing.expectEqual(TlsVersion.tls_1_2, v12.?);

    const invalid = TlsVersion.fromU16(0x9999);
    try std.testing.expect(invalid == null);
}

test "cipher suite key sizes" {
    try std.testing.expectEqual(@as(usize, 16), CipherSuite.tls_aes_128_gcm_sha256.getKeySize());
    try std.testing.expectEqual(@as(usize, 32), CipherSuite.tls_aes_256_gcm_sha384.getKeySize());
    try std.testing.expectEqual(@as(usize, 32), CipherSuite.tls_chacha20_poly1305_sha256.getKeySize());
}

test "cipher suite to string" {
    const suite = CipherSuite.tls_aes_256_gcm_sha384;
    try std.testing.expectEqualStrings("TLS_AES_256_GCM_SHA384", suite.toString());
}

test "certificate validity" {
    const allocator = std.testing.allocator;

    const now = std.time.timestamp();
    var cert = try CertificateInfo.init(
        allocator,
        "CN=test.example.com",
        "CN=Test CA",
        now - 86400, // Valid from yesterday
        now + 86400 * 30, // Valid for 30 days
        "1234567890",
        "AA:BB:CC:DD",
    );
    defer cert.deinit();

    try std.testing.expect(cert.isValid());

    const days = cert.daysUntilExpiry();
    try std.testing.expect(days >= 29 and days <= 30);
}

test "TLS config initialization" {
    const allocator = std.testing.allocator;

    var config = TlsConfig.init(allocator);
    defer config.deinit();

    try std.testing.expectEqual(TlsVersion.tls_1_2, config.min_version);
    try std.testing.expectEqual(TlsVersion.tls_1_3, config.preferred_version);
    try std.testing.expect(config.verify_peer);
    try std.testing.expect(config.verify_hostname);
}

test "TLS config cipher suites" {
    const allocator = std.testing.allocator;

    var config = TlsConfig.init(allocator);
    defer config.deinit();

    try config.setDefaultCipherSuites();

    try std.testing.expect(config.cipher_suites.items.len >= 3);
    try std.testing.expectEqual(CipherSuite.tls_aes_256_gcm_sha384, config.cipher_suites.items[0]);
}

test "encryption algorithm sizes" {
    const aes128 = EncryptionAlgorithm.aes_128_gcm;
    try std.testing.expectEqual(@as(usize, 16), aes128.getKeySize());
    try std.testing.expectEqual(@as(usize, 12), aes128.getIvSize());
    try std.testing.expectEqual(@as(usize, 16), aes128.getTagSize());

    const aes256 = EncryptionAlgorithm.aes_256_gcm;
    try std.testing.expectEqual(@as(usize, 32), aes256.getKeySize());
}

test "encryption context initialization" {
    const allocator = std.testing.allocator;

    var ctx = try EncryptionContext.init(allocator, .aes_256_gcm);
    defer ctx.deinit();

    try std.testing.expectEqual(@as(usize, 32), ctx.key.len);
    try std.testing.expectEqual(@as(usize, 12), ctx.iv.len);
    try std.testing.expectEqual(@as(u64, 0), ctx.sequence);
}

test "encryption context set key" {
    const allocator = std.testing.allocator;

    var ctx = try EncryptionContext.init(allocator, .aes_128_gcm);
    defer ctx.deinit();

    const test_key = [_]u8{0x01} ** 16;
    try ctx.setKey(&test_key);

    try std.testing.expectEqualSlices(u8, &test_key, ctx.key);

    // Test invalid key size
    const wrong_key = [_]u8{0x01} ** 8;
    const result = ctx.setKey(&wrong_key);
    try std.testing.expectError(error.InvalidKeySize, result);
}

test "encryption context nonce derivation" {
    const allocator = std.testing.allocator;

    var ctx = try EncryptionContext.init(allocator, .aes_256_gcm);
    defer ctx.deinit();

    ctx.sequence = 42;

    const nonce1 = try ctx.deriveNonce(allocator);
    defer allocator.free(nonce1);

    try std.testing.expectEqual(@as(usize, 12), nonce1.len);

    ctx.sequence = 43;
    const nonce2 = try ctx.deriveNonce(allocator);
    defer allocator.free(nonce2);

    // Nonces should be different
    try std.testing.expect(!std.mem.eql(u8, nonce1, nonce2));
}

test "encrypted packet serialization" {
    const allocator = std.testing.allocator;

    const ciphertext = try allocator.dupe(u8, "encrypted data");
    const tag = try allocator.dupe(u8, "authentication tag");

    var packet = EncryptedPacket{
        .ciphertext = ciphertext,
        .tag = tag,
        .sequence = 123,
        .allocator = allocator,
    };
    defer packet.deinit();

    const serialized = try packet.serialize(allocator);
    defer allocator.free(serialized);

    var deserialized = try EncryptedPacket.deserialize(allocator, serialized);
    defer deserialized.deinit();

    try std.testing.expectEqual(packet.sequence, deserialized.sequence);
    try std.testing.expectEqualSlices(u8, packet.ciphertext, deserialized.ciphertext);
    try std.testing.expectEqualSlices(u8, packet.tag, deserialized.tag);
}

test "crypto engine encryption and decryption" {
    const allocator = std.testing.allocator;

    var engine = try CryptoEngine.init(allocator, .aes_256_gcm);
    defer engine.deinit();

    // Set same keys for encrypt and decrypt contexts (for testing)
    const test_key = [_]u8{0x42} ** 32;
    try engine.encrypt_ctx.setKey(&test_key);
    try engine.decrypt_ctx.setKey(&test_key);

    const test_iv = [_]u8{0x99} ** 12;
    try engine.encrypt_ctx.setIv(&test_iv);
    try engine.decrypt_ctx.setIv(&test_iv);

    const plaintext = "Hello, secure VPN world!";

    var encrypted = try engine.encrypt(plaintext);
    defer encrypted.deinit();

    try std.testing.expect(encrypted.ciphertext.len > 0);
    try std.testing.expectEqual(@as(usize, 16), encrypted.tag.len);

    const decrypted = try engine.decrypt(&encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "session keys generation" {
    const allocator = std.testing.allocator;

    var keys = try SessionKeys.init(allocator, 32, 12);
    defer keys.deinit();

    keys.generateRandom();

    try std.testing.expectEqual(@as(usize, 32), keys.client_write_key.len);
    try std.testing.expectEqual(@as(usize, 32), keys.server_write_key.len);
    try std.testing.expectEqual(@as(usize, 12), keys.client_write_iv.len);
    try std.testing.expectEqual(@as(usize, 12), keys.server_write_iv.len);

    // Keys should be different
    try std.testing.expect(!std.mem.eql(u8, keys.client_write_key, keys.server_write_key));
}

test "key exchange method to string" {
    try std.testing.expectEqualStrings("DHE", KeyExchangeMethod.dhe.toString());
    try std.testing.expectEqualStrings("ECDHE", KeyExchangeMethod.ecdhe.toString());
}
