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

pub const SHA0_SIZE: usize = 20; // SHA-0 produces 160-bit (20-byte) output
pub const SHA1_SIZE: usize = 20; // SHA-1 produces 160-bit (20-byte) output
pub const SHA256_SIZE: usize = 32; // SHA-256 produces 256-bit (32-byte) output

// ============================================================================
// SHA-0 Implementation (Deprecated - For SoftEther Compatibility Only)
// ============================================================================
// SHA-0 is the original SHA algorithm published in 1993, withdrawn in 1995
// due to security flaws. SoftEther VPN protocol uses SHA-0 for password hashing
// and session key derivation for backward compatibility with older servers.
//
// WARNING: SHA-0 is cryptographically broken and should NOT be used for new protocols.
// This implementation is provided solely for compatibility with legacy SoftEther servers.

pub const Sha0Context = struct {
    count: u64,
    buf: [64]u8,
    state: [5]u32,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .count = 0,
            .buf = [_]u8{0} ** 64,
            .state = [5]u32{
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            },
        };
    }

    fn rol(bits: u5, value: u32) u32 {
        if (bits == 0) return value;
        const right_shift: u6 = 32 - @as(u6, bits);
        return (value << bits) | (value >> @intCast(right_shift));
    }

    fn transform(self: *Self) void {
        var W: [80]u32 = undefined;
        var p: usize = 0;

        // Load first 16 words (big-endian)
        var t: usize = 0;
        while (t < 16) : (t += 1) {
            W[t] = (@as(u32, self.buf[p]) << 24) |
                (@as(u32, self.buf[p + 1]) << 16) |
                (@as(u32, self.buf[p + 2]) << 8) |
                @as(u32, self.buf[p + 3]);
            p += 4;
        }

        // Extend to 80 words (NOTE: SHA-0 bug - no rotation!)
        while (t < 80) : (t += 1) {
            // SHA-0 BUG: Missing rol(1, ...) that SHA-1 has
            W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
        }

        var A = self.state[0];
        var B = self.state[1];
        var C = self.state[2];
        var D = self.state[3];
        var E = self.state[4];

        t = 0;
        while (t < 80) : (t += 1) {
            var tmp = rol(5, A) +% E +% W[t];
            if (t < 20) {
                tmp +%= (D ^ (B & (C ^ D))) +% 0x5A827999;
            } else if (t < 40) {
                tmp +%= (B ^ C ^ D) +% 0x6ED9EBA1;
            } else if (t < 60) {
                tmp +%= ((B & C) | (D & (B | C))) +% 0x8F1BBCDC;
            } else {
                tmp +%= (B ^ C ^ D) +% 0xCA62C1D6;
            }
            E = D;
            D = C;
            C = rol(30, B);
            B = A;
            A = tmp;
        }

        self.state[0] +%= A;
        self.state[1] +%= B;
        self.state[2] +%= C;
        self.state[3] +%= D;
        self.state[4] +%= E;
    }

    pub fn update(self: *Self, data: []const u8) void {
        var i = @as(usize, @intCast(self.count & 63));
        var p: usize = 0;
        var len = data.len;

        self.count += @as(u64, len);

        while (len > 0) {
            self.buf[i] = data[p];
            i += 1;
            p += 1;
            len -= 1;

            if (i == 64) {
                self.transform();
                i = 0;
            }
        }
    }

    pub fn final(self: *Self, output: *[SHA0_SIZE]u8) void {
        // Calculate length BEFORE padding (count will change during padding)
        const cnt = self.count * 8;

        // Padding
        const padding = [_]u8{0x80} ++ [_]u8{0} ** 63;
        self.update(padding[0..1]);

        while ((self.count & 63) != 56) {
            self.update(padding[1..2]);
        }

        // Append length in bits (big-endian)
        var length_bytes: [8]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            length_bytes[i] = @as(u8, @truncate(cnt >> @as(u6, @intCast((7 - i) * 8))));
        }
        self.update(&length_bytes);

        // Output hash (big-endian)
        i = 0;
        var p: usize = 0;
        while (i < 5) : (i += 1) {
            const tmp = self.state[i];
            output[p] = @as(u8, @truncate(tmp >> 24));
            output[p + 1] = @as(u8, @truncate(tmp >> 16));
            output[p + 2] = @as(u8, @truncate(tmp >> 8));
            output[p + 3] = @as(u8, @truncate(tmp));
            p += 4;
        }
    }

    /// Convenience function: Hash data in one call
    pub fn hash(data: []const u8, output: *[SHA0_SIZE]u8) void {
        var ctx = Sha0Context.init();
        ctx.update(data);
        ctx.final(output);
    }
};

// ============================================================================
// Session Key Derivation (SoftEther Protocol)
// ============================================================================
// SoftEther uses a simple but insecure key derivation method:
// 1. Hash plaintext password with SHA-0 → hashed_password (20 bytes)
// 2. Concatenate hashed_password + random (20 bytes each) → 40 bytes
// 3. Hash the concatenation with SHA-0 → secure_password (20 bytes)
//
// This is used for both password authentication and RC4 key derivation.

pub const KeyDerivation = struct {
    /// Hash a plaintext password with SHA-0 (first step)
    /// Returns 20-byte hash suitable for storage or further derivation
    pub fn hashPassword(password: []const u8, output: *[SHA0_SIZE]u8) void {
        Sha0Context.hash(password, output);
    }

    /// Derive secure password from hashed password + random challenge
    /// This is SoftEther's SecurePassword() function
    /// Used for authentication and RC4 key derivation
    pub fn securePassword(
        hashed_password: *const [SHA0_SIZE]u8,
        random: *const [SHA0_SIZE]u8,
        output: *[SHA0_SIZE]u8,
    ) void {
        var ctx = Sha0Context.init();
        ctx.update(hashed_password);
        ctx.update(random);
        ctx.final(output);
    }

    /// Complete password authentication flow:
    /// plaintext_password → SHA-0 → hashed_password
    /// hashed_password + random → SHA-0 → secure_password
    pub fn deriveAuthKey(
        plaintext_password: []const u8,
        random: *const [SHA0_SIZE]u8,
        output: *[SHA0_SIZE]u8,
    ) void {
        var hashed: [SHA0_SIZE]u8 = undefined;
        hashPassword(plaintext_password, &hashed);
        securePassword(&hashed, random, output);
    }

    /// Generate 160-bit (20-byte) random challenge
    /// Used as the "random" parameter in authentication
    pub fn generateRandom(output: *[SHA0_SIZE]u8) !void {
        std.crypto.random.bytes(output);
    }
};

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
    rc4, // Stream cipher (legacy, SoftEther uses this)
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn getKeySize(self: EncryptionAlgorithm) usize {
        return switch (self) {
            .rc4 => 20, // SoftEther uses SHA1_SIZE (20 bytes)
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    pub fn getIvSize(self: EncryptionAlgorithm) usize {
        return switch (self) {
            .rc4 => 0, // RC4 doesn't use IV
            .aes_128_gcm, .aes_256_gcm => 12, // GCM uses 96-bit IVs
            .chacha20_poly1305 => 12,
        };
    }

    pub fn getTagSize(self: EncryptionAlgorithm) usize {
        return switch (self) {
            .rc4 => 0, // RC4 is not AEAD, no authentication tag
            .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 => 16, // AEAD algorithms use 128-bit tags
        };
    }

    pub fn isAead(self: EncryptionAlgorithm) bool {
        return switch (self) {
            .rc4 => false,
            .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 => true,
        };
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
// RC4 Stream Cipher (Legacy Support for SoftEther)
// ============================================================================

// OpenSSL C bindings for RC4
const c = @cImport({
    @cInclude("openssl/rc4.h");
    @cInclude("openssl/evp.h");
});

/// RC4 cipher state (wraps OpenSSL's RC4_KEY)
pub const Rc4Cipher = struct {
    key: c.RC4_KEY,
    allocator: Allocator,

    pub fn init(allocator: Allocator, key: []const u8) !Rc4Cipher {
        if (key.len == 0 or key.len > 256) {
            return error.InvalidKeySize;
        }

        var cipher = Rc4Cipher{
            .key = undefined,
            .allocator = allocator,
        };

        // Initialize RC4 key using OpenSSL
        c.RC4_set_key(&cipher.key, @intCast(key.len), key.ptr);

        return cipher;
    }

    pub fn deinit(self: *Rc4Cipher) void {
        // Zero out sensitive key state
        @memset(std.mem.asBytes(&self.key), 0);
    }

    /// Encrypt data in-place or to destination buffer
    /// RC4 is a stream cipher, so encrypt and decrypt are the same operation
    pub fn encrypt(self: *Rc4Cipher, dst: []u8, src: []const u8) void {
        std.debug.assert(dst.len >= src.len);
        c.RC4(&self.key, @intCast(src.len), src.ptr, dst.ptr);
    }

    /// Decrypt data (same as encrypt for RC4)
    pub fn decrypt(self: *Rc4Cipher, dst: []u8, src: []const u8) void {
        self.encrypt(dst, src);
    }

    /// Encrypt in-place
    pub fn encryptInPlace(self: *Rc4Cipher, data: []u8) void {
        c.RC4(&self.key, @intCast(data.len), data.ptr, data.ptr);
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

        // Handle RC4 separately (stream cipher, no IV/tag)
        if (algorithm == .rc4) {
            var rc4 = try Rc4Cipher.init(self.allocator, self.encrypt_ctx.key);
            defer rc4.deinit();
            rc4.encrypt(ciphertext, plaintext);

            const sequence = self.encrypt_ctx.sequence;
            self.encrypt_ctx.incrementSequence();

            return .{
                .ciphertext = ciphertext,
                .tag = tag, // Empty tag for RC4
                .sequence = sequence,
                .allocator = self.allocator,
            };
        }

        // Derive nonce for AEAD algorithms
        const nonce = try self.encrypt_ctx.deriveNonce(self.allocator);
        defer self.allocator.free(nonce);

        // Perform AEAD encryption
        switch (algorithm) {
            .rc4 => unreachable, // Already handled above
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

        // Handle RC4 separately (stream cipher, no IV/tag verification)
        if (algorithm == .rc4) {
            var rc4 = try Rc4Cipher.init(self.allocator, self.decrypt_ctx.key);
            defer rc4.deinit();
            rc4.decrypt(plaintext, encrypted.ciphertext);

            self.decrypt_ctx.incrementSequence();
            return plaintext;
        }

        // Derive nonce for AEAD algorithms
        const nonce = try self.decrypt_ctx.deriveNonce(self.allocator);
        defer self.allocator.free(nonce);

        // Perform AEAD decryption
        switch (algorithm) {
            .rc4 => unreachable, // Already handled above
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
// IV (Initialization Vector) Generation
// ============================================================================

pub const IvGenerator = struct {
    /// Generate a random IV for AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
    /// IV size is algorithm-specific: 12 bytes for GCM/ChaCha20
    pub fn generateRandom(output: []u8) void {
        std.crypto.random.bytes(output);
    }

    /// Generate a deterministic IV from a base IV and sequence number
    /// Used for packet encryption where IV must be unique per packet
    /// Formula: IV = base_iv XOR sequence_counter
    pub fn deriveFromSequence(base_iv: []const u8, sequence: u64, output: []u8) void {
        std.debug.assert(output.len == base_iv.len);
        std.debug.assert(output.len >= 8); // Need at least 8 bytes for u64 sequence

        // Copy base IV
        @memcpy(output, base_iv);

        // XOR last 8 bytes with sequence number (big-endian)
        const offset = output.len - 8;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            const seq_byte = @as(u8, @truncate(sequence >> @intCast((7 - i) * 8)));
            output[offset + i] ^= seq_byte;
        }
    }

    /// Generate IV from timestamp (for time-based uniqueness)
    /// WARNING: Not recommended for high-frequency operations (use sequence-based instead)
    pub fn deriveFromTimestamp(base_iv: []const u8, timestamp_ns: i64, output: []u8) void {
        std.debug.assert(output.len == base_iv.len);
        std.debug.assert(output.len >= 8);

        @memcpy(output, base_iv);

        const offset = output.len - 8;
        const ts = @as(u64, @bitCast(timestamp_ns));
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            const ts_byte = @as(u8, @truncate(ts >> @intCast((7 - i) * 8)));
            output[offset + i] ^= ts_byte;
        }
    }

    /// Validate IV for security properties
    /// - Must not be all zeros
    /// - Must not be reused (caller's responsibility to track)
    /// - Should be unique for each encryption with same key
    pub fn validate(iv: []const u8) error{InvalidIv}!void {
        // Check not all zeros
        var all_zeros = true;
        for (iv) |byte| {
            if (byte != 0) {
                all_zeros = false;
                break;
            }
        }
        if (all_zeros) {
            return error.InvalidIv;
        }
    }
};

// ============================================================================
// Key Rotation
// ============================================================================

pub const KeyRotationPolicy = struct {
    /// Maximum number of packets before key rotation required
    max_packets: u64 = 1_000_000, // 1 million packets (conservative)

    /// Maximum bytes encrypted before key rotation required
    max_bytes: u64 = 1024 * 1024 * 1024, // 1 GB

    /// Maximum time (seconds) before key rotation required
    max_time_secs: u64 = 3600, // 1 hour

    /// Check if rotation is needed based on packet count
    pub fn shouldRotateByPackets(self: KeyRotationPolicy, packet_count: u64) bool {
        return packet_count >= self.max_packets;
    }

    /// Check if rotation is needed based on bytes encrypted
    pub fn shouldRotateByBytes(self: KeyRotationPolicy, bytes_encrypted: u64) bool {
        return bytes_encrypted >= self.max_bytes;
    }

    /// Check if rotation is needed based on time
    pub fn shouldRotateByTime(self: KeyRotationPolicy, elapsed_secs: u64) bool {
        return elapsed_secs >= self.max_time_secs;
    }

    /// Check if rotation is needed (any condition)
    pub fn shouldRotate(self: KeyRotationPolicy, packet_count: u64, bytes_encrypted: u64, elapsed_secs: u64) bool {
        return self.shouldRotateByPackets(packet_count) or
            self.shouldRotateByBytes(bytes_encrypted) or
            self.shouldRotateByTime(elapsed_secs);
    }
};

pub const KeyRotationState = struct {
    packet_count: u64 = 0,
    bytes_encrypted: u64 = 0,
    start_time: i64, // Unix timestamp in seconds
    policy: KeyRotationPolicy,

    pub fn init(policy: KeyRotationPolicy) KeyRotationState {
        return .{
            .start_time = std.time.timestamp(),
            .policy = policy,
        };
    }

    /// Record encryption of a packet
    pub fn recordPacket(self: *KeyRotationState, packet_size: usize) void {
        self.packet_count += 1;
        self.bytes_encrypted += packet_size;
    }

    /// Check if key rotation is needed
    pub fn needsRotation(self: *KeyRotationState) bool {
        const now = std.time.timestamp();
        const elapsed = @as(u64, @intCast(now - self.start_time));
        return self.policy.shouldRotate(self.packet_count, self.bytes_encrypted, elapsed);
    }

    /// Reset state after key rotation
    pub fn reset(self: *KeyRotationState) void {
        self.packet_count = 0;
        self.bytes_encrypted = 0;
        self.start_time = std.time.timestamp();
    }

    /// Get rotation statistics
    pub fn getStats(self: KeyRotationState) RotationStats {
        const now = std.time.timestamp();
        const elapsed = @as(u64, @intCast(now - self.start_time));
        return .{
            .packet_count = self.packet_count,
            .bytes_encrypted = self.bytes_encrypted,
            .elapsed_secs = elapsed,
            .packets_remaining = if (self.packet_count < self.policy.max_packets)
                self.policy.max_packets - self.packet_count
            else
                0,
            .bytes_remaining = if (self.bytes_encrypted < self.policy.max_bytes)
                self.policy.max_bytes - self.bytes_encrypted
            else
                0,
            .time_remaining = if (elapsed < self.policy.max_time_secs)
                self.policy.max_time_secs - elapsed
            else
                0,
        };
    }
};

pub const RotationStats = struct {
    packet_count: u64,
    bytes_encrypted: u64,
    elapsed_secs: u64,
    packets_remaining: u64,
    bytes_remaining: u64,
    time_remaining: u64,
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

test "SHA-0: basic hash" {
    // Test with empty string
    var output: [SHA0_SIZE]u8 = undefined;
    Sha0Context.hash("", &output);

    // SHA-0("") = f96cea198ad1dd5617ac084a3d92c6107708c0ef
    const expected_empty = [_]u8{
        0xf9, 0x6c, 0xea, 0x19, 0x8a, 0xd1, 0xdd, 0x56,
        0x17, 0xac, 0x08, 0x4a, 0x3d, 0x92, 0xc6, 0x10,
        0x77, 0x08, 0xc0, 0xef,
    };
    try std.testing.expectEqualSlices(u8, &expected_empty, &output);
}

test "SHA-0: known test vectors" {
    // Test with "abc"
    var output: [SHA0_SIZE]u8 = undefined;
    Sha0Context.hash("abc", &output);

    // SHA-0("abc") = 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
    const expected_abc = [_]u8{
        0x01, 0x64, 0xb8, 0xa9, 0x14, 0xcd, 0x2a, 0x5e,
        0x74, 0xc4, 0xf7, 0xff, 0x08, 0x2c, 0x4d, 0x97,
        0xf1, 0xed, 0xf8, 0x80,
    };
    try std.testing.expectEqualSlices(u8, &expected_abc, &output);
}

test "SHA-0: multiple updates" {
    // Test streaming API
    var ctx = Sha0Context.init();
    ctx.update("a");
    ctx.update("b");
    ctx.update("c");

    var output: [SHA0_SIZE]u8 = undefined;
    ctx.final(&output);

    // Should match SHA-0("abc")
    const expected = [_]u8{
        0x01, 0x64, 0xb8, 0xa9, 0x14, 0xcd, 0x2a, 0x5e,
        0x74, 0xc4, 0xf7, 0xff, 0x08, 0x2c, 0x4d, 0x97,
        0xf1, 0xed, 0xf8, 0x80,
    };
    try std.testing.expectEqualSlices(u8, &expected, &output);
}

test "SHA-0: long message" {
    // Test with a message longer than one block (>64 bytes)
    const message = "The quick brown fox jumps over the lazy dog. " ++
        "The quick brown fox jumps over the lazy dog.";

    var output: [SHA0_SIZE]u8 = undefined;
    Sha0Context.hash(message, &output);

    // Just verify it produces 20 bytes and doesn't crash
    try std.testing.expectEqual(@as(usize, 20), output.len);
}

test "KeyDerivation: hash password" {
    // Test password hashing (first step)
    const password = "test_password";
    var hashed: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.hashPassword(password, &hashed);

    // Verify it produces 20 bytes
    try std.testing.expectEqual(@as(usize, 20), hashed.len);

    // Hash same password again - should be identical
    var hashed2: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.hashPassword(password, &hashed2);
    try std.testing.expectEqualSlices(u8, &hashed, &hashed2);
}

test "KeyDerivation: secure password" {
    // Test secure password derivation (second step)
    const hashed_password = [_]u8{0x42} ** SHA0_SIZE;
    const random = [_]u8{0x99} ** SHA0_SIZE;

    var secure: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.securePassword(&hashed_password, &random, &secure);

    // Verify it produces 20 bytes
    try std.testing.expectEqual(@as(usize, 20), secure.len);

    // Different random should produce different output
    const random2 = [_]u8{0xAA} ** SHA0_SIZE;
    var secure2: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.securePassword(&hashed_password, &random2, &secure2);

    // Should NOT be equal
    try std.testing.expect(!std.mem.eql(u8, &secure, &secure2));
}

test "KeyDerivation: derive auth key (complete flow)" {
    // Test complete authentication key derivation
    const password = "MySecretPassword123";
    const random = [_]u8{
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC,
    };

    var auth_key: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.deriveAuthKey(password, &random, &auth_key);

    // Verify it produces 20 bytes
    try std.testing.expectEqual(@as(usize, 20), auth_key.len);

    // Manually verify the two-step process
    var step1: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.hashPassword(password, &step1);

    var step2: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.securePassword(&step1, &random, &step2);

    // Should match
    try std.testing.expectEqualSlices(u8, &step2, &auth_key);
}

test "KeyDerivation: generate random" {
    // Test random generation
    var random1: [SHA0_SIZE]u8 = undefined;
    var random2: [SHA0_SIZE]u8 = undefined;

    try KeyDerivation.generateRandom(&random1);
    try KeyDerivation.generateRandom(&random2);

    // Should produce 20 bytes
    try std.testing.expectEqual(@as(usize, 20), random1.len);
    try std.testing.expectEqual(@as(usize, 20), random2.len);

    // Should be different (extremely unlikely to be same)
    try std.testing.expect(!std.mem.eql(u8, &random1, &random2));
}

test "KeyDerivation: RC4 key derivation simulation" {
    // Simulate RC4 key derivation for SoftEther
    // RC4 uses the secure_password (20 bytes) as the key
    const password = "vpn_password";
    const server_random = [_]u8{0xAB} ** SHA0_SIZE;

    var rc4_key: [SHA0_SIZE]u8 = undefined;
    KeyDerivation.deriveAuthKey(password, &server_random, &rc4_key);

    // Verify we got 20 bytes (RC4 key size)
    try std.testing.expectEqual(@as(usize, 20), rc4_key.len);

    // This key would be passed to Rc4Cipher.init()
    // (Integration test would verify RC4 encryption with this key)
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

// ============================================================================
// RC4 Tests
// ============================================================================

test "RC4: basic encryption and decryption" {
    const allocator = std.testing.allocator;

    const key = "TestKey123";
    var cipher = try Rc4Cipher.init(allocator, key);
    defer cipher.deinit();

    const plaintext = "Hello, RC4 World!";
    var ciphertext: [plaintext.len]u8 = undefined;

    // Encrypt
    cipher.encrypt(&ciphertext, plaintext);

    // Ciphertext should be different from plaintext
    try std.testing.expect(!std.mem.eql(u8, plaintext, &ciphertext));

    // Decrypt (need new cipher with same key since RC4 is stateful)
    var decipher = try Rc4Cipher.init(allocator, key);
    defer decipher.deinit();

    var decrypted: [plaintext.len]u8 = undefined;
    decipher.decrypt(&decrypted, &ciphertext);

    // Decrypted should match original plaintext
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "RC4: encrypt in place" {
    const allocator = std.testing.allocator;

    const key = "SecretKey";
    var cipher = try Rc4Cipher.init(allocator, key);
    defer cipher.deinit();

    const original = "In-place encryption test";
    var data: [original.len]u8 = undefined;
    @memcpy(&data, original);

    // Encrypt in place
    cipher.encryptInPlace(&data);

    // Data should be different after encryption
    try std.testing.expect(!std.mem.eql(u8, original, &data));

    // Decrypt with fresh cipher
    var decipher = try Rc4Cipher.init(allocator, key);
    defer decipher.deinit();

    decipher.encryptInPlace(&data); // RC4 encrypt == decrypt

    // Should match original
    try std.testing.expectEqualSlices(u8, original, &data);
}

test "RC4: different keys produce different output" {
    const allocator = std.testing.allocator;

    const plaintext = "Same plaintext";
    const key1 = "Key1";
    const key2 = "Key2";

    var cipher1 = try Rc4Cipher.init(allocator, key1);
    defer cipher1.deinit();

    var cipher2 = try Rc4Cipher.init(allocator, key2);
    defer cipher2.deinit();

    var ciphertext1: [plaintext.len]u8 = undefined;
    var ciphertext2: [plaintext.len]u8 = undefined;

    cipher1.encrypt(&ciphertext1, plaintext);
    cipher2.encrypt(&ciphertext2, plaintext);

    // Different keys should produce different ciphertext
    try std.testing.expect(!std.mem.eql(u8, &ciphertext1, &ciphertext2));
}

test "RC4: empty key error" {
    const allocator = std.testing.allocator;

    const empty_key: []const u8 = &[_]u8{};
    const result = Rc4Cipher.init(allocator, empty_key);

    try std.testing.expectError(error.InvalidKeySize, result);
}

test "RC4: key too long error" {
    const allocator = std.testing.allocator;

    var long_key: [257]u8 = undefined;
    @memset(&long_key, 'X');

    const result = Rc4Cipher.init(allocator, &long_key);

    try std.testing.expectError(error.InvalidKeySize, result);
}

test "RC4: CryptoEngine integration" {
    const allocator = std.testing.allocator;

    var engine = try CryptoEngine.init(allocator, .rc4);
    defer engine.deinit();

    // Set same keys for encrypt and decrypt (for testing)
    const test_key = [_]u8{0x42} ** 20; // SHA1_SIZE for RC4
    try engine.encrypt_ctx.setKey(&test_key);
    try engine.decrypt_ctx.setKey(&test_key);

    const plaintext = "RC4 CryptoEngine test message!";

    // Encrypt
    var encrypted = try engine.encrypt(plaintext);
    defer encrypted.deinit();

    try std.testing.expect(encrypted.ciphertext.len > 0);
    try std.testing.expectEqual(@as(usize, 0), encrypted.tag.len); // RC4 has no tag

    // Decrypt
    const decrypted = try engine.decrypt(&encrypted);
    defer allocator.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "RC4: algorithm properties" {
    const rc4 = EncryptionAlgorithm.rc4;

    try std.testing.expectEqual(@as(usize, 20), rc4.getKeySize()); // SHA1_SIZE
    try std.testing.expectEqual(@as(usize, 0), rc4.getIvSize()); // No IV
    try std.testing.expectEqual(@as(usize, 0), rc4.getTagSize()); // No tag
    try std.testing.expect(!rc4.isAead()); // Not AEAD
}

test "RC4: large data encryption" {
    const allocator = std.testing.allocator;

    const key = "LargeDataKey";
    var cipher = try Rc4Cipher.init(allocator, key);
    defer cipher.deinit();

    // Create 10KB of test data
    const data_size = 10 * 1024;
    const plaintext = try allocator.alloc(u8, data_size);
    defer allocator.free(plaintext);

    // Fill with pattern
    for (plaintext, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }

    const ciphertext = try allocator.alloc(u8, data_size);
    defer allocator.free(ciphertext);

    // Encrypt
    cipher.encrypt(ciphertext, plaintext);

    // Decrypt with fresh cipher
    var decipher = try Rc4Cipher.init(allocator, key);
    defer decipher.deinit();

    const decrypted = try allocator.alloc(u8, data_size);
    defer allocator.free(decrypted);

    decipher.decrypt(decrypted, ciphertext);

    // Verify
    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "IvGenerator: random generation" {
    var iv1: [12]u8 = undefined;
    var iv2: [12]u8 = undefined;

    IvGenerator.generateRandom(&iv1);
    IvGenerator.generateRandom(&iv2);

    // Should be different (extremely unlikely to be same)
    try std.testing.expect(!std.mem.eql(u8, &iv1, &iv2));

    // Should not be all zeros
    try IvGenerator.validate(&iv1);
    try IvGenerator.validate(&iv2);
}

test "IvGenerator: sequence-based derivation" {
    const base_iv = [_]u8{0x11} ** 12;
    var iv1: [12]u8 = undefined;
    var iv2: [12]u8 = undefined;

    // Generate IVs for different sequences
    IvGenerator.deriveFromSequence(&base_iv, 0, &iv1);
    IvGenerator.deriveFromSequence(&base_iv, 1, &iv2);

    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &iv1, &iv2));

    // First 4 bytes should match base (only last 8 bytes XORed with sequence)
    try std.testing.expectEqualSlices(u8, base_iv[0..4], iv1[0..4]);
    try std.testing.expectEqualSlices(u8, base_iv[0..4], iv2[0..4]);

    // Verify deterministic (same sequence produces same IV)
    var iv1_again: [12]u8 = undefined;
    IvGenerator.deriveFromSequence(&base_iv, 0, &iv1_again);
    try std.testing.expectEqualSlices(u8, &iv1, &iv1_again);
}

test "IvGenerator: timestamp-based derivation" {
    const base_iv = [_]u8{0x22} ** 12;
    var iv1: [12]u8 = undefined;
    var iv2: [12]u8 = undefined;

    const ts1: i64 = @intCast(std.time.nanoTimestamp());
    const ts2: i64 = ts1 + 1000; // 1 microsecond later

    IvGenerator.deriveFromTimestamp(&base_iv, ts1, &iv1);
    IvGenerator.deriveFromTimestamp(&base_iv, ts2, &iv2);

    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &iv1, &iv2));
}

test "IvGenerator: validation" {
    // All zeros should fail
    const all_zeros = [_]u8{0} ** 12;
    try std.testing.expectError(error.InvalidIv, IvGenerator.validate(&all_zeros));

    // Non-zero should pass
    const valid_iv = [_]u8{0x01} ** 12;
    try IvGenerator.validate(&valid_iv);
}

test "IvGenerator: sequence wrapping" {
    const base_iv = [_]u8{0xFF} ** 12;
    var iv_max: [12]u8 = undefined;
    var iv_zero: [12]u8 = undefined;

    // Max sequence
    IvGenerator.deriveFromSequence(&base_iv, std.math.maxInt(u64), &iv_max);

    // Zero sequence
    IvGenerator.deriveFromSequence(&base_iv, 0, &iv_zero);

    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &iv_max, &iv_zero));

    // Should not crash or produce invalid IVs
    try IvGenerator.validate(&iv_max);
    try IvGenerator.validate(&iv_zero);
}

test "KeyRotationPolicy: packet count threshold" {
    const policy = KeyRotationPolicy{ .max_packets = 1000 };

    try std.testing.expect(!policy.shouldRotateByPackets(500));
    try std.testing.expect(!policy.shouldRotateByPackets(999));
    try std.testing.expect(policy.shouldRotateByPackets(1000));
    try std.testing.expect(policy.shouldRotateByPackets(1001));
}

test "KeyRotationPolicy: bytes threshold" {
    const policy = KeyRotationPolicy{ .max_bytes = 1024 * 1024 }; // 1 MB

    try std.testing.expect(!policy.shouldRotateByBytes(512 * 1024));
    try std.testing.expect(policy.shouldRotateByBytes(1024 * 1024));
    try std.testing.expect(policy.shouldRotateByBytes(2 * 1024 * 1024));
}

test "KeyRotationPolicy: time threshold" {
    const policy = KeyRotationPolicy{ .max_time_secs = 3600 }; // 1 hour

    try std.testing.expect(!policy.shouldRotateByTime(1800)); // 30 min
    try std.testing.expect(policy.shouldRotateByTime(3600)); // 1 hour
    try std.testing.expect(policy.shouldRotateByTime(7200)); // 2 hours
}

test "KeyRotationPolicy: combined thresholds" {
    const policy = KeyRotationPolicy{
        .max_packets = 1000,
        .max_bytes = 1024 * 1024,
        .max_time_secs = 3600,
    };

    // No rotation needed
    try std.testing.expect(!policy.shouldRotate(500, 512 * 1024, 1800));

    // Rotation needed by packets
    try std.testing.expect(policy.shouldRotate(1000, 512 * 1024, 1800));

    // Rotation needed by bytes
    try std.testing.expect(policy.shouldRotate(500, 1024 * 1024, 1800));

    // Rotation needed by time
    try std.testing.expect(policy.shouldRotate(500, 512 * 1024, 3600));
}

test "KeyRotationState: initialization and recording" {
    const policy = KeyRotationPolicy{ .max_packets = 1000 };
    var state = KeyRotationState.init(policy);

    // Initial state
    try std.testing.expectEqual(@as(u64, 0), state.packet_count);
    try std.testing.expectEqual(@as(u64, 0), state.bytes_encrypted);

    // Record packets
    state.recordPacket(1500); // 1 packet, 1500 bytes
    try std.testing.expectEqual(@as(u64, 1), state.packet_count);
    try std.testing.expectEqual(@as(u64, 1500), state.bytes_encrypted);

    state.recordPacket(1500); // 2 packets, 3000 bytes
    try std.testing.expectEqual(@as(u64, 2), state.packet_count);
    try std.testing.expectEqual(@as(u64, 3000), state.bytes_encrypted);
}

test "KeyRotationState: rotation detection" {
    const policy = KeyRotationPolicy{
        .max_packets = 10,
        .max_bytes = 15000,
        .max_time_secs = 1, // 1 second for testing
    };
    var state = KeyRotationState.init(policy);

    // Not yet needed
    try std.testing.expect(!state.needsRotation());

    // Record packets until threshold
    var i: usize = 0;
    while (i < 9) : (i += 1) {
        state.recordPacket(1500);
    }
    try std.testing.expect(!state.needsRotation()); // 9 packets, 13.5 KB

    // One more packet triggers rotation
    state.recordPacket(1500); // 10 packets, 15 KB
    try std.testing.expect(state.needsRotation());
}

test "KeyRotationState: reset" {
    const policy = KeyRotationPolicy{ .max_packets = 10 };
    var state = KeyRotationState.init(policy);

    // Record some packets
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        state.recordPacket(1500);
    }

    try std.testing.expectEqual(@as(u64, 5), state.packet_count);
    try std.testing.expectEqual(@as(u64, 7500), state.bytes_encrypted);

    // Reset
    state.reset();

    try std.testing.expectEqual(@as(u64, 0), state.packet_count);
    try std.testing.expectEqual(@as(u64, 0), state.bytes_encrypted);
    try std.testing.expect(!state.needsRotation());
}

test "KeyRotationState: statistics" {
    const policy = KeyRotationPolicy{
        .max_packets = 1000,
        .max_bytes = 1024 * 1024,
        .max_time_secs = 3600,
    };
    var state = KeyRotationState.init(policy);

    // Record some activity
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        state.recordPacket(1500); // 100 packets, 150 KB
    }

    const stats = state.getStats();

    try std.testing.expectEqual(@as(u64, 100), stats.packet_count);
    try std.testing.expectEqual(@as(u64, 150000), stats.bytes_encrypted);
    try std.testing.expectEqual(@as(u64, 900), stats.packets_remaining);
    try std.testing.expect(stats.bytes_remaining > 0);
    try std.testing.expect(stats.time_remaining > 0);
}
