//! SoftEther Cryptographic Utilities Module
//!
//! This module provides cryptographic operations for the SoftEther VPN:
//! - Hash functions (SHA-256, SHA-1, MD5)
//! - Random number generation (cryptographically secure)
//! - Key derivation (PBKDF2)
//! - HMAC (Hash-based Message Authentication Code)
//!
//! All functions use Zig's standard library crypto implementations which
//! are well-audited and secure.
//!
//! Usage:
//! ```zig
//! const crypto = @import("mayaqua/crypto.zig");
//! const allocator = std.heap.page_allocator;
//!
//! // SHA-256 hash
//! var hash: [32]u8 = undefined;
//! crypto.sha256(&hash, "Hello World");
//!
//! // Random bytes
//! var random_data: [32]u8 = undefined;
//! crypto.randomBytes(&random_data);
//!
//! // PBKDF2 key derivation
//! var key: [32]u8 = undefined;
//! try crypto.pbkdf2(&key, "password", "salt", 10000);
//! ```

const std = @import("std");
const crypto_std = std.crypto;

/// Hash digest sizes
pub const SHA256_SIZE = 32;
pub const SHA1_SIZE = 20;
pub const SHA0_SIZE = 20; // SHA-0 (same size as SHA-1)
pub const MD5_SIZE = 16;

/// Default PBKDF2 iterations for key derivation
pub const DEFAULT_PBKDF2_ITERATIONS = 10000;

/// Compute SHA-256 hash
pub fn sha256(out: *[SHA256_SIZE]u8, data: []const u8) void {
    crypto_std.hash.sha2.Sha256.hash(data, out, .{});
}

/// Compute SHA-256 hash and return as hex string
pub fn sha256Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var hash: [SHA256_SIZE]u8 = undefined;
    sha256(&hash, data);

    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, SHA256_SIZE * 2);

    for (hash, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

/// Compute SHA-1 hash
pub fn sha1(out: *[SHA1_SIZE]u8, data: []const u8) void {
    crypto_std.hash.Sha1.hash(data, out, .{});
}

/// Compute SHA-1 hash and return as hex string
pub fn sha1Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var hash: [SHA1_SIZE]u8 = undefined;
    sha1(&hash, data);

    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, SHA1_SIZE * 2);

    for (hash, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

// ============================================================================
// SHA-0 Implementation (for SoftEther VPN compatibility)
// ============================================================================
// SHA-0 is the original (flawed) SHA algorithm from 1993.
// It's insecure and should NOT be used for new applications.
// Included here ONLY for SoftEther VPN protocol compatibility.
// ============================================================================

const Sha0Context = struct {
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
            W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
        }

        // Initialize working variables
        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];

        // Main loop
        t = 0;
        while (t < 80) : (t += 1) {
            var temp: u32 = rol(5, a) +% e +% W[t];

            if (t < 20) {
                temp +%= ((b & c) | ((~b) & d)) +% 0x5A827999;
            } else if (t < 40) {
                temp +%= (b ^ c ^ d) +% 0x6ED9EBA1;
            } else if (t < 60) {
                temp +%= ((b & c) | (b & d) | (c & d)) +% 0x8F1BBCDC;
            } else {
                temp +%= (b ^ c ^ d) +% 0xCA62C1D6;
            }

            e = d;
            d = c;
            c = rol(30, b);
            b = a;
            a = temp;
        }

        // Add to state
        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
    }

    pub fn update(self: *Self, data: []const u8) void {
        for (data) |byte| {
            const index = @as(usize, @intCast(self.count & 63));
            self.buf[index] = byte;
            self.count += 1;

            if (index == 63) {
                self.transform();
            }
        }
    }

    pub fn final(self: *Self, output: *[SHA0_SIZE]u8) void {
        // Padding
        const index = @as(usize, @intCast(self.count & 63));
        const pad_len = if (index < 56) 56 - index else 120 - index;

        var padding: [64]u8 = [_]u8{0} ** 64;
        padding[0] = 0x80;

        self.update(padding[0..pad_len]);

        // Length in bits (big-endian)
        const bit_count = self.count * 8;
        var length_bytes: [8]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            length_bytes[7 - i] = @as(u8, @truncate(bit_count >> @intCast(i * 8)));
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

    pub fn hash(data: []const u8, output: *[SHA0_SIZE]u8) void {
        var ctx = Sha0Context.init();
        ctx.update(data);
        ctx.final(output);
    }
};

/// Compute SHA-0 hash (INSECURE - for SoftEther compatibility only!)
/// SHA-0 is the original flawed SHA from 1993. Use SHA-256 for new code.
pub fn sha0(data: []const u8) [SHA0_SIZE]u8 {
    var output: [SHA0_SIZE]u8 = undefined;
    Sha0Context.hash(data, &output);
    return output;
}

/// Hash password using SoftEther method (SHA-0 with username)
/// This matches the SoftEther VPN password hashing:
/// SHA-0(password_bytes + uppercase_username_bytes)
pub fn softetherPasswordHash(password: []const u8, username: []const u8) [SHA0_SIZE]u8 {
    // Allocate temporary buffer for password + uppercase username
    var buffer: [512]u8 = undefined;
    if (password.len + username.len > buffer.len) {
        // Fallback: just hash password if combined length too long
        return sha0(password);
    }

    // Copy password
    @memcpy(buffer[0..password.len], password);

    // Copy and uppercase username
    const username_start = password.len;
    for (username, 0..) |c, i| {
        buffer[username_start + i] = std.ascii.toUpper(c);
    }

    const combined_len = password.len + username.len;
    return sha0(buffer[0..combined_len]);
}

/// Compute MD5 hash (legacy, use SHA-256 for new code)
pub fn md5(out: *[MD5_SIZE]u8, data: []const u8) void {
    crypto_std.hash.Md5.hash(data, out, .{});
}

/// Compute MD5 hash and return as hex string
pub fn md5Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var hash: [MD5_SIZE]u8 = undefined;
    md5(&hash, data);

    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, MD5_SIZE * 2);

    for (hash, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

/// Generate cryptographically secure random bytes
pub fn randomBytes(buffer: []u8) void {
    crypto_std.random.bytes(buffer);
}

/// Generate a random u32
pub fn randomU32() u32 {
    var buf: [4]u8 = undefined;
    randomBytes(&buf);
    return std.mem.readInt(u32, &buf, .little);
}

/// Generate a random u64
pub fn randomU64() u64 {
    var buf: [8]u8 = undefined;
    randomBytes(&buf);
    return std.mem.readInt(u64, &buf, .little);
}

/// Generate a random integer in range [min, max)
pub fn randomRange(comptime T: type, min: T, max: T) T {
    if (min >= max) return min;
    const range = max - min;

    return switch (T) {
        u32 => min + @as(u32, @intCast(randomU32() % range)),
        u64 => min + @as(u64, @intCast(randomU64() % range)),
        i32 => min + @as(i32, @intCast(@as(u32, @intCast(randomU32())) % @as(u32, @intCast(range)))),
        i64 => min + @as(i64, @intCast(@as(u64, @intCast(randomU64())) % @as(u64, @intCast(range)))),
        else => @compileError("Unsupported type for randomRange"),
    };
}

/// HMAC-SHA256
pub fn hmacSha256(out: *[SHA256_SIZE]u8, key: []const u8, message: []const u8) void {
    const HmacSha256 = crypto_std.auth.hmac.sha2.HmacSha256;
    var h = HmacSha256.init(key);
    h.update(message);
    h.final(out);
}

/// HMAC-SHA1
pub fn hmacSha1(out: *[SHA1_SIZE]u8, key: []const u8, message: []const u8) void {
    const HmacSha1 = crypto_std.auth.hmac.Sha1;
    var h = HmacSha1.init(key);
    h.update(message);
    h.final(out);
}

/// PBKDF2 key derivation with SHA-256
pub fn pbkdf2Sha256(
    derived_key: []u8,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
) !void {
    try crypto_std.pwhash.pbkdf2(derived_key, password, salt, iterations, crypto_std.auth.hmac.sha2.HmacSha256);
}

/// PBKDF2 key derivation with SHA-1 (for legacy compatibility)
pub fn pbkdf2Sha1(
    derived_key: []u8,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
) !void {
    try crypto_std.pwhash.pbkdf2(derived_key, password, salt, iterations, crypto_std.auth.hmac.Sha1);
}

/// Simple password hash for verification (not for storage - use Argon2 for that)
pub fn hashPassword(allocator: std.mem.Allocator, password: []const u8, salt: []const u8) ![]u8 {
    var key: [32]u8 = undefined;
    try pbkdf2Sha256(&key, password, salt, DEFAULT_PBKDF2_ITERATIONS);

    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, 64);

    for (key, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

/// Constant-time comparison (prevents timing attacks)
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }

    return result == 0;
}

/// Generate a random session ID
pub fn generateSessionId(out: *[16]u8) void {
    randomBytes(out);
}

/// Generate a random challenge for authentication
pub fn generateChallenge(out: *[32]u8) void {
    randomBytes(out);
}

/// XOR two byte arrays (for simple encryption/obfuscation)
pub fn xorBytes(dest: []u8, src1: []const u8, src2: []const u8) void {
    const len = @min(dest.len, @min(src1.len, src2.len));
    for (0..len) |i| {
        dest[i] = src1[i] ^ src2[i];
    }
}

/// Simple checksum (CRC32)
pub fn crc32(data: []const u8) u32 {
    return std.hash.Crc32.hash(data);
}

/// Secure zero memory (prevents sensitive data from remaining in memory)
pub fn secureZero(buffer: []u8) void {
    @memset(buffer, 0);
    // Compiler barrier to prevent optimization
    std.mem.doNotOptimizeAway(buffer.ptr);
}

//
// Tests
//

test "SHA-256 hash" {
    const allocator = std.testing.allocator;

    // Test vector from NIST
    var hash: [SHA256_SIZE]u8 = undefined;
    sha256(&hash, "abc");

    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };

    try std.testing.expectEqualSlices(u8, &expected, &hash);

    // Test hex conversion
    const hex = try sha256Hex(allocator, "abc");
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
}

test "SHA-1 hash" {
    var hash: [SHA1_SIZE]u8 = undefined;
    sha1(&hash, "abc");

    const expected = [_]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d,
    };

    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "MD5 hash" {
    var hash: [MD5_SIZE]u8 = undefined;
    md5(&hash, "abc");

    const expected = [_]u8{
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    };

    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "Random bytes generation" {
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    randomBytes(&buf1);
    randomBytes(&buf2);

    // Extremely unlikely to be equal
    try std.testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}

test "Random range" {
    for (0..100) |_| {
        const val = randomRange(u32, 10, 20);
        try std.testing.expect(val >= 10 and val < 20);
    }
}

test "HMAC-SHA256" {
    var mac: [SHA256_SIZE]u8 = undefined;
    hmacSha256(&mac, "key", "message");

    // Expected HMAC-SHA256 for key="key", message="message"
    const expected = [_]u8{
        0x6e, 0x9e, 0xf2, 0x9b, 0x75, 0xff, 0xfc, 0x5b,
        0x7a, 0xba, 0xe5, 0x27, 0xd5, 0x8f, 0xda, 0xdb,
        0x2f, 0xe4, 0x2e, 0x7e, 0x4b, 0x7d, 0xa5, 0x37,
        0xe8, 0x8f, 0x3f, 0x48, 0x04, 0xe9, 0xb9, 0x23,
    };

    try std.testing.expectEqualSlices(u8, &expected, &mac);
}

test "PBKDF2-SHA256" {
    var key: [32]u8 = undefined;
    try pbkdf2Sha256(&key, "password", "salt", 1000);

    // Should produce consistent results
    var key2: [32]u8 = undefined;
    try pbkdf2Sha256(&key2, "password", "salt", 1000);

    try std.testing.expectEqualSlices(u8, &key, &key2);

    // Different password should produce different key
    var key3: [32]u8 = undefined;
    try pbkdf2Sha256(&key3, "different", "salt", 1000);

    try std.testing.expect(!std.mem.eql(u8, &key, &key3));
}

test "Constant time comparison" {
    const a = "password123";
    const b = "password123";
    const c = "password456";

    try std.testing.expect(constantTimeEqual(a, b));
    try std.testing.expect(!constantTimeEqual(a, c));
    try std.testing.expect(!constantTimeEqual(a, "short"));
}

test "Session ID generation" {
    var id1: [16]u8 = undefined;
    var id2: [16]u8 = undefined;

    generateSessionId(&id1);
    generateSessionId(&id2);

    // Should be different
    try std.testing.expect(!std.mem.eql(u8, &id1, &id2));
}

test "XOR operation" {
    const src1 = [_]u8{ 0xFF, 0x00, 0xAA, 0x55 };
    const src2 = [_]u8{ 0x0F, 0xF0, 0xA5, 0x5A };
    var dest: [4]u8 = undefined;

    xorBytes(&dest, &src1, &src2);

    const expected = [_]u8{ 0xF0, 0xF0, 0x0F, 0x0F };
    try std.testing.expectEqualSlices(u8, &expected, &dest);
}

test "CRC32 checksum" {
    const data = "Hello, World!";
    const checksum = crc32(data);

    // CRC32 should be consistent
    const checksum2 = crc32(data);
    try std.testing.expectEqual(checksum, checksum2);

    // Different data should have different checksum
    const checksum3 = crc32("Different data");
    try std.testing.expect(checksum != checksum3);
}

test "Secure zero" {
    var buffer = [_]u8{ 1, 2, 3, 4, 5 };
    secureZero(&buffer);

    const expected = [_]u8{ 0, 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &expected, &buffer);
}
