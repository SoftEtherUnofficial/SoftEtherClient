//! Cryptographic Operations
//!
//! Safe wrappers around Mayaqua crypto FFI functions.

const std = @import("std");
const mayaqua = @import("../mayaqua.zig");
const c = mayaqua.c;
const MayaquaError = mayaqua.MayaquaError;
const checkResult = mayaqua.checkResult;

pub const SHA0_SIZE = 20;
pub const SHA1_SIZE = 20;
pub const PASSWORD_HASH_SIZE = 20;

/// Compute SHA-0 hash of data
///
/// ## Parameters
/// - `data`: Input data to hash
/// - `output`: Buffer to store 20-byte hash (must be at least SHA0_SIZE bytes)
///
/// ## Example
/// ```zig
/// var hash: [crypto.SHA0_SIZE]u8 = undefined;
/// try crypto.sha0("hello world", &hash);
/// ```
pub fn sha0(data: []const u8, output: *[SHA0_SIZE]u8) MayaquaError!void {
    const result = c.mayaqua_sha0(
        data.ptr,
        @intCast(data.len),
        output.ptr,
    );
    try checkResult(result);
}

/// Compute SHA-1 hash of data (requires sha1-compat feature)
///
/// ## Parameters
/// - `data`: Input data to hash
/// - `output`: Buffer to store 20-byte hash (must be at least SHA1_SIZE bytes)
///
/// ## Example
/// ```zig
/// var hash: [crypto.SHA1_SIZE]u8 = undefined;
/// try crypto.sha1("hello world", &hash);
/// ```
pub fn sha1(data: []const u8, output: *[SHA1_SIZE]u8) MayaquaError!void {
    const result = c.mayaqua_sha1(
        data.ptr,
        @intCast(data.len),
        output.ptr,
    );
    try checkResult(result);
}

/// Compute SoftEther password hash (username + password)
///
/// Uses SHA-0 with username and password concatenation.
///
/// ## Parameters
/// - `password`: User password
/// - `username`: Username for salting
/// - `output`: Buffer to store 20-byte hash
///
/// ## Example
/// ```zig
/// var hash: [crypto.PASSWORD_HASH_SIZE]u8 = undefined;
/// try crypto.passwordHash("mypassword", "alice", &hash);
/// ```
pub fn passwordHash(password: []const u8, username: []const u8, output: *[PASSWORD_HASH_SIZE]u8) MayaquaError!void {
    // Allocate null-terminated strings for C FFI
    var pass_buf: [256]u8 = undefined;
    var user_buf: [256]u8 = undefined;

    if (password.len >= pass_buf.len or username.len >= user_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(pass_buf[0..password.len], password);
    pass_buf[password.len] = 0;

    @memcpy(user_buf[0..username.len], username);
    user_buf[username.len] = 0;

    const result = c.mayaqua_password_hash(
        @ptrCast(&pass_buf),
        @ptrCast(&user_buf),
        output.ptr,
    );
    try checkResult(result);
}

/// RC4 cipher context for encryption/decryption
pub const RC4 = struct {
    key: []const u8,

    /// Create new RC4 context with key
    pub fn init(key: []const u8) RC4 {
        return .{ .key = key };
    }

    /// Apply RC4 cipher (encrypt or decrypt)
    ///
    /// ## Parameters
    /// - `data`: Input data to process
    /// - `output`: Output buffer (must be same size as input)
    ///
    /// ## Example
    /// ```zig
    /// const rc4 = crypto.RC4.init("secretkey");
    /// var encrypted: [100]u8 = undefined;
    /// try rc4.apply("plaintext", &encrypted);
    /// ```
    pub fn apply(self: RC4, data: []const u8, output: []u8) MayaquaError!void {
        if (data.len != output.len) {
            return MayaquaError.InvalidParameter;
        }

        const result = c.mayaqua_rc4_apply(
            self.key.ptr,
            @intCast(self.key.len),
            data.ptr,
            @intCast(data.len),
            output.ptr,
        );
        try checkResult(result);
    }

    /// Apply RC4 cipher in-place (modifies input buffer)
    ///
    /// ## Parameters
    /// - `data`: Buffer to encrypt/decrypt in-place
    ///
    /// ## Example
    /// ```zig
    /// const rc4 = crypto.RC4.init("secretkey");
    /// var buffer = "plaintext".*;
    /// try rc4.applyInPlace(&buffer);
    /// ```
    pub fn applyInPlace(self: RC4, data: []u8) MayaquaError!void {
        const result = c.mayaqua_rc4_apply_inplace(
            self.key.ptr,
            @intCast(self.key.len),
            data.ptr,
            @intCast(data.len),
        );
        try checkResult(result);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "sha0 basic" {
    const testing = std.testing;

    var hash: [SHA0_SIZE]u8 = undefined;
    try sha0("hello", &hash);

    // SHA-0 produces consistent output
    try testing.expect(hash.len == SHA0_SIZE);
}

test "sha1 basic" {
    const testing = std.testing;

    var hash: [SHA1_SIZE]u8 = undefined;
    try sha1("hello", &hash);

    try testing.expect(hash.len == SHA1_SIZE);
}

test "password hash" {
    const testing = std.testing;

    var hash1: [PASSWORD_HASH_SIZE]u8 = undefined;
    var hash2: [PASSWORD_HASH_SIZE]u8 = undefined;

    try passwordHash("password", "user1", &hash1);
    try passwordHash("password", "user2", &hash2);

    // Same password, different user -> different hash
    try testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "rc4 encryption roundtrip" {
    const testing = std.testing;

    const plaintext = "hello world";
    const key = "secretkey";

    const rc4 = RC4.init(key);

    var encrypted: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    // Encrypt
    try rc4.apply(plaintext, &encrypted);

    // Decrypt (RC4 is symmetric)
    try rc4.apply(&encrypted, &decrypted);

    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "rc4 in-place" {
    const testing = std.testing;

    const original = "hello world";
    var buffer: [original.len]u8 = undefined;
    @memcpy(&buffer, original);

    const rc4 = RC4.init("key");

    // Encrypt in-place
    try rc4.applyInPlace(&buffer);

    // Should be different after encryption
    try testing.expect(!std.mem.eql(u8, &buffer, original));

    // Decrypt in-place
    try rc4.applyInPlace(&buffer);

    // Should match original after decryption
    try testing.expectEqualSlices(u8, &buffer, original);
}
