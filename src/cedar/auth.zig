// Cedar Authentication Module
// Handles client authentication for VPN connections
// Based on SoftEtherRust/libs/cedar/src/client_auth.rs

const std = @import("std");
const crypto = @import("../mayaqua/crypto.zig");
const errors = @import("../errors.zig");

// Constants from SoftEther protocol
pub const MAX_USERNAME_LEN = 255;
pub const MAX_PASSWORD_LEN = 255;
pub const SHA0_SIZE = 20;

/// Authentication type enum
/// Matches CLIENT_AUTHTYPE from SoftEther VPN
pub const AuthType = enum(u32) {
    anonymous = 0,
    password = 1,
    plain_password = 2,
    certificate = 3,
    secure_device = 4,
    ticket = 99, // Used for cluster redirect session reuse

    pub fn fromU32(value: u32) !AuthType {
        return switch (value) {
            0 => .anonymous,
            1 => .password,
            2 => .plain_password,
            3 => .certificate,
            4 => .secure_device,
            99 => .ticket,
            else => error.InvalidAuthType,
        };
    }

    pub fn toU32(self: AuthType) u32 {
        return @intFromEnum(self);
    }
};

/// Client authentication credentials
/// Matches CLIENT_AUTH structure from SoftEther VPN
pub const ClientAuth = struct {
    auth_type: AuthType,
    username: []const u8,
    hashed_password: [SHA0_SIZE]u8, // SHA-0 hash of password or ticket
    plain_password: ?[]const u8, // Plaintext password (for some auth modes)
    client_cert: ?[]const u8, // Client certificate (X.509 DER)
    client_key: ?[]const u8, // Client private key (DER)
    secure_cert_name: []const u8, // Secure device certificate name
    secure_key_name: []const u8, // Secure device key name
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Create anonymous authentication
    pub fn initAnonymous(allocator: std.mem.Allocator) !*Self {
        const auth = try allocator.create(Self);
        auth.* = Self{
            .auth_type = .anonymous,
            .username = try allocator.dupe(u8, ""),
            .hashed_password = [_]u8{0} ** SHA0_SIZE,
            .plain_password = null,
            .client_cert = null,
            .client_key = null,
            .secure_cert_name = try allocator.dupe(u8, ""),
            .secure_key_name = try allocator.dupe(u8, ""),
            .allocator = allocator,
        };
        return auth;
    }

    /// Create password authentication
    pub fn initPassword(allocator: std.mem.Allocator, username: []const u8, password: []const u8) !*Self {
        if (username.len > MAX_USERNAME_LEN) return error.UsernameTooLong;
        if (password.len > MAX_PASSWORD_LEN) return error.PasswordTooLong;

        // Hash password using SoftEther method (SHA-0 with username)
        const hashed = hashPasswordWithUsername(password, username);

        const auth = try allocator.create(Self);
        auth.* = Self{
            .auth_type = .password,
            .username = try allocator.dupe(u8, username),
            .hashed_password = hashed,
            .plain_password = try allocator.dupe(u8, password),
            .client_cert = null,
            .client_key = null,
            .secure_cert_name = try allocator.dupe(u8, ""),
            .secure_key_name = try allocator.dupe(u8, ""),
            .allocator = allocator,
        };
        return auth;
    }

    /// Create certificate authentication
    pub fn initCertificate(
        allocator: std.mem.Allocator,
        username: []const u8,
        cert_der: []const u8,
        key_der: []const u8,
    ) !*Self {
        if (username.len > MAX_USERNAME_LEN) return error.UsernameTooLong;

        const auth = try allocator.create(Self);
        auth.* = Self{
            .auth_type = .certificate,
            .username = try allocator.dupe(u8, username),
            .hashed_password = [_]u8{0} ** SHA0_SIZE,
            .plain_password = null,
            .client_cert = try allocator.dupe(u8, cert_der),
            .client_key = try allocator.dupe(u8, key_der),
            .secure_cert_name = try allocator.dupe(u8, ""),
            .secure_key_name = try allocator.dupe(u8, ""),
            .allocator = allocator,
        };
        return auth;
    }

    /// Create secure device authentication
    pub fn initSecureDevice(
        allocator: std.mem.Allocator,
        username: []const u8,
        cert_name: []const u8,
        key_name: []const u8,
    ) !*Self {
        if (username.len > MAX_USERNAME_LEN) return error.UsernameTooLong;

        const auth = try allocator.create(Self);
        auth.* = Self{
            .auth_type = .secure_device,
            .username = try allocator.dupe(u8, username),
            .hashed_password = [_]u8{0} ** SHA0_SIZE,
            .plain_password = null,
            .client_cert = null,
            .client_key = null,
            .secure_cert_name = try allocator.dupe(u8, cert_name),
            .secure_key_name = try allocator.dupe(u8, key_name),
            .allocator = allocator,
        };
        return auth;
    }

    /// Create ticket authentication (for cluster redirect)
    pub fn initTicket(allocator: std.mem.Allocator, username: []const u8, ticket: []const u8) !*Self {
        if (username.len > MAX_USERNAME_LEN) return error.UsernameTooLong;
        if (ticket.len != SHA0_SIZE) return error.InvalidTicketSize;

        var ticket_bytes: [SHA0_SIZE]u8 = undefined;
        @memcpy(&ticket_bytes, ticket);

        const auth = try allocator.create(Self);
        auth.* = Self{
            .auth_type = .ticket,
            .username = try allocator.dupe(u8, username),
            .hashed_password = ticket_bytes,
            .plain_password = null,
            .client_cert = null,
            .client_key = null,
            .secure_cert_name = try allocator.dupe(u8, ""),
            .secure_key_name = try allocator.dupe(u8, ""),
            .allocator = allocator,
        };
        return auth;
    }

    /// Validate authentication data
    pub fn validate(self: *const Self) !void {
        if (self.username.len > MAX_USERNAME_LEN) return error.UsernameTooLong;

        switch (self.auth_type) {
            .anonymous => {
                // Anonymous auth is always valid
            },
            .password, .plain_password => {
                if (self.username.len == 0) return error.UsernameRequired;
                if (self.plain_password) |pwd| {
                    if (pwd.len > MAX_PASSWORD_LEN) return error.PasswordTooLong;
                }
            },
            .certificate => {
                if (self.username.len == 0) return error.UsernameRequired;
                if (self.client_cert == null or self.client_key == null) {
                    return error.CertificateRequired;
                }
            },
            .secure_device => {
                if (self.username.len == 0) return error.UsernameRequired;
                if (self.secure_cert_name.len == 0 or self.secure_key_name.len == 0) {
                    return error.SecureDeviceNamesRequired;
                }
            },
            .ticket => {
                if (self.username.len == 0) return error.UsernameRequired;
                // Ticket is stored in hashed_password field
            },
        }
    }

    /// Cleanup and free resources
    /// IMPORTANT: Also zeroes out sensitive data (password, keys)
    pub fn deinit(self: *Self) void {
        // Zeroize sensitive data before freeing
        @memset(&self.hashed_password, 0);

        if (self.plain_password) |pwd| {
            // Zeroize password before freeing
            const pwd_mut = @constCast(pwd);
            @memset(pwd_mut, 0);
            self.allocator.free(pwd);
        }

        if (self.client_key) |key| {
            // Zeroize private key before freeing
            const key_mut = @constCast(key);
            @memset(key_mut, 0);
            self.allocator.free(key);
        }

        // Free non-sensitive data
        self.allocator.free(self.username);
        if (self.client_cert) |cert| self.allocator.free(cert);
        self.allocator.free(self.secure_cert_name);
        self.allocator.free(self.secure_key_name);

        self.allocator.destroy(self);
    }

    /// Get authentication type as string (for debugging)
    pub fn authTypeString(self: *const Self) []const u8 {
        return switch (self.auth_type) {
            .anonymous => "Anonymous",
            .password => "Password",
            .plain_password => "PlainPassword",
            .certificate => "Certificate",
            .secure_device => "SecureDevice",
            .ticket => "Ticket",
        };
    }
};

/// Hash password using SoftEther method (SHA-0 with username)
/// This matches the original SoftEther VPN implementation:
/// SHA-0(password_bytes + uppercase_username_bytes)
pub fn hashPasswordWithUsername(password: []const u8, username: []const u8) [SHA0_SIZE]u8 {
    return crypto.softetherPasswordHash(password, username);
}

/// Hash password using SHA-0 (legacy, without username)
/// NOTE: For proper SoftEther hashing, use hashPasswordWithUsername instead
pub fn hashPassword(password: []const u8) [SHA0_SIZE]u8 {
    const result = crypto.sha0(password);
    return result;
}
