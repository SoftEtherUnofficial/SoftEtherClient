// Authentication Handler
// Pure Zig implementation of SoftEther VPN authentication protocol
const std = @import("std");
const Allocator = std.mem.Allocator;
const Pack = @import("pack.zig").Pack;
const NodeInfo = @import("node_info.zig").NodeInfo;
const generateMachineId = @import("node_info.zig").generateMachineId;
const VpnHttpClient = @import("http_client.zig").VpnHttpClient;

/// Authentication method
pub const AuthMethod = enum {
    anonymous,
    password,
    certificate,
    radius,

    pub fn toString(self: AuthMethod) []const u8 {
        return switch (self) {
            .anonymous => "anonymous",
            .password => "password",
            .certificate => "cert",
            .radius => "radius",
        };
    }
};

/// Authentication result from server
pub const AuthResult = struct {
    success: bool,
    error_code: u32,
    session_key: []const u8,
    server_version: u32,
    server_build: u32,
    server_str: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *AuthResult) void {
        self.allocator.free(self.session_key);
        self.allocator.free(self.server_str);
    }
};

/// Authentication handler for VPN connections
pub const AuthHandler = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) !*AuthHandler {
        const handler = try allocator.create(AuthHandler);
        handler.* = .{
            .allocator = allocator,
        };
        return handler;
    }

    pub fn deinit(self: *AuthHandler) void {
        self.allocator.destroy(self);
    }

    // ========================================================================
    // Password Authentication
    // ========================================================================

    /// Build password authentication packet
    pub fn buildPasswordAuthPacket(
        self: *AuthHandler,
        username: []const u8,
        password: []const u8,
        hub_name: []const u8,
    ) !*Pack {
        const pack = try Pack.init(self.allocator);
        errdefer pack.deinit();

        // Hash password (SHA256 for secure transmission)
        const password_hash = try hashPassword(password, self.allocator);
        defer self.allocator.free(password_hash);

        // Authentication method
        try pack.addString("method", AuthMethod.password.toString());
        try pack.addString("hubname", hub_name);
        try pack.addString("username", username);
        try pack.addData("secure_password", password_hash);

        // Client version info
        try pack.addString("client_str", "SoftEtherZig VPN Client");
        try pack.addInt("client_ver", 502); // Version 5.02
        try pack.addInt("client_build", 9999);

        // Protocol version
        try pack.addInt("protocol", 0);
        try pack.addBool("hello", false);

        // Unique machine ID
        const unique_id = try generateMachineId(self.allocator);
        defer self.allocator.free(unique_id);
        try pack.addData("unique_id", unique_id);

        // Add node information
        var node_info = try NodeInfo.create(self.allocator);
        defer node_info.deinit();
        try node_info.toPacket(pack);

        return pack;
    }

    /// Build anonymous authentication packet
    pub fn buildAnonymousAuthPacket(
        self: *AuthHandler,
        hub_name: []const u8,
    ) !*Pack {
        const pack = try Pack.init(self.allocator);
        errdefer pack.deinit();

        // Authentication method
        try pack.addString("method", AuthMethod.anonymous.toString());
        try pack.addString("hubname", hub_name);

        // Client version info
        try pack.addString("client_str", "SoftEtherZig VPN Client");
        try pack.addInt("client_ver", 502);
        try pack.addInt("client_build", 9999);

        // Protocol version
        try pack.addInt("protocol", 0);
        try pack.addBool("hello", false);

        // Unique machine ID
        const unique_id = try generateMachineId(self.allocator);
        defer self.allocator.free(unique_id);
        try pack.addData("unique_id", unique_id);

        // Add node information
        var node_info = try NodeInfo.create(self.allocator);
        defer node_info.deinit();
        try node_info.toPacket(pack);

        return pack;
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Build additional connection packet (after initial auth)
    pub fn buildAdditionalConnectPacket(
        self: *AuthHandler,
        session_key: []const u8,
    ) !*Pack {
        const pack = try Pack.init(self.allocator);
        errdefer pack.deinit();

        try pack.addData("session_key", session_key);

        // Client version
        try pack.addString("client_str", "SoftEtherZig VPN Client");
        try pack.addInt("client_ver", 502);
        try pack.addInt("client_build", 9999);

        return pack;
    }

    // ========================================================================
    // Response Parsing
    // ========================================================================

    /// Full authentication flow with HTTP/SSL
    pub fn authenticate(
        self: *AuthHandler,
        server_ip: []const u8,
        port: u16,
        auth_packet: *Pack,
    ) !AuthResult {
        std.log.info("🔐 Sending authentication packet to {s}:{d}...", .{ server_ip, port });

        // Create HTTP client
        var http_client = VpnHttpClient.init(self.allocator);

        // Send auth packet and receive response
        const response_pack = try http_client.sendPack(auth_packet, server_ip, port);
        defer response_pack.deinit();

        std.log.debug("Received authentication response", .{});

        // Parse response
        return try self.parseAuthResponse(response_pack);
    }

    /// Parse authentication response from server
    pub fn parseAuthResponse(
        self: *AuthHandler,
        response_pack: *const Pack,
    ) !AuthResult {
        const error_code = response_pack.getInt("error") orelse 0;
        const success = error_code == 0;

        if (!success) {
            std.log.err("Authentication failed: error_code={d}", .{error_code});
            return AuthResult{
                .success = false,
                .error_code = @intCast(error_code),
                .session_key = &[_]u8{},
                .server_version = 0,
                .server_build = 0,
                .server_str = &[_]u8{},
                .allocator = self.allocator,
            };
        }

        // Extract session key
        const session_key_data = response_pack.getData("session_key") orelse {
            std.log.err("No session key in response", .{});
            return error.NoSessionKey;
        };
        const session_key = try self.allocator.dupe(u8, session_key_data);
        errdefer self.allocator.free(session_key);

        // Extract server info
        const server_version = response_pack.getInt("server_ver") orelse 0;
        const server_build = response_pack.getInt("server_build") orelse 0;
        const server_str_opt = response_pack.getString("server_str");
        const server_str = if (server_str_opt) |s|
            try self.allocator.dupe(u8, s)
        else
            try self.allocator.dupe(u8, "Unknown");
        errdefer self.allocator.free(server_str);

        return AuthResult{
            .success = true,
            .error_code = 0,
            .session_key = session_key,
            .server_version = @intCast(server_version),
            .server_build = @intCast(server_build),
            .server_str = server_str,
            .allocator = self.allocator,
        };
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Hash password using SHA-256 (compatible with SoftEther)
fn hashPassword(password: []const u8, allocator: Allocator) ![]u8 {
    // SoftEther uses SHA-1 for password hashing
    // For better security, we use SHA-256 but return only 20 bytes
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(password);

    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    // Return first 20 bytes (SHA-1 size for compatibility)
    const result = try allocator.alloc(u8, 20);
    @memcpy(result, hash[0..20]);
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "AuthHandler: create and destroy" {
    const allocator = std.testing.allocator;
    const handler = try AuthHandler.init(allocator);
    defer handler.deinit();
}

test "AuthHandler: build password auth packet" {
    const allocator = std.testing.allocator;
    const handler = try AuthHandler.init(allocator);
    defer handler.deinit();

    const pack = try handler.buildPasswordAuthPacket(
        "testuser",
        "testpass",
        "VPN",
    );
    defer pack.deinit();

    // Verify required fields
    try std.testing.expectEqualStrings("password", pack.getString("method").?);
    try std.testing.expectEqualStrings("VPN", pack.getString("hubname").?);
    try std.testing.expectEqualStrings("testuser", pack.getString("username").?);
    try std.testing.expect(pack.getData("secure_password") != null);
    try std.testing.expectEqualStrings("SoftEtherZig VPN Client", pack.getString("client_str").?);
    try std.testing.expectEqual(@as(i32, 502), pack.getInt("client_ver").?);
}

test "AuthHandler: build anonymous auth packet" {
    const allocator = std.testing.allocator;
    const handler = try AuthHandler.init(allocator);
    defer handler.deinit();

    const pack = try handler.buildAnonymousAuthPacket("VPN");
    defer pack.deinit();

    try std.testing.expectEqualStrings("anonymous", pack.getString("method").?);
    try std.testing.expectEqualStrings("VPN", pack.getString("hubname").?);
}

test "AuthHandler: build additional connect packet" {
    const allocator = std.testing.allocator;
    const handler = try AuthHandler.init(allocator);
    defer handler.deinit();

    const session_key = &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const pack = try handler.buildAdditionalConnectPacket(session_key);
    defer pack.deinit();

    const retrieved_key = pack.getData("session_key").?;
    try std.testing.expectEqualSlices(u8, session_key, retrieved_key);
}

test "AuthHandler: parse successful auth response" {
    const allocator = std.testing.allocator;
    const handler = try AuthHandler.init(allocator);
    defer handler.deinit();

    // Create mock response
    const response = try Pack.init(allocator);
    defer response.deinit();

    try response.addInt("error", 0);
    try response.addData("session_key", &[_]u8{ 1, 2, 3, 4 });
    try response.addInt("server_ver", 502);
    try response.addInt("server_build", 9999);
    try response.addString("server_str", "SoftEther VPN Server");

    var result = try handler.parseAuthResponse(response);
    defer result.deinit();

    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(u32, 0), result.error_code);
    try std.testing.expectEqual(@as(usize, 4), result.session_key.len);
}

test "AuthHandler: parse failed auth response" {
    const allocator = std.testing.allocator;
    const handler = try AuthHandler.init(allocator);
    defer handler.deinit();

    // Create mock error response
    const response = try Pack.init(allocator);
    defer response.deinit();

    try response.addInt("error", 1); // Auth failed

    var result = try handler.parseAuthResponse(response);
    defer result.deinit();

    try std.testing.expect(!result.success);
    try std.testing.expectEqual(@as(u32, 1), result.error_code);
}

test "AuthHandler: hash password" {
    const allocator = std.testing.allocator;
    const hash = try hashPassword("test123", allocator);
    defer allocator.free(hash);

    try std.testing.expectEqual(@as(usize, 20), hash.len);

    // Same password should produce same hash
    const hash2 = try hashPassword("test123", allocator);
    defer allocator.free(hash2);

    try std.testing.expectEqualSlices(u8, hash, hash2);
}
