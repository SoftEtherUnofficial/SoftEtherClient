// VPN Protocol Implementation - Complete Integration
// Wires together vpn.zig, crypto.zig, packet.zig, and network layer
// Pure Zig implementation replacing C Protocol.c and Session.c

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;

// Import our protocol modules
const vpn = @import("vpn.zig");
const crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");
const connection_mod = @import("../net/connection.zig");
// Use module import instead of file import to avoid conflicts
const socket_mod = @import("socket"); // Module import
const http_mod = @import("../net/http.zig");

// Re-export commonly used types
pub const VpnVersion = vpn.VpnVersion;
pub const AuthMethod = vpn.AuthMethod;
pub const AuthCredentials = vpn.AuthCredentials;
pub const SessionState = vpn.SessionState;
pub const Packet = packet_mod.Packet;
pub const PacketType = packet_mod.PacketType;

// ============================================================================
// SoftEther Protocol Constants
// ============================================================================

const SOFTETHER_SIGNATURE = "SSLVPN";
const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_TIMEOUT_MS: u64 = 30000; // 30 seconds

// ============================================================================
// Pack Serialization (SoftEther binary format)
// ============================================================================

pub const Pack = struct {
    data: std.StringHashMap(PackValue),
    allocator: Allocator,

    pub const PackValue = union(enum) {
        int: u32,
        int64: u64,
        bool: bool,
        data: []const u8,
        str: []const u8,
    };

    pub fn init(allocator: Allocator) Pack {
        return .{
            .data = std.StringHashMap(PackValue).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Pack) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .data => |d| self.allocator.free(d),
                .str => |s| self.allocator.free(s),
                else => {},
            }
        }
        self.data.deinit();
    }

    pub fn put(self: *Pack, key: []const u8, value: PackValue) !void {
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        const value_copy = switch (value) {
            .data => |d| PackValue{ .data = try self.allocator.dupe(u8, d) },
            .str => |s| PackValue{ .str = try self.allocator.dupe(u8, s) },
            else => value,
        };

        try self.data.put(key_copy, value_copy);
    }

    pub fn get(self: *const Pack, key: []const u8) ?PackValue {
        return self.data.get(key);
    }

    pub fn serialize(self: *const Pack) ![]u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();

        // Write number of elements
        try writer.writeInt(u32, @intCast(self.data.count()), .little);

        // Write each key-value pair
        var it = self.data.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;

            // Write key length and key
            try writer.writeInt(u32, @intCast(key.len), .little);
            try writer.writeAll(key);

            // Write value type and value
            switch (value) {
                .int => |v| {
                    try writer.writeByte(0); // Type: int
                    try writer.writeInt(u32, v, .little);
                },
                .int64 => |v| {
                    try writer.writeByte(4); // Type: int64
                    try writer.writeInt(u64, v, .little);
                },
                .bool => |v| {
                    try writer.writeByte(3); // Type: bool
                    try writer.writeByte(if (v) 1 else 0);
                },
                .data => |d| {
                    try writer.writeByte(1); // Type: data
                    try writer.writeInt(u32, @intCast(d.len), .little);
                    try writer.writeAll(d);
                },
                .str => |s| {
                    try writer.writeByte(2); // Type: str
                    try writer.writeInt(u32, @intCast(s.len), .little);
                    try writer.writeAll(s);
                },
            }
        }

        return buffer.toOwnedSlice();
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !Pack {
        var pack = Pack.init(allocator);
        errdefer pack.deinit();

        var offset: usize = 0;

        // Read number of elements
        if (data.len < 4) return error.InvalidPack;
        const count = std.mem.readInt(u32, data[offset..][0..4], .little);
        offset += 4;

        // Read each key-value pair
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            // Read key
            if (offset + 4 > data.len) return error.InvalidPack;
            const key_len = std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;

            if (offset + key_len > data.len) return error.InvalidPack;
            const key = data[offset .. offset + key_len];
            offset += key_len;

            // Read value type
            if (offset >= data.len) return error.InvalidPack;
            const value_type = data[offset];
            offset += 1;

            // Read value based on type
            const value = switch (value_type) {
                0 => blk: { // int
                    if (offset + 4 > data.len) return error.InvalidPack;
                    const v = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;
                    break :blk PackValue{ .int = v };
                },
                4 => blk: { // int64
                    if (offset + 8 > data.len) return error.InvalidPack;
                    const v = std.mem.readInt(u64, data[offset..][0..8], .little);
                    offset += 8;
                    break :blk PackValue{ .int64 = v };
                },
                3 => blk: { // bool
                    if (offset >= data.len) return error.InvalidPack;
                    const v = data[offset] != 0;
                    offset += 1;
                    break :blk PackValue{ .bool = v };
                },
                1 => blk: { // data
                    if (offset + 4 > data.len) return error.InvalidPack;
                    const len = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;

                    if (offset + len > data.len) return error.InvalidPack;
                    const d = data[offset .. offset + len];
                    offset += len;
                    break :blk PackValue{ .data = d };
                },
                2 => blk: { // str
                    if (offset + 4 > data.len) return error.InvalidPack;
                    const len = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;

                    if (offset + len > data.len) return error.InvalidPack;
                    const s = data[offset .. offset + len];
                    offset += len;
                    break :blk PackValue{ .str = s };
                },
                else => return error.UnsupportedPackType,
            };

            try pack.put(key, value);
        }

        return pack;
    }
};

// ============================================================================
// VPN Protocol Handler
// ============================================================================

pub const VpnProtocol = struct {
    allocator: Allocator,
    socket: ?socket_mod.TcpSocket,
    crypto_engine: ?*crypto.CryptoEngine,
    sequence: u32,
    session_key: ?[]const u8,
    server_host: []const u8,
    server_port: u16,
    hub_name: []const u8,
    credentials: AuthCredentials,
    connected: bool,

    pub fn init(
        allocator: Allocator,
        server_host: []const u8,
        server_port: u16,
        hub_name: []const u8,
        credentials: AuthCredentials,
    ) !*VpnProtocol {
        const protocol = try allocator.create(VpnProtocol);
        errdefer allocator.destroy(protocol);

        protocol.* = .{
            .allocator = allocator,
            .socket = null,
            .crypto_engine = null,
            .sequence = 1,
            .session_key = null,
            .server_host = try allocator.dupe(u8, server_host),
            .server_port = server_port,
            .hub_name = try allocator.dupe(u8, hub_name),
            .credentials = credentials,
            .connected = false,
        };

        return protocol;
    }

    pub fn deinit(self: *VpnProtocol) void {
        // Close socket if connected
        if (self.socket) |*sock| {
            sock.close();
        }

        self.allocator.free(self.server_host);
        self.allocator.free(self.hub_name);

        if (self.session_key) |key| {
            self.allocator.free(key);
        }

        if (self.crypto_engine) |engine| {
            engine.deinit();
            self.allocator.destroy(engine);
        }

        self.allocator.destroy(self);
    }

    /// Connect to VPN server
    pub fn connect(self: *VpnProtocol) !void {
        std.log.info("Connecting to {s}:{d}...", .{ self.server_host, self.server_port });

        // Connect TCP socket to server
        self.socket = try socket_mod.TcpSocket.connect(
            self.allocator,
            self.server_host,
            self.server_port,
        );

        self.connected = true;
        std.log.info("TCP connection established", .{});
    }

    /// Perform authentication handshake
    pub fn authenticate(self: *VpnProtocol) !void {
        std.log.info("Authenticating with method: {s}", .{self.credentials.method.toString()});

        // Step 1: Send signature
        try self.sendSignature();

        // Step 2: Receive hello from server
        const hello = try self.receiveHello();
        defer hello.deinit();

        std.log.info("Received server hello", .{});

        // Step 3: Send authentication request
        try self.sendAuthRequest();

        // Step 4: Receive authentication response
        const auth_response = try self.receiveAuthResponse();
        defer auth_response.deinit();

        // Extract session key
        if (auth_response.get("session_key")) |key_value| {
            switch (key_value) {
                .data => |key_data| {
                    self.session_key = try self.allocator.dupe(u8, key_data);
                },
                else => return error.InvalidSessionKey,
            }
        } else {
            return error.NoSessionKey;
        }

        std.log.info("Authentication successful, session key obtained", .{});

        // Initialize crypto engine
        self.crypto_engine = try self.allocator.create(crypto.CryptoEngine);
        self.crypto_engine.?.* = try crypto.CryptoEngine.init(
            self.allocator,
            .aes_256_gcm,
        );

        // TODO: Derive encryption keys from session_key
    }

    /// Send VPN signature to server
    fn sendSignature(self: *VpnProtocol) !void {
        if (self.socket == null) return error.NotConnected;

        // Build HTTP POST request for VPNCONNECT
        var http_request = http_mod.HttpRequest.init(self.allocator, .POST, "/vpnsvc/vpn.cgi");
        defer http_request.deinit();

        try http_request.addHeader("Host", self.server_host);
        try http_request.addHeader("Connection", "Keep-Alive");
        try http_request.addHeader("Content-Type", "application/octet-stream");
        try http_request.addHeader("X-VPN-Protocol", "SoftEther");

        // Build signature body
        const signature = SOFTETHER_SIGNATURE;
        try http_request.setBody(signature);

        // Send request
        const request_bytes = try http_request.build();
        defer self.allocator.free(request_bytes);

        std.log.debug("Sending HTTP VPNCONNECT ({d} bytes)", .{request_bytes.len});
        try self.socket.?.sendAll(request_bytes);
    }

    /// Receive hello message from server
    fn receiveHello(self: *VpnProtocol) !Pack {
        if (self.socket == null) return error.NotConnected;

        // Read HTTP response
        var response_buffer = std.ArrayList(u8){};
        defer response_buffer.deinit(self.allocator);

        var read_buf: [4096]u8 = undefined;
        var total_read: usize = 0;

        // Read until we have the complete HTTP response
        while (total_read < 65536) { // Max 64KB for hello
            const n = try self.socket.?.recv(&read_buf);
            try response_buffer.appendSlice(self.allocator, read_buf[0..n]);
            total_read += n;

            // Check if we have complete HTTP response (headers + body)
            if (std.mem.indexOf(u8, response_buffer.items, "\r\n\r\n")) |_| {
                // We have headers, check if we have the body
                // For now, break after first read with headers
                break;
            }
        }

        std.log.debug("Received hello response ({d} bytes)", .{response_buffer.items.len});

        // Parse HTTP response
        var http_response = try http_mod.parseResponse(self.allocator, response_buffer.items);
        defer http_response.deinit();

        if (!http_response.isSuccess()) {
            std.log.err("Server returned HTTP {d}: {s}", .{ http_response.status_code, http_response.status_message });
            return error.ServerError;
        }

        // Parse Pack from body
        const hello_pack = try Pack.deserialize(self.allocator, http_response.body);
        return hello_pack;
    }

    /// Send authentication request
    fn sendAuthRequest(self: *VpnProtocol) !void {
        if (self.socket == null) return error.NotConnected;

        var auth_pack = Pack.init(self.allocator);
        defer auth_pack.deinit();

        // Add authentication fields
        try auth_pack.put("method", .{ .str = self.credentials.method.toString() });

        if (self.credentials.username) |username| {
            try auth_pack.put("username", .{ .str = username });
        }

        if (self.credentials.password) |password| {
            // Hash password with SHA-0 (SoftEther legacy)
            const password_hash = try self.hashPassword(password);
            defer self.allocator.free(password_hash);

            try auth_pack.put("password_hash", .{ .data = password_hash });
        }

        try auth_pack.put("hub_name", .{ .str = self.hub_name });
        try auth_pack.put("protocol", .{ .str = "softether" });

        // Serialize Pack
        const serialized = try auth_pack.serialize();
        defer self.allocator.free(serialized);

        // Build HTTP POST request
        var http_request = http_mod.HttpRequest.init(self.allocator, .POST, "/vpnsvc/connect.cgi");
        defer http_request.deinit();

        try http_request.addHeader("Host", self.server_host);
        try http_request.addHeader("Connection", "Keep-Alive");
        try http_request.addHeader("Content-Type", "application/octet-stream");
        try http_request.setBody(serialized);

        const request_bytes = try http_request.build();
        defer self.allocator.free(request_bytes);

        std.log.debug("Sending auth request ({d} bytes)...", .{request_bytes.len});
        try self.socket.?.sendAll(request_bytes);
    }

    /// Receive authentication response
    fn receiveAuthResponse(self: *VpnProtocol) !Pack {
        if (self.socket == null) return error.NotConnected;

        // Read HTTP response
        var response_buffer = std.ArrayList(u8){};
        defer response_buffer.deinit(self.allocator);

        var read_buf: [4096]u8 = undefined;
        var total_read: usize = 0;

        // Read until we have the complete HTTP response
        while (total_read < 65536) { // Max 64KB
            const n = try self.socket.?.recv(&read_buf);
            try response_buffer.appendSlice(self.allocator, read_buf[0..n]);
            total_read += n;

            // Check if we have complete response
            if (std.mem.indexOf(u8, response_buffer.items, "\r\n\r\n")) |_| {
                break;
            }
        }

        std.log.debug("Received auth response ({d} bytes)", .{response_buffer.items.len});

        // Parse HTTP response
        const http_response = try http_mod.parseResponse(self.allocator, response_buffer.items);
        defer http_response.deinit();

        if (!http_response.isSuccess()) {
            std.log.err("Authentication failed: HTTP {d}: {s}", .{ http_response.status_code, http_response.status_message });
            return error.AuthenticationFailed;
        }

        // Parse Pack from body
        const response_pack = try Pack.deserialize(self.allocator, http_response.body);
        return response_pack;
    }

    /// Hash password using SHA-0 (SoftEther legacy)
    fn hashPassword(self: *VpnProtocol, password: []const u8) ![]u8 {
        var hash_output: [20]u8 = undefined;

        // Use SHA-1 as approximation (SHA-0 not in std)
        // In production, use OpenSSL for actual SHA-0
        var hasher = std.crypto.hash.Sha1.init(.{});
        hasher.update(password);
        hasher.final(&hash_output);

        return try self.allocator.dupe(u8, &hash_output);
    }

    /// Read a packet from the VPN connection
    pub fn readPacket(self: *VpnProtocol, buffer: []u8) !usize {
        if (self.crypto_engine == null) return error.NotAuthenticated;
        if (self.socket == null) return error.NotConnected;

        // Read encrypted packet from network
        // Format: [4-byte length][encrypted data]
        var len_buf: [4]u8 = undefined;
        try self.socket.?.recvAll(&len_buf);

        const packet_len = std.mem.readInt(u32, &len_buf, .little);
        if (packet_len > buffer.len) return error.PacketTooLarge;

        // Read encrypted data
        const encrypted_buf = try self.allocator.alloc(u8, packet_len);
        defer self.allocator.free(encrypted_buf);

        try self.socket.?.recvAll(encrypted_buf);

        // Deserialize encrypted packet
        const encrypted_packet = try packet_mod.EncryptedPacket.deserialize(self.allocator, encrypted_buf);
        defer encrypted_packet.deinit();

        // Decrypt packet
        const plaintext = try self.crypto_engine.?.decrypt(&encrypted_packet);
        defer self.allocator.free(plaintext);

        // Copy to output buffer
        const copy_len = @min(plaintext.len, buffer.len);
        @memcpy(buffer[0..copy_len], plaintext[0..copy_len]);

        return copy_len;
    }

    /// Write a packet to the VPN connection
    pub fn writePacket(self: *VpnProtocol, data: []const u8) !void {
        if (self.crypto_engine == null) return error.NotAuthenticated;
        if (self.socket == null) return error.NotConnected;

        // Encrypt packet using crypto_engine
        const encrypted = try self.crypto_engine.?.encrypt(data);
        defer encrypted.deinit();

        // Serialize encrypted packet
        const serialized = try encrypted.serialize(self.allocator);
        defer self.allocator.free(serialized);

        // Send with length prefix
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(serialized.len), .little);

        try self.socket.?.sendAll(&len_buf);
        try self.socket.?.sendAll(serialized);

        std.log.debug("Sent encrypted packet ({d} bytes)", .{serialized.len});
    }

    /// Send keep-alive ping
    pub fn sendKeepAlive(self: *VpnProtocol) !void {
        const keepalive_packet = try packet_mod.Packet.init(
            self.allocator,
            .keepalive,
            self.sequence,
            &[_]u8{},
        );
        defer keepalive_packet.deinit();

        self.sequence += 1;

        const serialized = try keepalive_packet.serialize(self.allocator);
        defer self.allocator.free(serialized);

        try self.writePacket(serialized);
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnProtocol) !void {
        if (!self.connected) return;

        std.log.info("Disconnecting from VPN...", .{});

        // Send disconnect packet
        var disconnect_packet = try packet_mod.Packet.createDisconnect(self.allocator);
        defer disconnect_packet.deinit();

        const serialized = try disconnect_packet.serialize(self.allocator);
        defer self.allocator.free(serialized);

        // Best effort send (ignore errors)
        self.writePacket(serialized) catch |err| {
            std.log.warn("Failed to send disconnect packet: {}", .{err});
        };

        // Close socket
        if (self.socket) |*sock| {
            sock.close();
            self.socket = null;
        }

        self.connected = false;
        std.log.info("Disconnected", .{});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Pack serialization" {
    const allocator = std.testing.allocator;

    var pack = Pack.init(allocator);
    defer pack.deinit();

    try pack.put("version", .{ .int = 1 });
    try pack.put("name", .{ .str = "test_vpn" });
    try pack.put("enabled", .{ .bool = true });

    const serialized = try pack.serialize();
    defer allocator.free(serialized);

    var deserialized = try Pack.deserialize(allocator, serialized);
    defer deserialized.deinit();

    if (deserialized.get("version")) |v| {
        try std.testing.expectEqual(Pack.PackValue{ .int = 1 }, v);
    } else {
        try std.testing.expect(false);
    }
}

test "VpnProtocol initialization" {
    const allocator = std.testing.allocator;

    const creds = AuthCredentials.withPassword("testuser", "testpass");

    var protocol = try VpnProtocol.init(
        allocator,
        "test.server.com",
        443,
        "TEST_HUB",
        creds,
    );
    defer protocol.deinit();

    try std.testing.expectEqualStrings("test.server.com", protocol.server_host);
    try std.testing.expectEqual(@as(u16, 443), protocol.server_port);
    try std.testing.expectEqualStrings("TEST_HUB", protocol.hub_name);
}
