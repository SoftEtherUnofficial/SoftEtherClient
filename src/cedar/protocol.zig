// Cedar Protocol Handler Module
// High-level VPN protocol operations for SoftEther VPN
// Based on SoftEtherRust/libs/cedar/src/dataplane.rs and existing packet.zig

const std = @import("std");
const packet_mod = @import("../protocol/packet.zig");
const pack_mod = @import("../mayaqua/pack.zig");
const crypto = @import("../mayaqua/crypto.zig");
const time = @import("../mayaqua/time.zig");
const connection = @import("connection.zig");

// Re-export packet types for convenience
pub const PacketType = packet_mod.PacketType;
pub const Packet = packet_mod.Packet;
pub const PacketHeader = packet_mod.PacketHeader;
pub const Pack = pack_mod.Pack;

/// Protocol version constants
pub const PROTOCOL_VERSION: u32 = 1;
pub const SOFTETHER_SIGNATURE = "SOFTETHER_VPN";

/// Keep-alive interval in milliseconds
pub const DEFAULT_KEEPALIVE_INTERVAL_MS: u64 = 5000; // 5 seconds
pub const DEFAULT_TIMEOUT_MS: u64 = 30000; // 30 seconds

/// Link direction (for multi-link connections)
pub const LinkDirection = enum(u32) {
    both = 0, // Bidirectional
    client_to_server = 1, // TX only (client → server)
    server_to_client = 2, // RX only (server → client)

    pub fn fromU32(value: u32) !LinkDirection {
        return switch (value) {
            0 => .both,
            1 => .client_to_server,
            2 => .server_to_client,
            else => error.InvalidLinkDirection,
        };
    }

    pub fn toU32(self: LinkDirection) u32 {
        return @intFromEnum(self);
    }
};

/// Protocol statistics
pub const ProtocolStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    keepalives_sent: u64 = 0,
    keepalives_received: u64 = 0,
    errors: u64 = 0,
    last_keepalive_tick: u64 = 0,
    last_receive_tick: u64 = 0,

    pub fn init() ProtocolStats {
        const now = time.getTick64();
        return ProtocolStats{
            .last_keepalive_tick = now,
            .last_receive_tick = now,
        };
    }
};

/// Protocol handler for VPN operations
pub const ProtocolHandler = struct {
    sequence_number: u32,
    ack_number: u32,
    stats: ProtocolStats,
    keepalive_interval_ms: u64,
    timeout_ms: u64,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Create new protocol handler
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .sequence_number = 1,
            .ack_number = 0,
            .stats = ProtocolStats.init(),
            .keepalive_interval_ms = DEFAULT_KEEPALIVE_INTERVAL_MS,
            .timeout_ms = DEFAULT_TIMEOUT_MS,
            .allocator = allocator,
        };
    }

    /// Get next sequence number
    pub fn getNextSequence(self: *Self) u32 {
        const seq = self.sequence_number;
        self.sequence_number +%= 1; // Wrap on overflow
        return seq;
    }

    /// Update ACK number
    pub fn updateAck(self: *Self, ack: u32) void {
        self.ack_number = ack;
    }

    /// Create keepalive packet
    pub fn createKeepalive(self: *Self) !*Packet {
        const seq = self.getNextSequence();
        const empty: [0]u8 = undefined;
        var pkt = try self.allocator.create(Packet);
        pkt.* = try Packet.init(self.allocator, .keepalive, seq, &empty);

        // Empty payload for keepalive
        pkt.header.ack_number = self.ack_number;

        self.stats.keepalives_sent += 1;
        self.stats.last_keepalive_tick = time.getTick64();

        return pkt;
    }

    /// Create disconnect packet
    pub fn createDisconnect(self: *Self) !*Packet {
        const seq = self.getNextSequence();
        const empty: [0]u8 = undefined;
        var pkt = try self.allocator.create(Packet);
        pkt.* = try Packet.init(self.allocator, .disconnect, seq, &empty);

        pkt.header.ack_number = self.ack_number;

        return pkt;
    }

    /// Create data packet from payload
    pub fn createDataPacket(self: *Self, data: []const u8) !*Packet {
        const seq = self.getNextSequence();
        var pkt = try self.allocator.create(Packet);
        pkt.* = try Packet.init(self.allocator, .data, seq, data);

        pkt.header.ack_number = self.ack_number;

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += data.len;

        return pkt;
    }

    /// Create control packet with Pack data
    pub fn createControlPacket(self: *Self, pack: *Pack) !*Packet {
        const seq = self.getNextSequence();

        // Serialize Pack to bytes
        const pack_data = try pack.toBytes();
        defer self.allocator.free(pack_data);

        var pkt = try self.allocator.create(Packet);
        pkt.* = try Packet.init(self.allocator, .control, seq, pack_data);

        pkt.header.ack_number = self.ack_number;

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += pack_data.len;

        return pkt;
    }

    /// Create authentication packet
    pub fn createAuthPacket(self: *Self, auth_data: []const u8) !*Packet {
        const seq = self.getNextSequence();
        var pkt = try self.allocator.create(Packet);
        pkt.* = try Packet.init(self.allocator, .auth, seq, auth_data);

        pkt.header.ack_number = self.ack_number;

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += auth_data.len;

        return pkt;
    }

    /// Create ACK packet
    pub fn createAck(self: *Self, ack_seq: u32) !*Packet {
        const seq = self.getNextSequence();
        const empty: [0]u8 = undefined;
        var pkt = try self.allocator.create(Packet);
        pkt.* = try Packet.init(self.allocator, .ack, seq, &empty);

        pkt.header.ack_number = ack_seq;

        return pkt;
    }

    /// Process received packet
    pub fn processPacket(self: *Self, pkt: *const Packet) !void {
        // Update statistics
        self.stats.packets_received += 1;
        self.stats.bytes_received += pkt.header.payload_length;
        self.stats.last_receive_tick = time.getTick64();

        // Update ACK if packet has valid sequence
        if (pkt.header.sequence > self.ack_number) {
            self.ack_number = pkt.header.sequence;
        }

        // Handle specific packet types
        switch (pkt.header.packet_type) {
            .keepalive => {
                self.stats.keepalives_received += 1;
            },
            .disconnect => {
                // Connection termination requested
            },
            .data => {
                // Data packet received
            },
            .control => {
                // Control packet received
            },
            .auth => {
                // Authentication packet received
            },
            .ack => {
                // ACK received
            },
            .nack => {
                // NACK received (retransmission needed)
            },
            .fragment => {
                // Fragmented packet (needs reassembly)
            },
        }
    }

    /// Check if keepalive should be sent
    pub fn shouldSendKeepalive(self: *const Self) bool {
        const now = time.getTick64();
        const elapsed = now - self.stats.last_keepalive_tick;
        return elapsed >= self.keepalive_interval_ms;
    }

    /// Check if connection timed out
    pub fn isTimedOut(self: *const Self) bool {
        const now = time.getTick64();
        const elapsed = now - self.stats.last_receive_tick;
        return elapsed >= self.timeout_ms;
    }

    /// Get protocol statistics
    pub fn getStats(self: *const Self) ProtocolStats {
        return self.stats;
    }

    /// Reset statistics
    pub fn resetStats(self: *Self) void {
        self.stats = ProtocolStats.init();
    }

    /// Set keepalive interval
    pub fn setKeepaliveInterval(self: *Self, interval_ms: u64) void {
        self.keepalive_interval_ms = interval_ms;
    }

    /// Set timeout
    pub fn setTimeout(self: *Self, timeout_ms: u64) void {
        self.timeout_ms = timeout_ms;
    }
};

/// Helper functions for Pack creation
/// Create Hello Pack (initial handshake)
pub fn createHelloPack(allocator: std.mem.Allocator, client_str: []const u8, client_ver: u32, client_build: u32) !Pack {
    var pack = Pack.init(allocator);

    try pack.addStr("hello", client_str);
    try pack.addInt("client_version", client_ver);
    try pack.addInt("client_build", client_build);
    try pack.addBool("use_encrypt", true);
    try pack.addBool("use_compress", true);

    return pack;
}

/// Create authentication Pack
pub fn createAuthRequestPack(
    allocator: std.mem.Allocator,
    username: []const u8,
    hub_name: []const u8,
    auth_method: u32,
) !Pack {
    var pack = Pack.init(allocator);

    try pack.addStr("method", "login");
    try pack.addStr("username", username);
    try pack.addStr("hubname", hub_name);
    try pack.addInt("authtype", auth_method);

    return pack;
}

/// Parse Hello response Pack
pub fn parseHelloPack(pack: *const Pack) !struct {
    server_str: []const u8,
    server_ver: u32,
    server_build: u32,
} {
    const server_str = pack.getString("hello") orelse return error.MissingServerString;
    const server_ver = pack.getInt("server_version") orelse return error.MissingServerVersion;
    const server_build = pack.getInt("server_build") orelse return error.MissingServerBuild;

    return .{
        .server_str = server_str,
        .server_ver = server_ver,
        .server_build = server_build,
    };
}

/// Check if authentication was successful
pub fn isAuthSuccess(pack: *const Pack) bool {
    if (pack.getBool("authok")) |success| {
        return success;
    }
    return false;
}
