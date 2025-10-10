//! Packet Forwarding Module
//!
//! Handles bidirectional packet forwarding between TUN device and VPN session.
//! Implements packet loop, keep-alive, and connection monitoring.

const std = @import("std");
const cedar = @import("cedar/wrapper.zig");
const taptun = @import("taptun"); // Use build system module

/// Packet forwarding statistics
pub const ForwardingStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    errors: u64 = 0,
    keepalive_sent: u64 = 0,
    last_activity: i64 = 0, // Unix timestamp
};

/// Packet forwarder configuration
pub const ForwarderConfig = struct {
    keepalive_interval_ms: u32 = 30000, // 30 seconds
    read_timeout_ms: u32 = 1000, // 1 second
    buffer_size: usize = 65536, // 64KB
    max_packet_size: usize = 16384, // 16KB
};

/// Packet forwarder state
pub const PacketForwarder = struct {
    allocator: std.mem.Allocator,
    session: *cedar.Session,
    tun_adapter: *taptun.TunAdapter,
    config: ForwarderConfig,
    stats: ForwardingStats,
    running: std.atomic.Value(bool),
    last_keepalive: i64,

    const Self = @This();

    /// Create new packet forwarder
    pub fn init(
        allocator: std.mem.Allocator,
        session: *cedar.Session,
        tun_adapter: *taptun.TunAdapter,
        config: ForwarderConfig,
    ) !*Self {
        const self = try allocator.create(Self);

        self.* = .{
            .allocator = allocator,
            .session = session,
            .tun_adapter = tun_adapter,
            .config = config,
            .stats = .{},
            .running = std.atomic.Value(bool).init(false),
            .last_keepalive = std.time.timestamp(),
        };

        return self;
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        self.stop();
        self.allocator.destroy(self);
    }

    /// Start packet forwarding loop
    pub fn start(self: *Self) !void {
        if (self.running.load(.acquire)) {
            return error.AlreadyRunning;
        }

        self.running.store(true, .release);
        self.stats.last_activity = std.time.timestamp();

        std.debug.print("📡 Starting packet forwarding loop...\n", .{});

        // Main forwarding loop
        while (self.running.load(.acquire)) {
            // Check if we need to send keep-alive
            try self.checkKeepalive();

            // Try to read from TUN device (non-blocking)
            if (self.readFromTun()) |packet_sent| {
                if (packet_sent) {
                    self.stats.last_activity = std.time.timestamp();
                }
            } else |err| {
                if (err != error.WouldBlock) {
                    std.debug.print("⚠️  TUN read error: {}\n", .{err});
                    self.stats.errors += 1;
                }
            }

            // Try to read from VPN session
            if (self.readFromSession()) |packet_received| {
                if (packet_received) {
                    self.stats.last_activity = std.time.timestamp();
                }
            } else |err| {
                if (err != error.WouldBlock and err != error.NoPacketAvailable) {
                    std.debug.print("⚠️  Session read error: {}\n", .{err});
                    self.stats.errors += 1;
                }
            }

            // Small delay to prevent busy-waiting
            std.time.sleep(1 * std.time.ns_per_ms);
        }

        std.debug.print("📡 Packet forwarding loop stopped\n", .{});
    }

    /// Stop packet forwarding
    pub fn stop(self: *Self) void {
        if (self.running.load(.acquire)) {
            std.debug.print("🛑 Stopping packet forwarder...\n", .{});
            self.running.store(false, .release);
        }
    }

    /// Read packet from TUN and send to VPN session
    fn readFromTun(self: *Self) !bool {
        var buffer: [65536]u8 = undefined;

        // Read Ethernet frame from TUN device
        const eth_frame = self.tun_adapter.readEthernet(&buffer) catch |err| {
            return err;
        };

        if (eth_frame.len == 0) {
            return false;
        }

        // Create data packet for VPN
        var packet = try cedar.Packet.init("data");
        defer packet.deinit();

        // Add packet data
        try packet.addData("payload", eth_frame);

        // Send to VPN server
        try self.session.sendPacket(&packet);

        // Update statistics
        self.stats.packets_sent += 1;
        self.stats.bytes_sent += eth_frame.len;

        return true;
    }

    /// Read packet from VPN session and write to TUN
    fn readFromSession(self: *Self) !bool {
        // Try to receive packet from VPN
        var packet = self.session.receivePacket() catch |err| {
            return err;
        };
        defer packet.deinit();

        // Extract payload
        var buffer: [65536]u8 = undefined;
        const payload = try packet.getData("payload", &buffer);

        if (payload.len == 0) {
            return false;
        }

        // Write to TUN device
        try self.tun_adapter.writeEthernet(payload);

        // Update statistics
        self.stats.packets_received += 1;
        self.stats.bytes_received += payload.len;

        return true;
    }

    /// Check and send keep-alive if needed
    fn checkKeepalive(self: *Self) !void {
        const now = std.time.timestamp();
        const elapsed = now - self.last_keepalive;

        if (elapsed * 1000 >= self.config.keepalive_interval_ms) {
            try self.sendKeepalive();
            self.last_keepalive = now;
        }
    }

    /// Send keep-alive packet to server
    fn sendKeepalive(self: *Self) !void {
        var packet = try cedar.Packet.init("keepalive");
        defer packet.deinit();

        try packet.addInt("timestamp", @intCast(std.time.timestamp()));

        try self.session.sendPacket(&packet);
        self.stats.keepalive_sent += 1;
    }

    /// Get current statistics
    pub fn getStats(self: *Self) ForwardingStats {
        return self.stats;
    }

    /// Print statistics to console
    pub fn printStats(self: *Self) void {
        const stats = self.getStats();
        std.debug.print("\n📊 Packet Forwarding Statistics:\n", .{});
        std.debug.print("  Packets sent:     {d}\n", .{stats.packets_sent});
        std.debug.print("  Packets received: {d}\n", .{stats.packets_received});
        std.debug.print("  Bytes sent:       {d}\n", .{stats.bytes_sent});
        std.debug.print("  Bytes received:   {d}\n", .{stats.bytes_received});
        std.debug.print("  Errors:           {d}\n", .{stats.errors});
        std.debug.print("  Keep-alives sent: {d}\n", .{stats.keepalive_sent});

        const now = std.time.timestamp();
        const idle_time = now - stats.last_activity;
        std.debug.print("  Idle time:        {d}s\n", .{idle_time});
    }
};

// Test packet forwarder creation
test "PacketForwarder: creation and cleanup" {
    const testing = std.testing;
    const allocator = testing.allocator;
    _ = allocator; // autofix

    // Note: Can't create actual session/adapter without network
    // This test just verifies the struct is well-formed
    const config = ForwarderConfig{};
    _ = config;

    // Test that config has expected defaults
    const default_config = ForwarderConfig{};
    try testing.expect(default_config.keepalive_interval_ms == 30000);
    try testing.expect(default_config.buffer_size == 65536);
}

test "PacketForwarder: statistics initialization" {
    const testing = std.testing;
    const stats = ForwardingStats{};

    try testing.expect(stats.packets_sent == 0);
    try testing.expect(stats.packets_received == 0);
    try testing.expect(stats.bytes_sent == 0);
    try testing.expect(stats.bytes_received == 0);
}
