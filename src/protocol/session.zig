// VPN Session Management
// Complete lifecycle management: connect, authenticate, packet forwarding, keepalive
// Replaces C Session.c and integrates all protocol components

const std = @import("std");
const Allocator = std.mem.Allocator;
const Thread = std.Thread;

// Import protocol modules
const vpn = @import("vpn.zig");
const vpn_protocol = @import("vpn_protocol.zig");
const packet_mod = @import("packet.zig");
const crypto_mod = @import("crypto.zig");

// Import network layer
const adapter_mod = @import("../packet/adapter.zig");

// Re-export commonly used types
pub const SessionState = vpn.SessionState;
pub const AuthCredentials = vpn.AuthCredentials;
pub const SessionInfo = vpn.SessionInfo;
pub const VpnProtocol = vpn_protocol.VpnProtocol;

// ============================================================================
// Session Configuration
// ============================================================================

pub const SessionConfig = struct {
    /// Server connection details
    server_host: []const u8,
    server_port: u16 = 443,
    hub_name: []const u8,

    /// Authentication
    credentials: AuthCredentials,

    /// Timeouts
    connect_timeout_ms: u64 = 30000,
    keepalive_interval_ms: u64 = 15000,
    idle_timeout_ms: u64 = 300000, // 5 minutes

    /// Protocol options
    use_encryption: bool = true,
    use_compression: bool = false,
    max_packet_size: usize = 1500,

    /// Network adapter
    tun_device_name: []const u8 = "utun",
    virtual_ip: ?[]const u8 = null,

    pub fn validate(self: *const SessionConfig) !void {
        if (self.server_host.len == 0) return error.InvalidServerHost;
        if (self.hub_name.len == 0) return error.InvalidHubName;
        if (self.server_port == 0) return error.InvalidPort;
        if (self.max_packet_size < 576 or self.max_packet_size > 65535) {
            return error.InvalidMaxPacketSize;
        }
    }
};

// ============================================================================
// Session Statistics
// ============================================================================

pub const SessionStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    keepalives_sent: u64 = 0,
    keepalives_received: u64 = 0,
    errors: u64 = 0,
    reconnects: u64 = 0,
    dropped_packets: u64 = 0,

    session_start: i64 = 0,
    last_activity: i64 = 0,

    pub fn init() SessionStats {
        const now = std.time.milliTimestamp();
        return .{
            .session_start = now,
            .last_activity = now,
        };
    }

    pub fn recordPacketSent(self: *SessionStats, size: usize) void {
        self.packets_sent += 1;
        self.bytes_sent += size;
        self.last_activity = std.time.milliTimestamp();
    }

    pub fn recordPacketReceived(self: *SessionStats, size: usize) void {
        self.packets_received += 1;
        self.bytes_received += size;
        self.last_activity = std.time.milliTimestamp();
    }

    pub fn recordKeepAliveSent(self: *SessionStats) void {
        self.keepalives_sent += 1;
    }

    pub fn recordKeepAliveReceived(self: *SessionStats) void {
        self.keepalives_received += 1;
    }

    pub fn recordError(self: *SessionStats) void {
        self.errors += 1;
    }

    pub fn recordReconnect(self: *SessionStats) void {
        self.reconnects += 1;
    }

    pub fn recordDroppedPacket(self: *SessionStats) void {
        self.dropped_packets += 1;
    }

    pub fn sessionDuration(self: *const SessionStats) i64 {
        return std.time.milliTimestamp() - self.session_start;
    }

    pub fn idleTime(self: *const SessionStats) i64 {
        return std.time.milliTimestamp() - self.last_activity;
    }

    pub fn throughputMbps(self: *const SessionStats) f64 {
        const duration_secs = @as(f64, @floatFromInt(self.sessionDuration())) / 1000.0;
        if (duration_secs == 0) return 0;

        const total_bits = @as(f64, @floatFromInt(self.bytes_sent + self.bytes_received)) * 8.0;
        return (total_bits / duration_secs) / 1_000_000.0; // Mbps
    }
};

// ============================================================================
// VPN Session
// ============================================================================

pub const VpnSession = struct {
    allocator: Allocator,
    config: SessionConfig,
    state: SessionState,

    /// Protocol handler
    protocol: ?*VpnProtocol,

    /// Packet adapter (TUN device)
    adapter: ?*adapter_mod.ZigPacketAdapter,

    /// Session info
    info: ?SessionInfo,

    /// Statistics
    stats: SessionStats,

    /// Threading
    packet_thread: ?Thread,
    keepalive_thread: ?Thread,
    running: std.atomic.Value(bool),

    /// Synchronization
    mutex: Thread.Mutex,

    pub fn init(allocator: Allocator, config: SessionConfig) !*VpnSession {
        try config.validate();

        const session = try allocator.create(VpnSession);
        errdefer allocator.destroy(session);

        session.* = .{
            .allocator = allocator,
            .config = config,
            .state = .disconnected,
            .protocol = null,
            .adapter = null,
            .info = null,
            .stats = SessionStats.init(),
            .packet_thread = null,
            .keepalive_thread = null,
            .running = std.atomic.Value(bool).init(false),
            .mutex = Thread.Mutex{},
        };

        return session;
    }

    pub fn deinit(self: *VpnSession) void {
        // Stop threads if running
        if (self.running.load(.acquire)) {
            self.stop();
        }

        // Clean up protocol
        if (self.protocol) |protocol| {
            protocol.deinit();
        }

        // Clean up adapter
        if (self.adapter) |adapter| {
            adapter.deinit();
        }

        // Clean up info
        if (self.info) |*info| {
            info.deinit();
        }

        self.allocator.destroy(self);
    }

    /// Start VPN session
    pub fn start(self: *VpnSession) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .disconnected) {
            return error.AlreadyConnected;
        }

        std.log.info("Starting VPN session to {s}:{d}", .{
            self.config.server_host,
            self.config.server_port,
        });

        self.state = .connecting;

        // Initialize protocol
        self.protocol = try VpnProtocol.init(
            self.allocator,
            self.config.server_host,
            self.config.server_port,
            self.config.hub_name,
            self.config.credentials,
        );
        errdefer {
            if (self.protocol) |p| p.deinit();
            self.protocol = null;
        }

        // Connect to server
        try self.protocol.?.connect();

        self.state = .authenticating;

        // Authenticate
        try self.protocol.?.authenticate();

        self.state = .establishing;

        // Initialize packet adapter
        const adapter_config = adapter_mod.Config{
            .device_name = self.config.tun_device_name,
            .recv_queue_size = 256,
            .send_queue_size = 256,
            .packet_pool_size = 512,
            .batch_size = 32,
        };

        self.adapter = try adapter_mod.ZigPacketAdapter.init(self.allocator, adapter_config);
        errdefer {
            if (self.adapter) |a| a.deinit();
            self.adapter = null;
        }

        std.log.info("TUN adapter initialized", .{});

        // Create session info
        const client_version = vpn.VpnVersion.init(5, 0, 9759);
        const server_version = vpn.VpnVersion.init(5, 0, 9759); // TODO: Get from protocol

        self.info = try SessionInfo.init(
            self.allocator,
            "session_placeholder",
            server_version,
            client_version,
        );

        // Start packet forwarding threads
        self.running.store(true, .release);

        self.packet_thread = try Thread.spawn(.{}, packetForwardingLoop, .{self});
        self.keepalive_thread = try Thread.spawn(.{}, keepAliveLoop, .{self});

        self.state = .connected;

        std.log.info("VPN session established", .{});
    }

    /// Stop VPN session
    pub fn stop(self: *VpnSession) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .disconnected) {
            return;
        }

        std.log.info("Stopping VPN session...", .{});

        self.state = .disconnecting;

        // Signal threads to stop
        self.running.store(false, .release);

        // Wait for threads to finish
        if (self.packet_thread) |thread| {
            thread.join();
            self.packet_thread = null;
        }

        if (self.keepalive_thread) |thread| {
            thread.join();
            self.keepalive_thread = null;
        }

        // Disconnect protocol
        if (self.protocol) |protocol| {
            protocol.disconnect() catch |err| {
                std.log.err("Error during disconnect: {}", .{err});
            };
        }

        self.state = .disconnected;

        std.log.info("VPN session stopped", .{});
    }

    /// Get current session statistics
    pub fn getStats(self: *VpnSession) SessionStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Get session info
    pub fn getInfo(self: *VpnSession) ?SessionInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.info;
    }

    /// Packet forwarding loop (runs in separate thread)
    fn packetForwardingLoop(self: *VpnSession) void {
        std.log.info("Packet forwarding thread started", .{});

        while (self.running.load(.acquire)) {
            self.forwardPackets() catch |err| {
                std.log.err("Error forwarding packets: {}", .{err});
                self.mutex.lock();
                self.stats.recordError();
                self.mutex.unlock();
                Thread.sleep(100 * std.time.ns_per_ms);
            };
        }

        std.log.info("Packet forwarding thread stopped", .{});
    }

    /// Forward packets between TUN and network
    fn forwardPackets(self: *VpnSession) !void {
        const adapter = self.adapter orelse return error.NoAdapter;
        const protocol = self.protocol orelse return error.NoProtocol;

        var packet_processed = false;

        // Try to read from TUN device and send to network
        if (adapter.getNextPacket()) |pkt_buf| {
            const tun_packet = pkt_buf.data[0..pkt_buf.len];

            // Send packet to network
            protocol.writePacket(tun_packet) catch |err| {
                std.log.err("Failed to send packet to network: {}", .{err});
                self.mutex.lock();
                self.stats.recordDroppedPacket();
                self.mutex.unlock();
            };

            // Update stats
            self.mutex.lock();
            self.stats.recordPacketSent(tun_packet.len);
            self.mutex.unlock();

            packet_processed = true;
        }

        // Try to read from network and write to TUN
        var network_buffer: [2048]u8 = undefined;
        const network_packet_len = protocol.readPacket(&network_buffer) catch |err| blk: {
            if (err != error.WouldBlock and err != error.NotAuthenticated) {
                std.log.warn("Network read error: {}", .{err});
            }
            break :blk null;
        };

        if (network_packet_len) |len| {
            const network_packet = network_buffer[0..len];

            // Write packet to TUN
            const success = adapter.putPacket(network_packet);
            if (!success) {
                std.log.warn("Failed to write packet to TUN (queue full?)", .{});
                self.mutex.lock();
                self.stats.recordDroppedPacket();
                self.mutex.unlock();
            }

            // Update stats
            self.mutex.lock();
            self.stats.recordPacketReceived(len);
            self.mutex.unlock();

            packet_processed = true;
        }

        // If no packets were processed, sleep briefly to avoid busy loop
        if (!packet_processed) {
            Thread.sleep(1 * std.time.ns_per_ms); // 1ms sleep
        }
    }

    /// Keep-alive loop (runs in separate thread)
    fn keepAliveLoop(self: *VpnSession) void {
        std.log.info("Keep-alive thread started", .{});

        const interval_ns = self.config.keepalive_interval_ms * std.time.ns_per_ms;

        while (self.running.load(.acquire)) {
            Thread.sleep(interval_ns);

            if (!self.running.load(.acquire)) break;

            self.sendKeepAlive() catch |err| {
                std.log.err("Error sending keep-alive: {}", .{err});
                self.mutex.lock();
                self.stats.recordError();
                self.mutex.unlock();
            };
        }

        std.log.info("Keep-alive thread stopped", .{});
    }

    /// Send keep-alive packet
    fn sendKeepAlive(self: *VpnSession) !void {
        const protocol = self.protocol orelse return error.NoProtocol;

        try protocol.sendKeepAlive();

        self.mutex.lock();
        self.stats.recordKeepAliveSent();
        self.mutex.unlock();

        std.log.debug("Keep-alive sent", .{});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SessionConfig validation" {
    const allocator = std.testing.allocator;

    // Valid config
    const valid_config = SessionConfig{
        .server_host = "test.server.com",
        .server_port = 443,
        .hub_name = "TEST_HUB",
        .credentials = AuthCredentials.withPassword("user", "pass"),
    };
    try valid_config.validate();

    // Invalid config - empty server host
    const invalid_config = SessionConfig{
        .server_host = "",
        .server_port = 443,
        .hub_name = "TEST_HUB",
        .credentials = AuthCredentials.withPassword("user", "pass"),
    };
    const result = invalid_config.validate();
    try std.testing.expectError(error.InvalidServerHost, result);

    _ = allocator;
}

test "SessionStats tracking" {
    var stats = SessionStats.init();

    stats.recordPacketSent(100);
    stats.recordPacketReceived(200);
    stats.recordKeepAliveSent();

    try std.testing.expectEqual(@as(u64, 1), stats.packets_sent);
    try std.testing.expectEqual(@as(u64, 1), stats.packets_received);
    try std.testing.expectEqual(@as(u64, 100), stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 200), stats.bytes_received);
    try std.testing.expectEqual(@as(u64, 1), stats.keepalives_sent);
}

test "VpnSession initialization" {
    const allocator = std.testing.allocator;

    const config = SessionConfig{
        .server_host = "test.server.com",
        .server_port = 443,
        .hub_name = "TEST_HUB",
        .credentials = AuthCredentials.withPassword("user", "pass"),
    };

    var session = try VpnSession.init(allocator, config);
    defer session.deinit();

    try std.testing.expectEqual(SessionState.disconnected, session.state);
    try std.testing.expect(session.protocol == null);
    try std.testing.expect(session.adapter == null);
}
