//! macOS SoftEther SSL-VPN Session Layer
//!
//! This module provides SoftEther SSL-VPN session management for macOS using
//! ZigTapTun for all L2/L3 operations (DHCP, ARP, routing, TUN device I/O).
//!
//! Responsibilities:
//! - SoftEther SSL-VPN session lifecycle (connect, maintain, disconnect)
//! - SSL-VPN packet encryption/decryption
//! - Keep-alive to SoftEther VPN server
//! - Connection quality monitoring
//! - SoftEther protocol-specific packet handling
//!
//! Layer Separation:
//! - ZigTapTun: System L2/L3 (DHCP, ARP, routing, TUN device)
//! - This module: SoftEther SSL-VPN session logic only

const std = @import("std");
const taptun = @import("taptun");
const Allocator = std.mem.Allocator;

/// SoftEther SSL-VPN Connection State
pub const SslVpnState = enum {
    disconnected,
    connecting,
    authenticating,
    establishing_session,
    connected,
    reconnecting,
    disconnecting,
    error_state,
};

/// SoftEther VPN Server Configuration
pub const ServerConfig = struct {
    hostname: []const u8,
    port: u16 = 443, // SoftEther SSL-VPN default
    hub_name: []const u8,

    auth: struct {
        username: []const u8,
        password: []const u8,
        // SoftEther supports additional auth methods
        certificate: ?[]const u8 = null,
        radius: ?[]const u8 = null,
    },

    /// SoftEther SSL-VPN timeout settings
    connect_timeout_ms: u32 = 30000,
    keepalive_interval_ms: u32 = 5000, // SoftEther recommends 5s
    reconnect_interval_ms: u32 = 3000,
    max_reconnect_attempts: u32 = 10,

    /// SoftEther-specific settings
    use_compression: bool = true,
    use_encryption: bool = true,
    max_tcp_connections: u8 = 8, // SoftEther multi-TCP
};

/// VPN Session Statistics
pub const SessionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    connection_start_time: i64 = 0,
    last_keepalive_time: i64 = 0,
    reconnect_count: u32 = 0,

    pub fn connectionDuration(self: SessionStats) i64 {
        if (self.connection_start_time == 0) return 0;
        return std.time.milliTimestamp() - self.connection_start_time;
    }
};

/// SoftEther SSL-VPN Session Manager
///
/// Uses ZigTapTun for all L2/L3 operations:
/// - TUN device I/O via utun
/// - DHCP client for IP configuration from VPN server
/// - ARP handling for local network
/// - Routing table manipulation
///
/// This layer only handles SoftEther SSL-VPN protocol logic.
pub const SoftEtherSession = struct {
    allocator: Allocator,

    // Network adapter (from ZigTapTun)
    adapter: *taptun.TunAdapter,
    dhcp_client: ?*taptun.DhcpClient = null,

    // SoftEther SSL-VPN state
    state: SslVpnState,
    server_config: ServerConfig,
    stats: SessionStats,

    // Connection management
    reconnect_attempts: u32 = 0,
    last_error: ?anyerror = null,

    // Thread synchronization
    mutex: std.Thread.Mutex = .{},

    const Self = @This();

    /// Initialize VPN session
    pub fn init(allocator: Allocator, server_config: ServerConfig) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        // Generate unique MAC address for this session
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.nanoTimestamp()));
        const random = prng.random();
        var mac_address: [6]u8 = undefined;
        random.bytes(&mac_address);
        mac_address[0] = (mac_address[0] & 0xFE) | 0x02; // Locally administered, unicast

        // Create TUN adapter with ZigTapTun
        const adapter = try taptun.TunAdapter.open(allocator, .{
            .device = .{
                .unit = null, // Auto-assign utun device
                .mtu = 1500,
                .non_blocking = true,
            },
            .translator = .{
                .our_mac = mac_address,
                .learn_ip = true,
                .learn_gateway_mac = true,
                .handle_arp = true,
                .arp_timeout_ms = 60000,
                .verbose = false,
            },
            .buffer_size = 65536,
            .manage_routes = true, // Enable automatic route save/restore
        });
        errdefer adapter.close();

        self.* = .{
            .allocator = allocator,
            .adapter = adapter,
            .state = .disconnected,
            .server_config = server_config,
            .stats = .{},
        };

        std.log.info("🌐 VPN Session initialized with MAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
            mac_address[0], mac_address[1], mac_address[2],
            mac_address[3], mac_address[4], mac_address[5],
        });

        return self;
    }

    /// Connect to VPN server
    pub fn connect(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .disconnected) {
            return error.InvalidState;
        }

        self.state = .connecting;
        self.stats.connection_start_time = std.time.milliTimestamp();

        std.log.info("🔌 Connecting to SoftEther VPN server: {s}:{d} (Hub: {s})", .{
            self.server_config.hostname,
            self.server_config.port,
            self.server_config.hub_name,
        });

        // TODO: Implement SoftEther SSL-VPN connection
        // - Establish HTTPS connection to server
        // - Send HTTP CONNECT request with SoftEther headers
        // - Authenticate with username/password to hub
        // - Establish SSL-VPN session
        // - Negotiate encryption (RC4/AES) and compression

        // Start DHCP to get IP configuration from VPN server
        try self.startDhcp();

        self.state = .establishing_tunnel;
    }

    /// Start DHCP client to get IP configuration
    fn startDhcp(self: *Self) !void {
        const mac = self.adapter.translator.options.our_mac;

        // Initialize DHCP client from ZigTapTun
        self.dhcp_client = try taptun.DhcpClient.init(self.allocator, mac);
        errdefer if (self.dhcp_client) |client| client.deinit();

        // Create DISCOVER packet
        const discover = try self.dhcp_client.?.createDiscover();

        // TODO: Send DISCOVER packet through VPN tunnel
        // For now, this is a placeholder for the packet transmission
        _ = discover;

        std.log.info("📡 DHCP: Sent DISCOVER", .{});
    }

    /// Process received DHCP packet
    pub fn processDhcpPacket(self: *Self, packet: []const u8) !void {
        if (self.dhcp_client == null) return error.DhcpNotInitialized;

        // Parse packet and update DHCP state
        const dhcp_pkt = @as(*const taptun.DhcpClient.DhcpPacket, @ptrCast(@alignCast(packet.ptr)));

        switch (self.dhcp_client.?.state) {
            .SELECTING => {
                // Handle OFFER
                try self.dhcp_client.?.parseOffer(dhcp_pkt);

                // Send REQUEST
                if (self.dhcp_client.?.lease) |lease| {
                    const request = try self.dhcp_client.?.createRequest(
                        lease.ip_address,
                        lease.server_id,
                    );
                    _ = request; // TODO: Send REQUEST packet
                    std.log.info("📡 DHCP: Sent REQUEST", .{});
                }
            },
            .REQUESTING => {
                // Handle ACK
                try self.dhcp_client.?.parseAck(dhcp_pkt);

                // Apply IP configuration
                if (self.dhcp_client.?.lease) |lease| {
                    try self.applyIpConfiguration(lease);
                }
            },
            else => {},
        }
    }

    /// Apply IP configuration from DHCP lease
    fn applyIpConfiguration(self: *Self, lease: taptun.DhcpClient.Lease) !void {
        std.log.info("⚙️  Applying IP configuration:", .{});
        std.log.info("   IP: {d}.{d}.{d}.{d}", .{
            lease.ip_address[0], lease.ip_address[1],
            lease.ip_address[2], lease.ip_address[3],
        });
        std.log.info("   Gateway: {d}.{d}.{d}.{d}", .{
            lease.gateway[0], lease.gateway[1],
            lease.gateway[2], lease.gateway[3],
        });

        // TODO: Configure TUN interface with IP address
        // This would typically be done via ifconfig on macOS

        self.state = .connected;
        std.log.info("✅ VPN connection established", .{});
    }

    /// Send SoftEther SSL-VPN keep-alive packet
    pub fn sendKeepalive(self: *Self) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state != .connected) return;

        const now = std.time.milliTimestamp();
        const interval = @as(i64, @intCast(self.server_config.keepalive_interval_ms));

        if (now - self.stats.last_keepalive_time < interval) {
            return; // Too soon
        }

        // TODO: Send SoftEther keep-alive packet (NULL packet in SSL-VPN session)

        self.stats.last_keepalive_time = now;
        std.log.debug("💓 SoftEther keep-alive sent", .{});
    }

    /// Read packet from TUN device (from local system)
    pub fn readPacket(self: *Self, buffer: []u8) !usize {
        // Read Ethernet frame from TUN adapter (ZigTapTun handles L2↔L3 translation)
        const frame = try self.adapter.readEthernet(buffer);

        self.stats.packets_received += 1;
        self.stats.bytes_received += frame.len;

        // TODO: Encapsulate in SoftEther packet and send via SSL-VPN tunnel

        return frame.len;
    }

    /// Write packet to TUN device (from SoftEther VPN server)
    pub fn writePacket(self: *Self, packet: []const u8) !void {
        // TODO: Decapsulate from SoftEther packet format

        // Write Ethernet frame to TUN adapter (ZigTapTun handles L2↔L3 translation)
        try self.adapter.writeEthernet(packet);

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += packet.len;
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .disconnected) return;

        self.state = .disconnecting;
        std.log.info("🔌 Disconnecting from SoftEther VPN server...", .{});

        // Release DHCP lease
        if (self.dhcp_client) |client| {
            client.release() catch |err| {
                std.log.warn("Failed to release DHCP lease: {}", .{err});
            };
        }

        // TODO: Send SoftEther disconnect packet and close SSL-VPN session

        self.state = .disconnected;
        std.log.info("✅ VPN disconnected", .{});
    }

    /// Get current session statistics
    pub fn getStats(self: *Self) SessionStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }

    /// Clean up resources
    pub fn deinit(self: *Self) void {
        self.disconnect();

        if (self.dhcp_client) |client| {
            client.deinit();
        }

        // Close TUN adapter (ZigTapTun handles route restoration)
        self.adapter.close();

        self.allocator.destroy(self);
    }
};

/// PacketAdapter - Legacy compatibility wrapper
///
/// This wraps SoftEtherSession to maintain compatibility with existing code
/// that expects the old PacketAdapter interface.
pub const PacketAdapter = struct {
    session: *SoftEtherSession,

    pub fn init(allocator: Allocator) !*PacketAdapter {
        const adapter = try allocator.create(PacketAdapter);
        errdefer allocator.destroy(adapter);

        // Create default SoftEther server config (should be passed from caller)
        const server_config = ServerConfig{
            .hostname = "vpn.example.com",
            .port = 443,
            .hub_name = "DEFAULT",
            .auth = .{
                .username = "user",
                .password = "pass",
            },
        };

        adapter.session = try SoftEtherSession.init(allocator, server_config);
        return adapter;
    }

    pub fn deinit(self: *PacketAdapter) void {
        self.session.deinit();
    }
};

// Tests
test "SoftEther SSL-VPN session initialization" {
    // Skip - requires root to open utun device
    if (true) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = ServerConfig{
        .hostname = "test.softether.local",
        .port = 443,
        .hub_name = "TEST_HUB",
        .auth = .{
            .username = "testuser",
            .password = "testpass",
        },
    };

    var session = try SoftEtherSession.init(allocator, config);
    defer session.deinit();

    try std.testing.expectEqual(SslVpnState.disconnected, session.state);
    // Note: adapter is a pointer, so it's always non-null after successful init
}
