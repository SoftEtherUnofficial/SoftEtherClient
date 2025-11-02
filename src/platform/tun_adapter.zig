//! High-level TUN adapter combining device I/O with L2↔L3 translation
//!
//! This provides a complete TUN device abstraction with automatic
//! Ethernet ↔ IP packet translation, ARP handling, and IP/MAC learning.
//!
//! NOTE: This is a convenience wrapper that combines:
//! - Platform TUN device (from TapTun)
//! - Protocol translation (from parent protocol layer)
//!
//! Usage:
//! ```zig
//! var adapter = try TunAdapter.open(allocator, .{}, .{
//!     .our_mac = [_]u8{0x00, 0xAC, 0x00, 0x00, 0x00, 0x01},
//! });
//! defer adapter.close();
//!
//! // Read Ethernet frame (automatic conversion from IP)
//! var buffer: [2048]u8 = undefined;
//! const eth_frame = try adapter.readEthernet(&buffer);
//!
//! // Write Ethernet frame (automatic conversion to IP)
//! try adapter.writeEthernet(eth_frame);
//! ```

const std = @import("std");
const builtin = @import("builtin");
const taptun = @import("taptun");
const protocol = @import("protocol");

// RouteManager from TapTun (platform concern - OS routing tables)
const RouteManager = taptun.RouteManager;

pub const TunAdapter = struct {
    allocator: std.mem.Allocator,
    device: taptun.TunDevice,
    translator: protocol.L2L3Translator,
    route_manager: ?*RouteManager, // Optional route management
    read_buffer: []u8, // Internal buffer for AF header handling
    write_buffer: []u8, // Internal buffer for AF header construction

    const Self = @This();

    /// Options for TunAdapter creation
    pub const Options = struct {
        device: taptun.DeviceOptions = .{},
        translator: protocol.TranslatorOptions,
        buffer_size: usize = 65536, // Internal buffer size for packet handling
        manage_routes: bool = false, // Enable automatic route management (save/restore)
    };

    /// Open TUN device with L2↔L3 translation
    pub fn open(allocator: std.mem.Allocator, options: Options) !*Self {
        // Open platform-specific TUN device
        var device = try taptun.TunDevice.open(allocator, options.device.unit);
        errdefer device.close();

        // Set non-blocking if requested
        if (options.device.non_blocking) {
            try device.setNonBlocking(true);
        }

        // Initialize L2↔L3 translator (from protocol layer)
        var translator = try protocol.L2L3Translator.init(allocator, options.translator);
        errdefer translator.deinit();

        // Allocate internal buffers
        const read_buffer = try allocator.alloc(u8, options.buffer_size);
        errdefer allocator.free(read_buffer);

        const write_buffer = try allocator.alloc(u8, options.buffer_size);
        errdefer allocator.free(write_buffer);

        // Initialize route manager if enabled (macOS/Linux only)
        var route_manager: ?*RouteManager = null;
        if (options.manage_routes and (builtin.os.tag == .macos or builtin.os.tag == .linux)) {
            route_manager = try RouteManager.init(allocator);
            errdefer if (route_manager) |rm| rm.deinit();

            // Save original gateway immediately
            try route_manager.?.getDefaultGateway();
        }

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .device = device,
            .translator = translator,
            .route_manager = route_manager,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
        };

        return self;
    }

    /// Close device and free resources
    pub fn close(self: *Self) void {
        std.log.info("[TUN CLOSE] Starting TUN adapter cleanup...", .{});

        // ✅ CRITICAL: Restore routes BEFORE closing device!
        if (self.route_manager) |rm| {
            std.log.info("[TUN CLOSE] Restoring routes...", .{});
            rm.deinit();
            std.log.info("[TUN CLOSE] ✅ Routes restored", .{});
        }

        std.log.info("[TUN CLOSE] Closing TUN device...", .{});
        self.device.close();
        std.log.info("[TUN CLOSE] ✅ TUN device closed", .{});

        std.log.info("[TUN CLOSE] Cleaning up translator...", .{});
        self.translator.deinit();
        std.log.info("[TUN CLOSE] ✅ Translator cleaned up", .{});

        self.allocator.free(self.read_buffer);
        self.allocator.free(self.write_buffer);
        self.allocator.destroy(self);
        std.log.info("[TUN CLOSE] ✅ TUN adapter cleanup complete", .{});
    }

    /// Read Ethernet frame from TUN device
    /// Returns Ethernet frame in provided buffer (automatically translated from IP packet)
    /// Buffer must be large enough for Ethernet frame (IP packet size + 14 bytes)
    pub fn readEthernet(self: *Self, buffer: []u8) ![]u8 {
        // Read IP packet from device (handles AF header stripping internally)
        const ip_packet_with_header = try self.device.read(self.read_buffer);

        // Strip AF header (4 bytes on macOS/BSD)
        const ip_packet = try taptun.platform.stripProtocolHeader(ip_packet_with_header);

        // Translate IP → Ethernet
        const eth_frame = try self.translator.ipToEthernet(ip_packet);
        defer self.allocator.free(eth_frame);

        if (eth_frame.len > buffer.len) {
            return error.BufferTooSmall;
        }

        @memcpy(buffer[0..eth_frame.len], eth_frame);
        return buffer[0..eth_frame.len];
    }

    /// Write Ethernet frame to TUN device
    /// Automatically translates Ethernet frame to IP packet and handles AF header
    pub fn writeEthernet(self: *Self, eth_frame: []const u8) !void {
        // Translate Ethernet → IP (may return null for ARP, etc.)
        const maybe_ip = try self.translator.ethernetToIp(eth_frame);

        if (maybe_ip) |ip_packet| {
            defer self.allocator.free(ip_packet);

            // Add AF header for macOS/BSD
            const packet_with_header = try taptun.platform.addProtocolHeader(
                self.allocator,
                ip_packet,
            );
            defer self.allocator.free(packet_with_header);

            // Write to device
            try self.device.write(packet_with_header);
        }
        // If null, packet was handled internally (e.g., ARP reply sent)
    }

    /// Read raw IP packet (no L2↔L3 translation)
    /// Returns IP packet in provided buffer (AF header already stripped)
    pub fn readIp(self: *Self, buffer: []u8) ![]u8 {
        const ip_packet_with_header = try self.device.read(self.read_buffer);
        const ip_packet = try taptun.platform.stripProtocolHeader(ip_packet_with_header);

        if (ip_packet.len > buffer.len) {
            return error.BufferTooSmall;
        }

        @memcpy(buffer[0..ip_packet.len], ip_packet);
        return buffer[0..ip_packet.len];
    }

    /// Write raw IP packet (no L2↔L3 translation)
    /// Automatically adds AF header for platform
    pub fn writeIp(self: *Self, ip_packet: []const u8) !void {
        const packet_with_header = try taptun.platform.addProtocolHeader(
            self.allocator,
            ip_packet,
        );
        defer self.allocator.free(packet_with_header);

        try self.device.write(packet_with_header);
    }

    /// Get device name (e.g., "utun4")
    pub fn getDeviceName(self: *Self) []const u8 {
        return self.device.getName();
    }

    /// Get device file descriptor (Unix) or handle (Windows)
    pub fn getFd(self: *Self) i32 {
        return switch (builtin.os.tag) {
            .macos, .ios, .linux => self.device.fd,
            .windows => @intCast(@intFromPtr(self.device.handle)),
            else => -1,
        };
    }

    /// Get learned IP address (auto-detected from outgoing packets)
    pub fn getLearnedIp(self: *Self) ?u32 {
        return self.translator.our_ip;
    }

    /// Get learned gateway MAC address (from ARP replies)
    pub fn getGatewayMac(self: *Self) ?[6]u8 {
        return self.translator.gateway_mac;
    }

    /// Get translator statistics
    pub fn getStats(self: *Self) TranslatorStats {
        return .{
            .packets_l3_to_l2 = self.translator.packets_translated_l3_to_l2,
            .packets_l2_to_l3 = self.translator.packets_translated_l2_to_l3,
            .arp_requests_handled = self.translator.arp_requests_handled,
            .arp_replies_learned = self.translator.arp_replies_learned,
        };
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: *Self, enabled: bool) !void {
        try self.device.setNonBlocking(enabled);
    }

    /// Configure VPN routing (replace default gateway)
    /// Requires manage_routes=true in Options
    pub fn configureVpnRouting(self: *Self, vpn_gateway: [4]u8, vpn_server: ?[4]u8) !void {
        inline for (.{RouteManager}) |RM| {
            if (RM == void) {
                return error.PlatformNotSupported;
            }
        }

        if (self.route_manager) |rm| {
            // Add host route for VPN server through original gateway (if provided)
            if (vpn_server) |server| {
                if (rm.local_gateway) |orig_gw| {
                    try rm.addHostRoute(server, orig_gw);
                }
            }

            // Replace default gateway with VPN gateway
            try rm.replaceDefaultGateway(vpn_gateway);
        } else {
            return error.RouteManagementDisabled;
        }
    }

    /// Configure VPN network route (for point-to-point TUN interfaces)
    /// This adds an explicit route for the VPN subnet through the gateway
    /// Critical for macOS TUN interfaces where routing isn't automatic
    pub fn configureVpnNetworkRoute(self: *Self, network: [4]u8, netmask: [4]u8, gateway: [4]u8) !void {
        inline for (.{RouteManager}) |RM| {
            if (RM == void) {
                return error.PlatformNotSupported;
            }
        }

        if (self.route_manager) |rm| {
            try rm.addNetworkRoute(network, netmask, gateway);
        } else {
            return error.RouteManagementDisabled;
        }
    }

    pub const TranslatorStats = struct {
        packets_l3_to_l2: u64,
        packets_l2_to_l3: u64,
        arp_requests_handled: u64,
        arp_replies_learned: u64,
    };
};

test "TunAdapter basic operations" {
    // This test requires root privileges
    if (std.posix.getenv("CI") != null or std.posix.getenv("SKIP_INTEGRATION_TESTS") != null) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var adapter = TunAdapter.open(allocator, .{
        .device = .{ .unit = null, .non_blocking = true },
        .translator = .{
            .our_mac = [_]u8{ 0x00, 0xAC, 0x00, 0x00, 0x00, 0x01 },
            .learn_ip = true,
            .learn_gateway_mac = true,
            .handle_arp = true,
            .verbose = false,
        },
    }) catch |err| {
        std.debug.print("Skipping test (requires root): {}\n", .{err});
        return error.SkipZigTest;
    };
    defer adapter.close();

    std.debug.print("Opened TUN adapter: {s}\n", .{adapter.getDeviceName()});
    try std.testing.expect(adapter.getFd() >= 0);
}
