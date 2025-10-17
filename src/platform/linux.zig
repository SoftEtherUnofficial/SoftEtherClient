//! Linux TUN/TAP Device Implementation
//! Replaces: src/bridge/platform/packet_adapter_linux.c (~2,000 lines C → ~500 lines Zig)
//!
//! Features:
//! - /dev/net/tun device handling
//! - TUN and TAP mode support
//! - Multi-queue support (for high-performance)
//! - Persistent device creation
//! - IP configuration via netlink or ip command
//! - Route manipulation
//!
//! Phase 4: Platform Layer Migration - Linux Support

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const log = std.log.scoped(.linux_tun);

/// Linux TUN/TAP device flags (from linux/if_tun.h)
pub const IFF_TUN = 0x0001;
pub const IFF_TAP = 0x0002;
pub const IFF_NO_PI = 0x1000; // Don't include packet info
pub const IFF_MULTI_QUEUE = 0x0100; // Multi-queue support
pub const IFF_VNET_HDR = 0x4000; // Virtio net header

/// ioctl request codes for TUN/TAP (from linux/if_tun.h)
const TUNSETIFF = 0x400454ca;
const TUNSETPERSIST = 0x400454cb;
const TUNSETOWNER = 0x400454cc;
const TUNSETGROUP = 0x400454ce;
const TUNGETIFF = 0x800454d2;
const TUNSETNOCSUM = 0x400454c8;
const TUNSETDEBUG = 0x400454c9;
const TUNSETLINK = 0x400454cd;
const TUNGETFEATURES = 0x800454cf;

/// ifreq structure for ioctl (from linux/if.h)
pub const ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_flags: c_short,
    _padding: [22]u8 = undefined,
};

/// Device mode
pub const DeviceMode = enum {
    tun, // Layer 3 (IP packets)
    tap, // Layer 2 (Ethernet frames)
};

/// Linux TUN/TAP device configuration
pub const LinuxTunConfig = struct {
    /// Device name (e.g., "tun0", "tap0")
    /// If null, kernel assigns a name
    name: ?[]const u8 = null,

    /// Device mode (TUN or TAP)
    mode: DeviceMode = .tun,

    /// Enable multi-queue for better performance
    multi_queue: bool = false,

    /// Make device persistent (survives process exit)
    persistent: bool = false,

    /// Set device owner (UID)
    owner: ?u32 = null,

    /// Set device group (GID)
    group: ?u32 = null,

    /// Disable packet info header
    no_packet_info: bool = true,

    /// MTU size
    mtu: u32 = 1500,
};

/// Linux TUN/TAP device
pub const LinuxTunDevice = struct {
    fd: posix.fd_t,
    name: [16]u8,
    mode: DeviceMode,
    allocator: std.mem.Allocator,
    config: LinuxTunConfig,

    const Self = @This();

    /// Open /dev/net/tun and create TUN/TAP device
    pub fn open(allocator: std.mem.Allocator, config: LinuxTunConfig) !Self {
        // Open /dev/net/tun
        const fd = try posix.open("/dev/net/tun", .{
            .ACCMODE = .RDWR,
            .NONBLOCK = false, // Blocking mode for dedicated reader thread
        }, 0);
        errdefer posix.close(fd);

        // Prepare ifreq structure
        var ifr: ifreq = .{
            .ifr_name = [_]u8{0} ** 16,
            .ifr_flags = 0,
        };

        // Set flags based on configuration
        ifr.ifr_flags = switch (config.mode) {
            .tun => IFF_TUN,
            .tap => IFF_TAP,
        };

        if (config.no_packet_info) {
            ifr.ifr_flags |= IFF_NO_PI;
        }

        if (config.multi_queue) {
            ifr.ifr_flags |= IFF_MULTI_QUEUE;
        }

        // Set device name if provided
        if (config.name) |name| {
            if (name.len >= ifr.ifr_name.len) return error.DeviceNameTooLong;
            @memcpy(ifr.ifr_name[0..name.len], name);
        }

        // Create TUN/TAP device via ioctl
        const result = std.c.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
        if (result < 0) {
            const err = std.c._errno().*;
            posix.close(fd);
            return switch (err) {
                .PERM => error.PermissionDenied,
                .BUSY => error.DeviceBusy,
                .INVAL => error.InvalidArgument,
                .NODEV => error.NoDevice,
                else => error.IoctlFailed,
            };
        }

        log.info("Created {s} device: {s}", .{ @tagName(config.mode), std.mem.sliceTo(&ifr.ifr_name, 0) });

        // Set persistence if requested
        if (config.persistent) {
            const persist: c_int = 1;
            _ = std.c.ioctl(fd, TUNSETPERSIST, persist);
        }

        // Set owner if provided
        if (config.owner) |uid| {
            _ = std.c.ioctl(fd, TUNSETOWNER, uid);
        }

        // Set group if provided
        if (config.group) |gid| {
            _ = std.c.ioctl(fd, TUNSETGROUP, gid);
        }

        return Self{
            .fd = fd,
            .name = ifr.ifr_name,
            .mode = config.mode,
            .allocator = allocator,
            .config = config,
        };
    }

    /// Get device name as string
    pub fn getName(self: *const Self) []const u8 {
        return std.mem.sliceTo(&self.name, 0);
    }

    /// Read packet from TUN device
    /// For TUN mode: Returns IP packet
    /// For TAP mode: Returns Ethernet frame
    pub fn readPacket(self: *Self, buffer: []u8) ![]u8 {
        const n = try posix.read(self.fd, buffer);
        if (n == 0) return error.EndOfStream;
        return buffer[0..n];
    }

    /// Write packet to TUN device
    /// For TUN mode: Expects IP packet
    /// For TAP mode: Expects Ethernet frame
    pub fn writePacket(self: *Self, packet: []const u8) !void {
        const n = try posix.write(self.fd, packet);
        if (n != packet.len) return error.PartialWrite;
    }

    /// Configure IP address using ip command
    /// Example: 192.168.10.1/24
    pub fn configureIp(self: *Self, ip_with_prefix: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const ally = arena.allocator();

        const dev_name = self.getName();

        // Build command: ip addr add <ip>/<prefix> dev <device>
        const cmd = try std.fmt.allocPrint(ally, "ip addr add {s} dev {s}", .{ ip_with_prefix, dev_name });

        const result = try std.process.Child.run(.{
            .allocator = ally,
            .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
        });

        if (result.term.Exited != 0) {
            log.err("Failed to configure IP: {s}", .{result.stderr});
            return error.IpConfigFailed;
        }

        log.info("Configured IP {s} on {s}", .{ ip_with_prefix, dev_name });
    }

    /// Bring interface up
    pub fn bringUp(self: *Self) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const ally = arena.allocator();

        const dev_name = self.getName();
        const cmd = try std.fmt.allocPrint(ally, "ip link set {s} up", .{dev_name});

        const result = try std.process.Child.run(.{
            .allocator = ally,
            .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
        });

        if (result.term.Exited != 0) {
            log.err("Failed to bring interface up: {s}", .{result.stderr});
            return error.InterfaceUpFailed;
        }

        log.info("Brought {s} up", .{dev_name});
    }

    /// Bring interface down
    pub fn bringDown(self: *Self) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const ally = arena.allocator();

        const dev_name = self.getName();
        const cmd = try std.fmt.allocPrint(ally, "ip link set {s} down", .{dev_name});

        const result = try std.process.Child.run(.{
            .allocator = ally,
            .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
        });

        if (result.term.Exited != 0) {
            log.err("Failed to bring interface down: {s}", .{result.stderr});
            return error.InterfaceDownFailed;
        }

        log.info("Brought {s} down", .{dev_name});
    }

    /// Set MTU
    pub fn setMtu(self: *Self, mtu: u32) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const ally = arena.allocator();

        const dev_name = self.getName();
        const cmd = try std.fmt.allocPrint(ally, "ip link set {s} mtu {d}", .{ dev_name, mtu });

        const result = try std.process.Child.run(.{
            .allocator = ally,
            .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
        });

        if (result.term.Exited != 0) {
            log.err("Failed to set MTU: {s}", .{result.stderr});
            return error.MtuSetFailed;
        }

        log.info("Set MTU to {d} on {s}", .{ mtu, dev_name });
    }

    /// Add default route via this interface
    pub fn addDefaultRoute(self: *Self, gateway: []const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const ally = arena.allocator();

        const dev_name = self.getName();
        const cmd = try std.fmt.allocPrint(ally, "ip route add default via {s} dev {s}", .{ gateway, dev_name });

        const result = try std.process.Child.run(.{
            .allocator = ally,
            .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
        });

        if (result.term.Exited != 0) {
            log.warn("Failed to add default route (may already exist): {s}", .{result.stderr});
            // Don't error - route might already exist
        } else {
            log.info("Added default route via {s} dev {s}", .{ gateway, dev_name });
        }
    }

    /// Delete default route
    pub fn deleteDefaultRoute(self: *Self) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const ally = arena.allocator();

        const dev_name = self.getName();
        const cmd = try std.fmt.allocPrint(ally, "ip route del default dev {s}", .{dev_name});

        const result = try std.process.Child.run(.{
            .allocator = ally,
            .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
        });

        if (result.term.Exited != 0) {
            log.warn("Failed to delete default route: {s}", .{result.stderr});
        } else {
            log.info("Deleted default route dev {s}", .{dev_name});
        }
    }

    /// Add a specific route
    pub fn addRoute(self: *Self, destination: []const u8, gateway: ?[]const u8) !void {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const ally = arena.allocator();

        const dev_name = self.getName();
        const cmd = if (gateway) |gw|
            try std.fmt.allocPrint(ally, "ip route add {s} via {s} dev {s}", .{ destination, gw, dev_name })
        else
            try std.fmt.allocPrint(ally, "ip route add {s} dev {s}", .{ destination, dev_name });

        const result = try std.process.Child.run(.{
            .allocator = ally,
            .argv = &[_][]const u8{ "/bin/sh", "-c", cmd },
        });

        if (result.term.Exited != 0) {
            log.warn("Failed to add route to {s}: {s}", .{ destination, result.stderr });
        } else {
            log.info("Added route to {s} dev {s}", .{ destination, dev_name });
        }
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: *Self, enabled: bool) !void {
        const flags = try posix.fcntl(self.fd, posix.F.GETFL, 0);
        const new_flags = if (enabled)
            flags | @as(u32, posix.O.NONBLOCK)
        else
            flags & ~@as(u32, posix.O.NONBLOCK);
        _ = try posix.fcntl(self.fd, posix.F.SETFL, new_flags);
    }

    /// Close device
    pub fn close(self: *Self) void {
        posix.close(self.fd);
        log.info("Closed {s} device: {s}", .{ @tagName(self.mode), self.getName() });
    }

    /// Deinitialize (alias for close for consistency)
    pub fn deinit(self: *Self) void {
        self.close();
    }
};

/// Helper function to parse IP and netmask
pub const IpConfig = struct {
    ip: [4]u8,
    prefix_len: u8,

    /// Parse IP address with CIDR notation (e.g., "192.168.1.1/24")
    pub fn parse(ip_with_prefix: []const u8) !IpConfig {
        var parts = std.mem.splitScalar(u8, ip_with_prefix, '/');
        const ip_str = parts.next() orelse return error.InvalidFormat;
        const prefix_str = parts.next() orelse return error.InvalidFormat;

        // Parse IP
        var ip: [4]u8 = undefined;
        var octets = std.mem.splitScalar(u8, ip_str, '.');
        for (0..4) |i| {
            const octet_str = octets.next() orelse return error.InvalidIpFormat;
            ip[i] = try std.fmt.parseInt(u8, octet_str, 10);
        }

        // Parse prefix length
        const prefix_len = try std.fmt.parseInt(u8, prefix_str, 10);
        if (prefix_len > 32) return error.InvalidPrefixLength;

        return IpConfig{
            .ip = ip,
            .prefix_len = prefix_len,
        };
    }

    /// Calculate netmask from prefix length
    pub fn netmask(self: IpConfig) [4]u8 {
        const mask: u32 = if (self.prefix_len == 0)
            0
        else
            @as(u32, 0xFFFFFFFF) << @intCast(32 - self.prefix_len);

        return [4]u8{
            @intCast((mask >> 24) & 0xFF),
            @intCast((mask >> 16) & 0xFF),
            @intCast((mask >> 8) & 0xFF),
            @intCast(mask & 0xFF),
        };
    }

    /// Format IP as string
    pub fn format(
        self: IpConfig,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{d}.{d}.{d}.{d}/{d}", .{
            self.ip[0],
            self.ip[1],
            self.ip[2],
            self.ip[3],
            self.prefix_len,
        });
    }
};

// ============================================================================
// TESTS
// ============================================================================

test "Linux TUN device creation requires root" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = LinuxTunConfig{
        .name = "zig_tun_test",
        .mode = .tun,
        .no_packet_info = true,
    };

    var device = LinuxTunDevice.open(allocator, config) catch |err| {
        if (err == error.PermissionDenied) {
            std.debug.print("Skipping test: requires root privileges\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    try std.testing.expect(device.fd >= 0);
    try std.testing.expectEqualStrings("zig_tun_test", device.getName());
}

test "IpConfig parsing" {
    const config = try IpConfig.parse("192.168.1.100/24");

    try std.testing.expectEqual([4]u8{ 192, 168, 1, 100 }, config.ip);
    try std.testing.expectEqual(@as(u8, 24), config.prefix_len);

    const mask = config.netmask();
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 0 }, mask);
}

test "IpConfig formatting" {
    const config = IpConfig{
        .ip = [4]u8{ 10, 0, 0, 1 },
        .prefix_len = 8,
    };

    var buf: [32]u8 = undefined;
    const result = try std.fmt.bufPrint(&buf, "{}", .{config});
    try std.testing.expectEqualStrings("10.0.0.1/8", result);
}

test "Device name extraction" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // This test doesn't actually open a device, just tests the name extraction
    var device = LinuxTunDevice{
        .fd = -1,
        .name = [_]u8{0} ** 16,
        .mode = .tun,
        .allocator = std.testing.allocator,
        .config = .{},
    };

    // Set a test name
    const test_name = "test_tun0";
    @memcpy(device.name[0..test_name.len], test_name);

    try std.testing.expectEqualStrings("test_tun0", device.getName());
}
