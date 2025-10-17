//! Platform-agnostic TUN/TAP Device Interface
//! Provides unified API across macOS, Linux, and Windows
//!
//! Phase 4: Platform Layer Migration - Unified Abstraction

const std = @import("std");
const builtin = @import("builtin");

// Import platform-specific implementations
// NOTE: These are conditional imports that work at compile time
// For build system integration, tun module is imported from src/tun/tun.zig
const PlatformImpl = if (builtin.os.tag == .linux) @import("linux.zig") else struct {};

/// Platform-specific TUN device type
/// This will be properly resolved by the build system's module configuration
pub const PlatformTunDevice = switch (builtin.os.tag) {
    .linux => PlatformImpl.LinuxTunDevice,
    .macos => @compileError("For macOS, import directly from tun module: @import(\"tun\")"),
    else => @compileError("Unsupported platform for TUN device. Supported: macOS, Linux"),
};

/// Unified TUN device configuration
pub const DeviceConfig = struct {
    /// Device name (platform-specific format)
    /// - macOS: "utun" (kernel assigns number)
    /// - Linux: "tun0", "tap0", etc. (null for auto-assign)
    /// - Windows: GUID or adapter name
    name: ?[]const u8 = null,

    /// Device mode
    mode: DeviceMode = .tun,

    /// MTU size
    mtu: u32 = 1500,

    /// Platform-specific options
    platform: PlatformOptions = .{},
};

/// Device mode
pub const DeviceMode = enum {
    tun, // Layer 3 (IP packets)
    tap, // Layer 2 (Ethernet frames)
};

/// Platform-specific configuration options
pub const PlatformOptions = union(enum) {
    /// No platform-specific options
    none: void,

    /// Linux-specific options
    linux: struct {
        multi_queue: bool = false,
        persistent: bool = false,
        owner: ?u32 = null,
        group: ?u32 = null,
        no_packet_info: bool = true,
    },

    /// macOS-specific options
    macos: struct {
        // macOS utun options (currently minimal)
    },

    /// Windows-specific options
    windows: struct {
        // Windows TAP options (TODO)
    },

    /// Get platform-appropriate default options
    pub fn default() PlatformOptions {
        return switch (builtin.os.tag) {
            .linux => .{ .linux = .{} },
            .macos => .{ .macos = .{} },
            .windows => .{ .windows = .{} },
            else => .{ .none = {} },
        };
    }
};

/// Platform-agnostic TUN device wrapper
pub const TunDevice = struct {
    inner: PlatformTunDevice,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Open a TUN device for the current platform
    pub fn open(allocator: std.mem.Allocator, config: DeviceConfig) !Self {
        const device = switch (builtin.os.tag) {
            .linux => blk: {
                // Linux: Convert to LinuxTunConfig
                const linux_config = PlatformImpl.LinuxTunConfig{
                    .name = config.name,
                    .mode = switch (config.mode) {
                        .tun => .tun,
                        .tap => .tap,
                    },
                    .mtu = config.mtu,
                    .multi_queue = if (config.platform == .linux) config.platform.linux.multi_queue else false,
                    .persistent = if (config.platform == .linux) config.platform.linux.persistent else false,
                    .owner = if (config.platform == .linux) config.platform.linux.owner else null,
                    .group = if (config.platform == .linux) config.platform.linux.group else null,
                    .no_packet_info = if (config.platform == .linux) config.platform.linux.no_packet_info else true,
                };
                break :blk try PlatformImpl.LinuxTunDevice.open(allocator, linux_config);
            },
            else => return error.UnsupportedPlatform,
        };

        return Self{
            .inner = device,
            .allocator = allocator,
        };
    }

    /// Get device name
    pub fn getName(self: *const Self) []const u8 {
        return self.inner.getName();
    }

    /// Read packet from device
    pub fn readPacket(self: *Self, buffer: []u8) ![]u8 {
        return self.inner.readPacket(buffer);
    }

    /// Write packet to device
    pub fn writePacket(self: *Self, packet: []const u8) !void {
        return self.inner.writePacket(packet);
    }

    /// Configure IP address
    /// Format: "192.168.1.1/24" (CIDR notation)
    pub fn configureIp(self: *Self, ip_with_prefix: []const u8) !void {
        if (builtin.os.tag == .linux) {
            return self.inner.configureIp(ip_with_prefix);
        }
        // For other platforms, would need platform-specific implementation
        std.log.warn("IP configuration not implemented for {s}", .{@tagName(builtin.os.tag)});
        return error.NotImplemented;
    }

    /// Bring interface up
    pub fn bringUp(self: *Self) !void {
        if (builtin.os.tag == .linux) {
            return self.inner.bringUp();
        }
        // macOS interfaces are typically up by default
        std.log.info("Interface up not needed for {s}", .{@tagName(builtin.os.tag)});
    }

    /// Bring interface down
    pub fn bringDown(self: *Self) !void {
        if (builtin.os.tag == .linux) {
            return self.inner.bringDown();
        }
        std.log.warn("Interface down not supported for {s}", .{@tagName(builtin.os.tag)});
    }

    /// Set MTU
    pub fn setMtu(self: *Self, mtu: u32) !void {
        if (builtin.os.tag == .linux) {
            return self.inner.setMtu(mtu);
        }
        std.log.warn("MTU setting not implemented for {s} (device: {s}, requested: {d})", .{ @tagName(builtin.os.tag), self.getName(), mtu });
        return error.NotImplemented;
    }

    /// Add default route
    pub fn addDefaultRoute(self: *Self, gateway: []const u8) !void {
        if (builtin.os.tag == .linux) {
            return self.inner.addDefaultRoute(gateway);
        }
        std.log.warn("Default route configuration not implemented for {s} (device: {s}, gateway: {s})", .{ @tagName(builtin.os.tag), self.getName(), gateway });
        return error.NotImplemented;
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: *Self, enabled: bool) !void {
        return self.inner.setNonBlocking(enabled);
    }

    /// Close device
    pub fn close(self: *Self) void {
        self.inner.close();
    }

    /// Deinitialize (alias for close)
    pub fn deinit(self: *Self) void {
        self.close();
    }
};

/// Platform capabilities detection
pub const Capabilities = struct {
    /// TUN support (Layer 3 - IP packets)
    has_tun: bool,

    /// TAP support (Layer 2 - Ethernet frames)
    has_tap: bool,

    /// Multi-queue support
    multi_queue: bool,

    /// Persistent device support
    persistent: bool,

    /// Can configure IP via API
    can_configure_ip: bool,

    /// Can configure routes via API
    can_configure_routes: bool,

    /// Detect capabilities for current platform
    pub fn detect() Capabilities {
        return switch (builtin.os.tag) {
            .macos => .{
                .has_tun = true,
                .has_tap = false, // macOS utun is TUN only
                .multi_queue = false,
                .persistent = false,
                .can_configure_ip = true,
                .can_configure_routes = true,
            },
            .linux => .{
                .has_tun = true,
                .has_tap = true,
                .multi_queue = true,
                .persistent = true,
                .can_configure_ip = true,
                .can_configure_routes = true,
            },
            .windows => .{
                .has_tun = false, // Windows uses TAP-Windows6
                .has_tap = true,
                .multi_queue = false,
                .persistent = true,
                .can_configure_ip = true,
                .can_configure_routes = true,
            },
            else => .{
                .has_tun = false,
                .has_tap = false,
                .multi_queue = false,
                .persistent = false,
                .can_configure_ip = false,
                .can_configure_routes = false,
            },
        };
    }

    /// Get platform name
    pub fn platformName() []const u8 {
        return switch (builtin.os.tag) {
            .macos => "macOS",
            .linux => "Linux",
            .windows => "Windows",
            else => "Unknown",
        };
    }

    /// Format capabilities as string
    pub fn format(
        self: Capabilities,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("Platform: {s}\n", .{platformName()});
        try writer.print("  TUN support: {}\n", .{self.has_tun});
        try writer.print("  TAP support: {}\n", .{self.has_tap});
        try writer.print("  Multi-queue: {}\n", .{self.multi_queue});
        try writer.print("  Persistent: {}\n", .{self.persistent});
        try writer.print("  IP config: {}\n", .{self.can_configure_ip});
        try writer.print("  Route config: {}\n", .{self.can_configure_routes});
    }
};

/// Helper: Open TUN device with default configuration
pub fn openTunDevice(allocator: std.mem.Allocator, name: ?[]const u8) !TunDevice {
    return TunDevice.open(allocator, .{
        .name = name,
        .mode = .tun,
        .platform = PlatformOptions.default(),
    });
}

/// Helper: Open TAP device with default configuration
pub fn openTapDevice(allocator: std.mem.Allocator, name: ?[]const u8) !TunDevice {
    const caps = Capabilities.detect();
    if (!caps.has_tap) {
        return error.TapNotSupported;
    }

    return TunDevice.open(allocator, .{
        .name = name,
        .mode = .tap,
        .platform = PlatformOptions.default(),
    });
}

// ============================================================================
// TESTS
// ============================================================================

test "Capabilities detection" {
    const caps = Capabilities.detect();

    // At minimum, we should detect the current platform
    if (builtin.os.tag == .macos) {
        try std.testing.expect(caps.has_tun);
        try std.testing.expect(!caps.has_tap);
    } else if (builtin.os.tag == .linux) {
        try std.testing.expect(caps.has_tun);
        try std.testing.expect(caps.has_tap);
        try std.testing.expect(caps.multi_queue);
    }
}

test "Platform name detection" {
    const name = Capabilities.platformName();
    try std.testing.expect(name.len > 0);

    if (builtin.os.tag == .macos) {
        try std.testing.expectEqualStrings("macOS", name);
    } else if (builtin.os.tag == .linux) {
        try std.testing.expectEqualStrings("Linux", name);
    }
}

test "TunDevice wrapper creation" {
    const allocator = std.testing.allocator;

    var device = openTunDevice(allocator, null) catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    const name = device.getName();
    try std.testing.expect(name.len > 0);
    std.debug.print("Created device: {s}\n", .{name});
}

test "TAP device on supported platforms" {
    if (!Capabilities.detect().has_tap) {
        std.debug.print("⚠️  TAP not supported on this platform\n", .{});
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var device = openTapDevice(allocator, "test_tap") catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    const name = device.getName();
    try std.testing.expect(name.len > 0);
}

test "Capabilities formatting" {
    const caps = Capabilities.detect();

    var buf: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try caps.format("", .{}, fbs.writer());

    const output = fbs.getWritten();
    try std.testing.expect(output.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, output, "Platform:") != null);
}
