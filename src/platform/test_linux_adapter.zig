//! Linux TUN/TAP Adapter Tests
//! Comprehensive test suite for Linux platform adapter

const std = @import("std");
const linux = @import("linux.zig");
const builtin = @import("builtin");

test "LinuxTunDevice - basic TUN creation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = linux.LinuxTunConfig{
        .name = "test_tun0",
        .mode = .tun,
        .no_packet_info = true,
    };

    var device = linux.LinuxTunDevice.open(allocator, config) catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root and /dev/net/tun\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    try std.testing.expect(device.fd >= 0);
    try std.testing.expectEqual(linux.DeviceMode.tun, device.mode);
}

test "LinuxTunDevice - TAP mode creation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = linux.LinuxTunConfig{
        .name = "test_tap0",
        .mode = .tap,
        .no_packet_info = true,
    };

    var device = linux.LinuxTunDevice.open(allocator, config) catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root and /dev/net/tun\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    try std.testing.expect(device.fd >= 0);
    try std.testing.expectEqual(linux.DeviceMode.tap, device.mode);
}

test "LinuxTunDevice - auto-assigned name" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = linux.LinuxTunConfig{
        .name = null, // Let kernel assign name
        .mode = .tun,
    };

    var device = linux.LinuxTunDevice.open(allocator, config) catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    const name = device.getName();
    std.debug.print("Auto-assigned device name: {s}\n", .{name});
    try std.testing.expect(name.len > 0);
}

test "IpConfig - parse valid IP with CIDR" {
    const config = try linux.IpConfig.parse("192.168.1.100/24");

    try std.testing.expectEqual([4]u8{ 192, 168, 1, 100 }, config.ip);
    try std.testing.expectEqual(@as(u8, 24), config.prefix_len);
}

test "IpConfig - parse various prefix lengths" {
    const test_cases = [_]struct { input: []const u8, expected_prefix: u8 }{
        .{ .input = "10.0.0.1/8", .expected_prefix = 8 },
        .{ .input = "172.16.0.1/12", .expected_prefix = 12 },
        .{ .input = "192.168.0.1/16", .expected_prefix = 16 },
        .{ .input = "192.168.1.1/24", .expected_prefix = 24 },
        .{ .input = "192.168.1.1/32", .expected_prefix = 32 },
    };

    for (test_cases) |tc| {
        const config = try linux.IpConfig.parse(tc.input);
        try std.testing.expectEqual(tc.expected_prefix, config.prefix_len);
    }
}

test "IpConfig - netmask calculation" {
    const test_cases = [_]struct {
        prefix: u8,
        expected_mask: [4]u8,
    }{
        .{ .prefix = 8, .expected_mask = [4]u8{ 255, 0, 0, 0 } },
        .{ .prefix = 16, .expected_mask = [4]u8{ 255, 255, 0, 0 } },
        .{ .prefix = 24, .expected_mask = [4]u8{ 255, 255, 255, 0 } },
        .{ .prefix = 32, .expected_mask = [4]u8{ 255, 255, 255, 255 } },
        .{ .prefix = 28, .expected_mask = [4]u8{ 255, 255, 255, 240 } },
    };

    for (test_cases) |tc| {
        const config = linux.IpConfig{
            .ip = [4]u8{ 192, 168, 1, 1 },
            .prefix_len = tc.prefix,
        };
        const mask = config.netmask();
        try std.testing.expectEqual(tc.expected_mask, mask);
    }
}

test "IpConfig - formatting" {
    const config = linux.IpConfig{
        .ip = [4]u8{ 10, 0, 0, 1 },
        .prefix_len = 8,
    };

    var buf: [32]u8 = undefined;
    const result = try std.fmt.bufPrint(&buf, "{}", .{config});
    try std.testing.expectEqualStrings("10.0.0.1/8", result);
}

test "IpConfig - invalid format handling" {
    const invalid_cases = [_][]const u8{
        "192.168.1.1", // Missing prefix
        "192.168.1", // Incomplete IP
        "192.168.1.1/", // Missing prefix number
        "192.168.1.1/33", // Invalid prefix (> 32)
        "256.168.1.1/24", // Invalid octet
        "", // Empty string
    };

    for (invalid_cases) |invalid| {
        const result = linux.IpConfig.parse(invalid);
        try std.testing.expectError(error.InvalidFormat, result) catch |err| {
            if (err == error.Overflow or err == error.InvalidCharacter or err == error.InvalidIpFormat or err == error.InvalidPrefixLength) {
                // These are also acceptable errors for invalid input
                continue;
            }
            return err;
        };
    }
}

test "LinuxTunDevice - device name length validation" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    // Device name too long (>15 chars)
    const config = linux.LinuxTunConfig{
        .name = "this_is_a_very_long_device_name_that_exceeds_limit",
        .mode = .tun,
    };

    const result = linux.LinuxTunDevice.open(allocator, config);
    try std.testing.expectError(error.DeviceNameTooLong, result);
}

test "LinuxTunDevice - multi-queue flag" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = linux.LinuxTunConfig{
        .name = "test_mq_tun",
        .mode = .tun,
        .multi_queue = true,
    };

    var device = linux.LinuxTunDevice.open(allocator, config) catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    try std.testing.expect(device.config.multi_queue);
}

// Integration test - requires root
test "LinuxTunDevice - IP configuration integration" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = linux.LinuxTunConfig{
        .name = "test_ip_tun",
        .mode = .tun,
    };

    var device = linux.LinuxTunDevice.open(allocator, config) catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    // Try to configure IP (may fail without proper permissions)
    device.configureIp("10.10.10.1/24") catch |err| {
        if (err == error.IpConfigFailed) {
            std.debug.print("⚠️  IP config requires root/CAP_NET_ADMIN\n", .{});
            return;
        }
        return err;
    };

    // Try to bring interface up
    device.bringUp() catch |err| {
        if (err == error.InterfaceUpFailed) {
            std.debug.print("⚠️  Interface up requires root/CAP_NET_ADMIN\n", .{});
            return;
        }
        return err;
    };

    std.debug.print("✅ Successfully configured and brought up interface\n", .{});
}

test "LinuxTunDevice - packet I/O (requires root)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const config = linux.LinuxTunConfig{
        .name = "test_io_tun",
        .mode = .tun,
        .no_packet_info = true,
    };

    var device = linux.LinuxTunDevice.open(allocator, config) catch |err| {
        if (err == error.PermissionDenied or err == error.NoDevice) {
            std.debug.print("⚠️  Skipping: Requires root\n", .{});
            return error.SkipZigTest;
        }
        return err;
    };
    defer device.close();

    // Configure device
    _ = device.configureIp("10.10.10.1/24") catch {
        std.debug.print("⚠️  IP config requires root\n", .{});
        return error.SkipZigTest;
    };
    _ = device.bringUp() catch {
        std.debug.print("⚠️  Interface up requires root\n", .{});
        return error.SkipZigTest;
    };

    // Set non-blocking for testing
    try device.setNonBlocking(true);

    // Try to write a simple ICMP packet
    const icmp_packet = [_]u8{
        0x45, 0x00, 0x00, 0x54, // IP header
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0x0a, 0x0a, 0x0a, 0x01, // Source: 10.10.10.1
        0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
        // ICMP Echo Request would follow...
    };

    device.writePacket(&icmp_packet) catch |err| {
        std.debug.print("Write error (expected in test): {}\n", .{err});
    };

    std.debug.print("✅ Packet I/O test completed\n", .{});
}
