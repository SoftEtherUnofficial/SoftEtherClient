//! Tests for macOS SoftEther SSL-VPN Session Layer
//!
//! Note: L2/L3 functionality (DHCP, ARP, routing) is tested in ZigTapTun.
//! These tests focus only on SoftEther SSL-VPN protocol logic.

const std = @import("std");
const testing = std.testing;
const macos = @import("macos.zig");

// Basic initialization tests
test "SoftEther session configuration" {
    const config = macos.ServerConfig{
        .hostname = "test.softether.local",
        .port = 443,
        .hub_name = "TEST_HUB",
        .auth = .{
            .username = "testuser",
            .password = "testpass",
        },
    };

    try testing.expectEqualStrings("test.softether.local", config.hostname);
    try testing.expectEqual(@as(u16, 443), config.port);
    try testing.expectEqualStrings("TEST_HUB", config.hub_name);
    try testing.expectEqual(@as(u32, 5000), config.keepalive_interval_ms);
}

test "SoftEther session state transitions" {
    // Skip - requires root to open utun device
    if (true) return error.SkipZigTest;

    const allocator = testing.allocator;

    const config = macos.ServerConfig{
        .hostname = "test.softether.local",
        .port = 443,
        .hub_name = "TEST_HUB",
        .auth = .{
            .username = "testuser",
            .password = "testpass",
        },
    };

    var session = try macos.SoftEtherSession.init(allocator, config);
    defer session.deinit();

    // Initial state should be disconnected
    try testing.expectEqual(macos.SslVpnState.disconnected, session.state);

    // Note: adapter is a pointer, so it's always non-null after successful init
    // Verify stats initialized
    try testing.expectEqual(@as(u64, 0), session.stats.bytes_sent);
    try testing.expectEqual(@as(u64, 0), session.stats.bytes_received);
}

test "SessionStats connection duration" {
    var stats = macos.SessionStats{};

    // Before connection
    try testing.expectEqual(@as(i64, 0), stats.connectionDuration());

    // After connection start
    stats.connection_start_time = std.time.milliTimestamp() - 5000;
    const duration = stats.connectionDuration();
    try testing.expect(duration >= 4900 and duration <= 5100); // ~5 seconds ±100ms
}

test "PacketAdapter legacy wrapper" {
    // Skip - requires root to open utun device
    if (true) return error.SkipZigTest;

    const allocator = testing.allocator;

    var adapter = try macos.PacketAdapter.init(allocator);
    defer adapter.deinit();

    // Note: session is a pointer, so it's always non-null after successful init
    try testing.expectEqual(macos.SslVpnState.disconnected, adapter.session.state);
}

// Integration marker tests (require actual network)
test "SoftEther connection - integration test" {
    // Skip in CI/automated testing
    if (true) return error.SkipZigTest;

    const allocator = testing.allocator;

    const config = macos.ServerConfig{
        .hostname = "test.softether.local",
        .port = 443,
        .hub_name = "TEST_HUB",
        .auth = .{
            .username = "testuser",
            .password = "testpass",
        },
    };

    var session = try macos.SoftEtherSession.init(allocator, config);
    defer session.deinit();

    // This would require actual SoftEther server
    // try session.connect();
    // try testing.expectEqual(macos.SslVpnState.connected, session.state);
}

// Note: DHCP, ARP, and routing tests are in ZigTapTun test suite
// This keeps test responsibilities clear and avoids duplication
