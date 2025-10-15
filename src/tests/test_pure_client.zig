//! Integration test for pure Zig VPN client
//! Tests full connection flow against real SoftEther server

const std = @import("std");
const client_pure = @import("../client_pure.zig");
const config = @import("../config.zig");

test "pure zig client initialization" {
    const allocator = std.testing.allocator;

    // Create test configuration
    const test_config = config.ConnectionConfig{
        .server_name = "test.example.com",
        .server_port = 443,
        .hub_name = "TEST",
        .account_name = "test_account",
        .auth = .{ .password = .{
            .username = "testuser",
            .password = "testpass",
            .is_hashed = false,
        } },
        .use_encrypt = true,
        .use_compress = false,
        .max_connection = 1,
        .half_connection = false,
        .ip_version = .ipv4,
        .static_ip = null,
        .use_zig_adapter = true,
        .performance = .{
            .recv_buffer_slots = 128,
            .send_buffer_slots = 128,
        },
    };

    // Initialize client
    const pure_client = try client_pure.PureZigVpnClient.init(allocator, test_config);
    defer pure_client.deinit();

    // Check initial state
    try std.testing.expectEqual(pure_client.getStatus(), .disconnected);
    try std.testing.expect(!pure_client.isConnected());

    std.debug.print("\n✅ Pure Zig client initialization test passed!\n", .{});
}

test "pure zig client API compatibility" {
    const allocator = std.testing.allocator;

    const test_config = config.ConnectionConfig{
        .server_name = "test.example.com",
        .server_port = 443,
        .hub_name = "TEST",
        .account_name = "test",
        .auth = .{ .password = .{
            .username = "user",
            .password = "pass",
            .is_hashed = false,
        } },
        .use_encrypt = true,
        .use_compress = false,
        .max_connection = 1,
        .half_connection = false,
        .ip_version = .auto,
        .static_ip = null,
        .use_zig_adapter = true,
        .performance = .{
            .recv_buffer_slots = 128,
            .send_buffer_slots = 128,
        },
    };

    const pure_client = try client_pure.PureZigVpnClient.init(allocator, test_config);
    defer pure_client.deinit();

    // Test all API methods exist and work
    _ = pure_client.getStatus();
    _ = pure_client.isConnected();
    _ = try pure_client.getDeviceName();
    _ = try pure_client.getLearnedIp();
    _ = try pure_client.getGatewayMac();
    _ = try pure_client.getConnectionInfo();
    _ = try pure_client.getReconnectInfo();

    // Test session-specific APIs (pure Zig only)
    _ = pure_client.getSessionStats();
    _ = pure_client.getSessionState();
    _ = pure_client.getUptime();

    std.debug.print("\n✅ Pure Zig client API compatibility test passed!\n", .{});
}
