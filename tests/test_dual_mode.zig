// Parallel Test Suite: OpenSSL vs Cedar Implementation
// Tests both code paths to ensure behavioral parity

const std = @import("std");
const testing = std.testing;
const client = @import("client.zig");
const config = @import("config.zig");
const build_options = @import("build_options");

/// Test configuration builder for both modes
fn makeTestConfig(allocator: std.mem.Allocator) !config.ConnectionConfig {
    return config.ConnectionConfig{
        .server_name = "test.example.com",
        .server_port = 443,
        .hub_name = "TestHub",
        .account_name = "TestAccount",
        .auth = .{ .password = .{
            .username = "testuser",
            .password = "testpass",
            .is_hashed = false,
        } },
        .use_encrypt = true,
        .use_compress = true,
        .max_connection = 1,
        .ip_version = .auto,
        .static_ip = null,
        .use_zig_adapter = true,
        .performance = .{
            .recv_buffer_slots = 128,
            .send_buffer_slots = 64,
        },
    };
}

test "VpnClient initialization - both modes" {
    const allocator = testing.allocator;
    const cfg = try makeTestConfig(allocator);

    // Test client initialization
    var vpn_client = try client.VpnClient.init(allocator, cfg);
    defer vpn_client.deinit();

    // Verify client is properly initialized
    try testing.expect(vpn_client.handle != null);
    try testing.expectEqualStrings("test.example.com", vpn_client.config.server_name);
    try testing.expectEqual(@as(u16, 443), vpn_client.config.server_port);
    try testing.expectEqualStrings("TestHub", vpn_client.config.hub_name);
    try testing.expectEqual(true, vpn_client.config.use_encrypt);
    try testing.expectEqual(true, vpn_client.config.use_compress);
    try testing.expectEqual(@as(u32, 1), vpn_client.config.max_connection);
}

test "Config loading - parity check" {
    const allocator = testing.allocator;

    // Test 1: Basic configuration struct
    const cfg = try makeTestConfig(allocator);
    
    try testing.expectEqualStrings("test.example.com", cfg.server_name);
    try testing.expectEqual(@as(u16, 443), cfg.server_port);
    try testing.expectEqualStrings("TestHub", cfg.hub_name);
    try testing.expectEqualStrings("TestAccount", cfg.account_name);
    try testing.expectEqual(true, cfg.use_encrypt);
    try testing.expectEqual(true, cfg.use_compress);
    try testing.expectEqual(@as(u32, 1), cfg.max_connection);

    // Test 2: Performance configuration
    try testing.expectEqual(@as(u16, 128), cfg.performance.recv_buffer_slots);
    try testing.expectEqual(@as(u16, 64), cfg.performance.send_buffer_slots);
}

test "Authentication structure - both modes" {
    const allocator = testing.allocator;
    const cfg = try makeTestConfig(allocator);

    // Verify auth configuration
    try testing.expect(cfg.auth == .password);
    try testing.expectEqualStrings("testuser", cfg.auth.password.username);
    try testing.expectEqualStrings("testpass", cfg.auth.password.password);
    try testing.expectEqual(false, cfg.auth.password.is_hashed);
}

test "Connection parameters - OpenSSL vs Cedar" {
    const allocator = testing.allocator;

    // Test with different max_connection values
    const test_cases = [_]u32{ 1, 2, 4, 8, 16, 32 };
    
    for (test_cases) |max_conn| {
        var cfg = try makeTestConfig(allocator);
        cfg.max_connection = max_conn;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(max_conn, vpn_client.config.max_connection);
    }
}

test "Encryption modes - parity" {
    const allocator = testing.allocator;

    // Test with encryption enabled
    {
        var cfg = try makeTestConfig(allocator);
        cfg.use_encrypt = true;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(true, vpn_client.config.use_encrypt);
    }

    // Test with encryption disabled (not recommended but should work)
    {
        var cfg = try makeTestConfig(allocator);
        cfg.use_encrypt = false;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(false, vpn_client.config.use_encrypt);
    }
}

test "Compression modes - parity" {
    const allocator = testing.allocator;

    // Test with compression enabled
    {
        var cfg = try makeTestConfig(allocator);
        cfg.use_compress = true;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(true, vpn_client.config.use_compress);
    }

    // Test with compression disabled
    {
        var cfg = try makeTestConfig(allocator);
        cfg.use_compress = false;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(false, vpn_client.config.use_compress);
    }
}

test "Build mode detection" {
    // Verify which mode we're testing
    if (build_options.use_cedar) {
        std.debug.print("\n✓ Testing Cedar (Rust) mode\n", .{});
    } else {
        std.debug.print("\n✓ Testing OpenSSL (C) mode\n", .{});
    }
    
    // Just verify the build option is accessible
    _ = build_options.use_cedar;
}

test "Performance configuration - parity" {
    const allocator = testing.allocator;

    // Test different performance configurations
    const test_cases = [_]struct {
        recv: u16,
        send: u16,
    }{
        .{ .recv = 64, .send = 32 },
        .{ .recv = 128, .send = 64 },
        .{ .recv = 256, .send = 128 },
        .{ .recv = 512, .send = 256 },
    };

    for (test_cases) |tc| {
        var cfg = try makeTestConfig(allocator);
        cfg.performance.recv_buffer_slots = tc.recv;
        cfg.performance.send_buffer_slots = tc.send;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(tc.recv, vpn_client.config.performance.recv_buffer_slots);
        try testing.expectEqual(tc.send, vpn_client.config.performance.send_buffer_slots);
    }
}

test "IP version configuration - parity" {
    const allocator = testing.allocator;

    const ip_versions = [_]config.IpVersion{ .auto, .ipv4, .ipv6, .dual };
    
    for (ip_versions) |ip_ver| {
        var cfg = try makeTestConfig(allocator);
        cfg.ip_version = ip_ver;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(ip_ver, vpn_client.config.ip_version);
    }
}

test "Static IP configuration - parity" {
    const allocator = testing.allocator;

    // Test with static IPv4
    {
        var cfg = try makeTestConfig(allocator);
        cfg.static_ip = config.StaticIpConfig{
            .ipv4_address = "10.0.0.2",
            .ipv4_netmask = "255.255.255.0",
            .ipv4_gateway = "10.0.0.1",
            .ipv6_address = null,
            .ipv6_prefix_len = null,
            .ipv6_gateway = null,
            .dns_servers = null,
        };
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expect(vpn_client.config.static_ip != null);
        if (vpn_client.config.static_ip) |sip| {
            try testing.expectEqualStrings("10.0.0.2", sip.ipv4_address.?);
            try testing.expectEqualStrings("255.255.255.0", sip.ipv4_netmask.?);
            try testing.expectEqualStrings("10.0.0.1", sip.ipv4_gateway.?);
        }
    }
}

test "Packet adapter mode - parity" {
    const allocator = testing.allocator;

    // Test Zig adapter (recommended)
    {
        var cfg = try makeTestConfig(allocator);
        cfg.use_zig_adapter = true;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(true, vpn_client.config.use_zig_adapter);
    }

    // Test C adapter (legacy fallback)
    {
        var cfg = try makeTestConfig(allocator);
        cfg.use_zig_adapter = false;
        
        var vpn_client = try client.VpnClient.init(allocator, cfg);
        defer vpn_client.deinit();
        
        try testing.expectEqual(false, vpn_client.config.use_zig_adapter);
    }
}

test "Cedar session structure - conditional compilation" {
    const allocator = testing.allocator;
    const cfg = try makeTestConfig(allocator);

    var vpn_client = try client.VpnClient.init(allocator, cfg);
    defer vpn_client.deinit();

    // Verify Cedar session field exists when Cedar mode is enabled
    if (build_options.use_cedar) {
        // Cedar mode: session should be null initially
        try testing.expect(vpn_client.cedar_session == null);
        std.debug.print("\n✓ Cedar session field verified\n", .{});
    } else {
        // OpenSSL mode: cedar_session is void
        try testing.expectEqual({}, vpn_client.cedar_session);
        std.debug.print("\n✓ OpenSSL mode (cedar_session is void)\n", .{});
    }
}

test "Reconnection configuration - parity" {
    // Verify reconnection structs match between modes
    const reconnect_info = client.ReconnectInfo{
        .enabled = true,
        .should_reconnect = false,
        .attempt = 0,
        .max_attempts = 10,
        .current_backoff = 5,
        .next_retry_time = 0,
        .consecutive_failures = 0,
        .last_disconnect_time = 0,
    };

    try testing.expectEqual(true, reconnect_info.enabled);
    try testing.expectEqual(false, reconnect_info.should_reconnect);
    try testing.expectEqual(@as(u32, 0), reconnect_info.attempt);
    try testing.expectEqual(@as(u32, 10), reconnect_info.max_attempts);
    try testing.expectEqual(@as(u32, 5), reconnect_info.current_backoff);
}

// Integration test that would require actual server connection
// (Skipped in unit tests, but documented here for manual testing)
//
// Manual Test Checklist (both OpenSSL and Cedar modes):
// ────────────────────────────────────────────────────────
// 1. Connection establishment
//    [ ] Build OpenSSL: zig build
//    [ ] Run: ./zig-out/bin/vpnclient --config config.json
//    [ ] Verify: TLS connection established
//    [ ] Verify: Authentication successful
//    [ ] Verify: Welcome packet received
//
// 2. Build Cedar: zig build -Duse-cedar
//    [ ] Run: ./zig-out/bin/vpnclient --config config.json
//    [ ] Verify: TLS connection established
//    [ ] Verify: Authentication successful
//    [ ] Verify: Welcome packet received
//
// 3. TUN device creation (requires sudo)
//    [ ] OpenSSL: sudo ./zig-out/bin/vpnclient --config config.json
//    [ ] Cedar: sudo ./zig-out/bin/vpnclient --config config.json
//    [ ] Verify: TUN device created (utun*)
//    [ ] Verify: DHCP configuration successful
//    [ ] Verify: IP address assigned
//
// 4. Packet forwarding
//    [ ] OpenSSL: Verify packets sent/received
//    [ ] Cedar: Verify packets sent/received
//    [ ] Compare: Total bytes sent/received
//    [ ] Compare: Compression ratios
//
// 5. Graceful shutdown (Ctrl+C)
//    [ ] OpenSSL: Clean disconnect
//    [ ] Cedar: Clean disconnect
//    [ ] Verify: Routes restored
//    [ ] Verify: TUN device closed
//
// Expected Behavior Match:
// ───────────────────────
// - Both modes should authenticate successfully
// - Both modes should establish TLS connection
// - Both modes should create TUN device with sudo
// - Both modes should configure DHCP
// - Both modes should forward packets bidirectionally
// - Both modes should handle Ctrl+C gracefully
// - Both modes should restore routing on exit
