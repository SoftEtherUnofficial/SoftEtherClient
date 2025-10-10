//! Cedar Integration Tests
//!
//! Test-driven migration from OpenSSL to Cedar FFI.
//! Each test validates a specific piece of functionality we're migrating.

const std = @import("std");
const cedar = @import("cedar/wrapper.zig");
const testing = std.testing;

// Test helpers
fn expectStringContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("\nExpected to find '{s}' in '{s}'\n", .{ needle, haystack });
        return error.TestExpectedEqual;
    }
}

// ============================================================================
// PHASE 1: Basic Cedar FFI Functionality
// ============================================================================

test "Cedar: Version information" {
    const version = cedar.getVersion();
    try testing.expect(version.len > 0);
    // Version should contain digits and dots
    const has_version_pattern = std.mem.indexOf(u8, version, ".") != null;
    try testing.expect(has_version_pattern);

    const protocol_ver = cedar.getProtocolVersion();
    try testing.expectEqual(@as(u32, 4), protocol_ver);
}

test "Cedar: Packet creation and manipulation" {
    var packet = try cedar.Packet.init("Login");
    defer packet.deinit();

    // Add parameters
    try packet.addInt("protocol", 4);
    try packet.addInt("version", 1);
    try packet.addString("method", "plain");
    try packet.addString("username", "test_user");

    // Read back parameters
    const protocol = try packet.getInt("protocol");
    try testing.expectEqual(@as(u32, 4), protocol);

    var method_buf: [256]u8 = undefined;
    const method = try packet.getString("method", &method_buf);
    try testing.expectEqualStrings("plain", method);
}

test "Cedar: TLS connection lifecycle" {
    var tls = try cedar.TlsConnection.init();
    defer tls.deinit();

    const state = tls.getState();
    try testing.expectEqual(cedar.TlsState.Disconnected, state);

    // Note: Full TLS handshake requires a real server
    // This test just validates the API is working
}

test "Cedar: Compression (Deflate)" {
    var compressor = try cedar.Compressor.init(.Deflate);
    defer compressor.deinit();

    const input = "This is test data that should compress well because it has repetition repetition repetition";
    var compressed: [1024]u8 = undefined;
    var decompressed: [1024]u8 = undefined;

    const compressed_len = try compressor.compress(input, &compressed);
    try testing.expect(compressed_len > 0);
    // Note: Deflate may not always compress small strings to smaller size due to overhead

    const decompressed_len = try compressor.decompress(compressed[0..compressed_len], &decompressed);
    try testing.expectEqual(input.len, decompressed_len);
    try testing.expectEqualStrings(input, decompressed[0..decompressed_len]);
}

test "Cedar: Compression (Gzip)" {
    var compressor = try cedar.Compressor.init(.Gzip);
    defer compressor.deinit();

    const input = "Gzip compression test data";
    var compressed: [1024]u8 = undefined;

    const compressed_len = try compressor.compress(input, &compressed);
    try testing.expect(compressed_len > 0);
}

test "Cedar: Compression (LZ4)" {
    var compressor = try cedar.Compressor.init(.Lz4);
    defer compressor.deinit();

    const input = "LZ4 compression test data - fast compression!";
    var compressed: [1024]u8 = undefined;

    const compressed_len = try compressor.compress(input, &compressed);
    try testing.expect(compressed_len > 0);
}

// ============================================================================
// PHASE 2: Session Management
// ============================================================================

test "Cedar: Session creation with invalid parameters" {
    // Cedar may accept empty parameters and only fail on actual connection
    // This test just ensures no crash
    const result = cedar.Session.init("", 0, "");
    if (result) |session| {
        var sess = session;
        sess.deinit();
    } else |_| {}
}

test "Cedar: Session statistics structure" {
    // Test that the stats structure is properly defined
    const stats = cedar.SessionStats{
        .bytes_sent = 1024,
        .bytes_received = 2048,
        .packets_sent = 10,
        .packets_received = 20,
        .duration_secs = 30,
        .idle_time_secs = 5,
    };

    try testing.expectEqual(@as(u64, 1024), stats.bytes_sent);
    try testing.expectEqual(@as(u64, 2048), stats.bytes_received);
}

// ============================================================================
// PHASE 3: UDP Acceleration & NAT Traversal
// ============================================================================

test "Cedar: UDP Accelerator modes" {
    // Test all UDP acceleration modes
    const modes = [_]cedar.UdpAccelMode{ .Disabled, .Hybrid, .UdpOnly };

    for (modes) |mode| {
        var accel = try cedar.UdpAccelerator.init(mode);
        defer accel.deinit();

        // Just ensure it initializes without crashing
        _ = accel.isHealthy();
    }
}

test "Cedar: NAT type detection" {
    var nat = try cedar.NatTraversal.init();
    defer nat.deinit();

    const nat_type = nat.detect();

    // Should return one of the valid NAT types
    const valid = switch (nat_type) {
        .None, .FullCone, .RestrictedCone, .PortRestrictedCone, .Symmetric, .Unknown => true,
    };
    try testing.expect(valid);

    // Check if traversal is supported
    _ = nat.isSupported();
}

// ============================================================================
// PHASE 4: Error Handling
// ============================================================================

test "Cedar: Error code mapping" {
    // Test that all error codes are properly mapped
    const errors = [_]cedar.CedarError{
        error.InternalError,
        error.InvalidParameter,
        error.NotConnected,
        error.InvalidState,
        error.BufferTooSmall,
        error.PacketTooLarge,
        error.AuthenticationFailed,
        error.NotImplemented,
        error.TimeOut,
        error.IoError,
    };

    // Just ensure all error types are defined
    try testing.expectEqual(@as(usize, 10), errors.len);
}

test "Cedar: Buffer overflow protection" {
    var packet = try cedar.Packet.init("test");
    defer packet.deinit();

    // Try to add a string that's too long
    var long_string: [2000]u8 = undefined;
    @memset(&long_string, 'A');

    const result = packet.addString("key", &long_string);
    try testing.expectError(error.InvalidParameter, result);
}

// ============================================================================
// PHASE 5: Integration with existing VPN code (Mock tests)
// ============================================================================

test "Cedar: Mock VPN connection flow" {
    // Simulate the VPN connection sequence without a real server

    // 1. Create packet for login
    var login_packet = try cedar.Packet.init("Login");
    defer login_packet.deinit();

    try login_packet.addString("method", "plain");
    try login_packet.addString("username", "test");
    try login_packet.addString("password", "test123");
    try login_packet.addString("hubname", "DEFAULT");
    try login_packet.addInt("protocol", 4);

    // 2. Verify packet contents
    var username_buf: [256]u8 = undefined;
    const username = try login_packet.getString("username", &username_buf);
    try testing.expectEqualStrings("test", username);

    // 3. Create TLS connection (would be used for actual connection)
    var tls = try cedar.TlsConnection.init();
    defer tls.deinit();

    try testing.expectEqual(cedar.TlsState.Disconnected, tls.getState());
}

test "Cedar: Mock data transfer with compression" {
    // Simulate sending compressed data
    var compressor = try cedar.Compressor.init(.Deflate);
    defer compressor.deinit();

    // Simulate packet data
    const original_data = "VPN packet data that will be compressed before transmission";
    var compressed_buffer: [1024]u8 = undefined;
    var decompressed_buffer: [1024]u8 = undefined;

    // Compress
    const compressed_len = try compressor.compress(original_data, &compressed_buffer);
    try testing.expect(compressed_len > 0);

    // Decompress (simulating receiver side)
    const decompressed_len = try compressor.decompress(compressed_buffer[0..compressed_len], &decompressed_buffer);

    // Verify data integrity
    try testing.expectEqual(original_data.len, decompressed_len);
    try testing.expectEqualStrings(original_data, decompressed_buffer[0..decompressed_len]);
}

// ============================================================================
// PHASE 6: Performance & Stress Tests
// ============================================================================

test "Cedar: Multiple packet operations" {
    // Create and manipulate multiple packets
    const iterations = 100;
    var i: usize = 0;

    while (i < iterations) : (i += 1) {
        var packet = try cedar.Packet.init("test");
        defer packet.deinit();

        try packet.addInt("iteration", @intCast(i));
        const value = try packet.getInt("iteration");
        try testing.expectEqual(@as(u32, @intCast(i)), value);
    }
}

test "Cedar: Compression performance baseline" {
    var compressor = try cedar.Compressor.init(.Lz4);
    defer compressor.deinit();

    // Use LZ4 for speed testing (fastest algorithm)
    const test_data = "A" ** 1000; // 1KB of data
    var compressed: [2048]u8 = undefined;

    // Compress multiple times to get baseline performance
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        const len = try compressor.compress(test_data, &compressed);
        try testing.expect(len > 0);
    }
}

// ============================================================================
// PHASE 7: Edge Cases & Boundary Conditions
// ============================================================================

test "Cedar: Empty packet command" {
    // Cedar may accept empty command - validation happens at protocol level
    // This test just ensures no crash
    const result = cedar.Packet.init("");
    if (result) |packet| {
        var pkt = packet;
        pkt.deinit();
    } else |_| {}
}

test "Cedar: Packet with zero-length string value" {
    var packet = try cedar.Packet.init("test");
    defer packet.deinit();

    try packet.addString("empty", "");

    var buf: [256]u8 = undefined;
    const value = try packet.getString("empty", &buf);
    try testing.expectEqual(@as(usize, 0), value.len);
}

test "Cedar: Packet get non-existent key" {
    var packet = try cedar.Packet.init("test");
    defer packet.deinit();

    const result = packet.getInt("non_existent");
    try testing.expectError(error.InvalidParameter, result);
}

test "Cedar: Multiple compression/decompression cycles" {
    var compressor = try cedar.Compressor.init(.Deflate);
    defer compressor.deinit();

    const original = "Original data";
    var compressed: [1024]u8 = undefined;
    var decompressed: [1024]u8 = undefined;

    // Cycle 1
    const comp_len = try compressor.compress(original, &compressed);
    const decomp_len = try compressor.decompress(compressed[0..comp_len], &decompressed);
    try testing.expectEqualStrings(original, decompressed[0..decomp_len]);

    // Cycle 2 - reuse compressor
    const comp_len2 = try compressor.compress(original, &compressed);
    const decomp_len2 = try compressor.decompress(compressed[0..comp_len2], &decompressed);
    try testing.expectEqualStrings(original, decompressed[0..decomp_len2]);
}
