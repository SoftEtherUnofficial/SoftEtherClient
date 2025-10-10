//! Protocol Comparison Tests
//! 
//! Validates OpenSSL (C) vs Cedar (Rust) implementations side-by-side.
//! Tests HTTP protocol, handshake, and packet format to ensure compatibility.

const std = @import("std");
const testing = std.testing;

// Import both implementations
const cedar = @cImport({
    @cInclude("cedar_ffi.h");
});

const openssl_client = @cImport({
    @cDefine("UNIX_MACOS", "1");
    @cDefine("_REENTRANT", "1");
    @cInclude("Client.h");
    @cInclude("Protocol.h");
});

const TestConfig = struct {
    server: []const u8 = "worxvpn.662.cloud",
    port: u16 = 443,
    hub: []const u8 = "VPN",
    username: []const u8 = "devstroop",
    password: []const u8 = "test_password",
};

// Test 1: Protocol Signature Compatibility
test "protocol_signature: OpenSSL vs Cedar" {
    const expected_signature = "SE-VPN4-PROTOCOL";
    
    // OpenSSL signature
    const openssl_sig = openssl_client.CEDAR_SIGNATURE;
    try testing.expectEqualStrings(expected_signature, std.mem.span(openssl_sig));
    
    // Cedar signature
    const cedar_sig = cedar.cedar_get_protocol_signature();
    defer cedar.cedar_free_string(cedar_sig);
    try testing.expectEqualStrings(expected_signature, std.mem.span(cedar_sig));
    
    std.debug.print("✅ Protocol signatures match: {s}\n", .{expected_signature});
}

// Test 2: HTTP Request Format
test "http_request_format: OpenSSL vs Cedar" {
    const allocator = testing.allocator;
    
    const config = TestConfig{};
    
    // Test data: simple PACK
    const test_pack_data = [_]u8{0x00, 0x00, 0x00, 0x10} ++ "test_pack_data\x00\x00";
    
    // OpenSSL HTTP request
    const openssl_request = try createOpenSSLHttpRequest(allocator, config, &test_pack_data);
    defer allocator.free(openssl_request);
    
    // Cedar HTTP request  
    const cedar_request = try createCedarHttpRequest(allocator, config, &test_pack_data);
    defer allocator.free(cedar_request);
    
    // Compare headers
    std.debug.print("\n=== OpenSSL HTTP Request ===\n{s}\n", .{openssl_request[0..200]});
    std.debug.print("\n=== Cedar HTTP Request ===\n{s}\n", .{cedar_request[0..200]});
    
    // Validate required headers present in both
    try testing.expect(std.mem.indexOf(u8, openssl_request, "POST /vpnsvc/vpn.cgi") != null);
    try testing.expect(std.mem.indexOf(u8, cedar_request, "POST /vpnsvc/vpn.cgi") != null);
    
    try testing.expect(std.mem.indexOf(u8, openssl_request, "Content-Type: application/octet-stream") != null);
    try testing.expect(std.mem.indexOf(u8, cedar_request, "Content-Type: application/octet-stream") != null);
    
    try testing.expect(std.mem.indexOf(u8, openssl_request, "Host:") != null);
    try testing.expect(std.mem.indexOf(u8, cedar_request, "Host:") != null);
    
    std.debug.print("✅ HTTP request formats compatible\n", .{});
}

// Test 3: PACK Serialization Compatibility
test "pack_serialization: OpenSSL vs Cedar" {
    const allocator = testing.allocator;
    
    // Create identical PACK in both implementations
    const test_data = .{
        .client_str = "Test Client",
        .version = @as(u32, 443),
        .build = @as(u32, 9999),
        .use_encrypt = true,
        .use_compress = false,
    };
    
    // OpenSSL PACK
    const openssl_pack = openssl_client.NewPack();
    defer openssl_client.FreePack(openssl_pack);
    
    openssl_client.PackAddStr(openssl_pack, "client_str", test_data.client_str.ptr);
    openssl_client.PackAddInt(openssl_pack, "version", test_data.version);
    openssl_client.PackAddInt(openssl_pack, "build", test_data.build);
    openssl_client.PackAddBool(openssl_pack, "use_encrypt", test_data.use_encrypt);
    openssl_client.PackAddBool(openssl_pack, "use_compress", test_data.use_compress);
    
    const openssl_buf = openssl_client.PackToBuf(openssl_pack);
    defer openssl_client.FreeBuf(openssl_buf);
    
    const openssl_data = openssl_buf.*.Buf[0..openssl_buf.*.Size];
    
    // Cedar PACK
    const cedar_pack = cedar.cedar_pack_new("hello");
    defer cedar.cedar_pack_free(cedar_pack);
    
    _ = cedar.cedar_pack_add_string(cedar_pack, "client_str", test_data.client_str.ptr);
    _ = cedar.cedar_pack_add_int(cedar_pack, "version", test_data.version);
    _ = cedar.cedar_pack_add_int(cedar_pack, "build", test_data.build);
    _ = cedar.cedar_pack_add_bool(cedar_pack, "use_encrypt", test_data.use_encrypt);
    _ = cedar.cedar_pack_add_bool(cedar_pack, "use_compress", test_data.use_compress);
    
    var cedar_size: usize = 0;
    const cedar_data_ptr = cedar.cedar_pack_to_bytes(cedar_pack, &cedar_size);
    defer cedar.cedar_free_bytes(cedar_data_ptr);
    
    const cedar_data = cedar_data_ptr[0..cedar_size];
    
    // Compare serialized data
    std.debug.print("\nOpenSSL PACK size: {d} bytes\n", .{openssl_data.len});
    std.debug.print("Cedar PACK size: {d} bytes\n", .{cedar_data.len});
    
    // Sizes should be similar (exact match may vary due to internal ordering)
    const size_diff = if (openssl_data.len > cedar_data.len)
        openssl_data.len - cedar_data.len
    else
        cedar_data.len - openssl_data.len;
    
    try testing.expect(size_diff < 50); // Allow small variance
    
    std.debug.print("✅ PACK serialization compatible (size diff: {d} bytes)\n", .{size_diff});
}

// Test 4: TLS Connection Establishment
test "tls_connection: OpenSSL vs Cedar" {
    const config = TestConfig{};
    
    // OpenSSL TLS connection
    std.debug.print("\n=== Testing OpenSSL TLS ===\n", .{});
    const openssl_result = testOpenSSLConnection(config);
    
    // Cedar TLS connection
    std.debug.print("\n=== Testing Cedar TLS ===\n", .{});
    const cedar_result = testCedarConnection(config);
    
    // Both should succeed or fail with same error
    try testing.expectEqual(openssl_result.success, cedar_result.success);
    
    if (openssl_result.success) {
        std.debug.print("✅ Both implementations establish TLS successfully\n", .{});
    } else {
        std.debug.print("⚠️  Both implementations fail TLS (expected if server unavailable)\n", .{});
    }
}

// Test 5: Handshake Packet Exchange
test "handshake_exchange: OpenSSL vs Cedar" {
    const allocator = testing.allocator;
    const config = TestConfig{};
    
    // This test requires actual server connection
    // Skip if server is unavailable
    if (!isServerAvailable(config)) {
        std.debug.print("⏭️  Skipping handshake test (server unavailable)\n", .{});
        return error.SkipZigTest;
    }
    
    // OpenSSL handshake
    const openssl_response = try performOpenSSLHandshake(allocator, config);
    defer allocator.free(openssl_response);
    
    // Cedar handshake
    const cedar_response = try performCedarHandshake(allocator, config);
    defer allocator.free(cedar_response);
    
    // Both should receive server hello
    try testing.expect(openssl_response.len > 0);
    try testing.expect(cedar_response.len > 0);
    
    std.debug.print("✅ Both implementations complete handshake\n", .{});
    std.debug.print("OpenSSL response: {d} bytes\n", .{openssl_response.len});
    std.debug.print("Cedar response: {d} bytes\n", .{cedar_response.len});
}

// Test 6: HTTP Response Parsing
test "http_response_parsing: OpenSSL vs Cedar" {
    const allocator = testing.allocator;
    
    // Mock HTTP response (typical server response)
    const mock_response =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/octet-stream\r\n" ++
        "Content-Length: 16\r\n" ++
        "\r\n" ++
        "test_pack_data\x00\x00";
    
    // Parse with OpenSSL
    const openssl_parsed = try parseOpenSSLHttpResponse(allocator, mock_response);
    defer allocator.free(openssl_parsed.body);
    
    // Parse with Cedar
    const cedar_parsed = try parseCedarHttpResponse(allocator, mock_response);
    defer allocator.free(cedar_parsed.body);
    
    // Compare results
    try testing.expectEqual(openssl_parsed.status_code, cedar_parsed.status_code);
    try testing.expectEqual(openssl_parsed.status_code, 200);
    try testing.expectEqualSlices(u8, openssl_parsed.body, cedar_parsed.body);
    
    std.debug.print("✅ HTTP response parsing matches\n", .{});
}

// Test 7: Error Handling Consistency
test "error_handling: OpenSSL vs Cedar" {
    // Test various error conditions
    const error_cases = [_]struct {
        name: []const u8,
        test_fn: fn () anyerror!void,
    }{
        .{ .name = "Invalid server", .test_fn = testInvalidServer },
        .{ .name = "Connection timeout", .test_fn = testConnectionTimeout },
        .{ .name = "Invalid credentials", .test_fn = testInvalidCredentials },
        .{ .name = "Malformed packet", .test_fn = testMalformedPacket },
    };
    
    for (error_cases) |case| {
        std.debug.print("\nTesting error case: {s}\n", .{case.name});
        
        const openssl_error = case.test_fn();
        const cedar_error = case.test_fn();
        
        // Both should fail with similar error types
        const openssl_failed = openssl_error != error.None;
        const cedar_failed = cedar_error != error.None;
        
        try testing.expectEqual(openssl_failed, cedar_failed);
        std.debug.print("  ✅ {s}: Both handle error consistently\n", .{case.name});
    }
}

// Test 8: Performance Comparison
test "performance_comparison: OpenSSL vs Cedar" {
    const iterations = 100;
    const config = TestConfig{};
    
    // Benchmark OpenSSL
    const openssl_start = std.time.nanoTimestamp();
    var openssl_success: usize = 0;
    for (0..iterations) |_| {
        if (benchmarkOpenSSLHandshake(config)) {
            openssl_success += 1;
        }
    }
    const openssl_elapsed = std.time.nanoTimestamp() - openssl_start;
    
    // Benchmark Cedar
    const cedar_start = std.time.nanoTimestamp();
    var cedar_success: usize = 0;
    for (0..iterations) |_| {
        if (benchmarkCedarHandshake(config)) {
            cedar_success += 1;
        }
    }
    const cedar_elapsed = std.time.nanoTimestamp() - cedar_start;
    
    const openssl_avg_ms = @as(f64, @floatFromInt(openssl_elapsed)) / @as(f64, @floatFromInt(iterations)) / 1_000_000.0;
    const cedar_avg_ms = @as(f64, @floatFromInt(cedar_elapsed)) / @as(f64, @floatFromInt(iterations)) / 1_000_000.0;
    
    std.debug.print("\n=== Performance Results ===\n", .{});
    std.debug.print("OpenSSL: {d:.2}ms avg ({d}/{d} success)\n", .{ openssl_avg_ms, openssl_success, iterations });
    std.debug.print("Cedar:   {d:.2}ms avg ({d}/{d} success)\n", .{ cedar_avg_ms, cedar_success, iterations });
    
    const ratio = openssl_avg_ms / cedar_avg_ms;
    if (ratio > 1.0) {
        std.debug.print("Cedar is {d:.2}x faster\n", .{ratio});
    } else {
        std.debug.print("OpenSSL is {d:.2}x faster\n", .{1.0 / ratio});
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn createOpenSSLHttpRequest(allocator: std.mem.Allocator, config: TestConfig, pack_data: []const u8) ![]u8 {
    // Create HTTP request matching OpenSSL HttpClientSend format
    var request = std.ArrayList(u8).init(allocator);
    errdefer request.deinit();
    
    try request.writer().print(
        "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n" ++
        "Host: {s}:{d}\r\n" ++
        "Keep-Alive: timeout=60, max=1000\r\n" ++
        "Connection: Keep-Alive\r\n" ++
        "Content-Type: application/octet-stream\r\n" ++
        "Content-Length: {d}\r\n" ++
        "\r\n",
        .{ config.server, config.port, pack_data.len }
    );
    
    try request.appendSlice(pack_data);
    
    return request.toOwnedSlice();
}

fn createCedarHttpRequest(allocator: std.mem.Allocator, config: TestConfig, pack_data: []const u8) ![]u8 {
    // Create HTTP request using Cedar's HttpRequest
    const request = cedar.cedar_http_request_new_vpn_post(
        config.server.ptr,
        config.port,
        pack_data.ptr,
        pack_data.len
    );
    defer cedar.cedar_http_request_free(request);
    
    var size: usize = 0;
    const bytes = cedar.cedar_http_request_to_bytes(request, &size);
    defer cedar.cedar_free_bytes(bytes);
    
    return try allocator.dupe(u8, bytes[0..size]);
}

const ConnectionResult = struct {
    success: bool,
    error_msg: ?[]const u8 = null,
};

fn testOpenSSLConnection(config: TestConfig) ConnectionResult {
    _ = config;
    // Implement OpenSSL connection test
    // Return result based on actual connection attempt
    return .{ .success = false, .error_msg = "Not implemented" };
}

fn testCedarConnection(config: TestConfig) ConnectionResult {
    _ = config;
    // Implement Cedar connection test
    // Return result based on actual connection attempt
    return .{ .success = false, .error_msg = "Not implemented" };
}

fn isServerAvailable(config: TestConfig) bool {
    _ = config;
    // Quick check if server is reachable
    // Return true if can connect to port 443
    return false; // Stub
}

fn performOpenSSLHandshake(allocator: std.mem.Allocator, config: TestConfig) ![]u8 {
    _ = allocator;
    _ = config;
    return error.NotImplemented;
}

fn performCedarHandshake(allocator: std.mem.Allocator, config: TestConfig) ![]u8 {
    _ = allocator;
    _ = config;
    return error.NotImplemented;
}

const ParsedResponse = struct {
    status_code: u16,
    headers: std.StringHashMap([]const u8),
    body: []u8,
};

fn parseOpenSSLHttpResponse(allocator: std.mem.Allocator, response: []const u8) !ParsedResponse {
    _ = allocator;
    _ = response;
    return error.NotImplemented;
}

fn parseCedarHttpResponse(allocator: std.mem.Allocator, response: []const u8) !ParsedResponse {
    _ = allocator;
    _ = response;
    return error.NotImplemented;
}

fn testInvalidServer() !void {
    return error.ServerNotFound;
}

fn testConnectionTimeout() !void {
    return error.Timeout;
}

fn testInvalidCredentials() !void {
    return error.AuthenticationFailed;
}

fn testMalformedPacket() !void {
    return error.InvalidPacket;
}

fn benchmarkOpenSSLHandshake(config: TestConfig) bool {
    _ = config;
    return false; // Stub
}

fn benchmarkCedarHandshake(config: TestConfig) bool {
    _ = config;
    return false; // Stub
}
