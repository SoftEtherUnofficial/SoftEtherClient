//! HTTP Protocol Format Test
//!
//! Compares HTTP request format between OpenSSL (C) and Cedar (Rust)
//! to identify the difference causing HTTP 501 error.

const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("\n=== SoftEther HTTP Protocol Format Comparison ===\n\n", .{});

    // Test configuration
    const server = "worxvpn.662.cloud";
    const port: u16 = 443;

    // Sample PACK data (simplified for testing)
    const sample_pack = createSamplePack();

    std.debug.print("Sample PACK data: {d} bytes\n\n", .{sample_pack.len});

    // Generate OpenSSL-style HTTP request
    std.debug.print("=== OpenSSL HTTP Request Format ===\n", .{});
    const openssl_request = try generateOpenSSLRequest(allocator, server, port, &sample_pack);
    defer allocator.free(openssl_request);

    printHttpRequest(openssl_request);

    // Generate Cedar-style HTTP request
    std.debug.print("\n=== Cedar HTTP Request Format ===\n", .{});
    const cedar_request = try generateCedarRequest(allocator, server, port, &sample_pack);
    defer allocator.free(cedar_request);

    printHttpRequest(cedar_request);

    // Compare
    std.debug.print("\n=== Comparison ===\n", .{});
    try compareRequests(openssl_request, cedar_request);

    std.debug.print("\n✅ Analysis complete. Check differences above.\n", .{});
}

fn createSamplePack() [140]u8 {
    // Simplified PACK structure matching what Cedar sends
    var pack = [_]u8{0} ** 140;

    // PACK header (simplified)
    pack[0] = 0x00; // Version
    pack[1] = 0x00;
    pack[2] = 0x00;
    pack[3] = 0x88; // Size: 136 bytes

    // Add some test data
    const test_data = "client_str=Cedar-Zig-Client/1.0";
    @memcpy(pack[4..][0..test_data.len], test_data);

    return pack;
}

fn generateOpenSSLRequest(allocator: std.mem.Allocator, server: []const u8, port: u16, pack_data: []const u8) ![]u8 {
    _ = port; // OpenSSL doesn't include port in Host header
    // This matches SoftEther's HttpClientSend() format from Network.c
    var request = try std.ArrayList(u8).initCapacity(allocator, 512);
    errdefer request.deinit(allocator);

    const writer = request.writer(allocator);

    // Request line
    try writer.writeAll("POST /vpnsvc/vpn.cgi HTTP/1.1\r\n");

    // Date header (OpenSSL includes this)
    try writer.print("Date: {s}\r\n", .{getCurrentHttpDate()});

    // Host header
    try writer.print("Host: {s}\r\n", .{server});

    // Keep-Alive headers
    try writer.writeAll("Keep-Alive: timeout=60, max=1000\r\n");
    try writer.writeAll("Connection: Keep-Alive\r\n");

    // Content headers
    try writer.writeAll("Content-Type: application/octet-stream\r\n");
    try writer.print("Content-Length: {d}\r\n", .{pack_data.len});

    // End headers
    try writer.writeAll("\r\n");

    // Binary body
    try writer.writeAll(pack_data);

    return request.toOwnedSlice(allocator);
}

fn generateCedarRequest(allocator: std.mem.Allocator, server: []const u8, port: u16, pack_data: []const u8) ![]u8 {
    _ = port; // Cedar doesn't include port in Host header (matches OpenSSL)
    // This matches Cedar's HttpRequest::new_vpn_post() format (FIXED VERSION)
    var request = try std.ArrayList(u8).initCapacity(allocator, 512);
    errdefer request.deinit(allocator);

    const writer = request.writer(allocator);

    // Request line
    try writer.writeAll("POST /vpnsvc/vpn.cgi HTTP/1.1\r\n");

    // Headers in exact order as OpenSSL (Date first!)
    try writer.print("Date: {s}\r\n", .{getCurrentHttpDate()});

    // Host header (WITHOUT port - matches OpenSSL)
    try writer.print("Host: {s}\r\n", .{server});

    // Keep-Alive headers
    try writer.writeAll("Keep-Alive: timeout=60, max=1000\r\n");
    try writer.writeAll("Connection: Keep-Alive\r\n");

    // Content headers
    try writer.writeAll("Content-Type: application/octet-stream\r\n");
    try writer.print("Content-Length: {d}\r\n", .{pack_data.len});

    // End headers
    try writer.writeAll("\r\n");

    // Binary body
    try writer.writeAll(pack_data);

    return request.toOwnedSlice(allocator);
}

fn printHttpRequest(request: []const u8) void {
    // Print headers (up to \r\n\r\n)
    var i: usize = 0;
    var header_end: usize = 0;

    while (i < request.len - 3) : (i += 1) {
        if (request[i] == '\r' and request[i + 1] == '\n' and
            request[i + 2] == '\r' and request[i + 3] == '\n')
        {
            header_end = i + 4;
            break;
        }
    }

    // Print headers
    const headers = request[0..header_end];
    std.debug.print("{s}", .{headers});

    // Print body info
    const body = request[header_end..];
    std.debug.print("Body: {d} bytes (binary PACK data)\n", .{body.len});
    std.debug.print("First 32 bytes: ", .{});
    for (body[0..@min(32, body.len)]) |byte| {
        std.debug.print("{x:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});
}

fn compareRequests(openssl: []const u8, cedar: []const u8) !void {
    // Find header sections
    const openssl_headers = extractHeaders(openssl);
    const cedar_headers = extractHeaders(cedar);

    // Parse headers into lines
    var openssl_lines = try std.ArrayList([]const u8).initCapacity(std.heap.page_allocator, 20);
    defer openssl_lines.deinit(std.heap.page_allocator);

    var cedar_lines = try std.ArrayList([]const u8).initCapacity(std.heap.page_allocator, 20);
    defer cedar_lines.deinit(std.heap.page_allocator);
    var it = std.mem.splitSequence(u8, openssl_headers, "\r\n");
    while (it.next()) |line| {
        if (line.len > 0) try openssl_lines.append(std.heap.page_allocator, line);
    }

    it = std.mem.splitSequence(u8, cedar_headers, "\r\n");
    while (it.next()) |line| {
        if (line.len > 0) try cedar_lines.append(std.heap.page_allocator, line);
    }

    // Compare line by line
    std.debug.print("\nLine-by-line comparison:\n", .{});
    std.debug.print("{s: <50} | {s}\n", .{ "OpenSSL", "Cedar" });
    std.debug.print("{s}\n", .{"-" ** 105});

    const max_lines = @max(openssl_lines.items.len, cedar_lines.items.len);

    for (0..max_lines) |i| {
        const openssl_line = if (i < openssl_lines.items.len) openssl_lines.items[i] else "";
        const cedar_line = if (i < cedar_lines.items.len) cedar_lines.items[i] else "";

        const match = std.mem.eql(u8, openssl_line, cedar_line);
        const marker: []const u8 = if (match) "✓" else "✗";

        std.debug.print("{s: <50} | {s: <50} {s}\n", .{ openssl_line, cedar_line, marker });
    }

    // Identify differences
    std.debug.print("\n🔍 Key Differences:\n", .{});

    // Check Host header format
    const openssl_has_port = std.mem.indexOf(u8, openssl_headers, "Host: worxvpn.662.cloud:443") != null;
    const cedar_has_port = std.mem.indexOf(u8, cedar_headers, "Host: worxvpn.662.cloud:443") != null;

    if (openssl_has_port != cedar_has_port) {
        std.debug.print("  • Host header: OpenSSL {s}port, Cedar {s}port\n", .{
            if (openssl_has_port) "includes " else "excludes ",
            if (cedar_has_port) "includes " else "excludes ",
        });
    }

    // Check Date header
    const openssl_has_date = std.mem.indexOf(u8, openssl_headers, "Date:") != null;
    const cedar_has_date = std.mem.indexOf(u8, cedar_headers, "Date:") != null;

    if (openssl_has_date != cedar_has_date) {
        std.debug.print("  • Date header: OpenSSL {s}, Cedar {s}\n", .{
            if (openssl_has_date) "present" else "missing",
            if (cedar_has_date) "present" else "missing",
        });
    }
}

fn extractHeaders(request: []const u8) []const u8 {
    var i: usize = 0;
    while (i < request.len - 3) : (i += 1) {
        if (request[i] == '\r' and request[i + 1] == '\n' and
            request[i + 2] == '\r' and request[i + 3] == '\n')
        {
            return request[0..i];
        }
    }
    return request;
}

fn getCurrentHttpDate() []const u8 {
    // Return a valid HTTP date string
    // For testing, use a static date
    return "Thu, 10 Oct 2025 14:00:00 GMT";
}
