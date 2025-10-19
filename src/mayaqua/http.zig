//! HTTP utilities for SoftEther VPN protocol communication
//!
//! This module provides minimal HTTP/1.1 client functionality needed for
//! SoftEther VPN operations including HTTP tunnel mode and server discovery.
//!
//! Features:
//! - HTTP request building (GET, POST, etc.)
//! - HTTP response parsing
//! - Header management
//! - Content-Length handling
//! - Basic error handling
//!
//! Reference: SoftEtherRust/libs/mayaqua/src/http.rs (199 lines)
//!
//! Usage:
//! ```zig
//! const http = @import("mayaqua/http.zig");
//!
//! var client = try http.HttpClient.init(allocator, "example.com", 80);
//! defer client.deinit();
//!
//! const headers = [_]http.Header{
//!     .{ .name = "User-Agent", .value = "SoftEtherVPN/5.0" },
//! };
//!
//! var response = try client.request("GET", "/", &headers, null);
//! defer response.deinit();
//!
//! if (response.isSuccess()) {
//!     std.debug.print("Body: {s}\n", .{response.body});
//! }
//! ```

const std = @import("std");
const network = @import("network.zig");
const Allocator = std.mem.Allocator;

/// HTTP request header
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP request structure
pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    headers: std.ArrayList(Header),
    body: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, method: []const u8, path: []const u8) !HttpRequest {
        return HttpRequest{
            .method = method,
            .path = path,
            .headers = try std.ArrayList(Header).initCapacity(allocator, 8),
            .body = &[_]u8{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpRequest) void {
        self.headers.deinit(self.allocator);
    }

    /// Add a header to the request
    pub fn addHeader(self: *HttpRequest, name: []const u8, value: []const u8) !void {
        try self.headers.append(self.allocator, .{ .name = name, .value = value });
    }

    /// Set the request body (does NOT add Content-Length header - caller should add it)
    pub fn setBody(self: *HttpRequest, body: []const u8) void {
        self.body = body;
    }

    /// Convert the request to bytes for transmission
    pub fn toBytes(self: *const HttpRequest, allocator: Allocator) ![]u8 {
        var list = try std.ArrayList(u8).initCapacity(allocator, 512);
        errdefer list.deinit(allocator);

        const writer = list.writer(allocator);

        // Write request line: METHOD PATH HTTP/1.1
        try writer.print("{s} {s} HTTP/1.1\r\n", .{ self.method, self.path });

        // Write headers
        for (self.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // End headers
        try writer.writeAll("\r\n");

        // Append body if present
        if (self.body.len > 0) {
            try writer.writeAll(self.body);
        }

        return list.toOwnedSlice(allocator);
    }
};

/// HTTP response structure
pub const HttpResponse = struct {
    status_code: u16,
    reason: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []u8,
    allocator: Allocator,

    pub fn deinit(self: *HttpResponse) void {
        // Free all lowercase header name keys
        var it = self.headers.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.headers.deinit();
        self.allocator.free(self.body);
        self.allocator.free(self.reason);
    }

    /// Parse HTTP response from raw bytes
    pub fn fromBytes(allocator: Allocator, data: []const u8) !HttpResponse {
        var lines = std.mem.splitSequence(u8, data, "\r\n");

        // Parse status line: HTTP/1.1 200 OK
        const status_line = lines.next() orelse return error.InvalidResponse;
        var status_parts = std.mem.splitScalar(u8, status_line, ' ');

        _ = status_parts.next(); // HTTP/1.1
        const code_str = status_parts.next() orelse return error.InvalidStatusCode;
        const reason = status_parts.rest();

        const status_code = try std.fmt.parseInt(u16, code_str, 10);

        // Parse headers
        var headers = std.StringHashMap([]const u8).init(allocator);
        errdefer headers.deinit();

        var content_length: usize = 0;

        while (lines.next()) |line| {
            if (line.len == 0) break; // End of headers

            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const name = line[0..colon_pos];
            var value = line[colon_pos + 1 ..];

            // Trim leading whitespace from value
            while (value.len > 0 and value[0] == ' ') {
                value = value[1..];
            }

            // Store header with lowercase name for case-insensitive lookup
            const name_lower = try std.ascii.allocLowerString(allocator, name);
            try headers.put(name_lower, value);

            // Track Content-Length
            if (std.mem.eql(u8, name_lower, "content-length")) {
                content_length = try std.fmt.parseInt(usize, value, 10);
            }
        }

        // Find body start (after \r\n\r\n)
        const body_marker = "\r\n\r\n";
        const body_start_pos = std.mem.indexOf(u8, data, body_marker) orelse data.len;
        const body_start = body_start_pos + body_marker.len;

        // Read body
        const body = if (body_start < data.len and content_length > 0)
            try allocator.dupe(u8, data[body_start .. body_start + @min(content_length, data.len - body_start)])
        else
            try allocator.alloc(u8, 0);

        return HttpResponse{
            .status_code = status_code,
            .reason = try allocator.dupe(u8, reason),
            .headers = headers,
            .body = body,
            .allocator = allocator,
        };
    }

    /// Get a header value (case-insensitive)
    pub fn getHeader(self: *const HttpResponse, name: []const u8) ?[]const u8 {
        // Convert name to lowercase for lookup
        var name_lower_buf: [256]u8 = undefined;
        if (name.len > name_lower_buf.len) return null;

        const name_lower = std.ascii.lowerString(&name_lower_buf, name);
        return self.headers.get(name_lower);
    }

    /// Check if response is successful (2xx status code)
    pub fn isSuccess(self: *const HttpResponse) bool {
        return self.status_code >= 200 and self.status_code < 300;
    }
};

/// HTTP client for making requests
pub const HttpClient = struct {
    stream: network.TcpClient,
    host: []const u8,
    port: u16,
    allocator: Allocator,

    pub fn init(allocator: Allocator, host: []const u8, port: u16) !HttpClient {
        const addr = network.Address{
            .hostname = host,
            .port = port,
        };

        const stream = try network.TcpClient.connect(addr, 5000); // 5 second timeout

        return HttpClient{
            .stream = stream,
            .host = host,
            .port = port,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpClient) void {
        self.stream.close();
    }

    /// Make an HTTP request
    pub fn request(
        self: *HttpClient,
        method: []const u8,
        path: []const u8,
        headers: ?[]const Header,
        body: ?[]const u8,
    ) !HttpResponse {
        // Build request
        var req = try HttpRequest.init(self.allocator, method, path);
        defer req.deinit();

        // Add Host header
        const host_header = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.host, self.port });
        defer self.allocator.free(host_header);
        try req.addHeader("Host", host_header);

        // Add custom headers
        if (headers) |hdrs| {
            for (hdrs) |hdr| {
                try req.addHeader(hdr.name, hdr.value);
            }
        }

        // Set body if present
        if (body) |b| {
            try req.setBody(b);
        }

        // Convert to bytes
        const request_bytes = try req.toBytes(self.allocator);
        defer self.allocator.free(request_bytes);

        // Send request
        _ = try self.stream.send(request_bytes);

        // Receive response
        const response_data = try self.stream.receive(self.allocator, 65536);
        defer self.allocator.free(response_data);

        // Parse response
        return try HttpResponse.fromBytes(self.allocator, response_data);
    }

    /// Make a GET request
    pub fn get(self: *HttpClient, path: []const u8, headers: ?[]const Header) !HttpResponse {
        return try self.request("GET", path, headers, null);
    }

    /// Make a POST request
    pub fn post(self: *HttpClient, path: []const u8, headers: ?[]const Header, body: []const u8) !HttpResponse {
        return try self.request("POST", path, headers, body);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "HTTP request creation" {
    const allocator = std.testing.allocator;

    var req = try HttpRequest.init(allocator, "GET", "/test");
    defer req.deinit();

    try req.addHeader("Host", "example.com");
    try req.addHeader("User-Agent", "TestClient/1.0");

    const bytes = try req.toBytes(allocator);
    defer allocator.free(bytes);

    const request_str = bytes;
    try std.testing.expect(std.mem.indexOf(u8, request_str, "GET /test HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "Host: example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "User-Agent: TestClient/1.0") != null);
}

test "HTTP request with body" {
    const allocator = std.testing.allocator;

    var req = try HttpRequest.init(allocator, "POST", "/api");
    defer req.deinit();

    try req.addHeader("Host", "api.example.com");
    try req.setBody("test body");

    const bytes = try req.toBytes(allocator);
    defer allocator.free(bytes);

    const request_str = bytes;
    try std.testing.expect(std.mem.indexOf(u8, request_str, "POST /api HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "Content-Length:") != null);
    try std.testing.expect(std.mem.endsWith(u8, request_str, "test body"));
}

test "HTTP response parsing - success" {
    const allocator = std.testing.allocator;

    const response_data = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\nHello World";

    var response = try HttpResponse.fromBytes(allocator, response_data);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expect(response.isSuccess());
    try std.testing.expectEqualStrings("OK", response.reason);

    const content_length = response.getHeader("Content-Length");
    try std.testing.expect(content_length != null);
    try std.testing.expectEqualStrings("11", content_length.?);

    const content_type = response.getHeader("content-type"); // Test case-insensitive
    try std.testing.expect(content_type != null);
    try std.testing.expectEqualStrings("text/plain", content_type.?);

    try std.testing.expectEqualStrings("Hello World", response.body);
}

test "HTTP response parsing - no body" {
    const allocator = std.testing.allocator;

    const response_data = "HTTP/1.1 204 No Content\r\n\r\n";

    var response = try HttpResponse.fromBytes(allocator, response_data);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 204), response.status_code);
    try std.testing.expect(response.isSuccess());
    try std.testing.expectEqual(@as(usize, 0), response.body.len);
}

test "HTTP response parsing - error status" {
    const allocator = std.testing.allocator;

    const response_data = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";

    var response = try HttpResponse.fromBytes(allocator, response_data);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 404), response.status_code);
    try std.testing.expect(!response.isSuccess());
    try std.testing.expectEqualStrings("Not Found", response.reason);
    try std.testing.expectEqualStrings("Not Found", response.body);
}

test "HTTP response header case insensitivity" {
    const allocator = std.testing.allocator;

    const response_data = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}";

    var response = try HttpResponse.fromBytes(allocator, response_data);
    defer response.deinit();

    // Test various case combinations
    try std.testing.expect(response.getHeader("Content-Type") != null);
    try std.testing.expect(response.getHeader("content-type") != null);
    try std.testing.expect(response.getHeader("CONTENT-TYPE") != null);
    try std.testing.expect(response.getHeader("CoNtEnT-tYpE") != null);
}

test "HTTP response with multiple headers" {
    const allocator = std.testing.allocator;

    const response_data =
        \\HTTP/1.1 200 OK
        \\Server: TestServer/1.0
        \\Content-Type: text/html
        \\Content-Length: 13
        \\Cache-Control: no-cache
        \\
        \\<html></html>
    ;

    var response = try HttpResponse.fromBytes(allocator, response_data);
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expect(response.getHeader("Server") != null);
    try std.testing.expect(response.getHeader("Content-Type") != null);
    try std.testing.expect(response.getHeader("Cache-Control") != null);
    try std.testing.expectEqualStrings("<html></html>", response.body);
}
