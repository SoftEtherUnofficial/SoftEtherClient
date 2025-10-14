// HTTP Client for SoftEther VPN Protocol
// Handles HTTP/SSL communication with VPN server
const std = @import("std");
const Allocator = std.mem.Allocator;
const Pack = @import("pack.zig").Pack;
const SslSocket = @import("ssl_socket.zig").SslSocket;

/// HTTP method
pub const HttpMethod = enum {
    GET,
    POST,

    pub fn toString(self: HttpMethod) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
        };
    }
};

/// HTTP header
pub const HttpHeader = struct {
    name: []const u8,
    value: []const u8,

    pub fn init(name: []const u8, value: []const u8) HttpHeader {
        return .{ .name = name, .value = value };
    }
};

/// HTTP request builder
pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    version: []const u8 = "HTTP/1.1",
    headers: std.ArrayList(HttpHeader),
    body: ?[]const u8 = null,
    allocator: Allocator,

    pub fn init(allocator: Allocator, method: HttpMethod, path: []const u8) HttpRequest {
        return .{
            .method = method,
            .path = path,
            .headers = std.ArrayList(HttpHeader).empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpRequest) void {
        self.headers.deinit(self.allocator);
    }

    pub fn addHeader(self: *HttpRequest, name: []const u8, value: []const u8) !void {
        try self.headers.append(self.allocator, HttpHeader.init(name, value));
    }

    pub fn setBody(self: *HttpRequest, body: []const u8) void {
        self.body = body;
    }

    /// Build HTTP request as string
    pub fn build(self: *const HttpRequest, writer: anytype) !void {
        // Request line: METHOD PATH VERSION
        try writer.print("{s} {s} {s}\r\n", .{
            self.method.toString(),
            self.path,
            self.version,
        });

        // Headers
        for (self.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // Content-Length if body exists
        if (self.body) |body| {
            try writer.print("Content-Length: {d}\r\n", .{body.len});
        }

        // End of headers
        try writer.writeAll("\r\n");

        // Body
        if (self.body) |body| {
            try writer.writeAll(body);
        }
    }

    /// Build HTTP request as byte array
    pub fn toBytes(self: *const HttpRequest) ![]u8 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.allocator);
        try self.build(list.writer(self.allocator));
        return try list.toOwnedSlice(self.allocator);
    }
};

/// HTTP response
pub const HttpResponse = struct {
    version: []const u8,
    status_code: u32,
    status_text: []const u8,
    headers: std.StringHashMap([]const u8),
    body: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *HttpResponse) void {
        var it = self.headers.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.headers.deinit();
        self.allocator.free(self.version);
        self.allocator.free(self.status_text);
        self.allocator.free(self.body);
    }

    pub fn getHeader(self: *const HttpResponse, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    /// Parse HTTP response from reader
    pub fn parse(reader: anytype, allocator: Allocator) !HttpResponse {
        var headers = std.StringHashMap([]const u8).init(allocator);
        errdefer {
            var it = headers.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                allocator.free(entry.value_ptr.*);
            }
            headers.deinit();
        }

        // Read status line: HTTP/1.1 200 OK
        var status_line_buf: [1024]u8 = undefined;
        const status_line = (try reader.readUntilDelimiterOrEof(&status_line_buf, '\n')) orelse return error.InvalidResponse;

        // Trim \r\n
        const trimmed_status = std.mem.trimRight(u8, status_line, "\r\n");

        // Parse: VERSION STATUS_CODE STATUS_TEXT
        var status_parts = std.mem.splitScalar(u8, trimmed_status, ' ');
        const version = status_parts.next() orelse return error.InvalidStatusLine;
        const status_code_str = status_parts.next() orelse return error.InvalidStatusLine;
        const status_text = status_parts.rest();

        const version_copy = try allocator.dupe(u8, version);
        errdefer allocator.free(version_copy);

        const status_text_copy = try allocator.dupe(u8, status_text);
        errdefer allocator.free(status_text_copy);

        const status_code = try std.fmt.parseInt(u32, status_code_str, 10);

        // Read headers
        while (true) {
            var header_buf: [4096]u8 = undefined;
            const header_line = (try reader.readUntilDelimiterOrEof(&header_buf, '\n')) orelse break;
            const trimmed = std.mem.trimRight(u8, header_line, "\r\n");

            if (trimmed.len == 0) break; // End of headers

            // Parse "Name: Value"
            const colon_pos = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
            const name = std.mem.trim(u8, trimmed[0..colon_pos], " ");
            const value = std.mem.trim(u8, trimmed[colon_pos + 1 ..], " ");

            const name_copy = try allocator.dupe(u8, name);
            errdefer allocator.free(name_copy);
            const value_copy = try allocator.dupe(u8, value);
            errdefer allocator.free(value_copy);

            try headers.put(name_copy, value_copy);
        }

        // Read body
        const content_length_str = headers.get("Content-Length") orelse "0";
        const content_length = try std.fmt.parseInt(usize, content_length_str, 10);

        const body = try allocator.alloc(u8, content_length);
        errdefer allocator.free(body);

        if (content_length > 0) {
            const bytes_read = try reader.readAll(body);
            if (bytes_read != content_length) {
                return error.IncompleteBody;
            }
        }

        return HttpResponse{
            .version = version_copy,
            .status_code = status_code,
            .status_text = status_text_copy,
            .headers = headers,
            .body = body,
            .allocator = allocator,
        };
    }
};

/// SoftEther VPN HTTP client
pub const VpnHttpClient = struct {
    allocator: Allocator,

    // SoftEther protocol constants
    pub const VPN_TARGET = "/vpnsvc/vpn.cgi";
    pub const CONTENT_TYPE = "application/octet-stream";
    pub const KEEP_ALIVE_TIMEOUT = "300";

    pub fn init(allocator: Allocator) VpnHttpClient {
        return .{ .allocator = allocator };
    }

    /// Send PACK to VPN server and receive response
    pub fn sendPack(
        self: *VpnHttpClient,
        pack: *const Pack,
        server_ip: []const u8,
        port: u16,
    ) !*Pack {
        // Initialize SSL library (idempotent, safe to call multiple times)
        SslSocket.initLibrary();

        // Serialize pack to bytes
        const pack_bytes = try pack.toBytes();
        defer self.allocator.free(pack_bytes);

        // Build HTTP POST request
        var request = HttpRequest.init(self.allocator, .POST, VPN_TARGET);
        defer request.deinit();

        // Get current time
        const timestamp = std.time.timestamp();
        var date_buf: [64]u8 = undefined;
        const date_str = try std.fmt.bufPrint(&date_buf, "{d}", .{timestamp});

        // Add headers
        try request.addHeader("Host", server_ip);
        try request.addHeader("Date", date_str);
        try request.addHeader("Keep-Alive", KEEP_ALIVE_TIMEOUT);
        try request.addHeader("Connection", "Keep-Alive");
        try request.addHeader("Content-Type", CONTENT_TYPE);

        // Set body
        request.setBody(pack_bytes);

        // Build request bytes
        const request_bytes = try request.toBytes();
        defer self.allocator.free(request_bytes);

        std.log.debug("Connecting to {s}:{d} via SSL...", .{ server_ip, port });

        // Connect to server via SSL
        const socket = SslSocket.connect(self.allocator, server_ip, port) catch |err| {
            std.log.err("SSL connection failed: {}", .{err});
            return err;
        };
        defer socket.close();

        std.log.debug("SSL connection established", .{});

        // Send HTTP request
        _ = socket.write(request_bytes) catch |err| {
            std.log.err("Failed to send request: {}", .{err});
            return err;
        };

        std.log.debug("Sent {d} bytes to server", .{request_bytes.len});

        // Read response
        var response_buffer: [65536]u8 = undefined; // 64 KB buffer
        const bytes_read = socket.read(&response_buffer) catch |err| {
            std.log.err("Failed to read response: {}", .{err});
            return err;
        };

        std.log.debug("Received {d} bytes from server", .{bytes_read});

        // Parse HTTP response
        const response = try HttpResponse.parse(self.allocator, response_buffer[0..bytes_read]);
        defer response.deinit();

        std.log.debug("HTTP response: status={d} body_len={d}", .{
            response.status_code,
            response.body.len,
        });

        // Check HTTP status
        if (response.status_code != 200) {
            std.log.err("Server returned error status: {d}", .{response.status_code});
            return error.HttpError;
        }

        // Parse PACK from response body
        return Pack.fromBytes(self.allocator, response.body);
    }

    /// Create a mock authentication success response
    /// In production, this would parse the actual server response
    fn createMockResponse(self: *VpnHttpClient) !*Pack {
        const response = try Pack.init(self.allocator);
        errdefer response.deinit();

        try response.addInt("error", 0); // 0 = success
        try response.addString("server_str", "SoftEther VPN Server (Mock)");
        try response.addInt("server_ver", 502);
        try response.addInt("server_build", 9999);

        // Mock session key (in production, server generates this)
        const mock_session_key = "MOCK_SESSION_KEY_1234567890";
        try response.addData("session_key", mock_session_key);

        return response;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "HttpRequest: build GET request" {
    const allocator = std.testing.allocator;

    var request = HttpRequest.init(allocator, .GET, "/test");
    defer request.deinit();

    try request.addHeader("Host", "example.com");
    try request.addHeader("User-Agent", "Test");

    const bytes = try request.toBytes();
    defer allocator.free(bytes);

    try std.testing.expect(std.mem.indexOf(u8, bytes, "GET /test HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Host: example.com") != null);
}

test "HttpRequest: build POST with body" {
    const allocator = std.testing.allocator;

    var request = HttpRequest.init(allocator, .POST, "/api");
    defer request.deinit();

    try request.addHeader("Content-Type", "text/plain");
    request.setBody("test data");

    const bytes = try request.toBytes();
    defer allocator.free(bytes);

    try std.testing.expect(std.mem.indexOf(u8, bytes, "POST /api HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "Content-Length: 9") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "test data") != null);
}

test "HttpResponse: parse simple response" {
    const allocator = std.testing.allocator;

    const response_text =
        \\HTTP/1.1 200 OK
        \\Content-Type: text/plain
        \\Content-Length: 4
        \\
        \\test
    ;

    var stream = std.io.fixedBufferStream(response_text);
    var response = try HttpResponse.parse(stream.reader(), allocator);
    defer response.deinit();

    try std.testing.expectEqual(@as(u32, 200), response.status_code);
    try std.testing.expectEqualStrings("OK", response.status_text);
    try std.testing.expectEqualStrings("text/plain", response.getHeader("Content-Type").?);
    try std.testing.expectEqualStrings("test", response.body);
}

test "VpnHttpClient: send pack (mock)" {
    const allocator = std.testing.allocator;

    var client = VpnHttpClient.init(allocator);

    // Create test pack
    const pack = try Pack.init(allocator);
    defer pack.deinit();
    try pack.addString("method", "password");
    try pack.addString("username", "test");

    // Send and receive response
    const response = try client.sendPack(pack, "192.168.1.1");
    defer response.deinit();

    // Verify response
    try std.testing.expectEqual(@as(i32, 0), response.getInt("error").?);
    try std.testing.expect(response.getData("session_key") != null);
}
