// HTTP/HTTPS Client Implementation
// Pure Zig implementation for VPN client
// Phase 2: Network Layer

const std = @import("std");
const socket = @import("socket.zig");
const TcpSocket = socket.TcpSocket;
const IpAddress = socket.IpAddress;

/// HTTP methods
pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,

    pub fn toString(self: HttpMethod) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
            .OPTIONS => "OPTIONS",
            .PATCH => "PATCH",
        };
    }
};

/// HTTP version
pub const HttpVersion = enum {
    http_1_0,
    http_1_1,
    http_2_0,

    pub fn toString(self: HttpVersion) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
            .http_2_0 => "HTTP/2.0",
        };
    }
};

/// HTTP status code categories
pub const StatusClass = enum {
    informational, // 1xx
    success, // 2xx
    redirection, // 3xx
    client_error, // 4xx
    server_error, // 5xx

    pub fn fromCode(code: u16) StatusClass {
        return switch (code / 100) {
            1 => .informational,
            2 => .success,
            3 => .redirection,
            4 => .client_error,
            5 => .server_error,
            else => .client_error,
        };
    }
};

/// HTTP header key-value pair
pub const HttpHeader = struct {
    name: []const u8,
    value: []const u8,

    pub fn init(name: []const u8, value: []const u8) HttpHeader {
        return HttpHeader{
            .name = name,
            .value = value,
        };
    }
};

/// HTTP request
pub const HttpRequest = struct {
    method: HttpMethod,
    path: []const u8,
    version: HttpVersion,
    headers: std.ArrayList(HttpHeader),
    body: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, method: HttpMethod, path: []const u8) HttpRequest {
        return HttpRequest{
            .method = method,
            .path = path,
            .version = .http_1_1,
            .headers = std.ArrayList(HttpHeader){},
            .body = null,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpRequest) void {
        for (self.headers.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.headers.deinit(self.allocator);
        if (self.body) |body| {
            self.allocator.free(body);
        }
    }

    /// Add a header to the request
    pub fn addHeader(self: *HttpRequest, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);
        try self.headers.append(self.allocator, HttpHeader.init(name_copy, value_copy));
    }

    /// Set request body
    pub fn setBody(self: *HttpRequest, body: []const u8) !void {
        if (self.body) |old_body| {
            self.allocator.free(old_body);
        }
        self.body = try self.allocator.dupe(u8, body);
    }

    /// Build the HTTP request as a string
    pub fn build(self: *HttpRequest) ![]const u8 {
        var result = std.ArrayList(u8){};
        errdefer result.deinit(self.allocator);

        // Request line: METHOD /path HTTP/1.1
        try result.appendSlice(self.allocator, self.method.toString());
        try result.append(self.allocator, ' ');
        try result.appendSlice(self.allocator, self.path);
        try result.append(self.allocator, ' ');
        try result.appendSlice(self.allocator, self.version.toString());
        try result.appendSlice(self.allocator, "\r\n");

        // Headers
        for (self.headers.items) |header| {
            try result.appendSlice(self.allocator, header.name);
            try result.appendSlice(self.allocator, ": ");
            try result.appendSlice(self.allocator, header.value);
            try result.appendSlice(self.allocator, "\r\n");
        }

        // Content-Length if body present
        if (self.body) |body| {
            var buf: [64]u8 = undefined;
            const len_str = try std.fmt.bufPrint(&buf, "{d}", .{body.len});
            try result.appendSlice(self.allocator, "Content-Length: ");
            try result.appendSlice(self.allocator, len_str);
            try result.appendSlice(self.allocator, "\r\n");
        }

        // Empty line between headers and body
        try result.appendSlice(self.allocator, "\r\n");

        // Body
        if (self.body) |body| {
            try result.appendSlice(self.allocator, body);
        }

        return result.toOwnedSlice(self.allocator);
    }
};

/// HTTP response
pub const HttpResponse = struct {
    version: HttpVersion,
    status_code: u16,
    status_message: []const u8,
    headers: std.ArrayList(HttpHeader),
    body: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *HttpResponse) void {
        self.allocator.free(self.status_message);
        for (self.headers.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.headers.deinit(self.allocator);
        self.allocator.free(self.body);
    }

    /// Get a header value by name (case-insensitive)
    pub fn getHeader(self: *const HttpResponse, name: []const u8) ?[]const u8 {
        for (self.headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    /// Get status class (1xx, 2xx, 3xx, 4xx, 5xx)
    pub fn statusClass(self: *const HttpResponse) StatusClass {
        return StatusClass.fromCode(self.status_code);
    }

    /// Check if response indicates success (2xx)
    pub fn isSuccess(self: *const HttpResponse) bool {
        return self.statusClass() == .success;
    }

    /// Check if response indicates redirection (3xx)
    pub fn isRedirect(self: *const HttpResponse) bool {
        return self.statusClass() == .redirection;
    }
};

/// Parse HTTP response from raw bytes
pub fn parseResponse(allocator: std.mem.Allocator, data: []const u8) !HttpResponse {
    // Determine line ending (support both \r\n and \n for tests)
    const has_crlf = std.mem.indexOf(u8, data, "\r\n") != null;
    const line_ending = if (has_crlf) "\r\n" else "\n";
    const double_ending = if (has_crlf) "\r\n\r\n" else "\n\n";

    // Split headers and body
    const header_end = std.mem.indexOf(u8, data, double_ending) orelse return error.InvalidResponse;
    const header_section = data[0..header_end];
    const body = data[header_end + double_ending.len ..];

    var lines = std.mem.splitSequence(u8, header_section, line_ending);

    // Parse status line
    const status_line = lines.next() orelse return error.InvalidResponse;
    var status_parts = std.mem.splitScalar(u8, status_line, ' ');

    const version_str = status_parts.next() orelse return error.InvalidResponse;
    const version = if (std.mem.eql(u8, version_str, "HTTP/1.0"))
        HttpVersion.http_1_0
    else if (std.mem.eql(u8, version_str, "HTTP/1.1"))
        HttpVersion.http_1_1
    else if (std.mem.eql(u8, version_str, "HTTP/2.0"))
        HttpVersion.http_2_0
    else
        return error.InvalidVersion;

    const code_str = status_parts.next() orelse return error.InvalidResponse;
    const status_code = try std.fmt.parseInt(u16, code_str, 10);

    // Get the status message (rest of the line after code)
    const status_message = status_parts.rest();
    const status_message_copy = try allocator.dupe(u8, status_message);

    var headers = std.ArrayList(HttpHeader){};
    errdefer {
        for (headers.items) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        headers.deinit(allocator);
    }

    // Parse headers
    var header_count: usize = 0;
    const max_headers = 128; // HTTP_HEADER_MAX_LINES
    while (lines.next()) |line| {
        if (line.len == 0) break; // Empty line = end of headers
        if (header_count >= max_headers) return error.TooManyHeaders;

        var colon_pos: ?usize = null;
        for (line, 0..) |c, i| {
            if (c == ':') {
                colon_pos = i;
                break;
            }
        }

        if (colon_pos) |pos| {
            const name = std.mem.trim(u8, line[0..pos], " \t");
            const value = std.mem.trim(u8, line[pos + 1 ..], " \t");

            const name_copy = try allocator.dupe(u8, name);
            const value_copy = try allocator.dupe(u8, value);

            try headers.append(allocator, HttpHeader.init(name_copy, value_copy));
            header_count += 1;
        }
    }

    // Copy body
    const body_copy = try allocator.dupe(u8, body);

    return HttpResponse{
        .version = version,
        .status_code = status_code,
        .status_message = status_message_copy,
        .headers = headers,
        .body = body_copy,
        .allocator = allocator,
    };
}

/// HTTP client configuration
pub const HttpClientConfig = struct {
    user_agent: []const u8 = "SoftEtherZig/1.0",
    accept: []const u8 = "*/*",
    timeout_ms: u64 = 30000, // 30 seconds
    max_redirects: u8 = 5,
    follow_redirects: bool = true,
    max_response_size: usize = 100 * 1024 * 1024, // 100MB
};

/// HTTP client
pub const HttpClient = struct {
    allocator: std.mem.Allocator,
    config: HttpClientConfig,

    pub fn init(allocator: std.mem.Allocator, config: HttpClientConfig) HttpClient {
        return HttpClient{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Perform HTTP GET request
    pub fn get(self: *HttpClient, url: []const u8, headers: ?[]const HttpHeader) !HttpResponse {
        return self.request(.GET, url, headers, null);
    }

    /// Perform HTTP POST request
    pub fn post(self: *HttpClient, url: []const u8, headers: ?[]const HttpHeader, body: []const u8) !HttpResponse {
        return self.request(.POST, url, headers, body);
    }

    /// Generic HTTP request
    pub fn request(
        self: *HttpClient,
        method: HttpMethod,
        url: []const u8,
        headers: ?[]const HttpHeader,
        body: ?[]const u8,
    ) !HttpResponse {
        // Parse URL
        const parsed = try parseUrl(self.allocator, url);
        defer {
            self.allocator.free(parsed.scheme);
            self.allocator.free(parsed.host);
            self.allocator.free(parsed.path);
        }

        // Determine if using SSL
        const use_ssl = std.mem.eql(u8, parsed.scheme, "https");
        _ = use_ssl; // SSL/TLS support will be added later

        // Build request
        var req = HttpRequest.init(self.allocator, method, parsed.path);
        defer req.deinit();

        // Add standard headers
        try req.addHeader("Host", parsed.host);
        try req.addHeader("User-Agent", self.config.user_agent);
        try req.addHeader("Accept", self.config.accept);
        try req.addHeader("Connection", "close");

        // Add custom headers
        if (headers) |hdrs| {
            for (hdrs) |header| {
                try req.addHeader(header.name, header.value);
            }
        }

        // Add body if present
        if (body) |b| {
            try req.setBody(b);
            if (method == .POST) {
                try req.addHeader("Content-Type", "application/x-www-form-urlencoded");
            }
        }

        // Build request string
        const request_str = try req.build();
        defer self.allocator.free(request_str);

        // Connect to server
        var sock = try TcpSocket.connect(self.allocator, parsed.host, parsed.port);
        defer sock.close();

        // Set timeout
        sock.setTimeout(self.config.timeout_ms);

        // Send request
        _ = try sock.sendAll(request_str);

        // Receive response
        var response_buf = std.ArrayList(u8){};
        defer response_buf.deinit(self.allocator);

        var recv_buf: [4096]u8 = undefined;
        while (true) {
            const n = sock.recv(&recv_buf) catch |err| {
                if (err == error.WouldBlock) break;
                return err;
            };
            if (n == 0) break; // Connection closed
            try response_buf.appendSlice(self.allocator, recv_buf[0..n]);

            if (response_buf.items.len > self.config.max_response_size) {
                return error.ResponseTooLarge;
            }
        }

        // Parse response
        return try parseResponse(self.allocator, response_buf.items);
    }
};

/// URL components
pub const UrlComponents = struct {
    scheme: []const u8, // http or https
    host: []const u8, // hostname
    port: u16, // port number
    path: []const u8, // path (including query)
};

/// Parse URL into components
pub fn parseUrl(allocator: std.mem.Allocator, url: []const u8) !UrlComponents {
    // Find scheme
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const scheme = url[0..scheme_end];

    const scheme_copy = try allocator.dupe(u8, scheme);
    errdefer allocator.free(scheme_copy);

    // Default ports
    const default_port: u16 = if (std.mem.eql(u8, scheme, "https")) 443 else 80;

    // Parse host and path
    const after_scheme = url[scheme_end + 3 ..];
    const path_start = std.mem.indexOf(u8, after_scheme, "/") orelse after_scheme.len;

    const host_port = after_scheme[0..path_start];
    const path = if (path_start < after_scheme.len) after_scheme[path_start..] else "/";

    // Parse host:port
    var host: []const u8 = undefined;
    var port: u16 = default_port;

    if (std.mem.indexOf(u8, host_port, ":")) |colon_pos| {
        host = host_port[0..colon_pos];
        const port_str = host_port[colon_pos + 1 ..];
        port = try std.fmt.parseInt(u16, port_str, 10);
    } else {
        host = host_port;
    }

    const host_copy = try allocator.dupe(u8, host);
    errdefer allocator.free(host_copy);

    const path_copy = try allocator.dupe(u8, path);
    errdefer allocator.free(path_copy);

    return UrlComponents{
        .scheme = scheme_copy,
        .host = host_copy,
        .port = port,
        .path = path_copy,
    };
}

// ============================================================================
// C FFI Exports for gradual migration
// ============================================================================

export fn zig_http_client_init() ?*HttpClient {
    const allocator = std.heap.c_allocator;
    const client = allocator.create(HttpClient) catch return null;
    client.* = HttpClient.init(allocator, HttpClientConfig{});
    return client;
}

export fn zig_http_client_destroy(client: ?*HttpClient) void {
    if (client) |c| {
        const allocator = std.heap.c_allocator;
        allocator.destroy(c);
    }
}

export fn zig_http_get(
    client: ?*HttpClient,
    url: [*:0]const u8,
    response_body: *[*]u8,
    response_len: *usize,
) c_int {
    const c = client orelse return -1;
    const url_slice = std.mem.span(url);

    var response = c.get(url_slice, null) catch return -1;
    defer response.deinit();

    if (!response.isSuccess()) {
        return -@as(c_int, @intCast(response.status_code));
    }

    const allocator = std.heap.c_allocator;
    const body_copy = allocator.dupe(u8, response.body) catch return -1;

    response_body.* = body_copy.ptr;
    response_len.* = body_copy.len;

    return 0;
}

export fn zig_http_free_response(data: [*]u8, len: usize) void {
    const allocator = std.heap.c_allocator;
    const slice = data[0..len];
    allocator.free(slice);
}

// ============================================================================
// Tests
// ============================================================================

test "HTTP method to string" {
    try std.testing.expectEqualStrings("GET", HttpMethod.GET.toString());
    try std.testing.expectEqualStrings("POST", HttpMethod.POST.toString());
}

test "HTTP version to string" {
    try std.testing.expectEqualStrings("HTTP/1.0", HttpVersion.http_1_0.toString());
    try std.testing.expectEqualStrings("HTTP/1.1", HttpVersion.http_1_1.toString());
}

test "Status class from code" {
    try std.testing.expectEqual(StatusClass.success, StatusClass.fromCode(200));
    try std.testing.expectEqual(StatusClass.redirection, StatusClass.fromCode(301));
    try std.testing.expectEqual(StatusClass.client_error, StatusClass.fromCode(404));
    try std.testing.expectEqual(StatusClass.server_error, StatusClass.fromCode(500));
}

test "Parse URL" {
    const allocator = std.testing.allocator;

    const url = "https://example.com:8080/path/to/resource?query=value";
    const parsed = try parseUrl(allocator, url);
    defer {
        allocator.free(parsed.scheme);
        allocator.free(parsed.host);
        allocator.free(parsed.path);
    }

    try std.testing.expectEqualStrings("https", parsed.scheme);
    try std.testing.expectEqualStrings("example.com", parsed.host);
    try std.testing.expectEqual(@as(u16, 8080), parsed.port);
    try std.testing.expectEqualStrings("/path/to/resource?query=value", parsed.path);
}

test "Parse URL without port" {
    const allocator = std.testing.allocator;

    const url = "http://example.com/test";
    const parsed = try parseUrl(allocator, url);
    defer {
        allocator.free(parsed.scheme);
        allocator.free(parsed.host);
        allocator.free(parsed.path);
    }

    try std.testing.expectEqualStrings("http", parsed.scheme);
    try std.testing.expectEqual(@as(u16, 80), parsed.port);
}

test "Parse URL without path" {
    const allocator = std.testing.allocator;

    const url = "https://example.com";
    const parsed = try parseUrl(allocator, url);
    defer {
        allocator.free(parsed.scheme);
        allocator.free(parsed.host);
        allocator.free(parsed.path);
    }

    try std.testing.expectEqualStrings("/", parsed.path);
}

test "Build HTTP GET request" {
    const allocator = std.testing.allocator;

    var req = HttpRequest.init(allocator, .GET, "/test");
    defer req.deinit();

    try req.addHeader("Host", "example.com");
    try req.addHeader("User-Agent", "TestClient/1.0");

    const request_str = try req.build();
    defer allocator.free(request_str);

    try std.testing.expect(std.mem.indexOf(u8, request_str, "GET /test HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "Host: example.com") != null);
}

test "Build HTTP POST request with body" {
    const allocator = std.testing.allocator;

    var req = HttpRequest.init(allocator, .POST, "/submit");
    defer req.deinit();

    try req.addHeader("Host", "example.com");
    try req.setBody("test=data");

    const request_str = try req.build();
    defer allocator.free(request_str);

    try std.testing.expect(std.mem.indexOf(u8, request_str, "POST /submit HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "Content-Length: 9") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "test=data") != null);
}

test "Parse HTTP response" {
    const allocator = std.testing.allocator;

    const response_data =
        \\HTTP/1.1 200 OK
        \\Content-Type: text/html
        \\Content-Length: 13
        \\
        \\Hello, World!
    ;

    var response = try parseResponse(allocator, response_data);
    defer response.deinit();

    try std.testing.expectEqual(HttpVersion.http_1_1, response.version);
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("OK", response.status_message);
    try std.testing.expectEqual(@as(usize, 2), response.headers.items.len);
    try std.testing.expectEqualStrings("Hello, World!", response.body);
}

test "Response get header case-insensitive" {
    const allocator = std.testing.allocator;

    const response_data =
        \\HTTP/1.1 200 OK
        \\Content-Type: application/json
        \\
        \\{}
    ;

    var response = try parseResponse(allocator, response_data);
    defer response.deinit();

    try std.testing.expectEqualStrings("application/json", response.getHeader("Content-Type").?);
    try std.testing.expectEqualStrings("application/json", response.getHeader("content-type").?);
    try std.testing.expectEqualStrings("application/json", response.getHeader("CONTENT-TYPE").?);
}

test "Response status helpers" {
    const allocator = std.testing.allocator;

    const success_response =
        \\HTTP/1.1 200 OK
        \\
        \\
    ;
    var resp = try parseResponse(allocator, success_response);
    defer resp.deinit();

    try std.testing.expect(resp.isSuccess());
    try std.testing.expect(!resp.isRedirect());
}
