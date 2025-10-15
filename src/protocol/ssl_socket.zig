// SSL Socket Wrapper for Zig
// Provides a clean interface to OpenSSL for VPN communication
const std = @import("std");
const Allocator = std.mem.Allocator;
const posix = std.posix;

// OpenSSL C bindings
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
    @cInclude("sys/socket.h");
    @cInclude("netinet/in.h");
    @cInclude("arpa/inet.h");
    @cInclude("netdb.h");
    @cInclude("unistd.h");
});

/// SSL connection errors
pub const SslError = error{
    InitializationFailed,
    ContextCreationFailed,
    ConnectionFailed,
    HandshakeFailed,
    ReadFailed,
    WriteFailed,
    SocketCreationFailed,
    HostResolutionFailed,
    Timeout,
    Disconnected,
};

/// SSL socket connection
pub const SslSocket = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,
    sock_fd: c_int,
    allocator: Allocator,

    /// Initialize OpenSSL library (call once at program start)
    pub fn initLibrary() void {
        // OpenSSL 1.1.0+ handles initialization automatically
        // These are no-ops in OpenSSL 3.x but included for compatibility
        _ = c.OPENSSL_init_ssl(0, null);
        _ = c.OPENSSL_init_crypto(0, null);
    }

    /// Cleanup OpenSSL library (call once at program end)
    pub fn cleanupLibrary() void {
        // OpenSSL 3.x handles cleanup automatically
        // No explicit cleanup needed in modern OpenSSL
    }

    /// Connect to server with SSL
    pub fn connect(allocator: Allocator, hostname: []const u8, port: u16) !*SslSocket {
        // Create SSL context
        const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse {
            std.log.err("Failed to create SSL context", .{});
            return SslError.ContextCreationFailed;
        };
        errdefer c.SSL_CTX_free(ctx);

        // Set SSL options for compatibility (OpenSSL 3.x handles this automatically)
        // Note: Specific SSL version disabling not needed in modern OpenSSL        // Resolve hostname
        const hostname_z = try allocator.dupeZ(u8, hostname);
        defer allocator.free(hostname_z);

        const port_str = try std.fmt.allocPrint(allocator, "{d}\x00", .{port});
        defer allocator.free(port_str);

        var hints: c.struct_addrinfo = std.mem.zeroes(c.struct_addrinfo);
        hints.ai_family = c.AF_UNSPEC; // IPv4 or IPv6
        hints.ai_socktype = c.SOCK_STREAM;

        var result: ?*c.struct_addrinfo = null;
        const ret = c.getaddrinfo(hostname_z.ptr, port_str.ptr, &hints, &result);
        if (ret != 0) {
            std.log.err("Failed to resolve hostname: {s}", .{hostname});
            return SslError.HostResolutionFailed;
        }
        defer c.freeaddrinfo(result);

        // Create socket
        const sock_fd = c.socket(result.?.ai_family, result.?.ai_socktype, result.?.ai_protocol);
        if (sock_fd < 0) {
            std.log.err("Failed to create socket", .{});
            return SslError.SocketCreationFailed;
        }
        errdefer _ = c.close(sock_fd);

        // Connect to server
        if (c.connect(sock_fd, result.?.ai_addr, @intCast(result.?.ai_addrlen)) < 0) {
            std.log.err("Failed to connect to {s}:{d}", .{ hostname, port });
            return SslError.ConnectionFailed;
        }

        // Create SSL structure
        const ssl = c.SSL_new(ctx) orelse {
            std.log.err("Failed to create SSL structure", .{});
            return SslError.InitializationFailed;
        };
        errdefer c.SSL_free(ssl);

        // Attach socket to SSL
        if (c.SSL_set_fd(ssl, sock_fd) != 1) {
            std.log.err("Failed to attach socket to SSL", .{});
            return SslError.InitializationFailed;
        }

        // Set hostname for SNI
        _ = c.SSL_set_tlsext_host_name(ssl, hostname_z.ptr);

        // Perform SSL handshake
        const handshake_ret = c.SSL_connect(ssl);
        if (handshake_ret != 1) {
            const err = c.SSL_get_error(ssl, handshake_ret);
            std.log.err("SSL handshake failed: error={d}", .{err});

            // Print OpenSSL error details
            var err_buf: [256]u8 = undefined;
            _ = c.ERR_error_string_n(c.ERR_get_error(), &err_buf, err_buf.len);
            std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});

            return SslError.HandshakeFailed;
        }

        std.log.debug("SSL handshake successful", .{});

        // Create and return socket wrapper
        const socket = try allocator.create(SslSocket);
        socket.* = .{
            .ssl = ssl,
            .ctx = ctx,
            .sock_fd = sock_fd,
            .allocator = allocator,
        };

        return socket;
    }

    /// Close and cleanup SSL connection
    pub fn close(self: *SslSocket) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ctx);
        _ = c.close(self.sock_fd);
        self.allocator.destroy(self);
    }

    /// Write data to SSL socket
    pub fn write(self: *SslSocket, data: []const u8) !usize {
        const written = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (written <= 0) {
            const err = c.SSL_get_error(self.ssl, written);
            std.log.err("SSL write failed: error={d}", .{err});
            return SslError.WriteFailed;
        }
        return @intCast(written);
    }

    /// Read data from SSL socket
    pub fn read(self: *SslSocket, buffer: []u8) !usize {
        const bytes_read = c.SSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));
        if (bytes_read < 0) {
            const err = c.SSL_get_error(self.ssl, bytes_read);
            if (err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE) {
                return 0; // Would block, not an error
            }
            std.log.err("SSL read failed: error={d}", .{err});
            return SslError.ReadFailed;
        }
        if (bytes_read == 0) {
            // Connection closed
            return SslError.Disconnected;
        }
        return @intCast(bytes_read);
    }

    /// Read all data until buffer is full or connection closes
    pub fn readAll(self: *SslSocket, buffer: []u8) !usize {
        var total: usize = 0;
        while (total < buffer.len) {
            const bytes_read = try self.read(buffer[total..]);
            if (bytes_read == 0) break; // Connection closed gracefully
            total += bytes_read;
        }
        return total;
    }

    /// Get reader interface
    pub fn reader(self: *SslSocket) Reader {
        return .{ .context = self };
    }

    /// Get writer interface
    pub fn writer(self: *SslSocket) Writer {
        return .{ .context = self };
    }

    pub const Reader = std.io.Reader(*SslSocket, SslError, readFn);
    pub const Writer = std.io.Writer(*SslSocket, SslError, writeFn);

    fn readFn(self: *SslSocket, buffer: []u8) SslError!usize {
        return self.read(buffer) catch |err| err;
    }

    fn writeFn(self: *SslSocket, data: []const u8) SslError!usize {
        return self.write(data) catch |err| err;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SslSocket: library init" {
    SslSocket.initLibrary();
    defer SslSocket.cleanupLibrary();

    // Just test that initialization doesn't crash
    try std.testing.expect(true);
}

test "SslSocket: context creation" {
    SslSocket.initLibrary();
    defer SslSocket.cleanupLibrary();

    const ctx = c.SSL_CTX_new(c.TLS_client_method());
    try std.testing.expect(ctx != null);
    if (ctx) |c_ctx| {
        c.SSL_CTX_free(c_ctx);
    }
}

// Note: Connection tests require a real SSL server
// For now, we test the API without actual network calls
test "SslSocket: API completeness" {
    const allocator = std.testing.allocator;
    _ = allocator;

    // Verify all methods exist
    try std.testing.expect(@hasDecl(SslSocket, "connect"));
    try std.testing.expect(@hasDecl(SslSocket, "close"));
    try std.testing.expect(@hasDecl(SslSocket, "write"));
    try std.testing.expect(@hasDecl(SslSocket, "read"));
    try std.testing.expect(@hasDecl(SslSocket, "readAll"));
    try std.testing.expect(@hasDecl(SslSocket, "reader"));
    try std.testing.expect(@hasDecl(SslSocket, "writer"));
}
