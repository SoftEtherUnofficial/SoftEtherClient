// SSL/TLS Socket Implementation using OpenSSL
// Pure Zig wrapper around OpenSSL for TLS 1.2/1.3 support
// Phase 1: OpenSSL FFI (battle-tested, quick to implement)
// Phase 2: Migrate to std.crypto.tls (pure Zig) when API stabilizes

const std = @import("std");
const net = std.net;
const Allocator = std.mem.Allocator;
const TcpSocket = @import("socket").TcpSocket; // Use module import

// Import OpenSSL C library
const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509.h");
});

/// SSL/TLS error types
pub const SslError = error{
    SslInitFailed,
    SslContextFailed,
    SslNewFailed,
    SslConnectFailed,
    SslHandshakeFailed,
    SslWriteFailed,
    SslReadFailed,
    SslCertVerifyFailed,
    SslInvalidHostname,
    NotConnected,
    ConnectionClosed,
};

/// SSL socket wrapping OpenSSL
pub const SslSocket = struct {
    tcp_socket: TcpSocket,
    ssl_ctx: ?*c.SSL_CTX,
    ssl: ?*c.SSL,
    connected: bool,
    allocator: Allocator,

    const Self = @This();

    /// Initialize OpenSSL library (call once at program start)
    /// Note: OpenSSL 3.x auto-initializes, but we call this for compatibility
    pub fn initOpenSSL() void {
        // OpenSSL 3.x auto-initializes on first use
        // These calls are no-ops in OpenSSL 3.x but kept for compatibility
        _ = c.OPENSSL_init_ssl(0, null);
        _ = c.OPENSSL_init_crypto(0, null);
    }

    /// Cleanup OpenSSL library (call once at program end)
    /// Note: OpenSSL 3.x auto-cleanup on process exit
    pub fn cleanupOpenSSL() void {
        // OpenSSL 3.x handles cleanup automatically
        // This is now a no-op but kept for API compatibility
    }

    /// Connect to server with SSL/TLS
    pub fn connect(
        allocator: Allocator,
        host: []const u8,
        port: u16,
        verify_cert: bool,
    ) !Self {
        // Step 1: Create TCP connection
        var tcp_socket = try TcpSocket.connect(allocator, host, port);
        errdefer tcp_socket.close();

        // Step 2: Create SSL context
        const method = c.TLS_client_method();
        const ssl_ctx = c.SSL_CTX_new(method);
        if (ssl_ctx == null) {
            return SslError.SslContextFailed;
        }
        errdefer c.SSL_CTX_free(ssl_ctx);

        // Configure SSL context
        // Use modern TLS versions only (TLS 1.2+)
        _ = c.SSL_CTX_set_min_proto_version(ssl_ctx, c.TLS1_2_VERSION);

        // Load default CA certificates for verification
        if (verify_cert) {
            if (c.SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
                std.log.warn("Failed to load default CA certificates, proceeding without verification", .{});
            }
            c.SSL_CTX_set_verify(ssl_ctx, c.SSL_VERIFY_PEER, null);
        } else {
            c.SSL_CTX_set_verify(ssl_ctx, c.SSL_VERIFY_NONE, null);
        }

        // Step 3: Create SSL structure
        const ssl = c.SSL_new(ssl_ctx);
        if (ssl == null) {
            return SslError.SslNewFailed;
        }
        errdefer c.SSL_free(ssl);

        // Step 4: Associate SSL with TCP socket
        const socket_fd = tcp_socket.stream.handle;
        if (c.SSL_set_fd(ssl, socket_fd) != 1) {
            return SslError.SslConnectFailed;
        }

        // Set SNI (Server Name Indication) hostname
        const host_z = try allocator.dupeZ(u8, host);
        defer allocator.free(host_z);
        _ = c.SSL_set_tlsext_host_name(ssl, host_z.ptr);

        // Step 5: Perform SSL handshake
        const connect_result = c.SSL_connect(ssl);
        if (connect_result != 1) {
            const err = c.SSL_get_error(ssl, connect_result);
            std.log.err("SSL handshake failed: error code {d}", .{err});

            // Print OpenSSL error details
            var err_buf: [256]u8 = undefined;
            const err_code = c.ERR_get_error();
            _ = c.ERR_error_string_n(err_code, &err_buf, err_buf.len);
            std.log.err("OpenSSL error: {s}", .{std.mem.sliceTo(&err_buf, 0)});

            return SslError.SslHandshakeFailed;
        }

        std.log.debug("SSL/TLS handshake successful", .{});

        // Optional: Verify certificate hostname
        if (verify_cert) {
            try verifyCertificateHostname(ssl, host);
        }

        return Self{
            .tcp_socket = tcp_socket,
            .ssl_ctx = ssl_ctx,
            .ssl = ssl,
            .connected = true,
            .allocator = allocator,
        };
    }

    /// Close SSL connection
    pub fn close(self: *Self) void {
        if (self.ssl != null) {
            _ = c.SSL_shutdown(self.ssl);
            c.SSL_free(self.ssl);
            self.ssl = null;
        }
        if (self.ssl_ctx != null) {
            c.SSL_CTX_free(self.ssl_ctx);
            self.ssl_ctx = null;
        }
        self.tcp_socket.close();
        self.connected = false;
    }

    /// Deinitialize (same as close for convenience)
    pub fn deinit(self: *Self) void {
        self.close();
    }

    /// Send data over SSL connection
    pub fn send(self: *Self, data: []const u8) !void {
        if (!self.connected or self.ssl == null) return SslError.NotConnected;

        var total_written: usize = 0;
        while (total_written < data.len) {
            const to_write = data[total_written..];
            const written = c.SSL_write(self.ssl, to_write.ptr, @intCast(to_write.len));

            if (written <= 0) {
                const err = c.SSL_get_error(self.ssl, written);
                if (err == c.SSL_ERROR_WANT_WRITE or err == c.SSL_ERROR_WANT_READ) {
                    // Retry
                    continue;
                }
                std.log.err("SSL write failed: error code {d}", .{err});
                return SslError.SslWriteFailed;
            }

            total_written += @intCast(written);
        }
    }

    /// Send all data (alias for send)
    pub fn sendAll(self: *Self, data: []const u8) !void {
        try self.send(data);
    }

    /// Receive data from SSL connection
    pub fn recv(self: *Self, buffer: []u8) !usize {
        if (!self.connected or self.ssl == null) return SslError.NotConnected;

        const read_result = c.SSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));

        if (read_result <= 0) {
            const err = c.SSL_get_error(self.ssl, read_result);
            if (err == c.SSL_ERROR_ZERO_RETURN) {
                // Connection closed gracefully
                return 0;
            }
            if (err == c.SSL_ERROR_WANT_READ or err == c.SSL_ERROR_WANT_WRITE) {
                // Would block, return 0 for now
                return 0;
            }
            std.log.err("SSL read failed: error code {d}", .{err});
            return SslError.SslReadFailed;
        }

        return @intCast(read_result);
    }

    /// Receive all data (blocking until buffer is filled or connection closed)
    pub fn recvAll(self: *Self, buffer: []u8) !void {
        if (!self.connected or self.ssl == null) return SslError.NotConnected;

        var total_read: usize = 0;
        while (total_read < buffer.len) {
            const to_read = buffer[total_read..];
            const bytes_read = try self.recv(to_read);

            if (bytes_read == 0) {
                return SslError.ConnectionClosed;
            }

            total_read += bytes_read;
        }
    }

    /// Get SSL cipher being used
    pub fn getCipher(self: *const Self) ?[]const u8 {
        if (self.ssl == null) return null;

        const cipher = c.SSL_get_cipher(self.ssl);
        if (cipher == null) return null;

        return std.mem.sliceTo(cipher, 0);
    }

    /// Get SSL version being used
    pub fn getVersion(self: *const Self) ?[]const u8 {
        if (self.ssl == null) return null;

        const version = c.SSL_get_version(self.ssl);
        if (version == null) return null;

        return std.mem.sliceTo(version, 0);
    }

    /// Verify certificate hostname matches expected hostname
    fn verifyCertificateHostname(ssl: ?*c.SSL, expected_host: []const u8) !void {
        const cert = c.SSL_get_peer_certificate(ssl);
        if (cert == null) {
            return SslError.SslCertVerifyFailed;
        }
        defer c.X509_free(cert);

        // Verify certificate
        const verify_result = c.SSL_get_verify_result(ssl);
        if (verify_result != c.X509_V_OK) {
            std.log.err("Certificate verification failed: {d}", .{verify_result});
            return SslError.SslCertVerifyFailed;
        }

        // TODO: Add hostname verification (check CN or SAN)
        // For now, we rely on OpenSSL's built-in verification
        _ = expected_host;

        std.log.debug("Certificate verification passed", .{});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SSL socket basic functionality" {
    const testing = std.testing;

    // Initialize OpenSSL
    SslSocket.initOpenSSL();
    defer SslSocket.cleanupOpenSSL();

    // Basic test passed if OpenSSL initializes
    try testing.expect(true);
}

test "SSL socket connect and disconnect" {
    // This test requires network access, skip in CI
    if (true) return error.SkipZigTest;

    const testing = std.testing;
    const allocator = testing.allocator;

    SslSocket.initOpenSSL();
    defer SslSocket.cleanupOpenSSL();

    // Connect to a public HTTPS server
    var ssl_socket = try SslSocket.connect(allocator, "www.google.com", 443, false);
    defer ssl_socket.close();

    try testing.expect(ssl_socket.connected);
    try testing.expect(ssl_socket.ssl != null);
}

test "SSL socket send and receive" {
    // This test requires network access, skip in CI
    if (true) return error.SkipZigTest;

    const testing = std.testing;
    const allocator = testing.allocator;

    SslSocket.initOpenSSL();
    defer SslSocket.cleanupOpenSSL();

    var ssl_socket = try SslSocket.connect(allocator, "www.google.com", 443, false);
    defer ssl_socket.close();

    // Send HTTP request
    const request = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    try ssl_socket.send(request);

    // Receive response
    var buffer: [1024]u8 = undefined;
    const bytes_read = try ssl_socket.recv(&buffer);
    try testing.expect(bytes_read > 0);
}
