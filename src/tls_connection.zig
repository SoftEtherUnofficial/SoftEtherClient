const std = @import("std");
const rustls = @import("rustls.zig");

/// TLS Connection Wrapper
///
/// This provides a high-level API for TLS connections using rustls,
/// designed to be easily integrated with existing SoftEther code.
///
/// Phase 3: This will gradually replace OpenSSL usage in SoftEther
pub const TlsConnection = struct {
    config: *rustls.ClientConfig,
    connection: ?rustls.Connection,
    socket: std.net.Stream,
    hostname: []const u8,
    allocator: std.mem.Allocator,

    read_buffer: []u8,
    write_buffer: []u8,
    handshake_complete: bool,

    pub const Config = struct {
        hostname: []const u8,
        port: u16,
        verify_certificates: bool = true,
        root_cert_path: ?[]const u8 = null,
        buffer_size: usize = 16384,
    };

    pub const Error = error{
        ConnectionFailed,
        HandshakeFailed,
        InvalidHostname,
        CertificateError,
        IoError,
        BufferTooSmall,
    } || rustls.Error || std.mem.Allocator.Error;

    /// Create a new TLS connection
    pub fn init(allocator: std.mem.Allocator, config: Config) Error!TlsConnection {
        // Initialize rustls
        try rustls.init();

        // Create client config
        var client_config = try rustls.ClientConfig.init(allocator);
        errdefer client_config.deinit();

        // Load root certificates if specified
        if (config.root_cert_path) |cert_path| {
            try client_config.loadRootCerts(cert_path);
        }

        // Connect to the server
        const addr = try std.net.Address.parseIp(config.hostname, config.port);
        const socket = try std.net.tcpConnectToAddress(addr);
        errdefer socket.close();

        // Allocate buffers
        const read_buffer = try allocator.alloc(u8, config.buffer_size);
        errdefer allocator.free(read_buffer);

        const write_buffer = try allocator.alloc(u8, config.buffer_size);
        errdefer allocator.free(write_buffer);

        // Duplicate hostname for lifetime management
        const hostname_owned = try allocator.dupe(u8, config.hostname);
        errdefer allocator.free(hostname_owned);

        return TlsConnection{
            .config = &client_config,
            .connection = null,
            .socket = socket,
            .hostname = hostname_owned,
            .allocator = allocator,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .handshake_complete = false,
        };
    }

    /// Perform TLS handshake
    pub fn connect(self: *TlsConnection) Error!void {
        if (self.connection != null) return error.AlreadyInitialized;

        // Create TLS connection
        const conn = try rustls.Connection.initClient(self.config, self.hostname);
        self.connection = conn;

        // Perform handshake
        try self.doHandshake();
        self.handshake_complete = true;
    }

    /// Internal: Perform TLS handshake loop
    fn doHandshake(self: *TlsConnection) Error!void {
        var conn = self.connection orelse return error.NotInitialized;

        while (conn.isHandshaking()) {
            // Write TLS data to socket
            _ = try self.writeTlsData();

            // Read TLS data from socket
            _ = try self.readTlsData();

            // Process any pending handshake messages
            // (rustls handles this internally during read/write)
        }
    }

    /// Write application data (will be encrypted)
    pub fn write(self: *TlsConnection, data: []const u8) Error!usize {
        if (!self.handshake_complete) return error.NotInitialized;

        var conn = self.connection orelse return error.NotInitialized;

        // Write plaintext to rustls (it will encrypt)
        const written = try conn.write(data);

        // Send encrypted data to socket
        _ = try self.writeTlsData();

        return written;
    }

    /// Read application data (will be decrypted)
    pub fn read(self: *TlsConnection, buffer: []u8) Error!usize {
        if (!self.handshake_complete) return error.NotInitialized;

        var conn = self.connection orelse return error.NotInitialized;

        // Read encrypted data from socket first
        _ = try self.readTlsData();

        // Read decrypted data from rustls
        const bytes_read = try conn.read(buffer);

        return bytes_read;
    }

    /// Internal: Write TLS data to socket
    fn writeTlsData(self: *TlsConnection) Error!usize {
        const conn = self.connection orelse return error.NotInitialized;

        // Get TLS bytes to write (encrypted)
        // This is a simplified version - real implementation needs proper I/O handling
        _ = conn;

        // For now, return 0 (placeholder)
        // Full implementation would use rustls_connection_write_tls with callbacks
        return 0;
    }

    /// Internal: Read TLS data from socket
    fn readTlsData(self: *TlsConnection) Error!usize {
        const conn = self.connection orelse return error.NotInitialized;

        // Read from socket
        const bytes_read = try self.socket.read(self.read_buffer);
        if (bytes_read == 0) return error.UnexpectedEof;

        // Feed to rustls (it will decrypt)
        // This is a simplified version - real implementation needs proper I/O handling
        _ = conn;

        return bytes_read;
    }

    /// Check if handshake is complete
    pub fn isConnected(self: *const TlsConnection) bool {
        return self.handshake_complete;
    }

    /// Close the connection
    pub fn close(self: *TlsConnection) void {
        if (self.connection) |*conn| {
            conn.deinit();
            self.connection = null;
        }
        self.socket.close();
    }

    /// Clean up resources
    pub fn deinit(self: *TlsConnection) void {
        self.close();
        self.allocator.free(self.read_buffer);
        self.allocator.free(self.write_buffer);
        self.allocator.free(self.hostname);
        self.config.deinit();
    }
};

/// Simple TLS client for testing
pub fn connectTls(allocator: std.mem.Allocator, hostname: []const u8, port: u16) !TlsConnection {
    var conn = try TlsConnection.init(allocator, .{
        .hostname = hostname,
        .port = port,
        .verify_certificates = true,
    });
    errdefer conn.deinit();

    try conn.connect();
    return conn;
}

// ============================================
// Tests
// ============================================

test "TlsConnection creation" {
    const allocator = std.testing.allocator;

    // This will fail to connect but should at least create the structure
    var conn = TlsConnection.init(allocator, .{
        .hostname = "127.0.0.1",
        .port = 8443,
        .verify_certificates = false,
    }) catch |err| {
        // Expected to fail (no server running)
        try std.testing.expect(err == error.ConnectionRefused or
            err == error.NetworkUnreachable or
            err == error.ConnectionTimedOut);
        return;
    };
    defer conn.deinit();

    try std.testing.expect(!conn.isConnected());
}

test "TlsConnection config" {
    const config = TlsConnection.Config{
        .hostname = "example.com",
        .port = 443,
        .verify_certificates = true,
        .buffer_size = 8192,
    };

    try std.testing.expectEqual(@as(u16, 443), config.port);
    try std.testing.expectEqual(@as(usize, 8192), config.buffer_size);
    try std.testing.expect(config.verify_certificates);
}
