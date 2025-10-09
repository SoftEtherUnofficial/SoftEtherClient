const std = @import("std");

/// Zig bindings for rustls-ffi
/// This wraps the C API provided by rustls-ffi in idiomatic Zig

// Import rustls C headers
pub const c = @cImport({
    @cInclude("rustls.h");
});

pub const Error = error{
    NullPointer,
    ConnectionFailed,
    HandshakeFailed,
    IoError,
    InvalidParameter,
    CertificateError,
    UnexpectedEof,
};

/// Convert rustls_result to Zig error
fn resultToError(result: c.rustls_result) Error!void {
    return switch (result) {
        c.RUSTLS_RESULT_OK => {},
        c.RUSTLS_RESULT_NULL_PARAMETER => Error.NullPointer,
        c.RUSTLS_RESULT_INVALID_DNS_NAME_ERROR => Error.InvalidParameter,
        c.RUSTLS_RESULT_CERT_INVALID => Error.CertificateError,
        c.RUSTLS_RESULT_UNEXPECTED_EOF => Error.UnexpectedEof,
        else => Error.ConnectionFailed,
    };
}

/// TLS Client Configuration
pub const ClientConfig = struct {
    inner: *c.rustls_client_config,

    /// Create a new client config with default settings
    pub fn init(allocator: std.mem.Allocator) !ClientConfig {
        _ = allocator; // May be needed for future use

        const builder = c.rustls_client_config_builder_new();
        if (builder == null) return Error.NullPointer;

        // Build the config
        const config = c.rustls_client_config_builder_build(builder);
        if (config == null) return Error.ConnectionFailed;

        return ClientConfig{ .inner = config };
    }

    /// Load root certificates from a PEM file
    pub fn loadRootCerts(self: *ClientConfig, pem_path: []const u8) !void {
        const path_z = try std.posix.toPosixPath(pem_path);
        const result = c.rustls_client_config_builder_load_roots_from_file(
            @ptrCast(self.inner),
            &path_z,
        );
        try resultToError(result);
    }

    pub fn deinit(self: *ClientConfig) void {
        c.rustls_client_config_free(self.inner);
    }
};

/// TLS Connection
pub const Connection = struct {
    inner: *c.rustls_connection,

    /// Create a new client connection
    pub fn initClient(config: *ClientConfig, hostname: []const u8) !Connection {
        // Need null-terminated hostname
        const hostname_z = try std.heap.c_allocator.dupeZ(u8, hostname);
        defer std.heap.c_allocator.free(hostname_z);

        const conn = c.rustls_client_connection_new(
            config.inner,
            hostname_z.ptr,
        );

        if (conn == null) return Error.ConnectionFailed;

        return Connection{ .inner = conn };
    }

    /// Check if handshake is in progress
    pub fn isHandshaking(self: *const Connection) bool {
        return c.rustls_connection_is_handshaking(self.inner);
    }

    /// Write application data to be encrypted
    pub fn write(self: *Connection, data: []const u8) !usize {
        var written: usize = 0;
        const result = c.rustls_connection_write(
            self.inner,
            data.ptr,
            data.len,
            &written,
        );
        try resultToError(result);
        return written;
    }

    /// Read decrypted application data
    pub fn read(self: *Connection, buffer: []u8) !usize {
        var read_bytes: usize = 0;
        const result = c.rustls_connection_read(
            self.inner,
            buffer.ptr,
            buffer.len,
            &read_bytes,
        );
        try resultToError(result);
        return read_bytes;
    }

    /// Write TLS data to the network (encrypted)
    pub fn writeTls(self: *Connection, socket: anytype) !usize {
        // This would use rustls_connection_write_tls with a callback
        // that writes to the socket
        _ = self;
        _ = socket;
        return 0; // Placeholder
    }

    /// Read TLS data from the network (to be decrypted)
    pub fn readTls(self: *Connection, socket: anytype) !usize {
        // This would use rustls_connection_read_tls with a callback
        // that reads from the socket
        _ = self;
        _ = socket;
        return 0; // Placeholder
    }

    pub fn deinit(self: *Connection) void {
        c.rustls_connection_free(self.inner);
    }
};

/// High-level VPN TLS connection wrapper
pub const VpnTlsConnection = struct {
    tls: Connection,
    socket: std.net.Stream,
    read_buffer: [8192]u8,
    write_buffer: [8192]u8,

    pub fn init(hostname: []const u8, port: u16) !VpnTlsConnection {
        // Create TLS config
        var config = try ClientConfig.init(std.heap.c_allocator);
        errdefer config.deinit();

        // Connect socket (pure Zig)
        const addr = try std.net.Address.parseIp(hostname, port);
        const socket = try std.net.tcpConnectToAddress(addr);
        errdefer socket.close();

        // Create TLS connection
        const tls = try Connection.initClient(&config, hostname);

        return VpnTlsConnection{
            .tls = tls,
            .socket = socket,
            .read_buffer = undefined,
            .write_buffer = undefined,
        };
    }

    /// Send encrypted VPN packet
    pub fn sendPacket(self: *VpnTlsConnection, packet: []const u8) !void {
        // 1. Encrypt with TLS
        _ = try self.tls.write(packet);

        // 2. Send encrypted data over socket
        _ = try self.tls.writeTls(self.socket);
    }

    /// Receive decrypted VPN packet
    pub fn receivePacket(self: *VpnTlsConnection, buffer: []u8) ![]const u8 {
        // 1. Read encrypted data from socket
        _ = try self.tls.readTls(self.socket);

        // 2. Decrypt with TLS
        const len = try self.tls.read(buffer);
        return buffer[0..len];
    }

    pub fn deinit(self: *VpnTlsConnection) void {
        self.tls.deinit();
        self.socket.close();
    }
};

test "rustls basic import" {
    // Just verify the C imports work
    const version = c.rustls_version();
    try std.testing.expect(version != null);
}
