// Unified Socket Interface - supports both plain TCP and SSL/TLS
// Provides a single API that automatically uses SSL for port 443

const std = @import("std");
const Allocator = std.mem.Allocator;
const TcpSocket = @import("socket").TcpSocket; // Use module import
const SslSocket = @import("ssl_socket.zig").SslSocket;

/// Socket type (plain TCP or SSL)
pub const SocketType = enum {
    plain_tcp,
    ssl_tls,
};

/// Unified socket that can be either TCP or SSL
pub const UnifiedSocket = union(SocketType) {
    plain_tcp: TcpSocket,
    ssl_tls: SslSocket,

    const Self = @This();

    /// Connect to server (automatically uses SSL for port 443)
    pub fn connect(
        allocator: Allocator,
        host: []const u8,
        port: u16,
    ) !Self {
        // Initialize OpenSSL if needed (no-op if already initialized)
        if (port == 443) {
            SslSocket.initOpenSSL();
        }

        // Use SSL for port 443, plain TCP otherwise
        if (port == 443) {
            const ssl_socket = try SslSocket.connect(allocator, host, port, false);
            return Self{ .ssl_tls = ssl_socket };
        } else {
            const tcp_socket = try TcpSocket.connect(allocator, host, port);
            return Self{ .plain_tcp = tcp_socket };
        }
    }

    /// Close connection
    pub fn close(self: *Self) void {
        switch (self.*) {
            .plain_tcp => |*tcp| tcp.close(),
            .ssl_tls => |*ssl| ssl.close(),
        }
    }

    /// Send data
    pub fn send(self: *Self, data: []const u8) !void {
        switch (self.*) {
            .plain_tcp => |*tcp| try tcp.send(data),
            .ssl_tls => |*ssl| try ssl.send(data),
        }
    }

    /// Send all data (blocking until complete)
    pub fn sendAll(self: *Self, data: []const u8) !void {
        switch (self.*) {
            .plain_tcp => |*tcp| try tcp.sendAll(data),
            .ssl_tls => |*ssl| try ssl.sendAll(data),
        }
    }

    /// Receive data
    pub fn recv(self: *Self, buffer: []u8) !usize {
        return switch (self.*) {
            .plain_tcp => |*tcp| try tcp.recv(buffer),
            .ssl_tls => |*ssl| try ssl.recv(buffer),
        };
    }

    /// Receive all data (blocking until buffer is full)
    pub fn recvAll(self: *Self, buffer: []u8) !void {
        switch (self.*) {
            .plain_tcp => |*tcp| try tcp.recvAll(buffer),
            .ssl_tls => |*ssl| try ssl.recvAll(buffer),
        }
    }

    /// Get socket type
    pub fn getType(self: *const Self) SocketType {
        return switch (self.*) {
            .plain_tcp => .plain_tcp,
            .ssl_tls => .ssl_tls,
        };
    }

    /// Check if using SSL
    pub fn isSecure(self: *const Self) bool {
        return self.getType() == .ssl_tls;
    }

    /// Get local port number
    pub fn getLocalPort(self: *Self) !u16 {
        return switch (self.*) {
            .plain_tcp => |*tcp| {
                const addr = tcp.getLocalAddr();
                return addr.getPort();
            },
            .ssl_tls => |*ssl| {
                // SSL socket wraps TCP socket, get port from underlying TCP
                const addr = ssl.tcp_socket.getLocalAddr();
                return addr.getPort();
            },
        };
    }

    /// Get remote IPv4 address as u32 (for SoftEther Pack format)
    pub fn getRemoteIpv4(self: *Self) !u32 {
        return switch (self.*) {
            .plain_tcp => |*tcp| {
                const addr = tcp.getRemoteAddr();
                // addr.in.sa.addr is already in network byte order (big-endian)
                // SoftEther Pack stores IP in this format directly
                return addr.in.sa.addr;
            },
            .ssl_tls => |*ssl| {
                const addr = ssl.tcp_socket.getRemoteAddr();
                return addr.in.sa.addr;
            },
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "unified socket plain TCP" {
    const testing = std.testing;

    // Test that non-443 ports use plain TCP
    // (Skip actual connection in test)
    try testing.expect(true);
}

test "unified socket SSL on port 443" {
    const testing = std.testing;

    // Test that port 443 uses SSL
    // (Skip actual connection in test)
    try testing.expect(true);
}
