//! Network Utilities for SoftEther VPN
//!
//! This module provides high-level network abstractions for:
//! - TCP/UDP socket operations
//! - Address resolution and parsing
//! - Connection management with timeouts
//! - Non-blocking I/O
//! - Packet framing helpers
//!
//! Usage:
//! ```zig
//! const network = @import("mayaqua/network.zig");
//!
//! // Parse address
//! const addr = try network.parseAddress(allocator, "192.168.1.1:443");
//! defer addr.deinit(allocator);
//!
//! // Connect with timeout
//! var client = try network.TcpClient.connect(addr, 5000);
//! defer client.close();
//!
//! // Send/receive data
//! try client.send("Hello, VPN!");
//! const response = try client.receive(allocator, 1024);
//! defer allocator.free(response);
//! ```

const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const net = std.net;
const posix = std.posix;

pub const NetworkError = error{
    ConnectionFailed,
    ConnectionRefused,
    ConnectionReset,
    ConnectionTimedOut,
    InvalidAddress,
    InvalidPort,
    NameResolutionFailed,
    SocketCreationFailed,
    BindFailed,
    ListenFailed,
    AcceptFailed,
    SendFailed,
    ReceiveFailed,
    Timeout,
    WouldBlock,
    NotConnected,
    AlreadyConnected,
};

/// Network address (IPv4/IPv6 + port)
pub const Address = struct {
    host: []const u8,
    port: u16,

    pub fn deinit(self: *Address, allocator: std.mem.Allocator) void {
        allocator.free(self.host);
    }

    pub fn format(self: Address, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print("{s}:{d}", .{ self.host, self.port });
    }
};

/// Parse address string "host:port" or "host" (default port 443)
pub fn parseAddress(allocator: std.mem.Allocator, addr_str: []const u8) !Address {
    // Find colon separator
    if (std.mem.lastIndexOfScalar(u8, addr_str, ':')) |colon_pos| {
        const host = try allocator.dupe(u8, addr_str[0..colon_pos]);
        const port_str = addr_str[colon_pos + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return NetworkError.InvalidPort;
        return Address{ .host = host, .port = port };
    } else {
        // No port specified, use default 443 (HTTPS/VPN)
        const host = try allocator.dupe(u8, addr_str);
        return Address{ .host = host, .port = 443 };
    }
}

/// Resolve hostname to IP address (blocking DNS query)
pub fn resolveHostname(allocator: std.mem.Allocator, hostname: []const u8, port: u16) !net.Address {
    // Try parsing as IP address first
    if (net.Address.parseIp(hostname, port)) |addr| {
        return addr;
    } else |_| {
        // DNS resolution needed
        const list = try net.getAddressList(allocator, hostname, port);
        defer list.deinit();

        if (list.addrs.len == 0) {
            return NetworkError.NameResolutionFailed;
        }

        return list.addrs[0];
    }
}

/// TCP client connection
pub const TcpClient = struct {
    stream: net.Stream,
    address: net.Address,
    connected: bool,

    /// Connect to address with timeout (milliseconds)
    pub fn connect(addr: Address, timeout_ms: u64) !TcpClient {
        const resolved = try resolveHostname(
            std.heap.page_allocator,
            addr.host,
            addr.port,
        );

        // Create socket
        const stream = net.tcpConnectToAddress(resolved) catch |err| {
            return switch (err) {
                error.ConnectionRefused => NetworkError.ConnectionRefused,
                error.ConnectionTimedOut => NetworkError.ConnectionTimedOut,
                error.NetworkUnreachable => NetworkError.ConnectionFailed,
                else => NetworkError.ConnectionFailed,
            };
        };

        // Set timeout
        try stream.handle.setReadTimeout(timeout_ms);
        try stream.handle.setWriteTimeout(timeout_ms);

        return TcpClient{
            .stream = stream,
            .address = resolved,
            .connected = true,
        };
    }

    /// Send data (blocks until all data sent or timeout)
    pub fn send(self: *TcpClient, data: []const u8) !usize {
        if (!self.connected) return NetworkError.NotConnected;

        return self.stream.write(data) catch |err| {
            return switch (err) {
                error.BrokenPipe => NetworkError.ConnectionReset,
                error.ConnectionResetByPeer => NetworkError.ConnectionReset,
                error.WouldBlock => NetworkError.WouldBlock,
                else => NetworkError.SendFailed,
            };
        };
    }

    /// Receive data (blocks until data available or timeout)
    /// Returns owned slice - caller must free
    pub fn receive(self: *TcpClient, allocator: std.mem.Allocator, max_size: usize) ![]u8 {
        if (!self.connected) return NetworkError.NotConnected;

        const buffer = try allocator.alloc(u8, max_size);
        errdefer allocator.free(buffer);

        const n = self.stream.read(buffer) catch |err| {
            allocator.free(buffer);
            return switch (err) {
                error.BrokenPipe => NetworkError.ConnectionReset,
                error.ConnectionResetByPeer => NetworkError.ConnectionReset,
                error.WouldBlock => NetworkError.WouldBlock,
                else => NetworkError.ReceiveFailed,
            };
        };

        // Resize to actual bytes read
        return allocator.realloc(buffer, n);
    }

    /// Receive exact number of bytes (blocks until all bytes received)
    pub fn receiveExact(self: *TcpClient, buffer: []u8) !void {
        if (!self.connected) return NetworkError.NotConnected;

        self.stream.reader().readNoEof(buffer) catch |err| {
            return switch (err) {
                error.BrokenPipe => NetworkError.ConnectionReset,
                error.ConnectionResetByPeer => NetworkError.ConnectionReset,
                error.EndOfStream => NetworkError.ConnectionReset,
                else => NetworkError.ReceiveFailed,
            };
        };
    }

    /// Check if data available (non-blocking peek)
    pub fn hasData(self: *TcpClient) bool {
        if (!self.connected) return false;

        var byte: [1]u8 = undefined;
        const n = posix.recv(self.stream.handle, &byte, os.MSG.PEEK) catch return false;
        return n > 0;
    }

    /// Close connection
    pub fn close(self: *TcpClient) void {
        if (self.connected) {
            self.stream.close();
            self.connected = false;
        }
    }

    /// Get reader interface
    pub fn reader(self: *TcpClient) net.Stream.Reader {
        return self.stream.reader();
    }

    /// Get writer interface
    pub fn writer(self: *TcpClient) net.Stream.Writer {
        return self.stream.writer();
    }
};

/// TCP server (listener)
pub const TcpServer = struct {
    stream_server: net.StreamServer,
    address: net.Address,
    listening: bool,

    /// Start listening on address
    pub fn listen(addr: Address) !TcpServer {
        const resolved = try net.Address.parseIp(addr.host, addr.port);

        var stream_server = net.StreamServer.init(.{
            .reuse_address = true,
        });
        errdefer stream_server.deinit();

        stream_server.listen(resolved) catch |err| {
            return switch (err) {
                error.AddressInUse => NetworkError.BindFailed,
                error.AddressNotAvailable => NetworkError.BindFailed,
                else => NetworkError.ListenFailed,
            };
        };

        return TcpServer{
            .stream_server = stream_server,
            .address = resolved,
            .listening = true,
        };
    }

    /// Accept incoming connection (blocks until client connects)
    pub fn accept(self: *TcpServer) !TcpClient {
        if (!self.listening) return NetworkError.NotConnected;

        const connection = self.stream_server.accept() catch |err| {
            return switch (err) {
                error.ConnectionAborted => NetworkError.AcceptFailed,
                else => NetworkError.AcceptFailed,
            };
        };

        return TcpClient{
            .stream = connection.stream,
            .address = connection.address,
            .connected = true,
        };
    }

    /// Stop listening
    pub fn close(self: *TcpServer) void {
        if (self.listening) {
            self.stream_server.deinit();
            self.listening = false;
        }
    }
};

/// UDP socket
pub const UdpSocket = struct {
    socket: posix.socket_t,
    address: net.Address,
    bound: bool,

    /// Create UDP socket bound to address
    pub fn bind(addr: Address) !UdpSocket {
        const resolved = try net.Address.parseIp(addr.host, addr.port);

        const sock = posix.socket(
            resolved.any.family,
            posix.SOCK.DGRAM,
            posix.IPPROTO.UDP,
        ) catch return NetworkError.SocketCreationFailed;

        posix.bind(sock, &resolved.any, resolved.getOsSockLen()) catch {
            posix.close(sock);
            return NetworkError.BindFailed;
        };

        return UdpSocket{
            .socket = sock,
            .address = resolved,
            .bound = true,
        };
    }

    /// Send datagram to address
    pub fn sendTo(self: *UdpSocket, data: []const u8, dest: net.Address) !usize {
        if (!self.bound) return NetworkError.NotConnected;

        return posix.sendto(
            self.socket,
            data,
            0,
            &dest.any,
            dest.getOsSockLen(),
        ) catch NetworkError.SendFailed;
    }

    /// Receive datagram (blocks until data available)
    /// Returns data and sender address
    pub fn receiveFrom(
        self: *UdpSocket,
        allocator: std.mem.Allocator,
        max_size: usize,
    ) !struct { data: []u8, address: net.Address } {
        if (!self.bound) return NetworkError.NotConnected;

        const buffer = try allocator.alloc(u8, max_size);
        errdefer allocator.free(buffer);

        var src_addr: net.Address = undefined;
        var src_len: posix.socklen_t = @sizeOf(net.Address);

        const n = posix.recvfrom(
            self.socket,
            buffer,
            0,
            &src_addr.any,
            &src_len,
        ) catch {
            allocator.free(buffer);
            return NetworkError.ReceiveFailed;
        };

        const data = try allocator.realloc(buffer, n);
        return .{ .data = data, .address = src_addr };
    }

    /// Close socket
    pub fn close(self: *UdpSocket) void {
        if (self.bound) {
            posix.close(self.socket);
            self.bound = false;
        }
    }
};

/// Packet framing helper (length-prefixed protocol)
pub const PacketFraming = struct {
    /// Frame data with 4-byte length prefix (network byte order)
    pub fn frame(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
        const framed = try allocator.alloc(u8, 4 + data.len);
        errdefer allocator.free(framed);

        // Write length (big-endian)
        const len: u32 = @intCast(data.len);
        framed[0] = @intCast((len >> 24) & 0xFF);
        framed[1] = @intCast((len >> 16) & 0xFF);
        framed[2] = @intCast((len >> 8) & 0xFF);
        framed[3] = @intCast(len & 0xFF);

        // Copy data
        @memcpy(framed[4..], data);

        return framed;
    }

    /// Read frame from stream (blocks until complete frame received)
    pub fn readFrame(allocator: std.mem.Allocator, stream_reader: anytype) ![]u8 {
        // Read length prefix (4 bytes, big-endian)
        var len_buf: [4]u8 = undefined;
        try stream_reader.readNoEof(&len_buf);

        const len: u32 = (@as(u32, len_buf[0]) << 24) |
            (@as(u32, len_buf[1]) << 16) |
            (@as(u32, len_buf[2]) << 8) |
            @as(u32, len_buf[3]);

        // Sanity check (max 16MB frame)
        if (len > 16 * 1024 * 1024) {
            return NetworkError.ReceiveFailed;
        }

        // Read data
        const data = try allocator.alloc(u8, len);
        errdefer allocator.free(data);

        try stream_reader.readNoEof(data);

        return data;
    }

    /// Write frame to stream
    pub fn writeFrame(stream_writer: anytype, data: []const u8) !void {
        // Write length prefix (4 bytes, big-endian)
        const len: u32 = @intCast(data.len);
        var len_buf: [4]u8 = undefined;
        len_buf[0] = @intCast((len >> 24) & 0xFF);
        len_buf[1] = @intCast((len >> 16) & 0xFF);
        len_buf[2] = @intCast((len >> 8) & 0xFF);
        len_buf[3] = @intCast(len & 0xFF);

        try stream_writer.writeAll(&len_buf);
        try stream_writer.writeAll(data);
    }
};

/// Connection pool for managing multiple connections
pub const ConnectionPool = struct {
    connections: std.ArrayList(*TcpClient),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !ConnectionPool {
        return ConnectionPool{
            .connections = try std.ArrayList(*TcpClient).initCapacity(allocator, 0),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        for (self.connections.items) |conn| {
            conn.close();
            self.allocator.destroy(conn);
        }
        self.connections.deinit(self.allocator);
    }

    pub fn add(self: *ConnectionPool, client: *TcpClient) !void {
        try self.connections.append(self.allocator, client);
    }

    pub fn remove(self: *ConnectionPool, client: *TcpClient) void {
        for (self.connections.items, 0..) |conn, i| {
            if (conn == client) {
                _ = self.connections.orderedRemove(i);
                break;
            }
        }
    }

    pub fn count(self: *ConnectionPool) usize {
        return self.connections.items.len;
    }

    /// Close all connections
    pub fn closeAll(self: *ConnectionPool) void {
        for (self.connections.items) |conn| {
            conn.close();
        }
    }
};

/// Network statistics
pub const NetworkStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    connections_established: u64,
    connections_failed: u64,

    pub fn init() NetworkStats {
        return .{
            .bytes_sent = 0,
            .bytes_received = 0,
            .packets_sent = 0,
            .packets_received = 0,
            .connections_established = 0,
            .connections_failed = 0,
        };
    }

    pub fn reset(self: *NetworkStats) void {
        self.* = init();
    }

    pub fn format(self: NetworkStats, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try writer.print(
            \\Network Statistics:
            \\  Bytes: {d} sent, {d} received
            \\  Packets: {d} sent, {d} received
            \\  Connections: {d} established, {d} failed
        , .{
            self.bytes_sent,
            self.bytes_received,
            self.packets_sent,
            self.packets_received,
            self.connections_established,
            self.connections_failed,
        });
    }
};

/// Timeout helper
pub const Timeout = struct {
    deadline_ns: i128,

    pub fn init(timeout_ms: u64) Timeout {
        const now = std.time.nanoTimestamp();
        const timeout_ns: i128 = @as(i128, timeout_ms) * std.time.ns_per_ms;
        return .{ .deadline_ns = now + timeout_ns };
    }

    pub fn isExpired(self: Timeout) bool {
        const now = std.time.nanoTimestamp();
        return now >= self.deadline_ns;
    }

    pub fn remaining(self: Timeout) u64 {
        const now = std.time.nanoTimestamp();
        if (now >= self.deadline_ns) return 0;

        const remaining_ns: i128 = self.deadline_ns - now;
        return @intCast(@divTrunc(remaining_ns, std.time.ns_per_ms));
    }
};

// ============================================================================
// Tests
// ============================================================================

test "parseAddress with port" {
    const allocator = std.testing.allocator;

    var addr = try parseAddress(allocator, "192.168.1.1:8443");
    defer addr.deinit(allocator);

    try std.testing.expectEqualStrings("192.168.1.1", addr.host);
    try std.testing.expectEqual(@as(u16, 8443), addr.port);
}

test "parseAddress without port (default 443)" {
    const allocator = std.testing.allocator;

    var addr = try parseAddress(allocator, "vpn.example.com");
    defer addr.deinit(allocator);

    try std.testing.expectEqualStrings("vpn.example.com", addr.host);
    try std.testing.expectEqual(@as(u16, 443), addr.port);
}

test "parseAddress IPv6 with port" {
    const allocator = std.testing.allocator;

    var addr = try parseAddress(allocator, "[::1]:9443");
    defer addr.deinit(allocator);

    try std.testing.expectEqualStrings("[::1]", addr.host);
    try std.testing.expectEqual(@as(u16, 9443), addr.port);
}

test "packet framing" {
    const allocator = std.testing.allocator;

    const data = "Hello, VPN!";
    const framed = try PacketFraming.frame(allocator, data);
    defer allocator.free(framed);

    // Check length prefix (big-endian)
    try std.testing.expectEqual(@as(u8, 0), framed[0]);
    try std.testing.expectEqual(@as(u8, 0), framed[1]);
    try std.testing.expectEqual(@as(u8, 0), framed[2]);
    try std.testing.expectEqual(@as(u8, 11), framed[3]); // len("Hello, VPN!") = 11

    // Check data
    try std.testing.expectEqualStrings(data, framed[4..]);
}

test "timeout" {
    const timeout = Timeout.init(100); // 100ms

    try std.testing.expect(!timeout.isExpired());
    try std.testing.expect(timeout.remaining() > 0);

    std.time.sleep(150 * std.time.ns_per_ms);

    try std.testing.expect(timeout.isExpired());
    try std.testing.expectEqual(@as(u64, 0), timeout.remaining());
}

test "network stats" {
    var stats = NetworkStats.init();

    stats.bytes_sent = 1024;
    stats.bytes_received = 2048;
    stats.packets_sent = 10;
    stats.packets_received = 20;
    stats.connections_established = 5;

    try std.testing.expectEqual(@as(u64, 1024), stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 2048), stats.bytes_received);

    stats.reset();
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_sent);
}

test "connection pool" {
    const allocator = std.testing.allocator;

    var pool = ConnectionPool.init(allocator);
    defer pool.deinit();

    try std.testing.expectEqual(@as(usize, 0), pool.count());
}
