//! Network Operations
//!
//! Safe wrappers around Mayaqua network FFI functions.
//! Provides RAII-style socket management with automatic cleanup.

const std = @import("std");
const mayaqua = @import("../mayaqua.zig");
const c = mayaqua.c;
const MayaquaError = mayaqua.MayaquaError;
const checkResult = mayaqua.checkResult;

/// TCP Socket with RAII cleanup
pub const TcpSocket = struct {
    handle: *c.MayaquaTcpSocket,

    /// Connect to TCP server
    ///
    /// ## Parameters
    /// - `hostname`: Server hostname or IP address
    /// - `port`: Server port number
    ///
    /// ## Returns
    /// - Connected TCP socket (caller must call close())
    ///
    /// ## Example
    /// ```zig
    /// var socket = try network.TcpSocket.connect("example.com", 443);
    /// defer socket.close();
    /// ```
    pub fn connect(hostname: []const u8, port: u16) MayaquaError!TcpSocket {
        var host_buf: [256]u8 = undefined;
        if (hostname.len >= host_buf.len) {
            return MayaquaError.InvalidParameter;
        }

        @memcpy(host_buf[0..hostname.len], hostname);
        host_buf[hostname.len] = 0;

        var socket_ptr: ?*c.MayaquaTcpSocket = null;

        const result = c.mayaqua_tcp_connect(
            @ptrCast(&host_buf),
            port,
            @ptrCast(&socket_ptr),
        );
        try checkResult(result);

        if (socket_ptr == null) {
            return MayaquaError.NullPointer;
        }

        return .{ .handle = socket_ptr.? };
    }

    /// Connect to TCP server with timeout
    ///
    /// ## Parameters
    /// - `hostname`: Server hostname or IP address
    /// - `port`: Server port number
    /// - `timeout_ms`: Connection timeout in milliseconds
    ///
    /// ## Returns
    /// - Connected TCP socket (caller must call close())
    ///
    /// ## Example
    /// ```zig
    /// var socket = try network.TcpSocket.connectTimeout("example.com", 443, 5000);
    /// defer socket.close();
    /// ```
    pub fn connectTimeout(hostname: []const u8, port: u16, timeout_ms: u32) MayaquaError!TcpSocket {
        var host_buf: [256]u8 = undefined;
        if (hostname.len >= host_buf.len) {
            return MayaquaError.InvalidParameter;
        }

        @memcpy(host_buf[0..hostname.len], hostname);
        host_buf[hostname.len] = 0;

        var socket_ptr: ?*c.MayaquaTcpSocket = null;

        const result = c.mayaqua_tcp_connect_timeout(
            @ptrCast(&host_buf),
            port,
            @intCast(timeout_ms),
            @ptrCast(&socket_ptr),
        );
        try checkResult(result);

        if (socket_ptr == null) {
            return MayaquaError.NullPointer;
        }

        return .{ .handle = socket_ptr.? };
    }

    /// Send data over TCP socket
    ///
    /// ## Parameters
    /// - `data`: Data to send
    ///
    /// ## Returns
    /// - Number of bytes sent
    ///
    /// ## Example
    /// ```zig
    /// const sent = try socket.send("GET / HTTP/1.1\r\n\r\n");
    /// ```
    pub fn send(self: TcpSocket, data: []const u8) MayaquaError!usize {
        const result = c.mayaqua_tcp_send(
            self.handle,
            data.ptr,
            @intCast(data.len),
        );

        if (result < 0) {
            return switch (result) {
                -1 => MayaquaError.NullPointer,
                -3 => MayaquaError.OperationFailed,
                else => MayaquaError.InvalidParameter,
            };
        }

        return @intCast(result);
    }

    /// Receive data from TCP socket
    ///
    /// ## Parameters
    /// - `buffer`: Buffer to receive data into
    ///
    /// ## Returns
    /// - Number of bytes received
    ///
    /// ## Example
    /// ```zig
    /// var buffer: [4096]u8 = undefined;
    /// const received = try socket.recv(&buffer);
    /// ```
    pub fn recv(self: TcpSocket, buffer: []u8) MayaquaError!usize {
        const result = c.mayaqua_tcp_recv(
            self.handle,
            buffer.ptr,
            @intCast(buffer.len),
        );

        if (result < 0) {
            return switch (result) {
                -1 => MayaquaError.NullPointer,
                -3 => MayaquaError.OperationFailed,
                else => MayaquaError.InvalidParameter,
            };
        }

        return @intCast(result);
    }

    /// Close TCP socket
    ///
    /// ## Example
    /// ```zig
    /// socket.close();
    /// ```
    pub fn close(self: TcpSocket) void {
        c.mayaqua_tcp_close(self.handle);
    }
};

/// TCP Listener for accepting connections
pub const TcpListener = struct {
    handle: *c.MayaquaTcpListener,

    /// Create TCP listener on port
    ///
    /// ## Parameters
    /// - `port`: Port to listen on
    ///
    /// ## Returns
    /// - TCP listener (caller must call close())
    ///
    /// ## Example
    /// ```zig
    /// var listener = try network.TcpListener.listen(8080);
    /// defer listener.close();
    /// ```
    pub fn listen(port: u16) MayaquaError!TcpListener {
        var listener_ptr: ?*c.MayaquaTcpListener = null;

        const result = c.mayaqua_tcp_listen(
            port,
            @ptrCast(&listener_ptr),
        );
        try checkResult(result);

        if (listener_ptr == null) {
            return MayaquaError.NullPointer;
        }

        return .{ .handle = listener_ptr.? };
    }

    /// Create TCP listener with options
    ///
    /// ## Parameters
    /// - `port`: Port to listen on
    /// - `local_only`: If true, bind to localhost only
    ///
    /// ## Returns
    /// - TCP listener (caller must call close())
    ///
    /// ## Example
    /// ```zig
    /// var listener = try network.TcpListener.listenEx(8080, true);
    /// defer listener.close();
    /// ```
    pub fn listenEx(port: u16, local_only: bool) MayaquaError!TcpListener {
        var listener_ptr: ?*c.MayaquaTcpListener = null;

        const result = c.mayaqua_tcp_listen_ex(
            port,
            local_only,
            @ptrCast(&listener_ptr),
        );
        try checkResult(result);

        if (listener_ptr == null) {
            return MayaquaError.NullPointer;
        }

        return .{ .handle = listener_ptr.? };
    }

    /// Accept incoming connection
    ///
    /// ## Returns
    /// - Connected TCP socket (caller must call close())
    ///
    /// ## Example
    /// ```zig
    /// var client = try listener.accept();
    /// defer client.close();
    /// ```
    pub fn accept(self: TcpListener) MayaquaError!TcpSocket {
        var socket_ptr: ?*c.MayaquaTcpSocket = null;

        const result = c.mayaqua_tcp_accept(
            self.handle,
            @ptrCast(&socket_ptr),
        );
        try checkResult(result);

        if (socket_ptr == null) {
            return MayaquaError.NullPointer;
        }

        return .{ .handle = socket_ptr.? };
    }

    /// Close TCP listener
    pub fn close(self: TcpListener) void {
        c.mayaqua_tcp_listener_close(self.handle);
    }
};

/// UDP Socket
pub const UdpSocket = struct {
    handle: *c.MayaquaUdpSocket,

    /// Create UDP socket bound to port
    ///
    /// ## Parameters
    /// - `port`: Port to bind to (0 for any available port)
    ///
    /// ## Returns
    /// - UDP socket (caller must call close())
    ///
    /// ## Example
    /// ```zig
    /// var socket = try network.UdpSocket.new(0);
    /// defer socket.close();
    /// ```
    pub fn new(port: u16) MayaquaError!UdpSocket {
        var socket_ptr: ?*c.MayaquaUdpSocket = null;

        const result = c.mayaqua_udp_new(
            port,
            @ptrCast(&socket_ptr),
        );
        try checkResult(result);

        if (socket_ptr == null) {
            return MayaquaError.NullPointer;
        }

        return .{ .handle = socket_ptr.? };
    }

    /// Send data to address
    ///
    /// ## Parameters
    /// - `data`: Data to send
    /// - `hostname`: Destination hostname or IP
    /// - `port`: Destination port
    ///
    /// ## Returns
    /// - Number of bytes sent
    ///
    /// ## Example
    /// ```zig
    /// const sent = try socket.sendTo("hello", "example.com", 1234);
    /// ```
    pub fn sendTo(self: UdpSocket, data: []const u8, hostname: []const u8, port: u16) MayaquaError!usize {
        var host_buf: [256]u8 = undefined;
        if (hostname.len >= host_buf.len) {
            return MayaquaError.InvalidParameter;
        }

        @memcpy(host_buf[0..hostname.len], hostname);
        host_buf[hostname.len] = 0;

        const result = c.mayaqua_udp_send_to(
            self.handle,
            data.ptr,
            @intCast(data.len),
            @ptrCast(&host_buf),
            port,
        );

        if (result < 0) {
            return switch (result) {
                -1 => MayaquaError.NullPointer,
                -2 => MayaquaError.EncodingError,
                -3 => MayaquaError.OperationFailed,
                else => MayaquaError.InvalidParameter,
            };
        }

        return @intCast(result);
    }

    /// Receive data from socket
    ///
    /// ## Parameters
    /// - `allocator`: Allocator for hostname string
    /// - `buffer`: Buffer to receive data into
    ///
    /// ## Returns
    /// - Tuple of (bytes_received, sender_hostname, sender_port)
    ///
    /// ## Example
    /// ```zig
    /// var buffer: [4096]u8 = undefined;
    /// const result = try socket.recvFrom(allocator, &buffer);
    /// defer allocator.free(result.hostname);
    /// ```
    pub fn recvFrom(self: UdpSocket, allocator: std.mem.Allocator, buffer: []u8) MayaquaError!struct {
        bytes: usize,
        hostname: []u8,
        port: u16,
    } {
        var hostname_ptr: [*c]u8 = null;
        var port_out: u16 = 0;

        const result = c.mayaqua_udp_recv_from(
            self.handle,
            buffer.ptr,
            @intCast(buffer.len),
            @ptrCast(&hostname_ptr),
            &port_out,
        );

        if (result < 0) {
            return switch (result) {
                -1 => MayaquaError.NullPointer,
                -2 => MayaquaError.EncodingError,
                -3 => MayaquaError.OperationFailed,
                else => MayaquaError.InvalidParameter,
            };
        }

        if (hostname_ptr == null) {
            return MayaquaError.NullPointer;
        }

        // Copy hostname from Rust allocation
        const hostname_len = std.mem.len(hostname_ptr);
        const hostname = try allocator.dupe(u8, hostname_ptr[0..hostname_len]);

        // Free Rust allocation
        c.mayaqua_free_string(hostname_ptr);

        return .{
            .bytes = @intCast(result),
            .hostname = hostname,
            .port = port_out,
        };
    }

    /// Close UDP socket
    pub fn close(self: UdpSocket) void {
        c.mayaqua_udp_close(self.handle);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "tcp connect to localhost" {
    const testing = std.testing;
    _ = testing;

    // Note: This test requires a server running on localhost:80
    // In real tests, we'd use a mock server or skip if unavailable
    _ = TcpSocket.connect("localhost", 80) catch return;
}

test "tcp listener basic" {
    // Create listener on ephemeral port
    var listener = try TcpListener.listen(0);
    defer listener.close();
}

test "udp socket basic" {
    // Create UDP socket on ephemeral port
    var socket = try UdpSocket.new(0);
    defer socket.close();
}
