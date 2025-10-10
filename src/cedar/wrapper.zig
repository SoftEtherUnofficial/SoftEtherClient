//! Cedar Zig Wrapper
//!
//! Ergonomic Zig API over Cedar FFI for VPN protocol operations.

const std = @import("std");
const c = @cImport({
    @cInclude("cedar_ffi.h");
});

/// Error type for Cedar operations
pub const CedarError = error{
    InternalError,
    InvalidParameter,
    NotConnected,
    InvalidState,
    BufferTooSmall,
    PacketTooLarge,
    AuthenticationFailed,
    NotImplemented,
    TimeOut,
    IoError,
};

/// Convert C error code to Zig error
fn errorFromCode(code: c.CedarErrorCode) CedarError!void {
    return switch (code) {
        c.Success => {},
        c.InternalError => error.InternalError,
        c.InvalidParameter => error.InvalidParameter,
        c.NotConnected => error.NotConnected,
        c.InvalidState => error.InvalidState,
        c.BufferTooSmall => error.BufferTooSmall,
        c.PacketTooLarge => error.PacketTooLarge,
        c.AuthenticationFailed => error.AuthenticationFailed,
        c.NotImplemented => error.NotImplemented,
        c.TimeOut => error.TimeOut,
        c.IoError => error.IoError,
        else => error.InternalError,
    };
}

/// Session status
pub const SessionStatus = enum {
    Init,
    Connecting,
    Authenticating,
    Established,
    Reconnecting,
    Closing,
    Terminated,

    fn fromC(status: c.CedarSessionStatus) SessionStatus {
        return switch (status) {
            c.Init => .Init,
            c.Connecting => .Connecting,
            c.Authenticating => .Authenticating,
            c.Established => .Established,
            c.Reconnecting => .Reconnecting,
            c.Closing => .Closing,
            c.Terminated => .Terminated,
            else => .Terminated,
        };
    }
};

/// Session statistics
pub const SessionStats = struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    duration_secs: u64,
    idle_time_secs: u64,

    pub fn fromC(stats: c.CedarSessionStats) SessionStats {
        return .{
            .bytes_sent = stats.bytes_sent,
            .bytes_received = stats.bytes_received,
            .packets_sent = stats.packets_sent,
            .packets_received = stats.packets_received,
            .duration_secs = stats.duration_secs,
            .idle_time_secs = stats.idle_time_secs,
        };
    }
};

/// VPN Session
pub const Session = struct {
    handle: c.CedarSessionHandle,

    /// Create new session
    pub fn init(server: []const u8, port: u16, hub: []const u8) !Session {
        // Null-terminate strings for C
        var server_buf: [256]u8 = undefined;
        var hub_buf: [256]u8 = undefined;

        if (server.len >= 255 or hub.len >= 255) {
            return error.InvalidParameter;
        }

        @memcpy(server_buf[0..server.len], server);
        server_buf[server.len] = 0;

        @memcpy(hub_buf[0..hub.len], hub);
        hub_buf[hub.len] = 0;

        const handle = c.cedar_session_new(&server_buf, port, &hub_buf);
        if (handle == null) {
            return error.InvalidParameter;
        }

        return Session{ .handle = handle };
    }

    /// Free session
    pub fn deinit(self: *Session) void {
        c.cedar_session_free(self.handle);
        self.handle = null;
    }

    /// Get session status
    pub fn getStatus(self: *const Session) SessionStatus {
        const status = c.cedar_session_get_status(self.handle);
        return SessionStatus.fromC(status);
    }

    /// Get session statistics
    pub fn getStats(self: *const Session) !SessionStats {
        var stats: c.CedarSessionStats = undefined;
        const result = c.cedar_session_get_stats(self.handle, &stats);
        try errorFromCode(result);
        return SessionStats.fromC(stats);
    }

    /// Connect to VPN server (TLS + initial handshake)
    pub fn connect(self: *Session) !void {
        const result = c.cedar_session_connect(self.handle);
        try errorFromCode(result);
    }

    /// Send protocol packet
    pub fn sendPacket(self: *Session, packet: *const Packet) !void {
        const result = c.cedar_session_send_packet(self.handle, packet.handle);
        try errorFromCode(result);
    }

    /// Receive protocol packet
    pub fn receivePacket(self: *Session) !Packet {
        var packet_handle: c.CedarPacketHandle = null;
        const result = c.cedar_session_receive_packet(self.handle, &packet_handle);
        try errorFromCode(result);

        if (packet_handle == null) {
            return error.InvalidState;
        }

        return Packet{ .handle = packet_handle };
    }

    /// Authenticate with username and password
    /// Password will be hashed with SHA-1 before sending
    pub fn authenticate(self: *Session, username: []const u8, password: []const u8) !void {
        // Compute SHA-1 hash of password
        var hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(password, &hash, .{});

        // Null-terminate username
        var username_buf: [256]u8 = undefined;
        if (username.len >= 255) {
            return error.InvalidParameter;
        }
        @memcpy(username_buf[0..username.len], username);
        username_buf[username.len] = 0;

        const result = c.cedar_session_authenticate(
            self.handle,
            &username_buf,
            &hash,
            hash.len,
        );
        try errorFromCode(result);
    }
};

/// VPN Packet
pub const Packet = struct {
    handle: c.CedarPacketHandle,

    /// Create new packet
    pub fn init(command: []const u8) !Packet {
        var cmd_buf: [256]u8 = undefined;
        if (command.len >= 255) {
            return error.InvalidParameter;
        }

        @memcpy(cmd_buf[0..command.len], command);
        cmd_buf[command.len] = 0;

        const handle = c.cedar_packet_new(&cmd_buf);
        if (handle == null) {
            return error.InvalidParameter;
        }

        return Packet{ .handle = handle };
    }

    /// Free packet
    pub fn deinit(self: *Packet) void {
        c.cedar_packet_free(self.handle);
        self.handle = null;
    }

    /// Add integer parameter
    pub fn addInt(self: *Packet, key: []const u8, value: u32) !void {
        var key_buf: [256]u8 = undefined;
        if (key.len >= 255) {
            return error.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        const result = c.cedar_packet_add_int(self.handle, &key_buf, value);
        try errorFromCode(result);
    }

    /// Add string parameter
    pub fn addString(self: *Packet, key: []const u8, value: []const u8) !void {
        var key_buf: [256]u8 = undefined;
        var val_buf: [1024]u8 = undefined;

        if (key.len >= 255 or value.len >= 1023) {
            return error.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        @memcpy(val_buf[0..value.len], value);
        val_buf[value.len] = 0;

        const result = c.cedar_packet_add_string(self.handle, &key_buf, &val_buf);
        try errorFromCode(result);
    }

    /// Get integer parameter
    pub fn getInt(self: *const Packet, key: []const u8) !u32 {
        var key_buf: [256]u8 = undefined;
        if (key.len >= 255) {
            return error.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        var value: u32 = undefined;
        const result = c.cedar_packet_get_int(self.handle, &key_buf, &value);
        try errorFromCode(result);
        return value;
    }

    /// Get string parameter
    pub fn getString(self: *const Packet, key: []const u8, buffer: []u8) ![]const u8 {
        var key_buf: [256]u8 = undefined;
        if (key.len >= 255) {
            return error.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        const result = c.cedar_packet_get_string(self.handle, &key_buf, buffer.ptr, buffer.len);
        try errorFromCode(result);

        // Find null terminator
        var len: usize = 0;
        while (len < buffer.len and buffer[len] != 0) : (len += 1) {}

        return buffer[0..len];
    }
};

/// TLS connection state
pub const TlsState = enum {
    Disconnected,
    Handshaking,
    Connected,
    Error,

    fn fromC(state: c.CedarTlsState) TlsState {
        return switch (state) {
            c.Disconnected => .Disconnected,
            c.Handshaking => .Handshaking,
            c.Connected => .Connected,
            c.Error => .Error,
            else => .Error,
        };
    }
};

/// TLS Connection
pub const TlsConnection = struct {
    handle: c.CedarTlsHandle,

    /// Create new TLS connection
    pub fn init() !TlsConnection {
        const handle = c.cedar_tls_new();
        if (handle == null) {
            return error.InternalError;
        }

        return TlsConnection{ .handle = handle };
    }

    /// Free TLS connection
    pub fn deinit(self: *TlsConnection) void {
        c.cedar_tls_free(self.handle);
        self.handle = null;
    }

    /// Get TLS state
    pub fn getState(self: *const TlsConnection) TlsState {
        const state = c.cedar_tls_get_state(self.handle);
        return TlsState.fromC(state);
    }

    /// Encrypt data
    pub fn encrypt(self: *TlsConnection, plaintext: []const u8, ciphertext: []u8) !usize {
        var bytes_written: usize = undefined;
        const result = c.cedar_tls_encrypt(
            self.handle,
            plaintext.ptr,
            plaintext.len,
            ciphertext.ptr,
            ciphertext.len,
            &bytes_written,
        );
        try errorFromCode(result);
        return bytes_written;
    }

    /// Connect to server and perform TLS handshake
    pub fn connect(self: *TlsConnection, host: []const u8, port: u16) !void {
        // Null-terminate host string
        var host_buf: [256]u8 = undefined;
        if (host.len >= 255) {
            return error.InvalidParameter;
        }
        @memcpy(host_buf[0..host.len], host);
        host_buf[host.len] = 0;

        const result = c.cedar_tls_connect(self.handle, &host_buf, port);
        try errorFromCode(result);
    }

    /// Send data over TLS connection
    pub fn send(self: *TlsConnection, data: []const u8) !usize {
        const bytes_sent = c.cedar_tls_send(self.handle, data.ptr, data.len);
        if (bytes_sent < 0) {
            return error.IoError;
        }
        return @intCast(bytes_sent);
    }

    /// Receive data from TLS connection
    pub fn receive(self: *TlsConnection, buffer: []u8) !usize {
        const bytes_received = c.cedar_tls_receive(self.handle, buffer.ptr, buffer.len);
        if (bytes_received < 0) {
            return error.IoError;
        }
        if (bytes_received == 0) {
            return 0; // EOF
        }
        return @intCast(bytes_received);
    }
};

/// Compression algorithm
pub const CompressionAlgorithm = enum(c_int) {
    None = 0,
    Deflate = 1,
    Gzip = 2,
    Lz4 = 3,

    fn toC(self: CompressionAlgorithm) c.CedarCompressionAlgorithm {
        return switch (self) {
            .None => c.CompressionNone,
            .Deflate => c.Deflate,
            .Gzip => c.Gzip,
            .Lz4 => c.Lz4,
        };
    }
};

/// Compressor
pub const Compressor = struct {
    handle: c.CedarCompressorHandle,

    /// Create new compressor
    pub fn init(algorithm: CompressionAlgorithm) !Compressor {
        const handle = c.cedar_compressor_new(algorithm.toC());
        if (handle == null) {
            return error.InternalError;
        }

        return Compressor{ .handle = handle };
    }

    /// Free compressor
    pub fn deinit(self: *Compressor) void {
        c.cedar_compressor_free(self.handle);
        self.handle = null;
    }

    /// Compress data
    pub fn compress(self: *Compressor, input: []const u8, output: []u8) !usize {
        var bytes_written: usize = undefined;
        const result = c.cedar_compressor_compress(
            self.handle,
            input.ptr,
            input.len,
            output.ptr,
            output.len,
            &bytes_written,
        );
        try errorFromCode(result);
        return bytes_written;
    }

    /// Decompress data
    pub fn decompress(self: *Compressor, input: []const u8, output: []u8) !usize {
        var bytes_written: usize = undefined;
        const result = c.cedar_compressor_decompress(
            self.handle,
            input.ptr,
            input.len,
            output.ptr,
            output.len,
            &bytes_written,
        );
        try errorFromCode(result);
        return bytes_written;
    }
};

/// UDP acceleration mode
pub const UdpAccelMode = enum(c_int) {
    Disabled = 0,
    Hybrid = 1,
    UdpOnly = 2,

    fn toC(self: UdpAccelMode) c_uint {
        return @intCast(@intFromEnum(self));
    }
};

/// UDP Accelerator
pub const UdpAccelerator = struct {
    handle: c.CedarUdpAccelHandle,

    /// Create new UDP accelerator
    pub fn init(mode: UdpAccelMode) !UdpAccelerator {
        const handle = c.cedar_udp_accel_new(mode.toC());
        if (handle == null) {
            return error.InternalError;
        }

        return UdpAccelerator{ .handle = handle };
    }

    /// Free UDP accelerator
    pub fn deinit(self: *UdpAccelerator) void {
        c.cedar_udp_accel_free(self.handle);
        self.handle = null;
    }

    /// Check if UDP acceleration is healthy
    pub fn isHealthy(self: *const UdpAccelerator) bool {
        return c.cedar_udp_accel_is_healthy(self.handle) != 0;
    }
};

/// NAT type
pub const NatType = enum {
    None,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    Unknown,

    fn fromC(nat_type: c.CedarNatType) NatType {
        return switch (nat_type) {
            c.NatNone => .None,
            c.FullCone => .FullCone,
            c.RestrictedCone => .RestrictedCone,
            c.PortRestrictedCone => .PortRestrictedCone,
            c.Symmetric => .Symmetric,
            c.Unknown => .Unknown,
            else => .Unknown,
        };
    }
};

/// NAT Traversal
pub const NatTraversal = struct {
    handle: c.CedarNatTraversalHandle,

    /// Create new NAT traversal engine
    pub fn init() !NatTraversal {
        const handle = c.cedar_nat_traversal_new();
        if (handle == null) {
            return error.InternalError;
        }

        return NatTraversal{ .handle = handle };
    }

    /// Free NAT traversal engine
    pub fn deinit(self: *NatTraversal) void {
        c.cedar_nat_traversal_free(self.handle);
        self.handle = null;
    }

    /// Detect NAT type
    pub fn detect(self: *NatTraversal) NatType {
        const nat_type = c.cedar_nat_traversal_detect(self.handle);
        return NatType.fromC(nat_type);
    }

    /// Check if NAT traversal is supported
    pub fn isSupported(self: *const NatTraversal) bool {
        return c.cedar_nat_traversal_is_supported(self.handle) != 0;
    }
};

/// Get Cedar version
pub fn getVersion() [:0]const u8 {
    const ver_ptr = c.cedar_version();
    return std.mem.span(ver_ptr);
}

/// Get Cedar protocol version
pub fn getProtocolVersion() u32 {
    return c.cedar_protocol_version();
}

test "Cedar version" {
    const version = getVersion();
    try std.testing.expect(version.len > 0);

    const protocol_ver = getProtocolVersion();
    try std.testing.expectEqual(@as(u32, 4), protocol_ver);
}

test "Session creation" {
    // Test with invalid parameters should not crash
    // Note: Actual session creation requires valid server
}

test "Packet operations" {
    var packet = try Packet.init("test");
    defer packet.deinit();

    try packet.addInt("version", 4);
    try packet.addString("client", "Cedar-Zig");

    const version = try packet.getInt("version");
    try std.testing.expectEqual(@as(u32, 4), version);
}

test "TLS connection" {
    var tls = try TlsConnection.init();
    defer tls.deinit();

    const state = tls.getState();
    try std.testing.expectEqual(TlsState.Disconnected, state);
}

test "Compressor" {
    var compressor = try Compressor.init(.Deflate);
    defer compressor.deinit();

    const input = "test data to compress";
    var output: [1024]u8 = undefined;

    const compressed_len = try compressor.compress(input, &output);
    try std.testing.expect(compressed_len > 0);
}

test "UDP Accelerator" {
    var accel = try UdpAccelerator.init(.Hybrid);
    defer accel.deinit();

    // Initially not healthy (not initialized)
    _ = accel.isHealthy();
}

test "NAT Traversal" {
    var nat = try NatTraversal.init();
    defer nat.deinit();

    const nat_type = nat.detect();
    _ = nat_type; // Just ensure it doesn't crash

    _ = nat.isSupported();
}
