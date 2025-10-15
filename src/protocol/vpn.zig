// SSL-VPN Protocol Implementation
// Pure Zig implementation for VPN client
// Phase 3: Protocol Layer - Task 1

const std = @import("std");
// Use module imports instead of file paths to avoid conflicts
const http = @import("../net/http.zig"); // Keep file import for http (not in socket module)
// const socket = @import("../net/socket.zig"); // Commented out - conflicts with socket module
// connection module not needed - we use socket directly

/// VPN protocol version
pub const VpnVersion = struct {
    major: u8,
    minor: u8,
    build: u16,

    pub fn init(major: u8, minor: u8, build: u16) VpnVersion {
        return VpnVersion{
            .major = major,
            .minor = minor,
            .build = build,
        };
    }

    pub fn toString(self: VpnVersion, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "{d}.{d}.{d}", .{ self.major, self.minor, self.build });
    }

    pub fn parse(version_str: []const u8) !VpnVersion {
        var parts = std.mem.splitScalar(u8, version_str, '.');

        const major_str = parts.next() orelse return error.InvalidVersion;
        const minor_str = parts.next() orelse return error.InvalidVersion;
        const build_str = parts.next() orelse return error.InvalidVersion;

        return VpnVersion{
            .major = try std.fmt.parseInt(u8, major_str, 10),
            .minor = try std.fmt.parseInt(u8, minor_str, 10),
            .build = try std.fmt.parseInt(u16, build_str, 10),
        };
    }

    pub fn isCompatible(self: VpnVersion, other: VpnVersion) bool {
        return self.major == other.major;
    }
};

/// VPN authentication method
pub const AuthMethod = enum {
    anonymous,
    password,
    certificate,
    radius,
    ntlm,

    pub fn toString(self: AuthMethod) []const u8 {
        return switch (self) {
            .anonymous => "anonymous",
            .password => "password",
            .certificate => "certificate",
            .radius => "radius",
            .ntlm => "ntlm",
        };
    }
};

/// VPN authentication credentials
pub const AuthCredentials = struct {
    method: AuthMethod,
    username: ?[]const u8,
    password: ?[]const u8,
    certificate: ?[]const u8,

    pub fn init(method: AuthMethod) AuthCredentials {
        return AuthCredentials{
            .method = method,
            .username = null,
            .password = null,
            .certificate = null,
        };
    }

    pub fn withPassword(username: []const u8, password: []const u8) AuthCredentials {
        return AuthCredentials{
            .method = .password,
            .username = username,
            .password = password,
            .certificate = null,
        };
    }

    pub fn withCertificate(certificate: []const u8) AuthCredentials {
        return AuthCredentials{
            .method = .certificate,
            .username = null,
            .password = null,
            .certificate = certificate,
        };
    }
};

/// VPN session state
pub const SessionState = enum {
    disconnected,
    connecting,
    authenticating,
    establishing,
    connected,
    reconnecting,
    disconnecting,
    error_state,

    pub fn isActive(self: SessionState) bool {
        return self == .connected or self == .establishing or self == .authenticating;
    }

    pub fn canReconnect(self: SessionState) bool {
        return self == .connected or self == .error_state;
    }
};

/// VPN session information
pub const SessionInfo = struct {
    session_id: []const u8,
    server_version: VpnVersion,
    client_version: VpnVersion,
    virtual_ip: ?[]const u8,
    virtual_subnet: ?[]const u8,
    dns_servers: std.ArrayList([]const u8),
    established_at: i64,
    last_activity: i64,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        session_id: []const u8,
        server_version: VpnVersion,
        client_version: VpnVersion,
    ) !SessionInfo {
        const session_id_copy = try allocator.dupe(u8, session_id);
        const now = std.time.milliTimestamp();

        return SessionInfo{
            .session_id = session_id_copy,
            .server_version = server_version,
            .client_version = client_version,
            .virtual_ip = null,
            .virtual_subnet = null,
            .dns_servers = std.ArrayList([]const u8){},
            .established_at = now,
            .last_activity = now,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionInfo) void {
        self.allocator.free(self.session_id);
        if (self.virtual_ip) |ip| {
            self.allocator.free(ip);
        }
        if (self.virtual_subnet) |subnet| {
            self.allocator.free(subnet);
        }
        for (self.dns_servers.items) |dns| {
            self.allocator.free(dns);
        }
        self.dns_servers.deinit(self.allocator);
    }

    pub fn setVirtualIp(self: *SessionInfo, ip: []const u8) !void {
        if (self.virtual_ip) |old_ip| {
            self.allocator.free(old_ip);
        }
        self.virtual_ip = try self.allocator.dupe(u8, ip);
    }

    pub fn addDnsServer(self: *SessionInfo, dns: []const u8) !void {
        const dns_copy = try self.allocator.dupe(u8, dns);
        try self.dns_servers.append(self.allocator, dns_copy);
    }

    pub fn updateActivity(self: *SessionInfo) void {
        self.last_activity = std.time.milliTimestamp();
    }

    pub fn sessionDuration(self: *const SessionInfo) i64 {
        return std.time.milliTimestamp() - self.established_at;
    }

    pub fn idleTime(self: *const SessionInfo) i64 {
        return std.time.milliTimestamp() - self.last_activity;
    }
};

/// Keep-alive configuration
pub const KeepAliveConfig = struct {
    enabled: bool = true,
    interval_ms: u64 = 15000, // 15 seconds
    timeout_ms: u64 = 60000, // 60 seconds
    max_missed: u8 = 3,

    pub fn shouldSendKeepAlive(self: *const KeepAliveConfig, idle_time_ms: u64) bool {
        return self.enabled and idle_time_ms >= self.interval_ms;
    }

    pub fn isTimeout(self: *const KeepAliveConfig, idle_time_ms: u64) bool {
        return self.enabled and idle_time_ms >= self.timeout_ms;
    }
};

/// VPN session statistics
pub const SessionStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    keepalive_sent: u64 = 0,
    keepalive_received: u64 = 0,
    errors: u64 = 0,
    reconnects: u64 = 0,

    pub fn init() SessionStats {
        return SessionStats{};
    }

    pub fn recordPacketSent(self: *SessionStats, size: usize) void {
        self.packets_sent += 1;
        self.bytes_sent += size;
    }

    pub fn recordPacketReceived(self: *SessionStats, size: usize) void {
        self.packets_received += 1;
        self.bytes_received += size;
    }

    pub fn recordKeepAliveSent(self: *SessionStats) void {
        self.keepalive_sent += 1;
    }

    pub fn recordKeepAliveReceived(self: *SessionStats) void {
        self.keepalive_received += 1;
    }

    pub fn recordError(self: *SessionStats) void {
        self.errors += 1;
    }

    pub fn recordReconnect(self: *SessionStats) void {
        self.reconnects += 1;
    }

    pub fn totalPackets(self: *const SessionStats) u64 {
        return self.packets_sent + self.packets_received;
    }

    pub fn totalBytes(self: *const SessionStats) u64 {
        return self.bytes_sent + self.bytes_received;
    }
};

/// VPN protocol error codes
pub const VpnError = error{
    AuthenticationFailed,
    SessionExpired,
    ServerUnreachable,
    IncompatibleVersion,
    InvalidResponse,
    KeepAliveTimeout,
    ConnectionLost,
    ConfigurationError,
};

/// VPN session manager
pub const VpnSession = struct {
    allocator: std.mem.Allocator,
    server_host: []const u8,
    server_port: u16,
    credentials: AuthCredentials,
    state: SessionState,
    info: ?SessionInfo,
    stats: SessionStats,
    keepalive_config: KeepAliveConfig,
    last_keepalive: i64,
    missed_keepalives: u8,
    // conn_manager removed - not used in this old implementation

    pub fn init(
        allocator: std.mem.Allocator,
        server_host: []const u8,
        server_port: u16,
        credentials: AuthCredentials,
    ) !VpnSession {
        const host_copy = try allocator.dupe(u8, server_host);

        return VpnSession{
            .allocator = allocator,
            .server_host = host_copy,
            .server_port = server_port,
            .credentials = credentials,
            .state = .disconnected,
            .info = null,
            .stats = SessionStats.init(),
            .keepalive_config = KeepAliveConfig{},
            .last_keepalive = std.time.milliTimestamp(),
            .missed_keepalives = 0,
            // conn_manager removed
        };
    }

    pub fn deinit(self: *VpnSession) void {
        self.allocator.free(self.server_host);
        if (self.info) |*info| {
            info.deinit();
        }
    }

    /// Connect and authenticate to VPN server
    pub fn connect(self: *VpnSession) !void {
        if (self.state.isActive()) {
            return error.AlreadyConnected;
        }

        self.state = .connecting;

        // Note: Connection logic removed - see vpn_protocol.zig for actual implementation
        // This old code is not used anymore

        self.state = .authenticating;

        // Perform authentication handshake
        try self.authenticate();

        self.state = .establishing;

        // Establish session
        try self.establishSession();

        self.state = .connected;
        self.last_keepalive = std.time.milliTimestamp();
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnSession) void {
        if (!self.state.isActive()) {
            return;
        }

        self.state = .disconnecting;

        // Send disconnect message to server
        self.sendDisconnect() catch {};

        self.state = .disconnected;

        if (self.info) |*info| {
            info.deinit();
            self.info = null;
        }
    }

    /// Reconnect to VPN server
    pub fn reconnect(self: *VpnSession) !void {
        if (!self.state.canReconnect()) {
            return error.CannotReconnect;
        }

        self.state = .reconnecting;
        self.stats.recordReconnect();

        // Disconnect if still connected
        if (self.state.isActive()) {
            self.disconnect();
        }

        // Wait before reconnecting
        std.Thread.sleep(1000 * std.time.ns_per_ms);

        // Reconnect
        try self.connect();
    }

    /// Send keep-alive ping
    pub fn sendKeepAlive(self: *VpnSession) !void {
        if (self.state != .connected) {
            return error.NotConnected;
        }

        // TODO: Send actual keep-alive packet
        // For now, just update stats
        self.stats.recordKeepAliveSent();
        self.last_keepalive = std.time.milliTimestamp();

        if (self.info) |*info| {
            info.updateActivity();
        }
    }

    /// Check if keep-alive is needed
    pub fn needsKeepAlive(self: *const VpnSession) bool {
        if (self.state != .connected) {
            return false;
        }

        const now = std.time.milliTimestamp();
        const idle_time = @as(u64, @intCast(now - self.last_keepalive));

        return self.keepalive_config.shouldSendKeepAlive(idle_time);
    }

    /// Check if connection timed out
    pub fn isTimeout(self: *const VpnSession) bool {
        if (self.state != .connected) {
            return false;
        }

        const now = std.time.milliTimestamp();
        const idle_time = @as(u64, @intCast(now - self.last_keepalive));

        return self.keepalive_config.isTimeout(idle_time);
    }

    /// Get session statistics
    pub fn getStats(self: *const VpnSession) SessionStats {
        return self.stats;
    }

    /// Get session info
    pub fn getInfo(self: *const VpnSession) ?SessionInfo {
        return self.info;
    }

    // Private helper methods

    fn authenticate(self: *VpnSession) !void {
        // TODO: Implement actual authentication protocol
        // For now, create a mock session
        const client_version = VpnVersion.init(5, 0, 9759);
        const server_version = VpnVersion.init(5, 0, 9759);

        self.info = try SessionInfo.init(
            self.allocator,
            "session_12345",
            server_version,
            client_version,
        );
    }

    fn establishSession(self: *VpnSession) !void {
        // TODO: Implement session establishment
        // Configure virtual network interface, routes, etc.
        if (self.info) |*info| {
            try info.setVirtualIp("10.0.0.2");
            try info.addDnsServer("8.8.8.8");
        }
    }

    fn sendDisconnect(self: *VpnSession) !void {
        // TODO: Send disconnect packet to server
        _ = self;
    }
};

// ============================================================================
// C FFI Exports for gradual migration
// ============================================================================

export fn zig_vpn_session_init(
    server_host: [*:0]const u8,
    server_port: u16,
    username: [*:0]const u8,
    password: [*:0]const u8,
    conn_manager: ?*anyopaque, // Changed from connection.ConnectionManager
) ?*VpnSession {
    _ = conn_manager; // Not used in this old implementation
    const allocator = std.heap.c_allocator;
    const host_slice = std.mem.span(server_host);
    const user_slice = std.mem.span(username);
    const pass_slice = std.mem.span(password);

    const credentials = AuthCredentials.withPassword(user_slice, pass_slice);

    const session = allocator.create(VpnSession) catch return null;
    session.* = VpnSession.init(allocator, host_slice, server_port, credentials) catch return null;
    return session;
}

export fn zig_vpn_session_destroy(session: ?*VpnSession) void {
    if (session) |s| {
        const allocator = std.heap.c_allocator;
        s.deinit();
        allocator.destroy(s);
    }
}

export fn zig_vpn_session_connect(session: ?*VpnSession) c_int {
    const s = session orelse return -1;
    s.connect() catch return -1;
    return 0;
}

export fn zig_vpn_session_disconnect(session: ?*VpnSession) void {
    if (session) |s| {
        s.disconnect();
    }
}

export fn zig_vpn_session_send_keepalive(session: ?*VpnSession) c_int {
    const s = session orelse return -1;
    s.sendKeepAlive() catch return -1;
    return 0;
}

export fn zig_vpn_session_needs_keepalive(session: ?*VpnSession) bool {
    const s = session orelse return false;
    return s.needsKeepAlive();
}

// ============================================================================
// Tests
// ============================================================================

test "VPN version parsing" {
    const version = try VpnVersion.parse("5.0.9759");

    try std.testing.expectEqual(@as(u8, 5), version.major);
    try std.testing.expectEqual(@as(u8, 0), version.minor);
    try std.testing.expectEqual(@as(u16, 9759), version.build);
}

test "VPN version to string" {
    const allocator = std.testing.allocator;
    const version = VpnVersion.init(5, 0, 9759);

    const version_str = try version.toString(allocator);
    defer allocator.free(version_str);

    try std.testing.expectEqualStrings("5.0.9759", version_str);
}

test "VPN version compatibility" {
    const v1 = VpnVersion.init(5, 0, 9759);
    const v2 = VpnVersion.init(5, 1, 9800);
    const v3 = VpnVersion.init(4, 9, 9700);

    try std.testing.expect(v1.isCompatible(v2)); // Same major version
    try std.testing.expect(!v1.isCompatible(v3)); // Different major version
}

test "Auth method to string" {
    try std.testing.expectEqualStrings("password", AuthMethod.password.toString());
    try std.testing.expectEqualStrings("certificate", AuthMethod.certificate.toString());
}

test "Auth credentials with password" {
    const creds = AuthCredentials.withPassword("user123", "pass456");

    try std.testing.expectEqual(AuthMethod.password, creds.method);
    try std.testing.expectEqualStrings("user123", creds.username.?);
    try std.testing.expectEqualStrings("pass456", creds.password.?);
}

test "Session state checks" {
    try std.testing.expect(SessionState.connected.isActive());
    try std.testing.expect(SessionState.authenticating.isActive());
    try std.testing.expect(!SessionState.disconnected.isActive());

    try std.testing.expect(SessionState.connected.canReconnect());
    try std.testing.expect(SessionState.error_state.canReconnect());
    try std.testing.expect(!SessionState.connecting.canReconnect());
}

test "Session info initialization" {
    const allocator = std.testing.allocator;

    const server_ver = VpnVersion.init(5, 0, 9759);
    const client_ver = VpnVersion.init(5, 0, 9759);

    var info = try SessionInfo.init(allocator, "sess_123", server_ver, client_ver);
    defer info.deinit();

    try std.testing.expectEqualStrings("sess_123", info.session_id);
    try std.testing.expectEqual(@as(u8, 5), info.server_version.major);
}

test "Session info virtual IP" {
    const allocator = std.testing.allocator;

    const server_ver = VpnVersion.init(5, 0, 9759);
    const client_ver = VpnVersion.init(5, 0, 9759);

    var info = try SessionInfo.init(allocator, "sess_123", server_ver, client_ver);
    defer info.deinit();

    try info.setVirtualIp("10.0.0.2");
    try std.testing.expectEqualStrings("10.0.0.2", info.virtual_ip.?);
}

test "Session info DNS servers" {
    const allocator = std.testing.allocator;

    const server_ver = VpnVersion.init(5, 0, 9759);
    const client_ver = VpnVersion.init(5, 0, 9759);

    var info = try SessionInfo.init(allocator, "sess_123", server_ver, client_ver);
    defer info.deinit();

    try info.addDnsServer("8.8.8.8");
    try info.addDnsServer("1.1.1.1");

    try std.testing.expectEqual(@as(usize, 2), info.dns_servers.items.len);
    try std.testing.expectEqualStrings("8.8.8.8", info.dns_servers.items[0]);
}

test "Keep-alive configuration" {
    const config = KeepAliveConfig{
        .interval_ms = 15000,
        .timeout_ms = 60000,
    };

    try std.testing.expect(config.shouldSendKeepAlive(20000)); // 20s > 15s
    try std.testing.expect(!config.shouldSendKeepAlive(10000)); // 10s < 15s

    try std.testing.expect(config.isTimeout(70000)); // 70s > 60s
    try std.testing.expect(!config.isTimeout(50000)); // 50s < 60s
}

test "Session statistics tracking" {
    var stats = SessionStats.init();

    stats.recordPacketSent(100);
    stats.recordPacketReceived(200);
    stats.recordKeepAliveSent();

    try std.testing.expectEqual(@as(u64, 1), stats.packets_sent);
    try std.testing.expectEqual(@as(u64, 1), stats.packets_received);
    try std.testing.expectEqual(@as(u64, 100), stats.bytes_sent);
    try std.testing.expectEqual(@as(u64, 200), stats.bytes_received);
    try std.testing.expectEqual(@as(u64, 1), stats.keepalive_sent);
    try std.testing.expectEqual(@as(u64, 2), stats.totalPackets());
    try std.testing.expectEqual(@as(u64, 300), stats.totalBytes());
}

test "Session info activity tracking" {
    const allocator = std.testing.allocator;

    const server_ver = VpnVersion.init(5, 0, 9759);
    const client_ver = VpnVersion.init(5, 0, 9759);

    var info = try SessionInfo.init(allocator, "sess_123", server_ver, client_ver);
    defer info.deinit();

    const initial_time = info.last_activity;

    // Simulate some time passing
    std.Thread.sleep(10 * std.time.ns_per_ms);

    info.updateActivity();

    try std.testing.expect(info.last_activity > initial_time);
    try std.testing.expect(info.idleTime() >= 0);
}
