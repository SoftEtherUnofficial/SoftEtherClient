// Wave 4: SoftEther Bridge - Zig Implementation
// Replaces: src/bridge/softether_bridge.c (1,384 lines)
//
// This module provides the bridge between our Zig code and SoftEther's C libraries.
// It manages VPN client lifecycle, configuration, and connection orchestration.

const std = @import("std");

// For now, we comment out C imports until we need them in Phase 3
// const c = @import("../c.zig");

/// VPN connection status
pub const VpnBridgeStatus = enum(u32) {
    DISCONNECTED = 0,
    CONNECTING = 1,
    CONNECTED = 2,
    DISCONNECTING = 3,
    ERROR = 4,

    pub fn toString(self: VpnBridgeStatus) []const u8 {
        return switch (self) {
            .DISCONNECTED => "disconnected",
            .CONNECTING => "connecting",
            .CONNECTED => "connected",
            .DISCONNECTING => "disconnecting",
            .ERROR => "error",
        };
    }
};

/// IP version configuration
pub const IpVersion = enum(i32) {
    AUTO = 0,
    IPV4_ONLY = 4,
    IPV6_ONLY = 6,

    pub fn fromInt(value: i32) IpVersion {
        return switch (value) {
            4 => .IPV4_ONLY,
            6 => .IPV6_ONLY,
            else => .AUTO,
        };
    }
};

/// Error codes
pub const BridgeError = error{
    NotInitialized,
    AlreadyInitialized,
    NullPointer,
    InvalidParameter,
    OutOfMemory,
    ConnectionFailed,
    AuthenticationFailed,
    AlreadyConnected,
    NotConnected,
    SessionCreationFailed,
    AccountCreationFailed,
    AdapterCreationFailed,
    InvalidIpVersion,
    InvalidMaxConnection,
    InitFailed,
    AllocFailed,
};

/// Error code enum for compatibility
pub const ErrorCode = enum(i32) {
    SUCCESS = 0,
    INIT_FAILED = -1,
    INVALID_PARAM = -2,
    ALLOC_FAILED = -3,
    CONNECT_FAILED = -4,
    AUTH_FAILED = -5,
    NOT_CONNECTED = -6,
    ALREADY_INIT = -7,
    NOT_INIT = -8,
    UNKNOWN = -999,

    /// Get error message for error code
    pub fn message(self: ErrorCode) []const u8 {
        return switch (self) {
            .SUCCESS => "Success",
            .INIT_FAILED => "Library initialization failed",
            .INVALID_PARAM => "Invalid parameter",
            .ALLOC_FAILED => "Memory allocation failed",
            .CONNECT_FAILED => "Connection failed",
            .AUTH_FAILED => "Authentication failed",
            .NOT_CONNECTED => "Not connected",
            .ALREADY_INIT => "Already initialized",
            .NOT_INIT => "Not initialized",
            .UNKNOWN => "Unknown error",
        };
    }

    /// Convert from integer
    pub fn fromInt(code: i32) ErrorCode {
        return switch (code) {
            0 => .SUCCESS,
            -1 => .INIT_FAILED,
            -2 => .INVALID_PARAM,
            -3 => .ALLOC_FAILED,
            -4 => .CONNECT_FAILED,
            -5 => .AUTH_FAILED,
            -6 => .NOT_CONNECTED,
            -7 => .ALREADY_INIT,
            -8 => .NOT_INIT,
            else => .UNKNOWN,
        };
    }
};

/// DHCP configuration information
pub const DhcpInfo = struct {
    has_ip: bool,
    ip_address: [64:0]u8,
    subnet_mask: [64:0]u8,
    gateway: [64:0]u8,
    dns_servers: [8][256:0]u8,
    dns_count: u32,
    lease_time: u32,

    pub fn init() DhcpInfo {
        return .{
            .has_ip = false,
            .ip_address = std.mem.zeroes([64:0]u8),
            .subnet_mask = std.mem.zeroes([64:0]u8),
            .gateway = std.mem.zeroes([64:0]u8),
            .dns_servers = std.mem.zeroes([8][256:0]u8),
            .dns_count = 0,
            .lease_time = 0,
        };
    }
};

/// Connection information
pub const ConnectionInfo = struct {
    server_name: [256:0]u8,
    server_ip: [64:0]u8,
    server_port: u16,
    hub_name: [256:0]u8,
    username: [256:0]u8,
    connection_start_time: u64,
    bytes_sent: u64,
    bytes_received: u64,
    session_name: [256:0]u8,
    connection_name: [256:0]u8,

    pub fn init() ConnectionInfo {
        return .{
            .server_name = std.mem.zeroes([256:0]u8),
            .server_ip = std.mem.zeroes([64:0]u8),
            .server_port = 0,
            .hub_name = std.mem.zeroes([256:0]u8),
            .username = std.mem.zeroes([256:0]u8),
            .connection_start_time = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
            .session_name = std.mem.zeroes([256:0]u8),
            .connection_name = std.mem.zeroes([256:0]u8),
        };
    }
};

/// Reconnection configuration
pub const ReconnectConfig = struct {
    enabled: bool,
    max_attempts: u32, // 0 = infinite
    min_backoff_seconds: u32,
    max_backoff_seconds: u32,
    current_attempt: u32,
    last_connect_time: u64,
    user_requested_disconnect: bool,

    pub fn init() ReconnectConfig {
        return .{
            .enabled = false,
            .max_attempts = 0,
            .min_backoff_seconds = 5,
            .max_backoff_seconds = 300,
            .current_attempt = 0,
            .last_connect_time = 0,
            .user_requested_disconnect = false,
        };
    }

    /// Calculate exponential backoff delay in seconds
    pub fn calculateBackoff(self: *const ReconnectConfig) u32 {
        if (!self.enabled) return 0;
        if (self.current_attempt == 0) return 0;

        // Exponential backoff: min * (2 ^ attempt)
        const base_delay = self.min_backoff_seconds;
        const multiplier = @as(u32, 1) << @intCast(@min(self.current_attempt - 1, 10)); // Cap at 2^10
        const delay = base_delay * multiplier;

        // Cap at max_backoff_seconds
        return @min(delay, self.max_backoff_seconds);
    }
};

/// Main VPN bridge client structure
pub const VpnBridgeClient = struct {
    // Configuration
    hostname: [256:0]u8,
    port: u16,
    hub_name: [256:0]u8,
    username: [256:0]u8,
    password: [256:0]u8,
    password_is_hashed: bool,
    max_connection: u32,

    // IP Configuration
    ip_version: IpVersion,
    use_static_ipv4: bool,
    static_ipv4: [64:0]u8,
    static_ipv4_netmask: [64:0]u8,
    static_ipv4_gateway: [64:0]u8,
    use_static_ipv6: bool,
    static_ipv6: [128:0]u8,
    static_ipv6_prefix: u8,
    static_ipv6_gateway: [128:0]u8,
    dns_servers: [8][256:0]u8,
    dns_server_count: u32,

    // Adapter configuration
    use_zig_adapter: bool,

    // State
    status: VpnBridgeStatus,
    last_error: u32,
    bytes_sent: u64,
    bytes_received: u64,
    connect_time: u64,

    // Reconnection
    reconnect: ReconnectConfig,

    // SoftEther C structures (opaque pointers)
    softether_client: ?*anyopaque, // CLIENT*
    softether_account: ?*anyopaque, // ACCOUNT*
    softether_session: ?*anyopaque, // SESSION*

    // Allocator
    allocator: std.mem.Allocator,

    /// Initialize a new VPN bridge client
    pub fn init(allocator: std.mem.Allocator) !*VpnBridgeClient {
        const client = try allocator.create(VpnBridgeClient);
        errdefer allocator.destroy(client);

        client.* = .{
            .hostname = std.mem.zeroes([256:0]u8),
            .port = 443,
            .hub_name = std.mem.zeroes([256:0]u8),
            .username = std.mem.zeroes([256:0]u8),
            .password = std.mem.zeroes([256:0]u8),
            .password_is_hashed = false,
            .max_connection = 1,
            .ip_version = .AUTO,
            .use_static_ipv4 = false,
            .static_ipv4 = std.mem.zeroes([64:0]u8),
            .static_ipv4_netmask = std.mem.zeroes([64:0]u8),
            .static_ipv4_gateway = std.mem.zeroes([64:0]u8),
            .use_static_ipv6 = false,
            .static_ipv6 = std.mem.zeroes([128:0]u8),
            .static_ipv6_prefix = 64,
            .static_ipv6_gateway = std.mem.zeroes([128:0]u8),
            .dns_servers = std.mem.zeroes([8][256:0]u8),
            .dns_server_count = 0,
            .use_zig_adapter = true, // Default to Zig adapter
            .status = .DISCONNECTED,
            .last_error = 0,
            .bytes_sent = 0,
            .bytes_received = 0,
            .connect_time = 0,
            .reconnect = ReconnectConfig.init(),
            .softether_client = null,
            .softether_account = null,
            .softether_session = null,
            .allocator = allocator,
        };

        return client;
    }

    /// Free the client and all resources
    pub fn deinit(self: *VpnBridgeClient) void {
        // Ensure disconnected
        if (self.status == .CONNECTED or self.status == .CONNECTING) {
            self.disconnect() catch {};
        }

        // Zero sensitive data
        @memset(&self.password, 0);

        self.allocator.destroy(self);
    }

    /// Configure basic connection parameters
    pub fn configure(
        self: *VpnBridgeClient,
        hostname: []const u8,
        port: u16,
        hub_name: []const u8,
        username: []const u8,
        password: []const u8,
    ) !void {
        if (self.status == .CONNECTED or self.status == .CONNECTING) {
            return BridgeError.AlreadyConnected;
        }

        // Copy hostname (ensure null-terminated)
        if (hostname.len >= self.hostname.len) return BridgeError.InvalidParameter;
        @memcpy(self.hostname[0..hostname.len], hostname);
        self.hostname[hostname.len] = 0;

        self.port = port;

        // Copy hub name
        if (hub_name.len >= self.hub_name.len) return BridgeError.InvalidParameter;
        @memcpy(self.hub_name[0..hub_name.len], hub_name);
        self.hub_name[hub_name.len] = 0;

        // Copy username
        if (username.len >= self.username.len) return BridgeError.InvalidParameter;
        @memcpy(self.username[0..username.len], username);
        self.username[username.len] = 0;

        // Copy password
        if (password.len >= self.password.len) return BridgeError.InvalidParameter;
        @memcpy(self.password[0..password.len], password);
        self.password[password.len] = 0;

        self.password_is_hashed = false;
    }

    /// Configure with pre-hashed password
    pub fn configureWithHash(
        self: *VpnBridgeClient,
        hostname: []const u8,
        port: u16,
        hub_name: []const u8,
        username: []const u8,
        password_hash: []const u8,
    ) !void {
        try self.configure(hostname, port, hub_name, username, password_hash);
        self.password_is_hashed = true;
    }

    /// Set IP version preference
    pub fn setIpVersion(self: *VpnBridgeClient, ip_ver: IpVersion) !void {
        if (self.status == .CONNECTED or self.status == .CONNECTING) {
            return BridgeError.AlreadyConnected;
        }
        self.ip_version = ip_ver;
    }

    /// Set maximum TCP connections
    pub fn setMaxConnection(self: *VpnBridgeClient, max_conn: u32) !void {
        if (max_conn == 0 or max_conn > 32) {
            return BridgeError.InvalidMaxConnection;
        }
        self.max_connection = max_conn;
    }

    /// Enable auto-reconnect
    pub fn enableReconnect(
        self: *VpnBridgeClient,
        max_attempts: u32,
        min_backoff: u32,
        max_backoff: u32,
    ) !void {
        self.reconnect.enabled = true;
        self.reconnect.max_attempts = max_attempts;
        self.reconnect.min_backoff_seconds = min_backoff;
        self.reconnect.max_backoff_seconds = max_backoff;
    }

    /// Disable auto-reconnect
    pub fn disableReconnect(self: *VpnBridgeClient) void {
        self.reconnect.enabled = false;
    }

    /// Mark disconnect as user-initiated (prevents auto-reconnect)
    pub fn markUserDisconnect(self: *VpnBridgeClient) void {
        self.reconnect.user_requested_disconnect = true;
    }

    /// Reset reconnection state
    pub fn resetReconnectState(self: *VpnBridgeClient) void {
        self.reconnect.current_attempt = 0;
        self.reconnect.last_connect_time = 0;
        self.reconnect.user_requested_disconnect = false;
    }

    /// Get current status
    pub fn getStatus(self: *const VpnBridgeClient) VpnBridgeStatus {
        return self.status;
    }

    /// Get last error code
    pub fn getLastError(self: *const VpnBridgeClient) u32 {
        return self.last_error;
    }

    /// Connect to VPN server (placeholder - will implement in Phase 3)
    pub fn connect(self: *VpnBridgeClient) !void {
        _ = self;
        // TODO: Implement in Phase 3
        return BridgeError.NotInitialized;
    }

    /// Disconnect from VPN server (placeholder - will implement in Phase 3)
    pub fn disconnect(self: *VpnBridgeClient) !void {
        _ = self;
        // TODO: Implement in Phase 3
        return BridgeError.NotConnected;
    }

    /// Get connection information (placeholder)
    pub fn getConnectionInfo(self: *const VpnBridgeClient) ConnectionInfo {
        _ = self;
        return ConnectionInfo.init();
    }

    /// Get DHCP information (placeholder)
    pub fn getDhcpInfo(self: *const VpnBridgeClient) DhcpInfo {
        _ = self;
        return DhcpInfo.init();
    }

    /// Get device name (TUN interface name)
    pub fn getDeviceName(self: *const VpnBridgeClient, buffer: []u8) ![]const u8 {
        if (self.status != .CONNECTED) {
            const msg = "not_connected";
            const len = @min(msg.len, buffer.len);
            @memcpy(buffer[0..len], msg[0..len]);
            return buffer[0..len];
        }

        // TODO: Get from adapter in Phase 3
        const msg = "utun?";
        const len = @min(msg.len, buffer.len);
        @memcpy(buffer[0..len], msg[0..len]);
        return buffer[0..len];
    }

    /// Get learned IP address
    pub fn getLearnedIp(self: *const VpnBridgeClient, buffer: []u8) ![]const u8 {
        const dhcp = self.getDhcpInfo();
        if (!dhcp.has_ip) {
            return error.NotConnected;
        }

        const ip_slice = std.mem.sliceTo(&dhcp.ip_address, 0);
        const len = @min(ip_slice.len, buffer.len);
        @memcpy(buffer[0..len], ip_slice[0..len]);
        return buffer[0..len];
    }

    /// Get gateway MAC address
    pub fn getGatewayMac(self: *const VpnBridgeClient, buffer: []u8) ![]const u8 {
        _ = self;
        if (buffer.len < 17) return error.InvalidParameter; // Need space for "XX:XX:XX:XX:XX:XX"

        // TODO: Get from adapter in Phase 3
        const msg = "00:00:00:00:00:00";
        @memcpy(buffer[0..17], msg[0..17]);
        return buffer[0..17];
    }

    /// Get bytes sent
    pub fn getBytesSent(self: *const VpnBridgeClient) u64 {
        return self.bytes_sent;
    }

    /// Get bytes received
    pub fn getBytesReceived(self: *const VpnBridgeClient) u64 {
        return self.bytes_received;
    }

    /// Get connection uptime in seconds
    pub fn getUptime(self: *const VpnBridgeClient) u64 {
        if (self.status != .CONNECTED or self.connect_time == 0) {
            return 0;
        }
        const now = getCurrentTimeMs();
        return (now - self.connect_time) / 1000;
    }

    /// Check if connected
    pub fn isConnected(self: *const VpnBridgeClient) bool {
        return self.status == .CONNECTED;
    }

    /// Check if connecting
    pub fn isConnecting(self: *const VpnBridgeClient) bool {
        return self.status == .CONNECTING;
    }
};

// ============================================
// Module-level state and initialization
// ============================================

var g_initialized: bool = false;

/// Initialize the VPN bridge system
pub fn init(debug: bool) !void {
    _ = debug;
    if (g_initialized) {
        return BridgeError.AlreadyInitialized;
    }

    // TODO: Call SoftEther InitMayaqua() etc.

    g_initialized = true;
}

/// Cleanup the VPN bridge system
pub fn deinit() void {
    if (!g_initialized) return;

    // TODO: Call SoftEther FreeMayaqua() etc.

    g_initialized = false;
}

/// Check if bridge is initialized
pub fn isInitialized() bool {
    return g_initialized;
}

/// Get bridge version
pub fn version() []const u8 {
    return "1.0.0";
}

/// Get SoftEther version
pub fn softetherVersion() []const u8 {
    return "4.44.9807"; // TODO: Get from SoftEther
}

/// Get error message for error code
pub fn getErrorMessage(error_code: i32) []const u8 {
    const code = ErrorCode.fromInt(error_code);
    return code.message();
}

/// Generate password hash (SoftEther format)
/// Uses SHA-0 hash + Base64 encoding
pub fn generatePasswordHash(
    allocator: std.mem.Allocator,
    username: []const u8,
    password: []const u8,
) ![]const u8 {
    // TODO: Implement SoftEther's HashPassword algorithm
    // For now, return a placeholder that indicates hashing is needed
    _ = allocator;
    _ = username;
    _ = password;
    return error.NotInitialized; // Will implement in Phase 3 with C FFI
}

/// Get current time in milliseconds
pub fn getCurrentTimeMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

// ============================================
// Tests
// ============================================

test "VpnBridgeClient creation and destruction" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    try std.testing.expectEqual(VpnBridgeStatus.DISCONNECTED, client.status);
    try std.testing.expectEqual(@as(u16, 443), client.port);
    try std.testing.expectEqual(@as(u32, 1), client.max_connection);
}

test "VpnBridgeClient configuration" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    try client.configure("test.vpn.com", 8443, "TestHub", "testuser", "testpass");

    try std.testing.expectEqualStrings("test.vpn.com", std.mem.sliceTo(&client.hostname, 0));
    try std.testing.expectEqual(@as(u16, 8443), client.port);
    try std.testing.expectEqualStrings("TestHub", std.mem.sliceTo(&client.hub_name, 0));
    try std.testing.expectEqualStrings("testuser", std.mem.sliceTo(&client.username, 0));
    try std.testing.expectEqual(false, client.password_is_hashed);
}

test "IP version configuration" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    try std.testing.expectEqual(IpVersion.AUTO, client.ip_version);

    try client.setIpVersion(.IPV4_ONLY);
    try std.testing.expectEqual(IpVersion.IPV4_ONLY, client.ip_version);

    try client.setIpVersion(.IPV6_ONLY);
    try std.testing.expectEqual(IpVersion.IPV6_ONLY, client.ip_version);
}

test "Max connection validation" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    // Valid values
    try client.setMaxConnection(1);
    try std.testing.expectEqual(@as(u32, 1), client.max_connection);

    try client.setMaxConnection(16);
    try std.testing.expectEqual(@as(u32, 16), client.max_connection);

    try client.setMaxConnection(32);
    try std.testing.expectEqual(@as(u32, 32), client.max_connection);

    // Invalid values
    try std.testing.expectError(BridgeError.InvalidMaxConnection, client.setMaxConnection(0));
    try std.testing.expectError(BridgeError.InvalidMaxConnection, client.setMaxConnection(33));
}

test "Reconnect configuration" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    try std.testing.expectEqual(false, client.reconnect.enabled);

    try client.enableReconnect(5, 10, 300);
    try std.testing.expectEqual(true, client.reconnect.enabled);
    try std.testing.expectEqual(@as(u32, 5), client.reconnect.max_attempts);
    try std.testing.expectEqual(@as(u32, 10), client.reconnect.min_backoff_seconds);
    try std.testing.expectEqual(@as(u32, 300), client.reconnect.max_backoff_seconds);

    client.disableReconnect();
    try std.testing.expectEqual(false, client.reconnect.enabled);
}

test "Exponential backoff calculation" {
    var config = ReconnectConfig.init();
    config.enabled = true;
    config.min_backoff_seconds = 5;
    config.max_backoff_seconds = 300;

    config.current_attempt = 0;
    try std.testing.expectEqual(@as(u32, 0), config.calculateBackoff());

    config.current_attempt = 1;
    try std.testing.expectEqual(@as(u32, 5), config.calculateBackoff());

    config.current_attempt = 2;
    try std.testing.expectEqual(@as(u32, 10), config.calculateBackoff());

    config.current_attempt = 3;
    try std.testing.expectEqual(@as(u32, 20), config.calculateBackoff());

    config.current_attempt = 10;
    const result = config.calculateBackoff();
    try std.testing.expect(result <= 300); // Should cap at max
}

test "Module initialization" {
    try init(false);
    defer deinit();

    try std.testing.expectEqual(true, isInitialized());
    try std.testing.expectError(BridgeError.AlreadyInitialized, init(false));
}

test "Error messages" {
    const msg1 = getErrorMessage(0);
    try std.testing.expectEqualStrings("Success", msg1);

    const msg2 = getErrorMessage(-1);
    try std.testing.expectEqualStrings("Library initialization failed", msg2);

    const msg3 = getErrorMessage(-2);
    try std.testing.expectEqualStrings("Invalid parameter", msg3);

    const msg4 = getErrorMessage(-999);
    try std.testing.expectEqualStrings("Unknown error", msg4);
}

test "Error code conversion" {
    const code1 = ErrorCode.fromInt(0);
    try std.testing.expectEqual(ErrorCode.SUCCESS, code1);

    const code2 = ErrorCode.fromInt(-5);
    try std.testing.expectEqual(ErrorCode.AUTH_FAILED, code2);

    const code3 = ErrorCode.fromInt(999);
    try std.testing.expectEqual(ErrorCode.UNKNOWN, code3);
}

test "Status getters" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    // Initial state
    try std.testing.expectEqual(false, client.isConnected());
    try std.testing.expectEqual(false, client.isConnecting());
    try std.testing.expectEqual(@as(u64, 0), client.getBytesSent());
    try std.testing.expectEqual(@as(u64, 0), client.getBytesReceived());
    try std.testing.expectEqual(@as(u64, 0), client.getUptime());

    // Simulate connection
    client.status = .CONNECTING;
    try std.testing.expectEqual(true, client.isConnecting());
    try std.testing.expectEqual(false, client.isConnected());

    client.status = .CONNECTED;
    client.connect_time = getCurrentTimeMs();
    try std.testing.expectEqual(true, client.isConnected());
    try std.testing.expectEqual(false, client.isConnecting());

    // Simulate traffic
    client.bytes_sent = 12345;
    client.bytes_received = 67890;
    try std.testing.expectEqual(@as(u64, 12345), client.getBytesSent());
    try std.testing.expectEqual(@as(u64, 67890), client.getBytesReceived());
}

test "Device name getter" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    var buffer: [256]u8 = undefined;

    // Not connected - should return placeholder
    const name1 = try client.getDeviceName(&buffer);
    try std.testing.expectEqualStrings("not_connected", name1);

    // Connected - should return device name (placeholder for now)
    client.status = .CONNECTED;
    const name2 = try client.getDeviceName(&buffer);
    try std.testing.expectEqualStrings("utun?", name2);
}

test "Gateway MAC getter" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    var buffer: [20]u8 = undefined;

    // Should return placeholder MAC
    const mac = try client.getGatewayMac(&buffer);
    try std.testing.expectEqualStrings("00:00:00:00:00:00", mac);

    // Small buffer should error
    var small_buffer: [10]u8 = undefined;
    try std.testing.expectError(error.InvalidParameter, client.getGatewayMac(&small_buffer));
}

test "Uptime calculation" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    // Not connected - uptime should be 0
    try std.testing.expectEqual(@as(u64, 0), client.getUptime());

    // Connected - uptime should be calculated
    client.status = .CONNECTED;
    client.connect_time = getCurrentTimeMs() - 5000; // 5 seconds ago
    const uptime = client.getUptime();
    try std.testing.expect(uptime >= 4 and uptime <= 6); // Allow 1 second tolerance
}

test "Version strings" {
    const v1 = version();
    try std.testing.expect(v1.len > 0);

    const v2 = softetherVersion();
    try std.testing.expect(v2.len > 0);
}
