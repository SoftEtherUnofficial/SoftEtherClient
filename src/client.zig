// VPN Client Wrapper - Pure Zig Implementation with Cedar Modules
// Replaces C bridge with pure Zig Cedar modules

const std = @import("std");
const errors = @import("errors.zig");
const config = @import("config.zig");
const types = @import("types.zig");

// Import Cedar modules (Pure Zig!)
const cedar = @import("cedar/mod.zig");
const session = @import("protocol/session.zig");

const VpnError = errors.VpnError;
const ConnectionConfig = config.ConnectionConfig;

/// Reconnection state information for CLI
pub const ReconnectInfo = struct {
    enabled: bool,
    should_reconnect: bool, // True if reconnection should be attempted
    attempt: u32, // Current attempt number
    max_attempts: u32, // Maximum attempts (0=infinite)
    current_backoff: u32, // Current backoff delay in seconds
    next_retry_time: u64, // Timestamp when next retry should occur
    consecutive_failures: u32, // Count of consecutive failures
    last_disconnect_time: u64, // When connection was lost
};

/// Reconnection configuration
pub const ReconnectConfig = struct {
    enabled: bool = false,
    max_attempts: u32 = 0, // 0 = infinite
    min_backoff_seconds: u32 = 1,
    max_backoff_seconds: u32 = 300, // 5 minutes
    current_attempt: u32 = 0,
    last_connect_time: u64 = 0,
    user_requested_disconnect: bool = false,

    pub fn calculateBackoff(self: *const ReconnectConfig) u32 {
        if (!self.enabled) return 0;

        // Exponential backoff: 2^attempt * min_backoff, capped at max_backoff
        const attempt = self.current_attempt;
        const base_backoff = self.min_backoff_seconds;

        if (attempt == 0) return base_backoff;

        // Calculate 2^attempt with overflow protection
        var multiplier: u32 = 1;
        var i: u32 = 0;
        while (i < attempt) : (i += 1) {
            const next_multiplier = multiplier *% 2;
            if (next_multiplier < multiplier) {
                // Overflow, return max
                return self.max_backoff_seconds;
            }
            multiplier = next_multiplier;
        }

        const backoff = base_backoff *% multiplier;
        return @min(backoff, self.max_backoff_seconds);
    }

    pub fn reset(self: *ReconnectConfig) void {
        self.current_attempt = 0;
        self.user_requested_disconnect = false;
    }
};

/// VPN Client wrapper - provides simplified interface for CLI
/// Now uses pure Zig Cedar modules instead of C bridge!
pub const VpnClient = struct {
    // Cedar components (Pure Zig!)
    auth: ?*cedar.ClientAuth,
    vpn_session: ?*session.VpnSession,

    // Configuration
    allocator: std.mem.Allocator,
    config: ConnectionConfig,
    reconnect: ReconnectConfig,

    // State
    connected: bool,
    learned_ip: ?u32,
    gateway_mac: ?[6]u8,

    /// Initialize a new VPN client
    pub fn init(allocator: std.mem.Allocator, cfg: ConnectionConfig) !VpnClient {
        // Create authentication object based on config
        var auth: ?*cedar.ClientAuth = null;
        if (cfg.auth == .password) {
            const auth_cfg = cfg.auth.password;
            // Cedar auth handles password hashing internally
            auth = try cedar.ClientAuth.initPassword(
                allocator,
                auth_cfg.username,
                auth_cfg.password,
            );
        } else {
            return VpnError.InvalidParameter;
        }
        errdefer if (auth) |a| a.deinit();

        return VpnClient{
            .auth = auth,
            .vpn_session = null,
            .allocator = allocator,
            .config = cfg,
            .reconnect = ReconnectConfig{},
            .connected = false,
            .learned_ip = null,
            .gateway_mac = null,
        };
    }

    /// Clean up and free resources
    pub fn deinit(self: *VpnClient) void {
        // Disconnect if still connected
        if (self.vpn_session != null) {
            self.disconnect();
        }

        // Clean up auth
        if (self.auth) |auth| {
            auth.deinit();
            self.auth = null;
        }
    }

    /// Connect to VPN server
    pub fn connect(self: *VpnClient) !void {
        if (self.connected) {
            return error.AlreadyConnected;
        }

        std.log.info("Connecting to VPN server {s}:{d}...", .{
            self.config.server_name,
            self.config.server_port,
        });

        // Create session configuration from our config
        const session_config = session.SessionConfig{
            .server_host = self.config.server_name,
            .server_port = self.config.server_port,
            .hub_name = self.config.hub_name,
            .credentials = blk: {
                if (self.config.auth == .password) {
                    const auth_cfg = self.config.auth.password;
                    break :blk session.AuthCredentials.withPassword(
                        auth_cfg.username,
                        auth_cfg.password,
                    );
                } else {
                    return VpnError.InvalidParameter;
                }
            },
            .use_encryption = true,
            .use_compression = false,
            .tun_device_name = "utun",
        };

        // Validate config
        try session_config.validate();

        // Create and start VPN session
        self.vpn_session = try session.VpnSession.init(self.allocator, session_config);
        errdefer {
            if (self.vpn_session) |s| {
                s.deinit();
                self.vpn_session = null;
            }
        }

        // Start the session (connects, authenticates, starts packet forwarding)
        try self.vpn_session.?.start();

        self.connected = true;
        self.reconnect.last_connect_time = @intCast(std.time.milliTimestamp());
        self.reconnect.reset();

        std.log.info("Successfully connected to VPN server", .{});
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnClient) void {
        if (!self.connected) {
            return;
        }

        std.log.info("Disconnecting from VPN server...", .{});

        // Stop the session
        if (self.vpn_session) |s| {
            s.stop();
            s.deinit();
            self.vpn_session = null;
        }

        self.connected = false;
        self.learned_ip = null;
        self.gateway_mac = null;

        std.log.info("Disconnected from VPN server", .{});
    }

    /// Get current connection status
    pub fn getStatus(self: *const VpnClient) types.ConnectionStatus {
        if (self.vpn_session) |s| {
            return switch (s.state) {
                .disconnected => .disconnected,
                .connecting => .connecting,
                .authenticating => .connecting,
                .establishing => .connecting,
                .connected => .connected,
                .reconnecting => .connecting,
                .disconnecting => .disconnected,
                .error_state => .error_state,
            };
        }
        return .disconnected;
    }

    /// Check if client is connected
    pub fn isConnected(self: *const VpnClient) bool {
        return self.getStatus() == .connected;
    }

    /// Get connection information (bytes sent/received, connection time)
    pub fn getConnectionInfo(self: *const VpnClient) !struct {
        bytes_sent: u64,
        bytes_received: u64,
        connected_seconds: u64,
    } {
        if (self.vpn_session) |s| {
            const stats = s.getStats();
            const now = std.time.milliTimestamp();
            const uptime_ms: u64 = if (now > stats.session_start)
                @intCast(now - stats.session_start)
            else
                0;
            const uptime_sec = uptime_ms / 1000;

            return .{
                .bytes_sent = stats.bytes_sent,
                .bytes_received = stats.bytes_received,
                .connected_seconds = uptime_sec,
            };
        }

        return .{
            .bytes_sent = 0,
            .bytes_received = 0,
            .connected_seconds = 0,
        };
    }

    /// Get TUN device name (e.g., "utun3")
    pub fn getDeviceName(self: *const VpnClient) ![64]u8 {
        var device_name: [64]u8 = std.mem.zeroes([64]u8);

        if (self.vpn_session) |s| {
            if (s.adapter) |adapter| {
                const name = adapter.tun_adapter.getDeviceName();
                const copy_len = @min(name.len, device_name.len - 1);
                @memcpy(device_name[0..copy_len], name[0..copy_len]);
                device_name[copy_len] = 0;
            }
        }

        return device_name;
    }

    /// Get learned IP address (0 if not yet learned)
    pub fn getLearnedIp(self: *const VpnClient) !u32 {
        if (self.learned_ip) |ip| {
            return ip;
        }
        return 0; // Not yet learned
    }

    /// Get learned gateway MAC address
    pub fn getGatewayMac(self: *const VpnClient) !?[6]u8 {
        return self.gateway_mac;
    }

    // ============================================
    // Reconnection Management
    // ============================================

    /// Enable automatic reconnection with specified parameters
    pub fn enableReconnect(
        self: *VpnClient,
        max_attempts: u32,
        min_backoff: u32,
        max_backoff: u32,
    ) !void {
        self.reconnect.enabled = true;
        self.reconnect.max_attempts = max_attempts;
        self.reconnect.min_backoff_seconds = min_backoff;
        self.reconnect.max_backoff_seconds = max_backoff;
    }

    /// Disable automatic reconnection
    pub fn disableReconnect(self: *VpnClient) !void {
        self.reconnect.enabled = false;
        self.reconnect.reset();
    }

    /// Get current reconnection state and determine if reconnection should occur
    pub fn getReconnectInfo(self: *const VpnClient) !ReconnectInfo {
        const status = self.getStatus();

        // Determine if we should reconnect
        const should_reconnect = self.reconnect.enabled and
            status == .disconnected and
            !self.reconnect.user_requested_disconnect and
            (self.reconnect.max_attempts == 0 or
                self.reconnect.current_attempt < self.reconnect.max_attempts);

        // Calculate backoff delay
        const backoff = self.reconnect.calculateBackoff();

        // Calculate next retry time
        const now: u64 = @intCast(std.time.milliTimestamp());
        const next_retry = now + (@as(u64, backoff) * 1000);

        return ReconnectInfo{
            .enabled = self.reconnect.enabled,
            .should_reconnect = should_reconnect,
            .attempt = self.reconnect.current_attempt,
            .max_attempts = self.reconnect.max_attempts,
            .current_backoff = backoff,
            .next_retry_time = next_retry,
            .consecutive_failures = self.reconnect.current_attempt,
            .last_disconnect_time = self.reconnect.last_connect_time,
        };
    }

    /// Mark current disconnect as user-requested (prevents reconnection)
    pub fn markUserDisconnect(self: *VpnClient) !void {
        self.reconnect.user_requested_disconnect = true;
    }
};
