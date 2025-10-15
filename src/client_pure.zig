//! Pure Zig VPN Client - No C Dependencies
//! Uses session.zig and vpn_protocol.zig for complete pure Zig implementation

const std = @import("std");
const errors = @import("errors.zig");
const config = @import("config.zig");
const types = @import("types.zig");

// Import pure Zig protocol implementation
const protocol = @import("protocol/mod.zig");
const VpnSession = protocol.VpnSession;
const SessionConfig = protocol.SessionConfig;
const AuthCredentials = protocol.AuthCredentials;
const SessionStats = protocol.SessionStats;
const SessionState = protocol.SessionState;

const VpnError = errors.VpnError;
const ConnectionConfig = config.ConnectionConfig;

/// Reconnection state for CLI (matches client.zig API)
pub const ReconnectInfo = struct {
    enabled: bool,
    should_reconnect: bool,
    attempt: u32,
    max_attempts: u32,
    current_backoff: u32,
    next_retry_time: u64,
    consecutive_failures: u32,
    last_disconnect_time: u64,
};

/// Pure Zig VPN Client - 100% Zig, no C bridge
pub const PureZigVpnClient = struct {
    session: *VpnSession,
    allocator: std.mem.Allocator,
    connection_config: ConnectionConfig,

    // Reconnection state
    reconnect_enabled: bool = false,
    reconnect_max_attempts: u32 = 0,
    reconnect_min_backoff: u32 = 5,
    reconnect_max_backoff: u32 = 300,
    reconnect_attempt: u32 = 0,
    reconnect_last_disconnect: u64 = 0,
    user_requested_disconnect: bool = false,

    /// Initialize pure Zig VPN client
    pub fn init(allocator: std.mem.Allocator, cfg: ConnectionConfig) !*PureZigVpnClient {
        // Only password auth supported for now
        if (cfg.auth != .password) {
            return VpnError.InvalidParameter;
        }

        const auth = cfg.auth.password;

        // Build SessionConfig from ConnectionConfig
        // Note: is_hashed is handled internally by the protocol layer
        const session_config = SessionConfig{
            .server_host = cfg.server_name,
            .server_port = cfg.server_port,
            .hub_name = cfg.hub_name,
            .credentials = AuthCredentials.withPassword(auth.username, auth.password),
            .use_encryption = true, // Always use encryption
            .use_compression = cfg.use_compress,
            // Note: max_connection and half_connection are managed internally by the session
        };

        // Create VPN session
        const session = try VpnSession.init(allocator, session_config);
        errdefer session.deinit();

        // Create client
        const client = try allocator.create(PureZigVpnClient);
        client.* = .{
            .session = session,
            .allocator = allocator,
            .connection_config = cfg,
        };

        return client;
    }

    /// Clean up and free resources
    pub fn deinit(self: *PureZigVpnClient) void {
        self.session.deinit();
        self.allocator.destroy(self);
    }

    /// Connect to VPN server
    pub fn connect(self: *PureZigVpnClient) !void {
        self.user_requested_disconnect = false;
        try self.session.start();
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *PureZigVpnClient) !void {
        self.user_requested_disconnect = true;
        self.session.stop();
    }

    /// Get current connection status
    pub fn getStatus(self: *const PureZigVpnClient) types.ConnectionStatus {
        const state = self.session.getState();
        return switch (state) {
            .disconnected => .disconnected,
            .connecting => .connecting,
            .authenticating => .connecting,
            .establishing => .connecting,
            .connected => .connected,
            .error_state => .error_state,
        };
    }

    /// Check if connected
    pub fn isConnected(self: *const PureZigVpnClient) bool {
        return self.session.getState() == .connected;
    }

    /// Get connection info (bytes sent/received, connection time)
    pub fn getConnectionInfo(self: *const PureZigVpnClient) !struct {
        bytes_sent: u64,
        bytes_received: u64,
        connected_seconds: u64,
    } {
        const stats = self.session.getStats();
        const uptime = self.session.getUptime();

        return .{
            .bytes_sent = stats.bytes_sent,
            .bytes_received = stats.bytes_received,
            .connected_seconds = uptime,
        };
    }

    /// Get TUN device name
    pub fn getDeviceName(self: *const PureZigVpnClient) ![64]u8 {
        _ = self;
        var result: [64]u8 = std.mem.zeroes([64]u8);

        // TODO: Get actual device name from adapter
        // For now, return a placeholder
        const placeholder = "utun-zig";
        const copy_len = @min(placeholder.len, result.len - 1);
        @memcpy(result[0..copy_len], placeholder[0..copy_len]);
        result[copy_len] = 0;

        return result;
    }

    /// Get learned IP address (0 if not yet learned)
    pub fn getLearnedIp(self: *const PureZigVpnClient) !u32 {
        // TODO: Implement IP address learning
        // For now, return 0 (not learned)
        _ = self;
        return 0;
    }

    /// Get learned gateway MAC address
    pub fn getGatewayMac(self: *const PureZigVpnClient) !?[6]u8 {
        // TODO: Implement gateway MAC learning
        // For now, return null (not learned)
        _ = self;
        return null;
    }

    // ============================================
    // Reconnection Management (matches client.zig API)
    // ============================================

    /// Enable automatic reconnection
    pub fn enableReconnect(
        self: *PureZigVpnClient,
        max_attempts: u32,
        min_backoff: u32,
        max_backoff: u32,
    ) !void {
        self.reconnect_enabled = true;
        self.reconnect_max_attempts = max_attempts;
        self.reconnect_min_backoff = min_backoff;
        self.reconnect_max_backoff = max_backoff;
        self.reconnect_attempt = 0;
    }

    /// Disable automatic reconnection
    pub fn disableReconnect(self: *PureZigVpnClient) !void {
        self.reconnect_enabled = false;
        self.reconnect_attempt = 0;
    }

    /// Get reconnection info
    pub fn getReconnectInfo(self: *const PureZigVpnClient) !ReconnectInfo {
        const status = self.getStatus();

        // Should reconnect if enabled, disconnected, not user-requested, and under max attempts
        const should_reconnect = self.reconnect_enabled and
            status == .disconnected and
            !self.user_requested_disconnect and
            (self.reconnect_max_attempts == 0 or self.reconnect_attempt < self.reconnect_max_attempts);

        // Calculate exponential backoff: min * (2^attempt), capped at max
        const backoff_raw = self.reconnect_min_backoff * (@as(u32, 1) << @intCast(@min(self.reconnect_attempt, 10)));
        const backoff = @min(backoff_raw, self.reconnect_max_backoff);

        // Calculate next retry time
        const next_retry = if (should_reconnect)
            self.reconnect_last_disconnect + (@as(u64, backoff) * 1000)
        else
            0;

        return ReconnectInfo{
            .enabled = self.reconnect_enabled,
            .should_reconnect = should_reconnect,
            .attempt = self.reconnect_attempt,
            .max_attempts = self.reconnect_max_attempts,
            .current_backoff = backoff,
            .next_retry_time = next_retry,
            .consecutive_failures = self.reconnect_attempt,
            .last_disconnect_time = self.reconnect_last_disconnect,
        };
    }

    /// Mark disconnect as user-requested (prevents reconnection)
    pub fn markUserDisconnect(self: *PureZigVpnClient) !void {
        self.user_requested_disconnect = true;
        self.reconnect_attempt = 0;
    }

    /// Record disconnect event (for reconnection tracking)
    pub fn recordDisconnect(self: *PureZigVpnClient) void {
        self.reconnect_last_disconnect = @intCast(std.time.milliTimestamp());
        if (!self.user_requested_disconnect) {
            self.reconnect_attempt += 1;
        }
    }

    /// Reset reconnection counter (after successful connection)
    pub fn resetReconnect(self: *PureZigVpnClient) void {
        self.reconnect_attempt = 0;
        self.user_requested_disconnect = false;
    }

    // ============================================
    // Pure Zig Specific - Enhanced API
    // ============================================

    /// Get detailed session statistics (pure Zig only)
    pub fn getSessionStats(self: *const PureZigVpnClient) SessionStats {
        return self.session.getStats();
    }

    /// Get current session state (pure Zig only)
    pub fn getSessionState(self: *const PureZigVpnClient) SessionState {
        return self.session.getState();
    }

    /// Get session uptime in seconds (pure Zig only)
    pub fn getUptime(self: *const PureZigVpnClient) u64 {
        return self.session.getUptime();
    }
};
