// SoftEtherZig - Core VPN Client Logic
// Platform-agnostic VPN connection management
//
// This module provides reusable VPN client functionality that can be used by:
// - Desktop CLI (src/platforms/desktop/)
// - iOS PacketTunnelProvider (src/platforms/ios/)
// - Android VpnService (src/platforms/android/)
// - Mobile FFI (src/ffi/ffi.zig)
//
// Design Philosophy:
// - No platform-specific code (no TUN/TAP, no file I/O, no signal handlers)
// - Pure business logic (connection, authentication, session management)
// - Callback-based for integration flexibility
// - All I/O operations delegated to platform-specific adapters

const std = @import("std");
const c_mod = @import("../c.zig");
const c = c_mod.c;
const errors = @import("../errors.zig");
const config = @import("../config.zig");
const types = @import("../types.zig");

const VpnError = errors.VpnError;
const ConnectionConfig = config.ConnectionConfig;

// ============================================================================
// Core Types
// ============================================================================

/// Reconnection state tracking
pub const ReconnectState = struct {
    enabled: bool,
    should_reconnect: bool,
    attempt: u32,
    max_attempts: u32, // 0 = infinite
    current_backoff: u32,
    next_retry_time: u64,
    consecutive_failures: u32,
    last_disconnect_time: u64,

    pub fn init(enabled: bool, max_attempts: u32) ReconnectState {
        return .{
            .enabled = enabled,
            .should_reconnect = false,
            .attempt = 0,
            .max_attempts = max_attempts,
            .current_backoff = 0,
            .next_retry_time = 0,
            .consecutive_failures = 0,
            .last_disconnect_time = 0,
        };
    }

    pub fn reset(self: *ReconnectState) void {
        self.should_reconnect = false;
        self.attempt = 0;
        self.current_backoff = 0;
        self.consecutive_failures = 0;
    }

    pub fn recordFailure(self: *ReconnectState, min_backoff: u32, max_backoff: u32) void {
        self.consecutive_failures += 1;
        self.attempt += 1;

        // Exponential backoff with jitter
        if (self.current_backoff == 0) {
            self.current_backoff = min_backoff;
        } else {
            self.current_backoff = @min(self.current_backoff * 2, max_backoff);
        }

        // Add jitter (±20%)
        const jitter_range = self.current_backoff / 5;
        const jitter = @as(u32, @intCast(std.crypto.random.intRangeAtMost(i32, -@as(i32, @intCast(jitter_range)), @as(i32, @intCast(jitter_range)))));
        self.current_backoff = @intCast(@as(i32, @intCast(self.current_backoff)) + jitter);

        self.last_disconnect_time = @intCast(std.time.milliTimestamp());
        self.next_retry_time = self.last_disconnect_time + (self.current_backoff * 1000);

        // Check if we should attempt reconnection
        self.should_reconnect = self.enabled and (self.max_attempts == 0 or self.attempt < self.max_attempts);
    }

    pub fn shouldRetryNow(self: *const ReconnectState) bool {
        if (!self.should_reconnect) return false;
        const now: u64 = @intCast(std.time.milliTimestamp());
        return now >= self.next_retry_time;
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    connected_duration_ms: u64 = 0,
    connection_start_time: i64 = 0,

    pub fn updateDuration(self: *ConnectionStats) void {
        if (self.connection_start_time > 0) {
            const now = std.time.milliTimestamp();
            self.connected_duration_ms = @intCast(now - self.connection_start_time);
        }
    }
};

// ============================================================================
// Core VPN Client
// ============================================================================

/// Core VPN client - platform-agnostic connection logic
pub const VpnCore = struct {
    handle: ?*c_mod.VpnBridgeClient,
    allocator: std.mem.Allocator,
    config: ConnectionConfig,
    status: types.ConnectionStatus,
    reconnect: ReconnectState,
    stats: ConnectionStats,

    // Callbacks (platform-specific)
    status_callback: ?*const fn (status: types.ConnectionStatus, user_data: ?*anyopaque) void = null,
    packet_callback: ?*const fn (data: []const u8, user_data: ?*anyopaque) void = null,
    error_callback: ?*const fn (err: VpnError, user_data: ?*anyopaque) void = null,
    user_data: ?*anyopaque = null,

    /// Initialize core VPN client
    pub fn init(allocator: std.mem.Allocator, cfg: ConnectionConfig) !VpnCore {
        // Initialize bridge library
        const init_result = c.vpn_bridge_init(0); // 0 = debug off
        if (init_result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.InitializationFailed;
        }

        // Create client instance
        const client_handle = c.vpn_bridge_create_client() orelse {
            return VpnError.ClientCreationFailed;
        };

        // Configure the client
        const host_z = try allocator.dupeZ(u8, cfg.server_name);
        defer allocator.free(host_z);

        const hub_z = try allocator.dupeZ(u8, cfg.hub_name);
        defer allocator.free(hub_z);

        // Extract auth credentials
        const username = switch (cfg.auth) {
            .password => |p| p.username,
            else => "anonymous",
        };
        const password = switch (cfg.auth) {
            .password => |p| p.password,
            else => "",
        };
        const is_hashed = switch (cfg.auth) {
            .password => |p| p.is_hashed,
            else => false,
        };

        const user_z = try allocator.dupeZ(u8, username);
        defer allocator.free(user_z);

        const pass_z = try allocator.dupeZ(u8, password);
        defer allocator.free(pass_z);

        // Configure connection
        const config_result = if (is_hashed)
            c.vpn_bridge_configure_with_hash(
                client_handle,
                host_z.ptr,
                cfg.server_port,
                hub_z.ptr,
                user_z.ptr,
                pass_z.ptr,
            )
        else
            c.vpn_bridge_configure(
                client_handle,
                host_z.ptr,
                cfg.server_port,
                hub_z.ptr,
                user_z.ptr,
                pass_z.ptr,
            );

        if (config_result != c_mod.VPN_BRIDGE_SUCCESS) {
            c.vpn_bridge_free_client(client_handle);
            return VpnError.ConfigurationError;
        }

        // Configure IP version
        const ip_version_code: c_int = switch (cfg.ip_version) {
            .auto => c_mod.VPN_IP_VERSION_AUTO,
            .ipv4 => c_mod.VPN_IP_VERSION_IPV4,
            .ipv6 => c_mod.VPN_IP_VERSION_IPV6,
            .dual => c_mod.VPN_IP_VERSION_DUAL,
        };
        _ = c.vpn_bridge_set_ip_version(client_handle, ip_version_code);

        // Configure max connections
        _ = c.vpn_bridge_set_max_connection(client_handle, @intCast(cfg.max_connection));

        // Configure adapter type
        if (cfg.use_zig_adapter) {
            _ = c.vpn_bridge_set_use_zig_adapter(client_handle, 1);
        }

        // Configure static IP if provided
        if (cfg.static_ip) |sip| {
            if (sip.ipv4_address) |ipv4| {
                const ipv4_z = try allocator.dupeZ(u8, ipv4);
                defer allocator.free(ipv4_z);

                const mask_z = if (sip.ipv4_netmask) |m| try allocator.dupeZ(u8, m) else null;
                defer if (mask_z) |m| allocator.free(m);

                const gw_z = if (sip.ipv4_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw_z) |g| allocator.free(g);

                _ = c.vpn_bridge_set_static_ipv4(
                    client_handle,
                    ipv4_z.ptr,
                    if (mask_z) |m| m.ptr else null,
                    if (gw_z) |g| g.ptr else null,
                );
            }

            if (sip.ipv6_address) |ipv6| {
                const ipv6_z = try allocator.dupeZ(u8, ipv6);
                defer allocator.free(ipv6_z);

                const gw6_z = if (sip.ipv6_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw6_z) |g| allocator.free(g);

                _ = c.vpn_bridge_set_static_ipv6(
                    client_handle,
                    ipv6_z.ptr,
                    sip.ipv6_prefix_len orelse 64,
                    if (gw6_z) |g| g.ptr else null,
                );
            }

            if (sip.dns_servers) |dns_list| {
                var dns_ptrs = try allocator.alloc([*c]const u8, dns_list.len);
                defer allocator.free(dns_ptrs);

                var dns_z_list = try allocator.alloc([]const u8, dns_list.len);
                defer {
                    for (dns_z_list) |dns_z| {
                        allocator.free(dns_z);
                    }
                    allocator.free(dns_z_list);
                }

                for (dns_list, 0..) |dns, i| {
                    dns_z_list[i] = try allocator.dupeZ(u8, dns);
                    dns_ptrs[i] = @ptrCast(dns_z_list[i].ptr);
                }

                _ = c.vpn_bridge_set_dns_servers(
                    client_handle,
                    @ptrCast(dns_ptrs.ptr),
                    @intCast(dns_list.len),
                );
            }
        }

        return VpnCore{
            .handle = client_handle,
            .allocator = allocator,
            .config = cfg,
            .status = .disconnected,
            .reconnect = ReconnectState.init(cfg.reconnect.enabled, cfg.reconnect.max_retries),
            .stats = .{},
        };
    }

    /// Clean up resources
    pub fn deinit(self: *VpnCore) void {
        if (self.handle) |handle| {
            c.vpn_bridge_free_client(handle);
            self.handle = null;
        }
    }

    /// Connect to VPN server
    pub fn connect(self: *VpnCore) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        self.setStatus(.connecting);
        self.stats.connection_start_time = std.time.milliTimestamp();

        const result = c.vpn_bridge_connect(handle);
        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            self.setStatus(.error_state);
            const err = switch (result) {
                c_mod.VPN_BRIDGE_ERROR_CONNECT_FAILED => VpnError.ConnectionFailed,
                c_mod.VPN_BRIDGE_ERROR_AUTH_FAILED => VpnError.AuthenticationFailed,
                c_mod.VPN_BRIDGE_ERROR_INVALID_PARAM => VpnError.InvalidParameter,
                else => VpnError.OperationFailed,
            };
            if (self.error_callback) |cb| {
                cb(err, self.user_data);
            }
            return err;
        }

        self.setStatus(.connected);
        self.reconnect.reset(); // Reset reconnection state on successful connect
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnCore) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_disconnect(handle);
        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        self.setStatus(.disconnected);
        self.stats.connection_start_time = 0;
    }

    /// Get current connection status
    pub fn getStatus(self: *const VpnCore) types.ConnectionStatus {
        const handle = self.handle orelse return .error_state;

        const status = c.vpn_bridge_get_status(handle);
        return switch (status) {
            c_mod.VPN_STATUS_DISCONNECTED => .disconnected,
            c_mod.VPN_STATUS_CONNECTING => .connecting,
            c_mod.VPN_STATUS_CONNECTED => .connected,
            c_mod.VPN_STATUS_ERROR => .error_state,
            else => .error_state,
        };
    }

    /// Check if connected
    pub fn isConnected(self: *const VpnCore) bool {
        return self.getStatus() == .connected;
    }

    /// Update connection statistics
    pub fn updateStats(self: *VpnCore) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var bytes_sent: u64 = 0;
        var bytes_received: u64 = 0;
        var connected_time: u64 = 0;

        const result = c.vpn_bridge_get_connection_info(
            handle,
            &bytes_sent,
            &bytes_received,
            &connected_time,
        );

        if (result == c_mod.VPN_BRIDGE_SUCCESS) {
            self.stats.bytes_sent = bytes_sent;
            self.stats.bytes_received = bytes_received;
            self.stats.updateDuration();
        }
    }

    /// Handle reconnection logic
    pub fn handleReconnect(self: *VpnCore) !void {
        if (!self.reconnect.enabled) return;

        // Record failure
        self.reconnect.recordFailure(
            self.config.reconnect.min_backoff_seconds,
            self.config.reconnect.max_backoff_seconds,
        );

        // Check if we should retry now
        if (self.reconnect.shouldRetryNow()) {
            std.debug.print("Reconnecting (attempt {d}/{d}, backoff: {d}s)...\n", .{
                self.reconnect.attempt,
                if (self.reconnect.max_attempts == 0) @as(u32, 0) else self.reconnect.max_attempts,
                self.reconnect.current_backoff,
            });

            self.connect() catch |err| {
                std.debug.print("Reconnection failed: {s}\n", .{@errorName(err)});
                return err;
            };
        }
    }

    /// Set status and trigger callback
    fn setStatus(self: *VpnCore, new_status: types.ConnectionStatus) void {
        if (self.status != new_status) {
            self.status = new_status;
            if (self.status_callback) |cb| {
                cb(new_status, self.user_data);
            }
        }
    }

    /// Set status callback
    pub fn setStatusCallback(
        self: *VpnCore,
        callback: *const fn (status: types.ConnectionStatus, user_data: ?*anyopaque) void,
        user_data: ?*anyopaque,
    ) void {
        self.status_callback = callback;
        self.user_data = user_data;
    }

    /// Set error callback
    pub fn setErrorCallback(
        self: *VpnCore,
        callback: *const fn (err: VpnError, user_data: ?*anyopaque) void,
        user_data: ?*anyopaque,
    ) void {
        self.error_callback = callback;
        self.user_data = user_data;
    }

    /// Set packet callback
    pub fn setPacketCallback(
        self: *VpnCore,
        callback: *const fn (data: []const u8, user_data: ?*anyopaque) void,
        user_data: ?*anyopaque,
    ) void {
        self.packet_callback = callback;
        self.user_data = user_data;
    }
};
