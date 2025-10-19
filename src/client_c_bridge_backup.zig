// VPN Client Wrapper - Bridges CLI to Zig VPN Implementation
// Wave 4 Phase 4: Direct integration with src/bridge/softether.zig

const std = @import("std");
const errors = @import("errors.zig");
const config = @import("config.zig");
const types = @import("types.zig");

// Import Zig VPN bridge implementation
const bridge = @import("bridge/softether.zig");

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

/// VPN Client wrapper - provides simplified interface for CLI
pub const VpnClient = struct {
    bridge_client: *bridge.VpnBridgeClient,
    allocator: std.mem.Allocator,
    config: ConnectionConfig,

    /// Initialize a new VPN client
    pub fn init(allocator: std.mem.Allocator, cfg: ConnectionConfig) !VpnClient {
        // Note: SoftEther library initialization is done in main() before this is called

        // Create Zig VPN bridge client
        const bridge_client = try bridge.VpnBridgeClient.init(allocator);
        errdefer bridge_client.deinit();

        // Configure the client
        if (cfg.auth == .password) {
            const auth = cfg.auth.password;
            if (auth.is_hashed) {
                try bridge_client.configureWithHash(
                    cfg.server_name,
                    cfg.server_port,
                    cfg.hub_name,
                    auth.username,
                    auth.password,
                );
            } else {
                try bridge_client.configure(
                    cfg.server_name,
                    cfg.server_port,
                    cfg.hub_name,
                    auth.username,
                    auth.password,
                );
            }
        } else {
            return VpnError.InvalidParameter;
        }

        // Configure IP version
        const ip_ver: bridge.IpVersion = switch (cfg.ip_version) {
            .auto => .AUTO,
            .ipv4 => .IPV4_ONLY,
            .ipv6 => .IPV6_ONLY,
            .dual => .AUTO, // Dual stack = auto
        };
        try bridge_client.setIpVersion(ip_ver);

        // Configure max connections
        if (cfg.max_connection > 0) {
            try bridge_client.setMaxConnection(cfg.max_connection);
        }

        // Configure adapter type
        bridge_client.use_zig_adapter = cfg.use_zig_adapter;

        // Configure static IP if provided
        if (cfg.static_ip) |sip| {
            if (sip.ipv4_address) |ipv4| {
                const ipv4_z = try allocator.dupeZ(u8, ipv4);
                defer allocator.free(ipv4_z);

                const mask_z = if (sip.ipv4_netmask) |m| try allocator.dupeZ(u8, m) else null;
                defer if (mask_z) |m| allocator.free(m);

                const gw_z = if (sip.ipv4_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw_z) |g| allocator.free(g);

                // Copy static IPv4 config into bridge client
                if (ipv4_z.len < bridge_client.static_ipv4.len) {
                    @memcpy(bridge_client.static_ipv4[0..ipv4_z.len], ipv4_z);
                    bridge_client.static_ipv4[ipv4_z.len] = 0;
                    bridge_client.use_static_ipv4 = true;
                }

                if (mask_z) |m| {
                    if (m.len < bridge_client.static_ipv4_netmask.len) {
                        @memcpy(bridge_client.static_ipv4_netmask[0..m.len], m);
                        bridge_client.static_ipv4_netmask[m.len] = 0;
                    }
                }

                if (gw_z) |g| {
                    if (g.len < bridge_client.static_ipv4_gateway.len) {
                        @memcpy(bridge_client.static_ipv4_gateway[0..g.len], g);
                        bridge_client.static_ipv4_gateway[g.len] = 0;
                    }
                }
            }

            if (sip.ipv6_address) |ipv6| {
                const ipv6_z = try allocator.dupeZ(u8, ipv6);
                defer allocator.free(ipv6_z);

                const gw6_z = if (sip.ipv6_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw6_z) |g| allocator.free(g);

                // Copy static IPv6 config into bridge client
                if (ipv6_z.len < bridge_client.static_ipv6.len) {
                    @memcpy(bridge_client.static_ipv6[0..ipv6_z.len], ipv6_z);
                    bridge_client.static_ipv6[ipv6_z.len] = 0;
                    bridge_client.use_static_ipv6 = true;
                    bridge_client.static_ipv6_prefix = sip.ipv6_prefix_len orelse 64;
                }

                if (gw6_z) |g| {
                    if (g.len < bridge_client.static_ipv6_gateway.len) {
                        @memcpy(bridge_client.static_ipv6_gateway[0..g.len], g);
                        bridge_client.static_ipv6_gateway[g.len] = 0;
                    }
                }
            }

            if (sip.dns_servers) |dns_list| {
                for (dns_list, 0..) |dns, i| {
                    if (i >= bridge_client.dns_servers.len) break;

                    const dns_z = try allocator.dupeZ(u8, dns);
                    defer allocator.free(dns_z);

                    if (dns_z.len < bridge_client.dns_servers[i].len) {
                        @memcpy(bridge_client.dns_servers[i][0..dns_z.len], dns_z);
                        bridge_client.dns_servers[i][dns_z.len] = 0;
                        bridge_client.dns_server_count += 1;
                    }
                }
            }
        }

        return VpnClient{
            .bridge_client = bridge_client,
            .allocator = allocator,
            .config = cfg,
        };
    }

    /// Clean up and free resources
    pub fn deinit(self: *VpnClient) void {
        self.bridge_client.deinit();
        bridge.deinit(); // Cleanup SoftEther library
    }

    /// Connect to VPN server
    pub fn connect(self: *VpnClient) !void {
        try self.bridge_client.connect();
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnClient) !void {
        self.bridge_client.disconnect();
    }

    /// Get current connection status
    pub fn getStatus(self: *const VpnClient) types.ConnectionStatus {
        const status = self.bridge_client.getStatus();
        return switch (status) {
            .DISCONNECTED => .disconnected,
            .CONNECTING => .connecting,
            .CONNECTED => .connected,
            .DISCONNECTING => .disconnected, // Treat as disconnected
            .ERROR => .error_state,
        };
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
        const info = self.bridge_client.getConnectionInfo();
        const uptime = self.bridge_client.getUptime();

        return .{
            .bytes_sent = info.bytes_sent,
            .bytes_received = info.bytes_received,
            .connected_seconds = uptime,
        };
    }

    /// Get TUN device name (e.g., "utun3")
    pub fn getDeviceName(self: *const VpnClient) ![64]u8 {
        var device_name: [64]u8 = undefined;
        const name_slice = try self.bridge_client.getDeviceName(&device_name);

        // Copy to fixed-size array and null-terminate
        var result: [64]u8 = std.mem.zeroes([64]u8);
        const copy_len = @min(name_slice.len, result.len - 1);
        @memcpy(result[0..copy_len], name_slice[0..copy_len]);
        result[copy_len] = 0;

        return result;
    }

    /// Get learned IP address (0 if not yet learned)
    pub fn getLearnedIp(self: *const VpnClient) !u32 {
        var ip_buf: [64]u8 = undefined;
        const ip_str = self.bridge_client.getLearnedIp(&ip_buf) catch {
            return 0; // Not yet learned
        };

        // Parse IP string (e.g., "10.21.0.2") to u32
        var octets: [4]u8 = .{ 0, 0, 0, 0 };
        var iter = std.mem.splitScalar(u8, ip_str, '.');
        var i: usize = 0;
        while (iter.next()) |octet_str| : (i += 1) {
            if (i >= 4) break;
            octets[i] = std.fmt.parseInt(u8, octet_str, 10) catch 0;
        }

        // Convert to u32 (network byte order)
        return (@as(u32, octets[0]) << 24) |
            (@as(u32, octets[1]) << 16) |
            (@as(u32, octets[2]) << 8) |
            @as(u32, octets[3]);
    }

    /// Get learned gateway MAC address
    pub fn getGatewayMac(self: *const VpnClient) !?[6]u8 {
        var mac_buf: [64]u8 = undefined;
        const mac_str = self.bridge_client.getGatewayMac(&mac_buf) catch {
            return null; // Not yet learned
        };

        // Parse MAC string (e.g., "00:11:22:33:44:55")
        var mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
        var iter = std.mem.splitScalar(u8, mac_str, ':');
        var i: usize = 0;
        while (iter.next()) |byte_str| : (i += 1) {
            if (i >= 6) break;
            mac[i] = std.fmt.parseInt(u8, byte_str, 16) catch 0;
        }

        // Check if MAC is valid (not all zeros)
        const is_valid = for (mac) |byte| {
            if (byte != 0) break true;
        } else false;

        return if (is_valid) mac else null;
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
        self.bridge_client.reconnect.enabled = true;
        self.bridge_client.reconnect.max_attempts = max_attempts;
        self.bridge_client.reconnect.min_backoff_seconds = min_backoff;
        self.bridge_client.reconnect.max_backoff_seconds = max_backoff;
    }

    /// Disable automatic reconnection
    pub fn disableReconnect(self: *VpnClient) !void {
        self.bridge_client.disableReconnect();
    }

    /// Get current reconnection state and determine if reconnection should occur
    pub fn getReconnectInfo(self: *const VpnClient) !ReconnectInfo {
        const rc = &self.bridge_client.reconnect;
        const status = self.bridge_client.getStatus();

        // Determine if we should reconnect
        const should_reconnect = rc.enabled and
            status == .DISCONNECTED and
            !rc.user_requested_disconnect and
            (rc.max_attempts == 0 or rc.current_attempt < rc.max_attempts);

        // Calculate backoff delay
        const backoff = rc.calculateBackoff();

        // Calculate next retry time (approximation)
        const now: u64 = @intCast(std.time.milliTimestamp());
        const next_retry = now + (@as(u64, backoff) * 1000);

        return ReconnectInfo{
            .enabled = rc.enabled,
            .should_reconnect = should_reconnect,
            .attempt = rc.current_attempt,
            .max_attempts = rc.max_attempts,
            .current_backoff = backoff,
            .next_retry_time = next_retry,
            .consecutive_failures = rc.current_attempt,
            .last_disconnect_time = rc.last_connect_time,
        };
    }

    /// Mark current disconnect as user-requested (prevents reconnection)
    pub fn markUserDisconnect(self: *VpnClient) !void {
        self.bridge_client.markUserDisconnect();
    }
};
