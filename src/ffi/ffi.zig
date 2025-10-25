// Generic Mobile VPN FFI Layer
// Platform-agnostic C API for iOS PacketTunnelProvider and Android VpnService
//
// Architecture:
//   Mobile App (Swift/Kotlin)
//     ↓
//   Platform Wrapper (iOS/Android)
//     ↓
//   **Generic Mobile FFI** (this file)
//     ↓
//   Zig Packet Adapter → TapTun → TUN device

const std = @import("std");
const builtin = @import("builtin");

// When used as mobile FFI (iOS/Android), these come from mobile_ffi.zig root
const root = @import("root");
const vpn_core = root.vpn_core;
const config_mod = root.config_mod;
const errors_mod = root.errors_mod;
const c_mod = root.c_mod;
const c = c_mod.c;

// Mobile FFI now uses VpnCore for real VPN connection
// This matches desktop vpnclient architecture:
//   - Full SoftEther client connection
//   - Real DHCP negotiation with server
//   - Encrypted packet tunneling
// The mobile app (iOS/Android) handles TUN device management
// and applies network configuration from DHCP

// Mobile VPN context with real VpnCore client
const MobileVpnContextInternal = struct {
    allocator: std.mem.Allocator,
    status: MobileVpnStatus,
    config: MobileVpnConfig,
    vpn_core: ?*vpn_core.VpnCore, // Real VPN client
    network_info: MobileNetworkInfo,
    start_time: i64,
    status_callback: ?MobileStatusCallback,
    stats_callback: ?MobileStatsCallback,
    network_callback: ?MobileNetworkCallback,
    user_data: ?*anyopaque,

    fn setStatus(self: *MobileVpnContextInternal, new_status: MobileVpnStatus) void {
        self.status = new_status;
        // Trigger status callback
        if (self.status_callback) |callback| {
            callback(new_status, self.user_data);
        }
    }
};

// Export types for C interop
pub const MobileVpnHandle = ?*anyopaque;

/// Platform-agnostic VPN configuration
pub const MobileVpnConfig = extern struct {
    // Connection parameters
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    username: [*:0]const u8,
    password_hash: [*:0]const u8,

    // Connection options
    use_encrypt: bool = true,
    use_compress: bool = true,
    half_connection: bool = false,
    max_connection: u8 = 1,

    // Performance tuning
    recv_queue_size: usize = 128,
    send_queue_size: usize = 128,
    packet_pool_size: usize = 256,
    batch_size: usize = 32,

    // Reserved for future use
    _reserved: [16]u8 = [_]u8{0} ** 16,
};

/// VPN connection status
pub const MobileVpnStatus = enum(c_int) {
    disconnected = 0,
    connecting = 1,
    connected = 2,
    reconnecting = 3,
    error_state = 4,
    _,
};

/// VPN statistics
pub const MobileVpnStats = extern struct {
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    connected_duration_ms: u64 = 0,
    queue_drops: u64 = 0,
    errors: u64 = 0,
};

/// Network configuration info (obtained from DHCP)
pub const MobileNetworkInfo = extern struct {
    ip_address: [4]u8 = [_]u8{0} ** 4, // IPv4 address
    gateway: [4]u8 = [_]u8{0} ** 4, // Gateway IP
    netmask: [4]u8 = [_]u8{0} ** 4, // Subnet mask
    dns_servers: [4][4]u8 = [_][4]u8{[_]u8{0} ** 4} ** 4, // Up to 4 DNS servers
    mtu: u16 = 1500,
    _reserved: [32]u8 = [_]u8{0} ** 32,
};

/// Status callback function type
pub const MobileStatusCallback = ?*const fn (status: MobileVpnStatus, user_data: ?*anyopaque) callconv(.c) void;

/// Stats callback function type
pub const MobileStatsCallback = ?*const fn (stats: *const MobileVpnStats, user_data: ?*anyopaque) callconv(.c) void;

/// Network info callback function type
pub const MobileNetworkCallback = ?*const fn (info: *const MobileNetworkInfo, user_data: ?*anyopaque) callconv(.c) void;

// Type alias for C API (uses internal context)
const MobileVpnContext = MobileVpnContextInternal;

// ============================================================================
// C API Exports
// ============================================================================

/// Initialize mobile VPN library
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_init() c_int {
    // Nothing to initialize globally
    return 0;
}

/// Create VPN connection handle
/// Returns handle on success, null on failure
export fn mobile_vpn_create(config: *const MobileVpnConfig) ?*MobileVpnContext {
    const allocator = std.heap.c_allocator;

    const ctx = allocator.create(MobileVpnContext) catch return null;
    errdefer allocator.destroy(ctx);

    ctx.* = .{
        .allocator = allocator,
        .status = .disconnected,
        .config = config.*,
        .vpn_core = null, // Will be created on connect
        .network_info = .{},
        .start_time = 0,
        .status_callback = null,
        .stats_callback = null,
        .network_callback = null,
        .user_data = null,
    };

    return ctx;
}

/// Free VPN connection handle
export fn mobile_vpn_destroy(handle: ?*MobileVpnContext) void {
    const ctx = handle orelse return;

    // Disconnect if still connected
    if (ctx.status == .connected or ctx.status == .connecting) {
        _ = mobile_vpn_disconnect(ctx);
    }

    // Free VpnCore if exists
    if (ctx.vpn_core) |core| {
        core.deinit();
        ctx.allocator.destroy(core);
        ctx.vpn_core = null;
    }

    ctx.allocator.destroy(ctx);
}

/// Connect to VPN server
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_connect(handle: ?*MobileVpnContext) c_int {
    const ctx = handle orelse return -1;

    if (ctx.status == .connected or ctx.status == .connecting) {
        return -2; // Already connected/connecting
    }

    ctx.setStatus(.connecting);
    ctx.start_time = std.time.milliTimestamp();

    // Convert MobileVpnConfig to ConnectionConfig
    const server_name = std.mem.span(ctx.config.server);
    const hub_name = std.mem.span(ctx.config.hub);
    const username = std.mem.span(ctx.config.username);
    const password_hash = std.mem.span(ctx.config.password_hash);

    const conn_config = config_mod.ConnectionConfig{
        .server_name = server_name,
        .server_port = ctx.config.port,
        .hub_name = hub_name,
        .auth = .{
            .password = .{
                .username = username,
                .password = password_hash,
                .is_hashed = true, // Mobile always sends hashed
            },
        },
        .use_encrypt = ctx.config.use_encrypt,
        .use_compress = ctx.config.use_compress,
        .half_connection = ctx.config.half_connection,
        .max_connection = ctx.config.max_connection,
        .ip_version = .auto,
        .device_name = null, // Mobile app manages TUN device
        .static_ip = null, // Will use DHCP
        .use_zig_adapter = false, // Mobile app handles packets
        .reconnect = .{
            .enabled = false, // Mobile app handles reconnection
            .max_attempts = 0,
            .min_interval = 5,
            .max_interval = 300,
        },
    };

    // Create and initialize VpnCore
    const core = ctx.allocator.create(vpn_core.VpnCore) catch {
        ctx.setStatus(.error_state);
        return -3; // Allocation failed
    };
    errdefer ctx.allocator.destroy(core);

    core.* = vpn_core.VpnCore.init(ctx.allocator, conn_config) catch |err| {
        ctx.setStatus(.error_state);
        std.debug.print("VpnCore init failed: {}\n", .{err});
        return -4; // Init failed
    };
    ctx.vpn_core = core;

    // Connect to VPN server (performs full SoftEther handshake + DHCP)
    core.connect() catch |err| {
        ctx.setStatus(.error_state);
        std.debug.print("VpnCore connect failed: {}\n", .{err});
        return -5; // Connect failed
    };

    // Get DHCP information from SoftEther client
    if (core.handle) |core_handle| {
        var dhcp_info: c.VpnBridgeDhcpInfo = undefined;
        const dhcp_result = c.vpn_bridge_get_dhcp_info(core_handle, &dhcp_info);

        if (dhcp_result == c_mod.VPN_BRIDGE_SUCCESS and dhcp_info.valid == 1) {
            // Convert network byte order to host byte order for mobile FFI
            const client_ip = @byteSwap(dhcp_info.client_ip);
            const gateway = @byteSwap(dhcp_info.gateway);
            const netmask = @byteSwap(dhcp_info.subnet_mask);
            const dns1 = @byteSwap(dhcp_info.dns_server1);
            const dns2 = @byteSwap(dhcp_info.dns_server2);

            // Populate network info from real DHCP
            ctx.network_info = .{
                .ip_address = .{
                    @intCast((client_ip >> 24) & 0xFF),
                    @intCast((client_ip >> 16) & 0xFF),
                    @intCast((client_ip >> 8) & 0xFF),
                    @intCast(client_ip & 0xFF),
                },
                .gateway = .{
                    @intCast((gateway >> 24) & 0xFF),
                    @intCast((gateway >> 16) & 0xFF),
                    @intCast((gateway >> 8) & 0xFF),
                    @intCast(gateway & 0xFF),
                },
                .netmask = .{
                    @intCast((netmask >> 24) & 0xFF),
                    @intCast((netmask >> 16) & 0xFF),
                    @intCast((netmask >> 8) & 0xFF),
                    @intCast(netmask & 0xFF),
                },
                .dns_servers = .{
                    .{
                        @intCast((dns1 >> 24) & 0xFF),
                        @intCast((dns1 >> 16) & 0xFF),
                        @intCast((dns1 >> 8) & 0xFF),
                        @intCast(dns1 & 0xFF),
                    },
                    .{
                        @intCast((dns2 >> 24) & 0xFF),
                        @intCast((dns2 >> 16) & 0xFF),
                        @intCast((dns2 >> 8) & 0xFF),
                        @intCast(dns2 & 0xFF),
                    },
                    .{ 0, 0, 0, 0 },
                    .{ 0, 0, 0, 0 },
                },
                .mtu = 1500, // Default MTU
                ._reserved = undefined,
            };

            std.debug.print("DHCP: IP={d}.{d}.{d}.{d} Gateway={d}.{d}.{d}.{d} DNS={d}.{d}.{d}.{d}\n", .{
                ctx.network_info.ip_address[0],     ctx.network_info.ip_address[1],
                ctx.network_info.ip_address[2],     ctx.network_info.ip_address[3],
                ctx.network_info.gateway[0],        ctx.network_info.gateway[1],
                ctx.network_info.gateway[2],        ctx.network_info.gateway[3],
                ctx.network_info.dns_servers[0][0], ctx.network_info.dns_servers[0][1],
                ctx.network_info.dns_servers[0][2], ctx.network_info.dns_servers[0][3],
            });
        } else {
            std.debug.print("Warning: DHCP info not available or invalid\n", .{});
        }
    }

    ctx.setStatus(.connected);

    // Notify network callback if set
    if (ctx.network_callback) |callback| {
        callback(&ctx.network_info, ctx.user_data);
    }

    return 0;
}

/// Disconnect from VPN server
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_disconnect(handle: ?*MobileVpnContext) c_int {
    const ctx = handle orelse return -1;

    if (ctx.status == .disconnected) {
        return 0; // Already disconnected
    }

    // Disconnect VpnCore
    if (ctx.vpn_core) |core| {
        core.disconnect() catch |err| {
            std.debug.print("VpnCore disconnect error: {}\n", .{err});
        };
        core.deinit();
        ctx.allocator.destroy(core);
        ctx.vpn_core = null;
    }

    ctx.setStatus(.disconnected);
    ctx.start_time = 0;

    return 0;
}

/// Get current VPN status
export fn mobile_vpn_get_status(handle: ?*MobileVpnContext) MobileVpnStatus {
    const ctx = handle orelse return .error_state;
    return ctx.status;
}

/// Get VPN statistics
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_get_stats(handle: ?*MobileVpnContext, out_stats: ?*MobileVpnStats) c_int {
    const ctx = handle orelse return -1;
    const stats = out_stats orelse return -2;

    // Get stats from VpnCore if available
    if (ctx.vpn_core) |core| {
        stats.* = .{
            .bytes_sent = core.stats.bytes_sent,
            .bytes_received = core.stats.bytes_received,
            .packets_sent = core.stats.packets_sent,
            .packets_received = core.stats.packets_received,
            .connected_duration_ms = core.stats.connected_duration_ms,
            .queue_drops = 0,
            .errors = 0,
        };
        core.stats.updateDuration();
    } else {
        // No VpnCore, return zeros
        stats.* = .{};
    }

    return 0;
}

/// Read packet from VPN (to write to TUN device)
/// Returns number of bytes read, 0 if no packet, negative on error
///
/// Note: For mobile platforms, packet I/O is handled by:
/// - iOS: NEPacketTunnelProvider reads from TUN, writes to server
/// - Android: VpnService reads from TUN, writes to server
/// This function is for future full VPN client integration
export fn mobile_vpn_read_packet(handle: ?*MobileVpnContext, buffer: [*]u8, buffer_len: u64, timeout_ms: u32) c_int {
    const ctx = handle orelse return -1;

    if (ctx.status != .connected) {
        return -2; // Not connected
    }

    const core = ctx.vpn_core orelse return -3; // No VPN core
    const core_handle = core.handle orelse return -4; // No C handle

    // Read packet from SoftEther client (packets coming FROM server TO client)
    const result = c.vpn_bridge_read_packet(
        core_handle,
        buffer,
        @intCast(buffer_len),
        timeout_ms,
    );

    if (result > 0) {
        // Update stats
        ctx.stats.bytes_received += @intCast(result);
        ctx.stats.packets_received += 1;
    }

    return @intCast(result);
}

/// Write packet to VPN (from TUN device)
/// Returns 0 on success, negative on error
///
/// This writes packets FROM the mobile device TO the VPN server
/// Mobile app should call this when it reads packets from its TUN device
export fn mobile_vpn_write_packet(handle: ?*MobileVpnContext, data: [*]const u8, data_len: u64) c_int {
    const ctx = handle orelse return -1;

    if (ctx.status != .connected) {
        return -2; // Not connected
    }

    const core = ctx.vpn_core orelse return -3; // No VPN core
    const core_handle = core.handle orelse return -4; // No C handle

    // Write packet to SoftEther client (packets going FROM client TO server)
    const result = c.vpn_bridge_write_packet(
        core_handle,
        data,
        @intCast(data_len),
    );

    if (result == 0) {
        // Update stats
        ctx.stats.bytes_sent += data_len;
        ctx.stats.packets_sent += 1;
    }

    return result;
}

/// Set network configuration (called by platform after DHCP)
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_set_network_info(handle: ?*MobileVpnContext, info: ?*const MobileNetworkInfo) c_int {
    const ctx = handle orelse return -1;
    const network_info = info orelse return -2;

    // Store network configuration from DHCP
    ctx.network_info = network_info.*;

    // Notify network config callback if set
    if (ctx.network_callback) |callback| {
        callback(&ctx.network_info, ctx.user_data);
    }

    return 0;
}

/// Get network configuration (after DHCP completes)
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_get_network_info(handle: ?*MobileVpnContext, out_info: ?*MobileNetworkInfo) c_int {
    const ctx = handle orelse return -1;
    const info = out_info orelse return -2;

    // Return configured network info
    info.* = ctx.network_info;

    return 0;
}

/// Set status callback
export fn mobile_vpn_set_status_callback(
    handle: ?*MobileVpnContext,
    callback: MobileStatusCallback,
    user_data: ?*anyopaque,
) void {
    const ctx = handle orelse return;
    ctx.status_callback = callback;
    ctx.user_data = user_data;
}

/// Set statistics callback
export fn mobile_vpn_set_stats_callback(
    handle: ?*MobileVpnContext,
    callback: MobileStatsCallback,
    user_data: ?*anyopaque,
) void {
    const ctx = handle orelse return;
    ctx.stats_callback = callback;
    ctx.user_data = user_data;
}

/// Set network info callback
export fn mobile_vpn_set_network_callback(
    handle: ?*MobileVpnContext,
    callback: MobileNetworkCallback,
    user_data: ?*anyopaque,
) void {
    const ctx = handle orelse return;
    ctx.network_callback = callback;
    ctx.user_data = user_data;
}

/// Get last error message
/// Returns error string (valid until next error)
export fn mobile_vpn_get_error(handle: ?*MobileVpnContext) [*:0]const u8 {
    _ = handle;
    // TODO: Implement error tracking
    return "Not implemented";
}

/// Check if VPN is connected
export fn mobile_vpn_is_connected(handle: ?*MobileVpnContext) bool {
    const ctx = handle orelse return false;
    return ctx.status == .connected;
}

/// Cleanup library resources
export fn mobile_vpn_cleanup() void {
    // Nothing to cleanup globally
}

// ============================================================================
// Platform-Specific Helpers
// ============================================================================

/// Get version string
export fn mobile_vpn_get_version() [*:0]const u8 {
    return "SoftEtherZig Mobile FFI v1.0.0";
}

/// Get build info string
export fn mobile_vpn_get_build_info() [*:0]const u8 {
    const platform = switch (builtin.os.tag) {
        .macos => "macOS",
        .ios => "iOS",
        .linux => "Linux",
        .windows => "Windows",
        else => "Unknown",
    };

    const arch = switch (builtin.cpu.arch) {
        .aarch64 => "ARM64",
        .x86_64 => "x86_64",
        else => "Unknown",
    };

    // Static string that includes platform and arch
    const info = std.fmt.comptimePrint("Platform: {s}, Arch: {s}, Zig: {s}", .{
        platform,
        arch,
        builtin.zig_version_string,
    });

    return info;
}
