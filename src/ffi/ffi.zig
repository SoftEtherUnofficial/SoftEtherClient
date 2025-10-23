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
//   Zig Packet Adapter → ZigTapTun → TUN device

const std = @import("std");
const builtin = @import("builtin");

// Mobile FFI is self-contained and doesn't use packet adapter
// The mobile app (iOS/Android) handles packet I/O directly via TUN device
// This FFI only handles VPN connection management

// Simplified configuration for mobile
const MobileVpnContextInternal = struct {
    allocator: std.mem.Allocator,
    status: MobileVpnStatus,
    config: MobileVpnConfig,
    start_time: i64,
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,

    fn setStatus(self: *MobileVpnContextInternal, new_status: MobileVpnStatus) void {
        self.status = new_status;
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

/// Internal VPN context
const MobileVpnContext = struct {
    allocator: std.mem.Allocator,
    status: MobileVpnStatus,

    // Callbacks
    status_callback: MobileStatusCallback = null,
    stats_callback: MobileStatsCallback = null,
    network_callback: MobileNetworkCallback = null,
    user_data: ?*anyopaque = null,

    // Statistics
    stats: MobileVpnStats = .{},
    start_time: i64 = 0,

    // Network configuration
    network_info: MobileNetworkInfo = .{},

    // Configuration
    config: MobileVpnConfig,

    fn setStatus(self: *MobileVpnContext, new_status: MobileVpnStatus) void {
        if (self.status != new_status) {
            self.status = new_status;
            if (self.status_callback) |callback| {
                callback(new_status, self.user_data);
            }
        }
    }

    fn updateStats(self: *MobileVpnContext) void {
        // Stats are updated by read/write operations
        _ = self;
    }
};

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

    // TODO: Implement actual connection logic
    // For now, simulate successful connection with mock network config
    ctx.setStatus(.connected);

    // Provide mock network configuration (typical VPN range)
    // In real implementation, this would come from DHCP/server
    ctx.network_info = .{
        .ip_address = .{ 192, 168, 30, 10 }, // 192.168.30.10
        .gateway = .{ 192, 168, 30, 1 }, // 192.168.30.1
        .netmask = .{ 255, 255, 255, 0 }, // 255.255.255.0
        .dns_servers = .{
            .{ 8, 8, 8, 8 }, // 8.8.8.8
            .{ 8, 8, 4, 4 }, // 8.8.4.4
            .{ 0, 0, 0, 0 },
            .{ 0, 0, 0, 0 },
        },
        .mtu = 1500,
        ._reserved = undefined,
    };

    // Notify network config callback if set
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

    // Adapter deinit will handle cleanup
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

    ctx.updateStats();
    stats.* = ctx.stats;

    return 0;
}

/// Read packet from VPN (to write to TUN device)
/// Returns number of bytes read, 0 if no packet, negative on error
export fn mobile_vpn_read_packet(handle: ?*MobileVpnContext, buffer: [*]u8, buffer_len: u64, timeout_ms: u32) c_int {
    const ctx = handle orelse return -1;

    if (ctx.status != .connected) {
        return -2; // Not connected
    }

    // TODO: Implement actual packet reading from VPN connection
    // For now, return 0 (no packet available)
    _ = buffer;
    _ = buffer_len;
    _ = timeout_ms;
    return 0;
}

/// Write packet to VPN (from TUN device)
/// Returns 0 on success, negative on error
export fn mobile_vpn_write_packet(handle: ?*MobileVpnContext, data: [*]const u8, data_len: u64) c_int {
    const ctx = handle orelse return -1;

    if (ctx.status != .connected) {
        return -2; // Not connected
    }

    // Update stats
    ctx.stats.bytes_sent += data_len;
    ctx.stats.packets_sent += 1;

    // TODO: Implement actual packet writing to VPN connection
    // For now, just pretend it succeeded
    _ = data;
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
