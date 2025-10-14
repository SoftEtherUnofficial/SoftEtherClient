// SoftEtherZig Mobile VPN FFI Layer - STUB IMPLEMENTATION
// Platform-agnostic C API for iOS PacketTunnelProvider
//
// This is a minimal stub that compiles and can be called from Swift.
// Full implementation will be added incrementally.

const std = @import("std");
const builtin = @import("builtin");

// ============================================================================
// FFI Types (matching include/ffi.h)
// ============================================================================

/// Opaque VPN connection handle (exported to C)
pub const MobileVpnHandle = ?*anyopaque;

/// Platform-agnostic VPN configuration
pub const MobileVpnConfig = extern struct {
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    username: [*:0]const u8,
    password_hash: [*:0]const u8,
    use_encrypt: bool = true,
    use_compress: bool = true,
    half_connection: bool = false,
    max_connection: u8 = 1,
    recv_queue_size: u64 = 128,
    send_queue_size: u64 = 128,
    packet_pool_size: u64 = 256,
    batch_size: u64 = 32,
    _reserved: [16]u8 = [_]u8{0} ** 16,
};

/// VPN connection status
pub const MobileVpnStatus = enum(c_int) {
    MOBILE_VPN_DISCONNECTED = 0,
    MOBILE_VPN_CONNECTING = 1,
    MOBILE_VPN_CONNECTED = 2,
    MOBILE_VPN_RECONNECTING = 3,
    MOBILE_VPN_ERROR = 4,
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

/// Network configuration info
pub const MobileNetworkInfo = extern struct {
    ip_address: [4]u8 = [_]u8{0} ** 4,
    gateway: [4]u8 = [_]u8{0} ** 4,
    netmask: [4]u8 = [_]u8{0} ** 4,
    dns_servers: [4][4]u8 = [_][4]u8{[_]u8{0} ** 4} ** 4,
    mtu: u16 = 1500,
    _reserved: [32]u8 = [_]u8{0} ** 32,
};

/// Callback function types
pub const MobileStatusCallback = ?*const fn (status: MobileVpnStatus, user_data: ?*anyopaque) callconv(.c) void;
pub const MobileStatsCallback = ?*const fn (stats: *const MobileVpnStats, user_data: ?*anyopaque) callconv(.c) void;
pub const MobileNetworkCallback = ?*const fn (info: *const MobileNetworkInfo, user_data: ?*anyopaque) callconv(.c) void;

// ============================================================================
// Internal Stub Context
// ============================================================================

const StubContext = struct {
    allocator: std.mem.Allocator,
    status: MobileVpnStatus = .MOBILE_VPN_DISCONNECTED,
    stats: MobileVpnStats = .{},
    status_callback: MobileStatusCallback = null,
    stats_callback: MobileStatsCallback = null,
    network_callback: MobileNetworkCallback = null,
    user_data: ?*anyopaque = null,
};

// ============================================================================
// C API Exports (STUB IMPLEMENTATION)
// ============================================================================

export fn mobile_vpn_init() c_int {
    // TODO: Initialize SoftEther library
    return 0;
}

export fn mobile_vpn_create(cfg: *const MobileVpnConfig) MobileVpnHandle {
    _ = cfg;
    const allocator = std.heap.c_allocator;
    const ctx = allocator.create(StubContext) catch return null;
    ctx.* = .{
        .allocator = allocator,
    };
    return @ptrCast(ctx);
}

export fn mobile_vpn_destroy(handle: MobileVpnHandle) void {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return));
    ctx.allocator.destroy(ctx);
}

export fn mobile_vpn_connect(handle: MobileVpnHandle) c_int {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return -1));
    ctx.status = .MOBILE_VPN_CONNECTING;
    // TODO: Implement actual connection
    ctx.status = .MOBILE_VPN_CONNECTED;
    if (ctx.status_callback) |cb| {
        cb(.MOBILE_VPN_CONNECTED, ctx.user_data);
    }
    return 0;
}

export fn mobile_vpn_disconnect(handle: MobileVpnHandle) c_int {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return -1));
    ctx.status = .MOBILE_VPN_DISCONNECTED;
    if (ctx.status_callback) |cb| {
        cb(.MOBILE_VPN_DISCONNECTED, ctx.user_data);
    }
    return 0;
}

export fn mobile_vpn_get_status(handle: MobileVpnHandle) MobileVpnStatus {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return .MOBILE_VPN_ERROR));
    return ctx.status;
}

export fn mobile_vpn_get_stats(handle: MobileVpnHandle, out_stats: ?*MobileVpnStats) c_int {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return -1));
    const stats = out_stats orelse return -2;
    stats.* = ctx.stats;
    return 0;
}

export fn mobile_vpn_read_packet(handle: MobileVpnHandle, buffer: [*]u8, buffer_len: u64, timeout_ms: u32) c_int {
    _ = handle;
    _ = buffer;
    _ = buffer_len;
    _ = timeout_ms;
    // TODO: Implement packet reading
    return 0; // No packets yet
}

export fn mobile_vpn_write_packet(handle: MobileVpnHandle, data: [*]const u8, data_len: u64) c_int {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return -1));
    _ = data;
    ctx.stats.bytes_sent += data_len;
    ctx.stats.packets_sent += 1;
    return 0;
}

export fn mobile_vpn_get_network_info(handle: MobileVpnHandle, out_info: ?*MobileNetworkInfo) c_int {
    _ = handle;
    const info = out_info orelse return -2;
    // TODO: Get real network info
    info.* = .{
        .ip_address = [_]u8{ 10, 0, 0, 2 },
        .gateway = [_]u8{ 10, 0, 0, 1 },
        .netmask = [_]u8{ 255, 255, 255, 0 },
        .mtu = 1500,
    };
    return 0;
}

export fn mobile_vpn_set_status_callback(handle: MobileVpnHandle, callback: MobileStatusCallback, user_data: ?*anyopaque) void {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return));
    ctx.status_callback = callback;
    ctx.user_data = user_data;
}

export fn mobile_vpn_set_stats_callback(handle: MobileVpnHandle, callback: MobileStatsCallback, user_data: ?*anyopaque) void {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return));
    ctx.stats_callback = callback;
    ctx.user_data = user_data;
}

export fn mobile_vpn_set_network_callback(handle: MobileVpnHandle, callback: MobileNetworkCallback, user_data: ?*anyopaque) void {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return));
    ctx.network_callback = callback;
    ctx.user_data = user_data;
}

export fn mobile_vpn_get_error(handle: MobileVpnHandle) [*:0]const u8 {
    _ = handle;
    return "Stub implementation - no errors yet";
}

export fn mobile_vpn_is_connected(handle: MobileVpnHandle) bool {
    const ctx: *StubContext = @ptrCast(@alignCast(handle orelse return false));
    return ctx.status == .MOBILE_VPN_CONNECTED;
}

export fn mobile_vpn_cleanup() void {
    // TODO: Cleanup library
}

export fn mobile_vpn_get_version() [*:0]const u8 {
    return "SoftEtherZig Mobile v1.0.0-stub";
}

export fn mobile_vpn_get_build_info() [*:0]const u8 {
    return switch (builtin.os.tag) {
        .ios => "iOS ARM64 Stub " ++ builtin.zig_version_string,
        .macos => "macOS ARM64 Stub " ++ builtin.zig_version_string,
        else => "Stub " ++ builtin.zig_version_string,
    };
}
