// SoftEtherZig Mobile VPN FFI Layer - Real Implementation
// Phase 2: Integrated with SoftEther via bridge
//
// Architecture:
//   Mobile App (Swift/Kotlin)
//     ↓
//   Mobile FFI (this file) ← YOU ARE HERE
//     ↓
//   Zig VPN Bridge (src/bridge/softether.zig)
//     ↓
//   SoftEther C Protocol

const std = @import("std");
const builtin = @import("builtin");

// Import Zig VPN bridge via named import (configured in build.zig)
const bridge = @import("bridge");

// ============================================================================
// FFI Types (matching include/ffi.h exactly)
// ============================================================================

/// Opaque VPN connection handle
pub const MobileVpnHandle = ?*anyopaque;

/// VPN connection status (matches ffi.h enum)
pub const MobileVpnStatus = enum(c_int) {
    MOBILE_VPN_STATUS_DISCONNECTED = 0,
    MOBILE_VPN_STATUS_CONNECTING = 1,
    MOBILE_VPN_STATUS_CONNECTED = 2,
    MOBILE_VPN_STATUS_RECONNECTING = 3,
    MOBILE_VPN_STATUS_ERROR = 4,
    _,
};

/// VPN statistics (matches ffi.h struct)
pub const MobileVpnStats = extern struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    connected_duration_ms: u64,
    queue_drops: u64,
    errors: u64,
};

/// Network configuration (matches ffi.h struct)
pub const MobileNetworkInfo = extern struct {
    ip_address: [4]u8,
    gateway: [4]u8,
    netmask: [4]u8,
    dns_servers: [4][4]u8,
    mtu: u16,
    _reserved: [32]u8,
};

/// Callback function types
pub const MobileStatusCallback = ?*const fn (status: MobileVpnStatus, user_data: ?*anyopaque) callconv(.c) void;
pub const MobileStatsCallback = ?*const fn (stats: *const MobileVpnStats, user_data: ?*anyopaque) callconv(.c) void;
pub const MobileNetworkCallback = ?*const fn (info: *const MobileNetworkInfo, user_data: ?*anyopaque) callconv(.c) void;

/// VPN configuration (matches ffi.h struct)
pub const MobileVpnConfig = extern struct {
    server: [*:0]const u8,
    port: u16,
    hub: [*:0]const u8,
    username: [*:0]const u8,
    password_hash: [*:0]const u8,
    use_encrypt: bool,
    use_compress: bool,
    half_connection: bool,
    max_connection: u8,
    recv_queue_size: u64,
    send_queue_size: u64,
    packet_pool_size: u64,
    batch_size: u64,
    _reserved: [16]u8,
};

// ============================================================================
// Internal Context
// ============================================================================

/// Internal VPN context wrapping Zig bridge
const MobileVpnContext = struct {
    allocator: std.mem.Allocator,
    bridge_client: *bridge.VpnBridgeClient,
    status: MobileVpnStatus,
    error_msg: []u8,

    // Callbacks
    status_callback: MobileStatusCallback,
    stats_callback: MobileStatsCallback,
    network_callback: MobileNetworkCallback,
    user_data: ?*anyopaque,

    // Statistics
    stats: MobileVpnStats,
    start_time: i64,

    // Network info from DHCP
    network_info: MobileNetworkInfo,
    has_network_info: bool,

    fn init(allocator: std.mem.Allocator) !*MobileVpnContext {
        const ctx = try allocator.create(MobileVpnContext);
        errdefer allocator.destroy(ctx);

        const bridge_client = try bridge.VpnBridgeClient.init(allocator);
        errdefer bridge_client.deinit();

        ctx.* = .{
            .allocator = allocator,
            .bridge_client = bridge_client,
            .status = .MOBILE_VPN_STATUS_DISCONNECTED,
            .error_msg = try allocator.dupe(u8, ""),
            .status_callback = null,
            .stats_callback = null,
            .network_callback = null,
            .user_data = null,
            .stats = std.mem.zeroes(MobileVpnStats),
            .start_time = 0,
            .network_info = std.mem.zeroes(MobileNetworkInfo),
            .has_network_info = false,
        };

        return ctx;
    }

    fn deinit(self: *MobileVpnContext) void {
        self.bridge_client.deinit();
        self.allocator.free(self.error_msg);
        self.allocator.destroy(self);
    }

    fn setStatus(self: *MobileVpnContext, new_status: MobileVpnStatus) void {
        if (self.status != new_status) {
            self.status = new_status;
            if (self.status_callback) |callback| {
                callback(new_status, self.user_data);
            }
        }
    }

    fn setError(self: *MobileVpnContext, err_msg: []const u8) void {
        self.allocator.free(self.error_msg);
        self.error_msg = self.allocator.dupe(u8, err_msg) catch blk: {
            const fallback = "Out of memory";
            break :blk self.allocator.dupe(u8, fallback) catch return;
        };
        self.setStatus(.MOBILE_VPN_STATUS_ERROR);
    }

    fn updateStats(self: *MobileVpnContext) void {
        // Update connected duration
        if (self.status == .MOBILE_VPN_STATUS_CONNECTED and self.start_time > 0) {
            const now = std.time.milliTimestamp();
            self.stats.connected_duration_ms = @intCast(now - self.start_time);
        }

        // Get stats from bridge client
        self.stats.bytes_sent = self.bridge_client.getBytesSent();
        self.stats.bytes_received = self.bridge_client.getBytesReceived();
        // Note: packets_sent/received are tracked by mobile OS, not bridge

        // Call stats callback if set
        if (self.stats_callback) |callback| {
            callback(&self.stats, self.user_data);
        }
    }

    fn extractNetworkInfo(self: *MobileVpnContext) void {
        // Get DHCP info from bridge
        const dhcp_info = self.bridge_client.getDhcpInfo();

        if (dhcp_info.has_ip) {
            // Parse IP address
            if (parseIpv4(std.mem.sliceTo(&dhcp_info.ip_address, 0), &self.network_info.ip_address)) {
                // Parse gateway
                _ = parseIpv4(std.mem.sliceTo(&dhcp_info.gateway, 0), &self.network_info.gateway);
                // Parse netmask
                _ = parseIpv4(std.mem.sliceTo(&dhcp_info.subnet_mask, 0), &self.network_info.netmask);

                // Parse DNS servers
                var i: usize = 0;
                while (i < dhcp_info.dns_count and i < 4) : (i += 1) {
                    _ = parseIpv4(std.mem.sliceTo(&dhcp_info.dns_servers[i], 0), &self.network_info.dns_servers[i]);
                }

                self.network_info.mtu = 1500; // Default MTU
                self.has_network_info = true;

                // Call network callback
                if (self.network_callback) |callback| {
                    callback(&self.network_info, self.user_data);
                }
            }
        }
    }
};

// Helper to parse IPv4 string to bytes
fn parseIpv4(ip_str: []const u8, out: *[4]u8) bool {
    var parts: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, ip_str, '.');
    var i: usize = 0;

    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return false;
        parts[i] = std.fmt.parseInt(u8, part, 10) catch return false;
    }

    if (i != 4) return false;
    @memcpy(out, &parts);
    return true;
}

// ============================================================================
// Global State
// ============================================================================

var g_initialized: bool = false;
var g_init_mutex = std.Thread.Mutex{};

// ============================================================================
// C API Exports
// ============================================================================

/// Initialize mobile VPN library
export fn mobile_vpn_init() c_int {
    g_init_mutex.lock();
    defer g_init_mutex.unlock();

    if (g_initialized) {
        return 0; // Already initialized
    }

    // Initialize SoftEther library via bridge
    bridge.init(false) catch return -1;

    g_initialized = true;
    return 0;
}

/// Cleanup mobile VPN library
export fn mobile_vpn_cleanup() void {
    g_init_mutex.lock();
    defer g_init_mutex.unlock();

    if (!g_initialized) {
        return;
    }

    bridge.deinit();
    g_initialized = false;
}

/// Create VPN connection handle
export fn mobile_vpn_create(cfg: *const MobileVpnConfig) MobileVpnHandle {
    const allocator = std.heap.c_allocator;

    // Ensure library is initialized
    if (!g_initialized) {
        _ = mobile_vpn_init();
    }

    // Create context
    var ctx = MobileVpnContext.init(allocator) catch return null;
    errdefer ctx.deinit();

    // Get string slices from C strings
    const server = std.mem.span(cfg.server);
    const hub = std.mem.span(cfg.hub);
    const username = std.mem.span(cfg.username);
    const password_hash = std.mem.span(cfg.password_hash);

    // Configure the bridge client
    ctx.bridge_client.configureWithHash(
        server,
        cfg.port,
        hub,
        username,
        password_hash,
    ) catch {
        ctx.deinit();
        return null;
    };

    // On iOS, disable the Zig packet adapter - iOS VPN framework handles packets
    if (builtin.os.tag == .ios) {
        ctx.bridge_client.use_zig_adapter = false;
        std.log.info("iOS: Using stub packet adapter (VPN framework handles packets)", .{});
    }

    // Set connection options
    ctx.bridge_client.setMaxConnection(cfg.max_connection) catch {};

    return @ptrCast(ctx);
}

/// Destroy VPN connection handle
export fn mobile_vpn_destroy(handle: MobileVpnHandle) void {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return));

    // Disconnect if connected
    if (ctx.status == .MOBILE_VPN_STATUS_CONNECTED or
        ctx.status == .MOBILE_VPN_STATUS_CONNECTING)
    {
        _ = mobile_vpn_disconnect(handle);
    }

    ctx.deinit();
}

/// Connect to VPN server
/// On iOS, this starts the connection in the background and returns immediately.
/// The mobile app should poll get_status() to check connection progress.
export fn mobile_vpn_connect(handle: MobileVpnHandle) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    if (ctx.status == .MOBILE_VPN_STATUS_CONNECTED or
        ctx.status == .MOBILE_VPN_STATUS_CONNECTING)
    {
        return -2; // Already connected/connecting
    }

    ctx.setStatus(.MOBILE_VPN_STATUS_CONNECTING);
    ctx.start_time = std.time.milliTimestamp();

    // On iOS, spawn a background thread for the connection since the VPN framework
    // handles the network interface and we can't block the main thread
    if (builtin.os.tag == .ios) {
        const thread = std.Thread.spawn(.{}, connectInBackground, .{ctx}) catch |err| {
            std.log.err("Failed to spawn connection thread: {}", .{err});
            ctx.setError("Failed to start connection thread");
            return -3;
        };
        thread.detach();
        return 0; // Return immediately, connection continues in background
    }

    // On other platforms, connect synchronously
    ctx.bridge_client.connect() catch |err| {
        const err_msg = switch (err) {
            error.ConnectionFailed => "Connection failed",
            error.AuthenticationFailed => "Authentication failed",
            error.NotInitialized => "Not initialized",
            else => "Unknown error",
        };
        ctx.setError(err_msg);
        return -3;
    };

    ctx.setStatus(.MOBILE_VPN_STATUS_CONNECTED);
    ctx.extractNetworkInfo();

    return 0;
}

/// Background connection thread for iOS
fn connectInBackground(ctx: *MobileVpnContext) void {
    std.log.info("iOS: Starting VPN connection in background thread", .{});

    // Attempt connection
    ctx.bridge_client.connect() catch |err| {
        const err_msg = switch (err) {
            error.ConnectionFailed => "Connection failed",
            error.AuthenticationFailed => "Authentication failed",
            error.NotInitialized => "Not initialized",
            else => "Unknown error",
        };
        std.log.err("iOS: Connection failed: {s}", .{err_msg});
        ctx.setError(err_msg);
        return;
    };

    std.log.info("iOS: VPN connection established", .{});
    ctx.setStatus(.MOBILE_VPN_STATUS_CONNECTED);

    // Extract network info from DHCP
    ctx.extractNetworkInfo();
}

/// Disconnect from VPN server
export fn mobile_vpn_disconnect(handle: MobileVpnHandle) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    if (ctx.status != .MOBILE_VPN_STATUS_CONNECTED and
        ctx.status != .MOBILE_VPN_STATUS_CONNECTING)
    {
        return -2; // Not connected
    }

    // Disconnect via bridge
    ctx.bridge_client.disconnect();

    ctx.setStatus(.MOBILE_VPN_STATUS_DISCONNECTED);
    ctx.start_time = 0;
    ctx.has_network_info = false;

    return 0;
}

/// Get connection status
export fn mobile_vpn_get_status(handle: MobileVpnHandle, out_status: *MobileVpnStatus) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    // Update status from bridge
    const bridge_status = ctx.bridge_client.getStatus();
    const new_status: MobileVpnStatus = switch (bridge_status) {
        .DISCONNECTED => .MOBILE_VPN_STATUS_DISCONNECTED,
        .CONNECTING => .MOBILE_VPN_STATUS_CONNECTING,
        .CONNECTED => .MOBILE_VPN_STATUS_CONNECTED,
        .DISCONNECTING => .MOBILE_VPN_STATUS_DISCONNECTED,
        .ERROR => .MOBILE_VPN_STATUS_ERROR,
    };

    ctx.status = new_status;
    out_status.* = new_status;
    return 0;
}

/// Get traffic statistics
export fn mobile_vpn_get_stats(handle: MobileVpnHandle, out_stats: *MobileVpnStats) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    ctx.updateStats();
    out_stats.* = ctx.stats;
    return 0;
}

/// Get last error message
export fn mobile_vpn_get_error(handle: MobileVpnHandle, out_msg: [*]u8, msg_size: usize) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    const msg = ctx.error_msg;
    const copy_len = @min(msg.len, msg_size - 1);
    @memcpy(out_msg[0..copy_len], msg[0..copy_len]);
    out_msg[copy_len] = 0; // Null terminate

    return 0;
}

/// Check if connected
export fn mobile_vpn_is_connected(handle: MobileVpnHandle) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return 0));
    return if (ctx.status == .MOBILE_VPN_STATUS_CONNECTED) 1 else 0;
}

/// Read packet from VPN tunnel
/// NOTE: For mobile VPN, packets should be read from OS VPN interface (PacketTunnelProvider/VpnService)
/// This function is provided for compatibility but always returns -1 (not implemented)
export fn mobile_vpn_read_packet(
    handle: MobileVpnHandle,
    buffer: [*]u8,
    size: usize,
    timeout_ms: c_int,
) c_int {
    _ = handle;
    _ = buffer;
    _ = size;
    _ = timeout_ms;

    // Mobile VPN packets flow through OS interface, not this API
    return -1; // Not implemented - use OS VPN interface
}

/// Write packet to VPN tunnel
/// NOTE: For mobile VPN, packets should be written to OS VPN interface (PacketTunnelProvider/VpnService)
/// This function is provided for compatibility but always returns -1 (not implemented)
export fn mobile_vpn_write_packet(
    handle: MobileVpnHandle,
    buffer: [*]const u8,
    size: usize,
) c_int {
    _ = handle;
    _ = buffer;
    _ = size;

    // Mobile VPN packets flow through OS interface, not this API
    return -1; // Not implemented - use OS VPN interface
}

/// Get network configuration info
export fn mobile_vpn_get_network_info(handle: MobileVpnHandle, out_info: *MobileNetworkInfo) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    if (!ctx.has_network_info) {
        ctx.extractNetworkInfo();
    }

    if (ctx.has_network_info) {
        out_info.* = ctx.network_info;
        return 0;
    }

    return -2; // No network info available yet
}

/// Set status change callback
export fn mobile_vpn_set_status_callback(
    handle: MobileVpnHandle,
    callback: MobileStatusCallback,
    user_data: ?*anyopaque,
) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));
    ctx.status_callback = callback;
    ctx.user_data = user_data;
    return 0;
}

/// Set statistics callback
export fn mobile_vpn_set_stats_callback(
    handle: MobileVpnHandle,
    callback: MobileStatsCallback,
    user_data: ?*anyopaque,
) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));
    ctx.stats_callback = callback;
    ctx.user_data = user_data;
    return 0;
}

/// Set network configuration callback
export fn mobile_vpn_set_network_callback(
    handle: MobileVpnHandle,
    callback: MobileNetworkCallback,
    user_data: ?*anyopaque,
) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));
    ctx.network_callback = callback;
    ctx.user_data = user_data;
    return 0;
}

/// Get library version string
export fn mobile_vpn_get_version() [*:0]const u8 {
    return "SoftEtherZig Mobile VPN 1.0.0";
}

/// Get build information
export fn mobile_vpn_get_build_info() [*:0]const u8 {
    return "SoftEtherZig Phase 2 - Real Implementation - Built " ++ @tagName(builtin.cpu.arch) ++ " " ++ @tagName(builtin.os.tag);
}
