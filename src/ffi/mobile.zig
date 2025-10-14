// SoftEtherZig Mobile VPN FFI Layer
// Platform-agnostic C API for iOS PacketTunnelProvider and Android VpnService
//
// Architecture:
//   Mobile App (Swift/Kotlin)
//     ↓
//   Platform Wrapper (iOS/Android)
//     ↓
//   **Mobile FFI** (this file) ← YOU ARE HERE
//     ↓
//   SoftEther C Bridge (extern functions)
//     ↓
//   SoftEther C Protocol (Mayaqua/Cedar)

const std = @import("std");
const builtin = @import("builtin");

// C headers for SoftEther
const c = @cImport({
    @cInclude("Mayaqua/Mayaqua.h");
    @cInclude("Cedar/Cedar.h");
    @cInclude("Cedar/Client.h");
});

// ============================================================================
// FFI Types (matching include/ffi.h)
// ============================================================================

/// Opaque VPN connection handle (exported to C)
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
    recv_queue_size: u64 = 128,
    send_queue_size: u64 = 128,
    packet_pool_size: u64 = 256,
    batch_size: u64 = 32,

    // Reserved for future use
    _reserved: [16]u8 = [_]u8{0} ** 16,
};

/// VPN connection status
pub const MobileVpnStatus = enum(c_int) {
    MOBILE_VPN_DISCONNECTED = 0,
    MOBILE_VPN_CONNECTING = 1,
    MOBILE_VPN_CONNECTED = 2,
    MOBILE_VPN_RECONNECTING = 3,
    MOBILE_VPN_ERROR = 4,
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
    ip_address: [4]u8 = [_]u8{0} ** 4,
    gateway: [4]u8 = [_]u8{0} ** 4,
    netmask: [4]u8 = [_]u8{0} ** 4,
    dns_servers: [4][4]u8 = [_][4]u8{[_]u8{0} ** 4} ** 4,
    mtu: u16 = 1500,
    _reserved: [32]u8 = [_]u8{0} ** 32,
};

/// Status callback function type
pub const MobileStatusCallback = ?*const fn (status: MobileVpnStatus, user_data: ?*anyopaque) callconv(.c) void;

/// Stats callback function type
pub const MobileStatsCallback = ?*const fn (stats: *const MobileVpnStats, user_data: ?*anyopaque) callconv(.c) void;

/// Network info callback function type
pub const MobileNetworkCallback = ?*const fn (info: *const MobileNetworkInfo, user_data: ?*anyopaque) callconv(.c) void;

// ============================================================================
// Internal Context
// ============================================================================

/// Internal VPN context (wraps SoftEther C client)
const MobileVpnContext = struct {
    allocator: std.mem.Allocator,
    client: ?*c.CLIENT,
    account: ?*c.ACCOUNT,
    status: MobileVpnStatus,
    error_msg: [:0]u8,

    // Callbacks
    status_callback: MobileStatusCallback = null,
    stats_callback: MobileStatsCallback = null,
    network_callback: MobileNetworkCallback = null,
    user_data: ?*anyopaque = null,

    // Statistics
    stats: MobileVpnStats = .{},
    start_time: i64 = 0,

    // Configuration copy
    server: [:0]u8,
    hub: [:0]u8,
    username: [:0]u8,
    password_hash: [:0]u8,
    port: u16,

    fn setStatus(self: *MobileVpnContext, new_status: MobileVpnStatus) void {
        if (self.status != new_status) {
            self.status = new_status;
            if (self.status_callback) |callback| {
                callback(new_status, self.user_data);
            }
        }
    }

    fn setError(self: *MobileVpnContext, err_msg: []const u8) void {
        // Free old error message
        if (self.error_msg.len > 0) {
            self.allocator.free(self.error_msg);
        }

        // Allocate new error message
        self.error_msg = self.allocator.dupeZ(u8, err_msg) catch "Out of memory";
        self.setStatus(.MOBILE_VPN_ERROR);
    }

    fn updateStats(self: *MobileVpnContext) void {
        // Update duration if connected
        if (self.status == .MOBILE_VPN_CONNECTED and self.start_time > 0) {
            const now = std.time.milliTimestamp();
            self.stats.connected_duration_ms = @intCast(now - self.start_time);
        }

        // Get stats from SoftEther client
        if (self.client) |client| {
            if (client.Session) |session| {
                self.stats.bytes_sent = session.TotalSendSize;
                self.stats.bytes_received = session.TotalRecvSize;
                self.stats.packets_sent = session.TotalSendSizeReal;
                self.stats.packets_received = session.TotalRecvSizeReal;
            }
        }

        // Call stats callback if set
        if (self.stats_callback) |callback| {
            callback(&self.stats, self.user_data);
        }
    }
};

// ============================================================================
// Global State
// ============================================================================

var g_initialized: bool = false;
var g_init_mutex = std.Thread.Mutex{};

// ============================================================================
// C API Exports
// ============================================================================

/// Initialize mobile VPN library
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_init() c_int {
    g_init_mutex.lock();
    defer g_init_mutex.unlock();

    if (g_initialized) {
        return 0; // Already initialized
    }

    // Initialize Mayaqua and Cedar libraries
    c.MayaquaMinimalMode();
    c.InitMayaqua(1, 1, null, null);
    c.InitCedar();

    g_initialized = true;
    return 0;
}

/// Create VPN connection handle
/// Returns handle on success, null on failure
export fn mobile_vpn_create(cfg: *const MobileVpnConfig) MobileVpnHandle {
    const allocator = std.heap.c_allocator;

    // Ensure library is initialized
    if (!g_initialized) {
        _ = mobile_vpn_init();
    }

    // Allocate context
    const ctx = allocator.create(MobileVpnContext) catch return null;
    errdefer allocator.destroy(ctx);

    // Copy string configuration
    const server = allocator.dupeZ(u8, std.mem.span(cfg.server)) catch return null;
    errdefer allocator.free(server);

    const hub = allocator.dupeZ(u8, std.mem.span(cfg.hub)) catch return null;
    errdefer allocator.free(hub);

    const username = allocator.dupeZ(u8, std.mem.span(cfg.username)) catch return null;
    errdefer allocator.free(username);

    const password_hash = allocator.dupeZ(u8, std.mem.span(cfg.password_hash)) catch return null;
    errdefer allocator.free(password_hash);

    // Create SoftEther CLIENT object
    const client = c.CiNewClient() orelse {
        allocator.free(password_hash);
        allocator.free(username);
        allocator.free(hub);
        allocator.free(server);
        allocator.destroy(ctx);
        return null;
    };

    // Create ACCOUNT object
    const account = c.ZeroMalloc(@sizeOf(c.ACCOUNT));
    if (account == null) {
        c.CiFreeClient(client);
        allocator.free(password_hash);
        allocator.free(username);
        allocator.free(hub);
        allocator.free(server);
        allocator.destroy(ctx);
        return null;
    }

    const acc: *c.ACCOUNT = @ptrCast(@alignCast(account));

    // Configure account
    c.StrCpy(acc.ClientOption.*.AccountName, @sizeOf(@TypeOf(acc.ClientOption.*.AccountName)), "Mobile");
    c.StrCpy(acc.ClientOption.*.Hostname, @sizeOf(@TypeOf(acc.ClientOption.*.Hostname)), server.ptr);
    acc.ClientOption.*.Port = cfg.port;
    c.StrCpy(acc.ClientOption.*.HubName, @sizeOf(@TypeOf(acc.ClientOption.*.HubName)), hub.ptr);
    c.StrCpy(acc.ClientOption.*.Username, @sizeOf(@TypeOf(acc.ClientOption.*.Username)), username.ptr);

    // Set authentication (use hashed password)
    acc.ClientAuth.*.AuthType = c.CLIENT_AUTHTYPE_PASSWORD;
    if (password_hash.len > 0) {
        c.StrCpy(@ptrCast(&acc.ClientAuth.*.HashedPassword), @sizeOf(@TypeOf(acc.ClientAuth.*.HashedPassword)), password_hash.ptr);
    }

    // Set options
    acc.ClientOption.*.UseEncrypt = cfg.use_encrypt;
    acc.ClientOption.*.UseCompress = cfg.use_compress;
    acc.ClientOption.*.HalfConnection = cfg.half_connection;
    acc.ClientOption.*.MaxConnection = cfg.max_connection;

    // Initialize context
    ctx.* = .{
        .allocator = allocator,
        .client = client,
        .account = acc,
        .status = .MOBILE_VPN_DISCONNECTED,
        .error_msg = allocator.dupeZ(u8, "") catch "",
        .server = server,
        .hub = hub,
        .username = username,
        .password_hash = password_hash,
        .port = cfg.port,
    };

    return @ptrCast(ctx);
}

/// Free VPN connection handle
export fn mobile_vpn_destroy(handle: MobileVpnHandle) void {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return));

    // Disconnect if still connected
    if (ctx.status == .MOBILE_VPN_CONNECTED or ctx.status == .MOBILE_VPN_CONNECTING) {
        _ = mobile_vpn_disconnect(handle);
    }

    // Clean up SoftEther client
    if (ctx.client) |client| {
        c.CiFreeClient(client);
    }
    if (ctx.account) |account| {
        c.Free(account);
    }

    // Free strings
    ctx.allocator.free(ctx.server);
    ctx.allocator.free(ctx.hub);
    ctx.allocator.free(ctx.username);
    ctx.allocator.free(ctx.password_hash);
    if (ctx.error_msg.len > 0) {
        ctx.allocator.free(ctx.error_msg);
    }

    ctx.allocator.destroy(ctx);
}

/// Connect to VPN server
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_connect(handle: MobileVpnHandle) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    if (ctx.status == .MOBILE_VPN_CONNECTED or ctx.status == .MOBILE_VPN_CONNECTING) {
        return -2; // Already connected/connecting
    }

    ctx.setStatus(.MOBILE_VPN_CONNECTING);
    ctx.start_time = std.time.milliTimestamp();

    // Start connection using SoftEther C API
    const client = ctx.client orelse return -1;
    const account = ctx.account orelse return -1;

    // Set the account in the client
    const result = c.CiSetAccount(client, account);
    if (result == 0) {
        ctx.setError("Failed to set account");
        return -3;
    }

    // Connect
    const connect_result = c.CiConnectToAccount(client, account);
    if (connect_result == 0) {
        ctx.setError("Failed to connect");
        return -4;
    }

    ctx.setStatus(.MOBILE_VPN_CONNECTED);

    // Get network info and call callback
    if (ctx.network_callback) |callback| {
        var net_info: MobileNetworkInfo = .{};
        const info_result = mobile_vpn_get_network_info(handle, &net_info);
        if (info_result == 0) {
            callback(&net_info, ctx.user_data);
        }
    }

    return 0;
}

/// Disconnect from VPN server
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_disconnect(handle: MobileVpnHandle) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    if (ctx.status == .MOBILE_VPN_DISCONNECTED) {
        return 0; // Already disconnected
    }

    // Disconnect using SoftEther C API
    if (ctx.client) |client| {
        c.CiDisconnect(client);
    }

    ctx.setStatus(.MOBILE_VPN_DISCONNECTED);
    ctx.start_time = 0;

    return 0;
}

/// Get current VPN status
export fn mobile_vpn_get_status(handle: MobileVpnHandle) MobileVpnStatus {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return .MOBILE_VPN_ERROR));
    return ctx.status;
}

/// Get VPN statistics
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_get_stats(handle: MobileVpnHandle, out_stats: ?*MobileVpnStats) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));
    const stats = out_stats orelse return -2;

    ctx.updateStats();
    stats.* = ctx.stats;

    return 0;
}

/// Read packet from VPN (to write to TUN device)
/// Returns number of bytes read, 0 if no packet available, negative on error
export fn mobile_vpn_read_packet(handle: MobileVpnHandle, buffer: [*]u8, buffer_len: u64, timeout_ms: u32) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    if (ctx.status != .MOBILE_VPN_CONNECTED) {
        return -2; // Not connected
    }

    // Read from SoftEther session
    const client = ctx.client orelse return -1;
    if (client.Session == null) {
        return 0; // No session yet
    }

    // Use packet adapter to read
    // TODO: Implement actual packet reading via session
    _ = timeout_ms;
    _ = buffer_len;
    _ = buffer;

    return 0; // No packets yet (stub)
}

/// Write packet to VPN (from TUN device)
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_write_packet(handle: MobileVpnHandle, data: [*]const u8, data_len: u64) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));

    if (ctx.status != .MOBILE_VPN_CONNECTED) {
        return -2; // Not connected
    }

    // Write to SoftEther session
    const client = ctx.client orelse return -1;
    if (client.Session == null) {
        return -2; // No session yet
    }

    // Use packet adapter to write
    // TODO: Implement actual packet writing via session
    _ = data;

    ctx.stats.bytes_sent += data_len;
    ctx.stats.packets_sent += 1;

    return 0; // Success (stub)
}

/// Get network configuration (after DHCP completes)
/// Returns 0 on success, negative error code on failure
export fn mobile_vpn_get_network_info(handle: MobileVpnHandle, out_info: ?*MobileNetworkInfo) c_int {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return -1));
    const info = out_info orelse return -2;

    // Get network info from SoftEther session
    const client = ctx.client orelse return -1;
    const session = client.Session orelse return -3; // No session yet

    // Get DHCP-assigned IP from session
    if (session.ClientIP != 0) {
        const ip = session.ClientIP;
        info.ip_address[0] = @intCast((ip >> 0) & 0xFF);
        info.ip_address[1] = @intCast((ip >> 8) & 0xFF);
        info.ip_address[2] = @intCast((ip >> 16) & 0xFF);
        info.ip_address[3] = @intCast((ip >> 24) & 0xFF);
    }

    // Get gateway
    if (session.DefaultGateway != 0) {
        const gw = session.DefaultGateway;
        info.gateway[0] = @intCast((gw >> 0) & 0xFF);
        info.gateway[1] = @intCast((gw >> 8) & 0xFF);
        info.gateway[2] = @intCast((gw >> 16) & 0xFF);
        info.gateway[3] = @intCast((gw >> 24) & 0xFF);
    }

    // Get netmask
    if (session.ClientMask != 0) {
        const mask = session.ClientMask;
        info.netmask[0] = @intCast((mask >> 0) & 0xFF);
        info.netmask[1] = @intCast((mask >> 8) & 0xFF);
        info.netmask[2] = @intCast((mask >> 16) & 0xFF);
        info.netmask[3] = @intCast((mask >> 24) & 0xFF);
    }

    // MTU
    info.mtu = 1500; // Default

    return 0;
}

/// Set status callback
export fn mobile_vpn_set_status_callback(
    handle: MobileVpnHandle,
    callback: MobileStatusCallback,
    user_data: ?*anyopaque,
) void {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return));
    ctx.status_callback = callback;
    ctx.user_data = user_data;
}

/// Set statistics callback
export fn mobile_vpn_set_stats_callback(
    handle: MobileVpnHandle,
    callback: MobileStatsCallback,
    user_data: ?*anyopaque,
) void {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return));
    ctx.stats_callback = callback;
    ctx.user_data = user_data;
}

/// Set network info callback
export fn mobile_vpn_set_network_callback(
    handle: MobileVpnHandle,
    callback: MobileNetworkCallback,
    user_data: ?*anyopaque,
) void {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return));
    ctx.network_callback = callback;
    ctx.user_data = user_data;
}

/// Get last error message
/// Returns error string (valid until next error)
export fn mobile_vpn_get_error(handle: MobileVpnHandle) [*:0]const u8 {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return "Invalid handle"));
    return ctx.error_msg.ptr;
}

/// Check if VPN is connected
export fn mobile_vpn_is_connected(handle: MobileVpnHandle) bool {
    const ctx: *MobileVpnContext = @ptrCast(@alignCast(handle orelse return false));
    return ctx.status == .MOBILE_VPN_CONNECTED;
}

/// Cleanup library resources
export fn mobile_vpn_cleanup() void {
    g_init_mutex.lock();
    defer g_init_mutex.unlock();

    if (!g_initialized) {
        return;
    }

    // Cleanup Cedar and Mayaqua
    c.FreeCedar();
    c.FreeMayaqua();

    g_initialized = false;
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get version string
export fn mobile_vpn_get_version() [*:0]const u8 {
    return "SoftEtherZig Mobile v1.0.0";
}

/// Get build info string
export fn mobile_vpn_get_build_info() [*:0]const u8 {
    return switch (builtin.os.tag) {
        .ios => "SoftEtherZig iOS ARM64 " ++ builtin.zig_version_string,
        .macos => "SoftEtherZig macOS ARM64 " ++ builtin.zig_version_string,
        .linux => "SoftEtherZig Linux x86_64 " ++ builtin.zig_version_string,
        else => "SoftEtherZig " ++ builtin.zig_version_string,
    };
}
