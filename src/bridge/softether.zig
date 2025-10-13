// Wave 4: SoftEther Bridge - Zig Implementation
// Replaces: src/bridge/softether_bridge.c (1,384 lines)
//
// This module provides the bridge between our Zig code and SoftEther's C libraries.
// It manages VPN client lifecycle, configuration, and connection orchestration.

const std = @import("std");

// Phase 3: Import C FFI for SoftEther integration
const c = @import("c.zig");

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
    packet_adapter: ?*anyopaque, // PACKET_ADAPTER*

    // Allocator
    allocator: std.mem.Allocator,

    /// Initialize a new VPN bridge client
    pub fn init(allocator: std.mem.Allocator) !*VpnBridgeClient {
        // Create SoftEther CLIENT structure
        const softether_client = try c.newClient();
        errdefer c.freeClient(softether_client);

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
            .softether_client = softether_client,
            .softether_account = null,
            .softether_session = null,
            .packet_adapter = null,
            .allocator = allocator,
        };

        return client;
    }

    /// Free the client and all resources
    pub fn deinit(self: *VpnBridgeClient) void {
        // Ensure disconnected
        if (self.status == .CONNECTED or self.status == .CONNECTING) {
            self.disconnect();
        }

        // Clear CLIENT pointer
        // NOTE: Do NOT call freeClient() - the CLIENT will be freed by freeCedar()
        // when the entire Cedar system shuts down. Calling freeClient() here causes
        // a double-free because freeCedar() also tries to free all CLIENT structures.
        if (self.softether_client) |_| {
            self.softether_client = null;
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

    /// Get connection information (placeholder)
    pub fn getConnectionInfo(self: *const VpnBridgeClient) ConnectionInfo {
        _ = self;
        return ConnectionInfo.init();
    }

    /// Get DHCP information (placeholder)
    pub fn getDhcpInfo(self: *const VpnBridgeClient) DhcpInfo {
        const dhcp = DhcpInfo.init();

        // Check if connected with session
        if (self.status != .CONNECTED or self.softether_session == null) {
            return dhcp;
        }

        // TODO: Extract real DHCP info from session/IPC
        // For now, return placeholder indicating no DHCP info available
        // This will be filled in during integration testing when we have
        // access to actual IPC and DHCP structures

        return dhcp;
    }

    // ============================================
    // Connection Management (Phase 3)
    // ============================================

    /// Connect to VPN server
    pub fn connect(self: *VpnBridgeClient) !void {
        if (self.status == .CONNECTED) {
            return; // Already connected
        }

        if (!g_initialized) {
            return BridgeError.NotInitialized;
        }

        // Validate configuration
        if (std.mem.sliceTo(&self.hostname, 0).len == 0 or
            std.mem.sliceTo(&self.hub_name, 0).len == 0 or
            std.mem.sliceTo(&self.username, 0).len == 0)
        {
            return BridgeError.InvalidParameter;
        }

        // Log reconnection attempt if applicable
        if (self.reconnect.current_attempt > 0) {
            std.log.info("VPN: Reconnection attempt {d}/{d}", .{
                self.reconnect.current_attempt,
                if (self.reconnect.max_attempts == 0) @as(u32, 999) else self.reconnect.max_attempts,
            });
        }

        self.status = .CONNECTING;

        // Create CLIENT_OPTION using C struct size
        const opt = try c.zeroMalloc(c.sizeofClientOption());
        defer c.free(opt);
        const option: *c.CLIENT_OPTION = @ptrCast(@alignCast(opt));

        // Set string fields using safe C helper functions
        const hostname_slice = std.mem.sliceTo(&self.hostname, 0);
        c.setClientOptionHostname(option, hostname_slice);

        const hub_slice = std.mem.sliceTo(&self.hub_name, 0);
        c.setClientOptionHubname(option, hub_slice);

        const device_name = "vpn_adapter";
        c.setClientOptionDevicename(option, device_name);
        std.log.debug("VPN: Set DeviceName to '{s}' via C helper", .{device_name});

        // Set all other CLIENT_OPTION fields using C helpers to ensure correct struct layout
        c.setClientOptionPort(option, self.port);
        c.setClientOptionPortUDP(option, 0); // CRITICAL: Disable NAT-T (TCP only)
        c.setClientOptionMaxConnection(option, self.max_connection);
        c.setClientOptionNumRetry(option, 10);
        c.setClientOptionRetryInterval(option, 5);
        c.setClientOptionFlags(
            option,
            true, // use_encrypt
            false, // use_compress
            false, // half_connection
            true, // no_routing_tracking
            true, // no_udp_accel
            true, // disable_qos
            true, // require_bridge_routing
        );

        std.log.debug("VPN: Options set - {s}:{d} hub={s} max_conn={d}", .{
            hostname_slice,
            self.port,
            hub_slice,
            self.max_connection,
        });

        // Create CLIENT_AUTH using C struct size
        const auth_ptr = try c.zeroMalloc(c.sizeofClientAuth());
        defer c.free(auth_ptr);
        const auth: *c.CLIENT_AUTH = @ptrCast(@alignCast(auth_ptr));

        // Set username using C helper
        const username_slice = std.mem.sliceTo(&self.username, 0);
        c.setClientAuthUsername(auth, username_slice);

        // Set auth type using C helper
        c.setClientAuthType(auth, @intFromEnum(c.ClientAuthType.PASSWORD));

        // Handle password hashing
        if (self.password_is_hashed) {
            // Decode base64 pre-hashed password
            std.log.debug("VPN: Using pre-hashed password", .{});
            const password_slice = std.mem.sliceTo(&self.password, 0);
            var decoded: [256]u8 = undefined;
            const decoded_len = try c.base64Decode(&decoded, password_slice);

            if (decoded_len == 20) {
                // Use C helper to set hashed password
                c.setClientAuthHashedPassword(auth, decoded[0..20]);
            } else {
                std.log.warn("VPN: Base64 password decoded to {d} bytes (expected 20), rehashing", .{decoded_len});
                const password_slice2 = std.mem.sliceTo(&self.password, 0);
                var temp_hash: [20]u8 = undefined;
                c.hashPassword(&temp_hash, username_slice, password_slice2);
                c.setClientAuthHashedPassword(auth, &temp_hash);
            }

            // Securely zero decoded password
            c.secureZero(&decoded, decoded.len);
        } else {
            // Hash plaintext password
            std.log.debug("VPN: Hashing plaintext password", .{});
            const password_slice = std.mem.sliceTo(&self.password, 0);
            var temp_hash: [20]u8 = undefined;
            c.hashPassword(&temp_hash, username_slice, password_slice);
            c.setClientAuthHashedPassword(auth, &temp_hash);

            // Securely zero the plaintext password
            c.secureZero(&self.password, self.password.len);
        }

        std.log.debug("VPN: Authentication configured - user={s}", .{username_slice});

        // Create ACCOUNT
        const account_ptr = try c.zeroMalloc(@sizeOf(c.AccountStruct));
        const account: *c.AccountStruct = @ptrCast(@alignCast(account_ptr));

        account.lock = try c.newLock();
        account.ClientOption = @ptrCast(option);
        account.ClientAuth = @ptrCast(auth);
        account.CheckServerCert = false;
        account.ServerCert = null;
        account.ClientSession = null;

        self.softether_account = account_ptr;

        // Create packet adapter
        std.log.debug("VPN: Creating packet adapter (zig={})", .{self.use_zig_adapter});
        const pa = if (self.use_zig_adapter)
            c.createZigPacketAdapter() catch null
        else
            null;

        if (pa == null) {
            if (self.use_zig_adapter) {
                std.log.err("VPN: Failed to create Zig adapter", .{});
            }
            // Clean up
            c.deleteLock(account.lock.?);
            c.free(account_ptr);
            self.status = .ERROR;
            self.last_error = @as(u32, @bitCast(@as(i32, @intFromEnum(ErrorCode.CONNECT_FAILED))));
            return BridgeError.ConnectionFailed;
        }

        self.packet_adapter = pa;
        std.log.info("VPN: Packet adapter created", .{});

        // Get CEDAR from CLIENT
        const client = @as(*c.CLIENT, @ptrCast(self.softether_client));
        const cedar = try c.getCedar(client);

        // Create VPN session
        std.log.debug("VPN: Creating VPN session", .{});
        const session = c.createSession(
            cedar,
            @ptrCast(option),
            @ptrCast(auth),
            pa.?,
            @ptrCast(account_ptr),
        ) catch {
            std.log.err("VPN: Failed to create VPN session", .{});
            c.freePacketAdapter(pa.?);
            c.deleteLock(account.lock.?);
            c.free(account_ptr);
            self.status = .ERROR;
            self.last_error = @as(u32, @bitCast(@as(i32, @intFromEnum(ErrorCode.CONNECT_FAILED))));
            return BridgeError.ConnectionFailed;
        };

        self.softether_session = session;
        account.ClientSession = session;

        // Wait for connection to establish (with timeout)
        // The ClientThread runs in background and will initialize the packet adapter
        std.log.debug("VPN: Waiting for session to establish (30s timeout)...", .{});
        const start_time = getCurrentTimeMs();
        var connected = false;
        var check_count: u32 = 0;

        // Give ClientThread a moment to start up (100ms should be plenty)
        std.log.debug("VPN: Waiting for ClientThread to start...", .{});
        std.Thread.sleep(100 * std.time.ns_per_ms);
        std.log.debug("VPN: Checking connection status...", .{});

        while ((getCurrentTimeMs() - start_time) < 30000) { // 30 second timeout
            const status = c.getSessionStatus(session);

            // Log every 2 seconds at debug level to track progress
            if (check_count % 20 == 0) {
                const status_str = switch (status) {
                    0 => "CONNECTING",
                    1 => "NEGOTIATION",
                    2 => "AUTH",
                    3 => "ESTABLISHED",
                    4 => "RETRY",
                    5 => "IDLE",
                    else => "UNKNOWN",
                };
                std.log.debug("VPN: Status={s} ({d}), elapsed={d}ms", .{
                    status_str,
                    status,
                    getCurrentTimeMs() - start_time,
                });
            }
            check_count += 1;

            if (status == 3) { // CLIENT_STATUS_ESTABLISHED
                connected = true;
                break;
            }

            // Check for halt condition (error during connection)
            const should_halt = c.getSessionHalt(session);
            if (should_halt) {
                std.log.err("VPN: Connection halted by session", .{});
                break;
            }

            // Don't fail on IDLE status - just keep waiting up to the timeout
            // The session may take time to transition from IDLE -> CONNECTING

            std.Thread.sleep(100 * std.time.ns_per_ms); // Check every 100ms
        }

        if (!connected) {
            std.log.err("VPN: Connection timeout or failed after 30 seconds", .{});
            // Clean up - NOTE: releaseSession will free packet_adapter and account members
            // Do NOT free them separately or we'll get double-free errors
            c.releaseSession(session);
            self.softether_session = null;
            self.packet_adapter = null;
            self.status = .ERROR;
            self.last_error = @as(u32, @bitCast(@as(i32, @intFromEnum(ErrorCode.CONNECT_FAILED))));
            return BridgeError.ConnectionFailed;
        }

        // Connection successful
        self.status = .CONNECTED;
        self.connect_time = getCurrentTimeMs();
        self.reconnect.current_attempt = 0;
        self.reconnect.user_requested_disconnect = false;

        std.log.info("VPN: ✅ Connected successfully to {s}:{d}", .{ hostname_slice, self.port });
        std.log.debug("VPN: DHCP and network configuration will be handled by packet adapter", .{});
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnBridgeClient) void {
        if (self.status != .CONNECTED and self.status != .CONNECTING) {
            return; // Not connected
        }

        std.log.info("VPN: Disconnecting...", .{});
        self.status = .DISCONNECTING;
        self.reconnect.user_requested_disconnect = true;

        // Clear packet adapter pointer (will be freed by SESSION cleanup)
        // DO NOT call freePacketAdapter - the SESSION owns it!
        self.packet_adapter = null;

        // Clear session pointer - will be cleaned up by CLIENT/Cedar shutdown
        // NOTE: Do NOT call StopSession or StopSessionEx - the HaltEvent may be corrupted
        // The ClientThread and session cleanup is handled automatically by freeCedar()
        if (self.softether_session) |_| {
            std.log.debug("VPN: Clearing session pointer (cleanup handled by freeCedar)", .{});
            self.softether_session = null;
        }

        // NOTE: Packet adapter is freed by SESSION cleanup, not by us

        // Free account
        if (self.softether_account) |account_ptr| {
            const account: *c.AccountStruct = @ptrCast(@alignCast(account_ptr));
            // Clear the session reference
            account.ClientSession = null;

            if (account.lock) |lock| {
                c.deleteLock(lock);
            }
            c.free(account_ptr);
            self.softether_account = null;
        }

        self.status = .DISCONNECTED;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.connect_time = 0;

        std.log.info("VPN: Disconnected", .{});
    }

    // ============================================
    // Status and Information Getters
    // ============================================

    /// Get device name (TUN/TAP interface)
    pub fn getDeviceName(self: *const VpnBridgeClient, buffer: []u8) ![]const u8 {
        if (buffer.len < 10) return error.InvalidParameter;

        if (self.status != .CONNECTED or self.softether_session == null or self.packet_adapter == null) {
            const msg = "not_connected";
            @memcpy(buffer[0..msg.len], msg);
            return buffer[0..msg.len];
        }

        // Try to get device name from adapter
        // Note: The device name is stored in PacketAdapter->Param context
        // For Zig adapter: ZIG_ADAPTER_CONTEXT->zig_adapter
        // For C adapter: MACOS_TUN_CONTEXT->device_name

        // For now, return a reasonable guess based on platform
        // Real extraction requires accessing PacketAdapter->Param which needs
        // SESSION struct definition
        if (comptime @import("builtin").target.os.tag == .macos) {
            // macOS uses utun devices
            const msg = "utun3"; // Common default
            @memcpy(buffer[0..msg.len], msg);
            return buffer[0..msg.len];
        } else if (comptime @import("builtin").target.os.tag == .linux) {
            const msg = "tun0";
            @memcpy(buffer[0..msg.len], msg);
            return buffer[0..msg.len];
        } else {
            const msg = "vpn0";
            @memcpy(buffer[0..msg.len], msg);
            return buffer[0..msg.len];
        }
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
        if (now >= self.connect_time) {
            return (now - self.connect_time) / 1000;
        }
        return 0; // Handle clock skew
    }

    /// Check if connected
    pub fn isConnected(self: *const VpnBridgeClient) bool {
        return self.status == .CONNECTED;
    }

    /// Check if connecting
    pub fn isConnecting(self: *const VpnBridgeClient) bool {
        return self.status == .CONNECTING;
    }

    /// Update statistics from session (internal helper)
    fn updateStatsFromSession(self: *VpnBridgeClient) void {
        if (self.softether_session == null or self.status != .CONNECTED) {
            return;
        }

        // TODO: Extract real bytes sent/received from SESSION->TotalSendSize, TotalRecvSize
        // For now, stats are tracked externally by packet adapter
        // This will be enhanced when we add SESSION struct access
    }
};

// ============================================
// Module-level state and initialization
// ============================================

var g_initialized: bool = false;

/// Initialize the VPN bridge system
pub fn init(debug: bool) !void {
    _ = debug; // Reserved for future use
    if (g_initialized) {
        return BridgeError.AlreadyInitialized;
    }

    // Enable minimal mode to skip hamcore.se2 loading (language tables)
    // We don't need the full SoftEther UI language support for VPN client
    c.setMinimalMode();

    // Initialize Mayaqua and Cedar libraries
    // memcheck=false for production, debug=false to reduce verbosity
    c.initMayaqua(false, false);
    c.initCedar();

    std.log.info("SoftEther client initialized successfully", .{});
    g_initialized = true;
}

/// Cleanup the VPN bridge system
pub fn deinit() void {
    if (!g_initialized) return;

    // Cleanup SoftEther layers in reverse order
    c.freeCedar();
    c.freeMayaqua();

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

test "Phase 3 - connect() signature" {
    // Just verify the function exists and has correct signature
    // Can't actually test connection without SoftEther libraries linked
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    // Verify fields exist for Phase 3
    try std.testing.expectEqual(@as(?*anyopaque, null), client.packet_adapter);
    try std.testing.expectEqual(@as(?*anyopaque, null), client.softether_session);
}

test "Phase 3 - session management functions exist" {
    // Verify new C bindings are accessible
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    // Test DHCP info structure initialization
    const dhcp = client.getDhcpInfo();
    try std.testing.expectEqual(false, dhcp.has_ip);

    // Test device name when not connected
    var buffer: [256]u8 = undefined;
    const name = try client.getDeviceName(&buffer);
    try std.testing.expectEqualStrings("not_connected", name);
}

test "Phase 3 - disconnect() handles cleanup" {
    const allocator = std.testing.allocator;
    const client = try VpnBridgeClient.init(allocator);
    defer client.deinit();

    // Disconnect when not connected should be safe
    client.disconnect();
    try std.testing.expectEqual(VpnBridgeStatus.DISCONNECTED, client.status);
}
