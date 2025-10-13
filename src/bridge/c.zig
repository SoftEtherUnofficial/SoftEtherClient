// Wave 4 Phase 3: C FFI Bindings for SoftEther
// This module provides Zig bindings to SoftEther's C API

const std = @import("std");

// ============================================
// SoftEther Core Types
// ============================================

/// Opaque pointer types for SoftEther structures
pub const CLIENT = opaque {};
pub const ACCOUNT = opaque {};
pub const SESSION = opaque {};
pub const CLIENT_OPTION = opaque {};
pub const CLIENT_AUTH = opaque {};

// Helper functions to get C struct sizes
extern "c" fn sizeof_CLIENT_OPTION() usize;
extern "c" fn sizeof_CLIENT_AUTH() usize;

pub fn sizeofClientOption() usize {
    return sizeof_CLIENT_OPTION();
}

pub fn sizeofClientAuth() usize {
    return sizeof_CLIENT_AUTH();
}

// Helper functions to set string fields safely
extern "c" fn set_client_option_hostname(opt: *anyopaque, hostname: [*:0]const u8) void;
extern "c" fn set_client_option_hubname(opt: *anyopaque, hubname: [*:0]const u8) void;
extern "c" fn set_client_option_devicename(opt: *anyopaque, devicename: [*:0]const u8) void;
extern "c" fn set_client_auth_username(auth: *anyopaque, username: [*:0]const u8) void;

// CLIENT_AUTH setters from session_helper.c
extern "c" fn SetClientAuthType(auth: *CLIENT_AUTH, auth_type: c_uint) void;
extern "c" fn SetClientAuthHashedPassword(auth: *CLIENT_AUTH, hashed_password: [*]const u8, len: c_uint) void;

// CLIENT_OPTION setters from session_helper.c
extern "c" fn SetClientOptionNumRetry(opt: *CLIENT_OPTION, num_retry: c_uint) void;
extern "c" fn SetClientOptionRetryInterval(opt: *CLIENT_OPTION, interval: c_uint) void;
extern "c" fn SetClientOptionPort(opt: *CLIENT_OPTION, port: c_uint) void;
extern "c" fn SetClientOptionPortUDP(opt: *CLIENT_OPTION, port_udp: c_uint) void;
extern "c" fn SetClientOptionMaxConnection(opt: *CLIENT_OPTION, max_conn: c_uint) void;
extern "c" fn SetClientOptionFlags(opt: *CLIENT_OPTION, use_encrypt: bool, use_compress: bool, half_connection: bool, no_routing_tracking: bool, no_udp_accel: bool, disable_qos: bool, require_bridge_routing: bool) void;

pub fn setClientOptionHostname(opt: *CLIENT_OPTION, hostname: []const u8) void {
    // hostname should already be null-terminated from sliceTo
    const hostname_z: [*:0]const u8 = @ptrCast(hostname.ptr);
    set_client_option_hostname(opt, hostname_z);
}

pub fn setClientOptionHubname(opt: *CLIENT_OPTION, hubname: []const u8) void {
    const hubname_z: [*:0]const u8 = @ptrCast(hubname.ptr);
    set_client_option_hubname(opt, hubname_z);
}

pub fn setClientOptionDevicename(opt: *CLIENT_OPTION, devicename: []const u8) void {
    const devicename_z: [*:0]const u8 = @ptrCast(devicename.ptr);
    set_client_option_devicename(opt, devicename_z);
}

pub fn setClientAuthUsername(auth: *CLIENT_AUTH, username: []const u8) void {
    const username_z: [*:0]const u8 = @ptrCast(username.ptr);
    set_client_auth_username(auth, username_z);
}

// Wrapper functions for CLIENT_AUTH field setters
pub fn setClientAuthType(auth: *CLIENT_AUTH, auth_type: u32) void {
    SetClientAuthType(auth, auth_type);
}

pub fn setClientAuthHashedPassword(auth: *CLIENT_AUTH, hashed_password: []const u8) void {
    if (hashed_password.len == 20) {
        SetClientAuthHashedPassword(auth, hashed_password.ptr, 20);
    }
}

// Wrapper functions for CLIENT_OPTION field setters
pub fn setClientOptionNumRetry(opt: *CLIENT_OPTION, num_retry: u32) void {
    SetClientOptionNumRetry(opt, num_retry);
}

pub fn setClientOptionRetryInterval(opt: *CLIENT_OPTION, interval: u32) void {
    SetClientOptionRetryInterval(opt, interval);
}

pub fn setClientOptionPort(opt: *CLIENT_OPTION, port: u32) void {
    SetClientOptionPort(opt, port);
}

pub fn setClientOptionPortUDP(opt: *CLIENT_OPTION, port_udp: u32) void {
    SetClientOptionPortUDP(opt, port_udp);
}

pub fn setClientOptionMaxConnection(opt: *CLIENT_OPTION, max_conn: u32) void {
    SetClientOptionMaxConnection(opt, max_conn);
}

pub fn setClientOptionFlags(opt: *CLIENT_OPTION, use_encrypt: bool, use_compress: bool, half_connection: bool, no_routing_tracking: bool, no_udp_accel: bool, disable_qos: bool, require_bridge_routing: bool) void {
    SetClientOptionFlags(opt, use_encrypt, use_compress, half_connection, no_routing_tracking, no_udp_accel, disable_qos, require_bridge_routing);
}

pub const PACKET_ADAPTER = opaque {};
pub const CEDAR = opaque {};
pub const LOCK = opaque {};
pub const IPC = opaque {};
pub const DHCPV4_DATA = opaque {};
pub const IP = opaque {};

// ============================================
// Authentication Types
// ============================================

/// Client authentication type (matches Cedar.h CLIENT_AUTHTYPE_*)
pub const ClientAuthType = enum(c_uint) {
    ANONYMOUS = 0,
    PASSWORD = 1,
    PLAIN_PASSWORD = 2,
    CERT = 3,
    SECURE = 4,
};

// ============================================
// SoftEther C API Functions
// ============================================

// Client Management
extern "c" fn CiNewClient() ?*CLIENT;
extern "c" fn CiCleanupClient(client: *CLIENT) void;
extern "c" fn CiGetCedar(client: *CLIENT) ?*CEDAR;

// Session Management
extern "c" fn NewClientSessionEx(
    cedar: *CEDAR,
    option: *CLIENT_OPTION,
    auth: *CLIENT_AUTH,
    packet_adapter: *PACKET_ADAPTER,
    account: *ACCOUNT,
) ?*SESSION;

extern "c" fn CiGetSessionStatus(session: *SESSION, status: *c_uint) bool;
extern "c" fn StopSession(session: *SESSION) void;
extern "c" fn StopSessionEx(session: *SESSION, no_wait: bool) void;
extern "c" fn ReleaseSession(session: *SESSION) void;

// Session helper functions (from session_helper.c)
extern "c" fn GetSessionClientStatus(session: *SESSION) c_uint;
extern "c" fn GetSessionHalt(session: *SESSION) bool;
extern "c" fn IsSessionLockInitialized(session: *SESSION) bool;

// DHCP and IPC Functions
extern "c" fn IPCSendDhcpRequest(
    ipc: *IPC,
    adapter: ?*anyopaque,
    transaction_id: u32,
    req: *anyopaque,
    opcode: u32,
    timeout: u32,
    tube: ?*anyopaque,
) ?*DHCPV4_DATA;
extern "c" fn FreeDHCPv4Data(data: *DHCPV4_DATA) void;
extern "c" fn IPToUINT(ip: *IP) u32;
extern "c" fn UINTToIP(ip: *IP, value: u32) void;

// Memory Management
extern "c" fn ZeroMalloc(size: usize) ?*anyopaque;
extern "c" fn Free(ptr: *anyopaque) void;

// Locking
extern "c" fn NewLock() ?*LOCK;
extern "c" fn DeleteLock(lock: *LOCK) void;
extern "c" fn Lock(lock: *LOCK) void;
extern "c" fn Unlock(lock: *LOCK) void;

// String Functions
extern "c" fn StrCpy(dst: [*c]u8, size: c_uint, src: [*c]const u8) void;
extern "c" fn UniStrCpy(dst: [*c]u16, size: c_uint, src: [*c]const u16) void;
extern "c" fn StrLen(str: [*c]const u8) c_uint;

// Password Hashing
extern "c" fn HashPassword(dst: [*c]u8, username: [*c]const u8, password: [*c]const u8) void;

// Base64
extern "c" fn B64_Decode(dst: [*c]u8, src: [*c]const u8, src_size: c_uint) c_int;
extern "c" fn B64_Encode(dst: [*c]u8, src: [*c]const u8, src_size: c_uint) c_uint;

// Packet Adapter
extern "c" fn NewZigPacketAdapter() ?*PACKET_ADAPTER;
extern "c" fn FreePacketAdapter(pa: *PACKET_ADAPTER) void;

// Zig Adapter Device Info
extern "c" fn zig_adapter_get_device_name(
    adapter: *anyopaque,
    buffer: [*]u8,
    buffer_size: usize,
) usize;

// Security (from security_utils.h)
extern "c" fn secure_lock_memory(ptr: *anyopaque, size: usize) c_int;
extern "c" fn secure_unlock_memory(ptr: *anyopaque, size: usize) c_int;
extern "c" fn secure_zero_explicit(ptr: *anyopaque, size: usize) void;

// ============================================
// CLIENT_OPTION Structure
// ============================================

/// Client connection options (must match C struct layout)
pub const ClientOption = extern struct {
    AccountName: [256]u16, // wchar_t[MAX_ACCOUNT_NAME_LEN + 1]
    Hostname: [256]u8, // char[MAX_HOST_NAME_LEN + 1]
    Port: u32, // UINT
    HubName: [256]u8, // char[MAX_HUBNAME_LEN + 1]
    DeviceName: [256]u8, // char[MAX_DEVICE_NAME_LEN + 1]
    PortUDP: u32, // UINT - 0 = TCP only
    MaxConnection: u32, // UINT
    UseEncrypt: bool, // BOOL
    UseCompress: bool, // BOOL
    HalfConnection: bool, // BOOL
    NoRoutingTracking: bool, // BOOL
    NumRetry: u32, // UINT
    RetryInterval: u32, // UINT
    AdditionalConnectionInterval: u32, // UINT
    NoUdpAcceleration: bool, // BOOL
    DisableQoS: bool, // BOOL
    RequireBridgeRoutingMode: bool, // BOOL

    // Add padding to match C struct size (simplified version)
    _padding: [512]u8,
};

// ============================================
// CLIENT_AUTH Structure
// ============================================

/// Client authentication (must match C struct layout)
pub const ClientAuth = extern struct {
    AuthType: c_uint, // UINT (ClientAuthType)
    Username: [256]u8, // char[MAX_USERNAME_LEN + 1]
    HashedPassword: [20]u8, // UCHAR[SHA1_SIZE] - SHA1 hash of password
    PlainPassword: [256]u8, // char[MAX_PASSWORD_LEN + 1] - unused

    // Add padding to match C struct size
    _padding: [512]u8,
};

// ============================================
// ACCOUNT Structure
// ============================================

/// Account structure (must match C struct layout)
pub const AccountStruct = extern struct {
    lock: ?*LOCK,
    ClientOption: ?*CLIENT_OPTION,
    ClientAuth: ?*CLIENT_AUTH,
    CheckServerCert: bool,
    ServerCert: ?*anyopaque, // X *
    ClientSession: ?*SESSION,

    // Add padding
    _padding: [512]u8,
};

// ============================================
// DHCP Information Structure
// ============================================

/// DHCP information (must match C VpnBridgeDhcpInfo)
pub const DhcpInfo = extern struct {
    client_ip: u32, // Client IP address (network byte order)
    subnet_mask: u32, // Subnet mask (network byte order)
    gateway: u32, // Default gateway (network byte order)
    dns_server1: u32, // Primary DNS server (network byte order)
    dns_server2: u32, // Secondary DNS server (network byte order)
    dhcp_server: u32, // DHCP server address (network byte order)
    lease_time: u32, // Lease time in seconds
    domain_name: [256]u8, // Domain name
    valid: u32, // Whether DHCP info is valid (0 = FALSE, 1 = TRUE)
};

// ============================================
// Zig Wrapper Functions
// ============================================

/// Create a new SoftEther CLIENT
pub fn createClient() !*CLIENT {
    const client = CiNewClient() orelse return error.ClientCreationFailed;
    return client;
}

/// Free a SoftEther CLIENT
/// Create a new CLIENT
pub fn newClient() !*CLIENT {
    const client = CiNewClient() orelse return error.ClientCreationFailed;
    return client;
}

/// Free a CLIENT (cleanup first, then free memory)
pub fn freeClient(client: *CLIENT) void {
    CiCleanupClient(client);
    free(client);
}

/// Get CEDAR from CLIENT
pub fn getCedar(client: *CLIENT) !*CEDAR {
    const cedar = CiGetCedar(client) orelse return error.CedarNotFound;
    return cedar;
}

/// Create a new VPN session
pub fn createSession(
    cedar: *CEDAR,
    option: *CLIENT_OPTION,
    auth: *CLIENT_AUTH,
    packet_adapter: *PACKET_ADAPTER,
    account: *ACCOUNT,
) !*SESSION {
    const session = NewClientSessionEx(cedar, option, auth, packet_adapter, account) orelse return error.SessionCreationFailed;
    return session;
}

/// Stop a VPN session (graceful shutdown)
pub fn stopSession(session: *SESSION) void {
    StopSession(session);
}

/// Stop a VPN session with optional no-wait flag
pub fn stopSessionEx(session: *SESSION, no_wait: bool) void {
    StopSessionEx(session, no_wait);
}

/// Release a VPN session (free resources)
pub fn releaseSession(session: *SESSION) void {
    ReleaseSession(session);
}

/// Get session status (direct field access - safe during initialization)
pub fn getSessionStatus(session: *SESSION) u32 {
    // Use C helper function that properly accesses session->ClientStatus with lock
    return GetSessionClientStatus(session);
}

/// Check if session should halt
pub fn getSessionHalt(session: *SESSION) bool {
    // Use C helper function that properly accesses session->Halt with lock
    return GetSessionHalt(session);
}

/// Check if session lock is initialized (safe to access other fields)
pub fn isSessionLockInitialized(session: *SESSION) bool {
    return IsSessionLockInitialized(session);
}

/// Allocate zero-initialized memory
pub fn zeroMalloc(size: usize) !*anyopaque {
    const ptr = ZeroMalloc(size) orelse return error.AllocationFailed;
    return ptr;
}

/// Free allocated memory
pub fn free(ptr: *anyopaque) void {
    Free(ptr);
}

/// Create a new lock
pub fn newLock() !*LOCK {
    const lock = NewLock() orelse return error.LockCreationFailed;
    return lock;
}

/// Delete a lock
pub fn deleteLock(lock: *LOCK) void {
    DeleteLock(lock);
}

/// Copy string (C-style)
pub fn strCpy(dst: []u8, src: []const u8) void {
    const src_ptr: [*c]const u8 = @ptrCast(src.ptr);
    const dst_ptr: [*c]u8 = @ptrCast(dst.ptr);
    StrCpy(dst_ptr, @intCast(dst.len), src_ptr);
}

/// Hash password using SoftEther's method
pub fn hashPassword(dst: []u8, username: []const u8, password: []const u8) void {
    std.debug.assert(dst.len >= 20); // SHA1 = 20 bytes

    const dst_ptr: [*c]u8 = @ptrCast(dst.ptr);
    const username_ptr: [*c]const u8 = @ptrCast(username.ptr);
    const password_ptr: [*c]const u8 = @ptrCast(password.ptr);

    HashPassword(dst_ptr, username_ptr, password_ptr);
}

/// Decode base64
pub fn base64Decode(dst: []u8, src: []const u8) !usize {
    const dst_ptr: [*c]u8 = @ptrCast(dst.ptr);
    const src_ptr: [*c]const u8 = @ptrCast(src.ptr);

    const result = B64_Decode(dst_ptr, src_ptr, @intCast(src.len));
    if (result < 0) return error.Base64DecodeFailed;

    return @intCast(result);
}

/// Create Zig packet adapter
pub fn createZigPacketAdapter() !*PACKET_ADAPTER {
    const pa = NewZigPacketAdapter() orelse return error.PacketAdapterCreationFailed;
    return pa;
}

/// Free packet adapter
pub fn freePacketAdapter(pa: *PACKET_ADAPTER) void {
    FreePacketAdapter(pa);
}

/// Get device name from Zig adapter
pub fn zigAdapterGetDeviceName(adapter: *anyopaque, buffer: []u8) usize {
    return zig_adapter_get_device_name(adapter, buffer.ptr, buffer.len);
}

// ============================================================================
// SoftEther Initialization Functions
// ============================================================================

extern "c" fn MayaquaMinimalMode() void;
extern "c" fn InitMayaqua(memcheck: bool, debug: bool, argc: c_int, argv: [*c][*c]u8) void;
extern "c" fn InitCedar() void;
extern "c" fn FreeCedar() void;
extern "c" fn FreeMayaqua() void;

pub fn setMinimalMode() void {
    MayaquaMinimalMode();
}

pub fn initMayaqua(memcheck: bool, debug: bool) void {
    // Provide a simple executable name
    var fake_argv = [_][*c]u8{ @constCast("vpnclient".ptr), null };
    InitMayaqua(memcheck, debug, 1, &fake_argv);
}

pub fn initCedar() void {
    InitCedar();
}

pub fn freeCedar() void {
    FreeCedar();
}

pub fn freeMayaqua() void {
    FreeMayaqua();
}

/// Lock memory (prevent swapping)
pub fn lockMemory(ptr: *anyopaque, size: usize) !void {
    const result = secure_lock_memory(ptr, size);
    if (result != 0) return error.MemoryLockFailed;
}

/// Unlock memory
pub fn unlockMemory(ptr: *anyopaque, size: usize) !void {
    const result = secure_unlock_memory(ptr, size);
    if (result != 0) return error.MemoryUnlockFailed;
}

/// Securely zero memory
pub fn secureZero(ptr: *anyopaque, size: usize) void {
    secure_zero_explicit(ptr, size);
}

// ============================================
// Helper Functions
// ============================================

/// Create CLIENT_OPTION with defaults
pub fn createClientOption(allocator: std.mem.Allocator) !*CLIENT_OPTION {
    _ = allocator;
    const opt_ptr = try zeroMalloc(@sizeOf(ClientOption));
    return @ptrCast(@alignCast(opt_ptr));
}

/// Create CLIENT_AUTH with defaults
pub fn createClientAuth(allocator: std.mem.Allocator) !*CLIENT_AUTH {
    _ = allocator;
    const auth_ptr = try zeroMalloc(@sizeOf(ClientAuth));
    return @ptrCast(@alignCast(auth_ptr));
}

/// Create ACCOUNT with defaults
pub fn createAccount(allocator: std.mem.Allocator) !*ACCOUNT {
    _ = allocator;
    const account_ptr = try zeroMalloc(@sizeOf(AccountStruct));
    const account: *AccountStruct = @ptrCast(@alignCast(account_ptr));

    // Initialize lock
    account.lock = try newLock();
    account.CheckServerCert = false;
    account.ServerCert = null;
    account.ClientSession = null;

    return @ptrCast(account_ptr);
}

// ============================================
// Tests
// ============================================

test "C FFI - client creation" {
    // This test requires SoftEther libraries to be initialized
    // Skipping for now, will test in integration tests
}

test "C FFI - memory allocation" {
    const ptr = try zeroMalloc(256);
    defer free(ptr);

    // Verify memory is zeroed
    const bytes: [*]u8 = @ptrCast(ptr);
    try std.testing.expectEqual(@as(u8, 0), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0), bytes[255]);
}
