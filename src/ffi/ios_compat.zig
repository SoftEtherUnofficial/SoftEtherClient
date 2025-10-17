//! iOS-Compatible FFI Layer for SoftEtherClient
//!
//! This module provides the softether_client_* API that iOS PacketTunnelProvider expects.
//! It wraps the Zig packet adapter implementation with the Rust FFI-compatible interface.
//!
//! Architecture:
//!   iOS PacketTunnelProvider (Swift)
//!     ↓ (calls softether_client_* functions)
//!   iOS Compat FFI (this file)
//!     ↓ (wraps Zig adapter)
//!   Zig Packet Adapter → SoftEther VPN Client

const std = @import("std");
const builtin = @import("builtin");

// Forward declarations for Zig packet adapter
// These will be implemented in the actual adapter integration
const ZigPacketAdapter = opaque {};

// External adapter functions (to be linked)
extern fn zig_adapter_create_from_json(json: [*:0]const u8) ?*ZigPacketAdapter;
extern fn zig_adapter_destroy(adapter: *ZigPacketAdapter) void;
extern fn zig_adapter_connect(adapter: *ZigPacketAdapter) c_int;
extern fn zig_adapter_disconnect(adapter: *ZigPacketAdapter) c_int;
extern fn zig_adapter_send_frame(adapter: *ZigPacketAdapter, data: [*]const u8, len: u32) c_int;
extern fn zig_adapter_send_ip_packet(adapter: *ZigPacketAdapter, data: [*]const u8, len: u32) c_int;
extern fn zig_adapter_arp_add(adapter: *ZigPacketAdapter, ipv4_be: u32, mac: [*]const u8) c_int;
extern fn zig_adapter_get_mac(adapter: *ZigPacketAdapter, out_mac: [*]u8) c_int;
extern fn zig_adapter_get_network_settings_json(adapter: *ZigPacketAdapter) ?[*:0]u8;
extern fn zig_adapter_get_error(adapter: *ZigPacketAdapter) ?[*:0]const u8;

// ============================================================================
// Callback Types (matching Rust FFI)
// ============================================================================

pub const SoftEtherRxCallback = ?*const fn (data: [*]const u8, len: u32, user: ?*anyopaque) callconv(.c) void;
pub const SoftEtherIpRxCallback = ?*const fn (ip_packet: [*]const u8, len: u32, user: ?*anyopaque) callconv(.c) void;
pub const SoftEtherStateCallback = ?*const fn (state: c_int, user: ?*anyopaque) callconv(.c) void;
pub const SoftEtherEventCallback = ?*const fn (level: c_int, code: c_int, message: [*:0]const u8, user: ?*anyopaque) callconv(.c) void;

// ============================================================================
// Client Context
// ============================================================================

const SoftEtherClientContext = struct {
    allocator: std.mem.Allocator,
    adapter: *ZigPacketAdapter,

    // Callbacks
    rx_callback: SoftEtherRxCallback = null,
    ip_rx_callback: SoftEtherIpRxCallback = null,
    state_callback: SoftEtherStateCallback = null,
    event_callback: SoftEtherEventCallback = null,
    user_data_rx: ?*anyopaque = null,
    user_data_ip_rx: ?*anyopaque = null,
    user_data_state: ?*anyopaque = null,
    user_data_event: ?*anyopaque = null,

    // Error tracking
    last_error: ?[]u8 = null,

    fn setError(self: *SoftEtherClientContext, msg: []const u8) void {
        if (self.last_error) |old| {
            self.allocator.free(old);
        }
        self.last_error = self.allocator.dupe(u8, msg) catch null;
    }

    fn clearError(self: *SoftEtherClientContext) void {
        if (self.last_error) |old| {
            self.allocator.free(old);
            self.last_error = null;
        }
    }
};

// Global callback wrappers that forward to context callbacks
// These are registered with the adapter and then dispatch to Swift callbacks

export fn zig_rx_callback_wrapper(data: [*]const u8, len: u32, user: ?*anyopaque) callconv(.c) void {
    const ctx: *SoftEtherClientContext = @ptrCast(@alignCast(user orelse return));
    if (ctx.rx_callback) |cb| {
        cb(data, len, ctx.user_data_rx);
    }
}

export fn zig_ip_rx_callback_wrapper(ip_packet: [*]const u8, len: u32, user: ?*anyopaque) callconv(.c) void {
    const ctx: *SoftEtherClientContext = @ptrCast(@alignCast(user orelse return));
    if (ctx.ip_rx_callback) |cb| {
        cb(ip_packet, len, ctx.user_data_ip_rx);
    }
}

export fn zig_state_callback_wrapper(state: c_int, user: ?*anyopaque) callconv(.c) void {
    const ctx: *SoftEtherClientContext = @ptrCast(@alignCast(user orelse return));
    if (ctx.state_callback) |cb| {
        cb(state, ctx.user_data_state);
    }
}

export fn zig_event_callback_wrapper(level: c_int, code: c_int, message: [*:0]const u8, user: ?*anyopaque) callconv(.c) void {
    const ctx: *SoftEtherClientContext = @ptrCast(@alignCast(user orelse return));
    if (ctx.event_callback) |cb| {
        cb(level, code, message, ctx.user_data_event);
    }
}

// External callback registration functions for adapter
extern fn zig_adapter_set_rx_callback(adapter: *ZigPacketAdapter, cb: SoftEtherRxCallback, user: ?*anyopaque) c_int;
extern fn zig_adapter_set_ip_rx_callback(adapter: *ZigPacketAdapter, cb: SoftEtherIpRxCallback, user: ?*anyopaque) c_int;
extern fn zig_adapter_set_state_callback(adapter: *ZigPacketAdapter, cb: SoftEtherStateCallback, user: ?*anyopaque) c_int;
extern fn zig_adapter_set_event_callback(adapter: *ZigPacketAdapter, cb: SoftEtherEventCallback, user: ?*anyopaque) c_int;

// ============================================================================
// iOS-Compatible C API (softether_client_* functions)
// ============================================================================

/// Create a client from JSON config
/// Returns handle on success, null on failure
export fn softether_client_create(json_config: [*:0]const u8) ?*SoftEtherClientContext {
    const allocator = std.heap.c_allocator;

    const ctx = allocator.create(SoftEtherClientContext) catch return null;
    errdefer allocator.destroy(ctx);

    // Create Zig adapter from JSON
    const adapter = zig_adapter_create_from_json(json_config) orelse {
        allocator.destroy(ctx);
        return null;
    };

    ctx.* = .{
        .allocator = allocator,
        .adapter = adapter,
    };

    return ctx;
}

/// Connect to VPN server
/// Returns 0 on success, negative on error
export fn softether_client_connect(handle: ?*SoftEtherClientContext) c_int {
    const ctx = handle orelse return -1;
    return zig_adapter_connect(ctx.adapter);
}

/// Disconnect from VPN server
/// Returns 0 on success, negative on error
export fn softether_client_disconnect(handle: ?*SoftEtherClientContext) c_int {
    const ctx = handle orelse return -1;
    return zig_adapter_disconnect(ctx.adapter);
}

/// Free the client handle
export fn softether_client_free(handle: ?*SoftEtherClientContext) void {
    const ctx = handle orelse return;

    // Cleanup error buffer
    if (ctx.last_error) |err| {
        ctx.allocator.free(err);
    }

    // Destroy adapter
    zig_adapter_destroy(ctx.adapter);

    // Free context
    ctx.allocator.destroy(ctx);
}

/// Register RX callback for L2 frames
/// Returns 0 on success, negative on error
export fn softether_client_set_rx_callback(
    handle: ?*SoftEtherClientContext,
    cb: SoftEtherRxCallback,
    user: ?*anyopaque,
) c_int {
    const ctx = handle orelse return -1;
    ctx.rx_callback = cb;
    ctx.user_data_rx = user;

    // Register wrapper with adapter
    return zig_adapter_set_rx_callback(ctx.adapter, zig_rx_callback_wrapper, ctx);
}

/// Send L2 frame into the tunnel
/// Returns 1 on queued, 0 if no link, negative on error
export fn softether_client_send_frame(
    handle: ?*SoftEtherClientContext,
    data: [*]const u8,
    len: u32,
) c_int {
    const ctx = handle orelse return -1;
    return zig_adapter_send_frame(ctx.adapter, data, len);
}

/// Register IP RX callback for IPv4 packets (L3)
/// Returns 0 on success, negative on error
export fn softether_client_set_ip_rx_callback(
    handle: ?*SoftEtherClientContext,
    cb: SoftEtherIpRxCallback,
    user: ?*anyopaque,
) c_int {
    const ctx = handle orelse return -1;
    ctx.ip_rx_callback = cb;
    ctx.user_data_ip_rx = user;

    // Register wrapper with adapter
    return zig_adapter_set_ip_rx_callback(ctx.adapter, zig_ip_rx_callback_wrapper, ctx);
}

/// Send IPv4 packet
/// Returns 1 on queued, 0 if no link, negative on error
export fn softether_client_send_ip_packet(
    handle: ?*SoftEtherClientContext,
    data: [*]const u8,
    len: u32,
) c_int {
    const ctx = handle orelse return -1;
    return zig_adapter_send_ip_packet(ctx.adapter, data, len);
}

/// Add static ARP entry
/// Returns 0 on success, negative on error
export fn softether_client_arp_add(
    handle: ?*SoftEtherClientContext,
    ipv4_be: u32,
    mac: [*]const u8,
) c_int {
    const ctx = handle orelse return -1;
    return zig_adapter_arp_add(ctx.adapter, ipv4_be, mac);
}

/// Register state callback
/// State values: 0=Idle, 1=Connecting, 2=Established, 3=Disconnecting
/// Returns 0 on success, negative on error
export fn softether_client_set_state_callback(
    handle: ?*SoftEtherClientContext,
    cb: SoftEtherStateCallback,
    user: ?*anyopaque,
) c_int {
    const ctx = handle orelse return -1;
    ctx.state_callback = cb;
    ctx.user_data_state = user;

    // Register wrapper with adapter
    return zig_adapter_set_state_callback(ctx.adapter, zig_state_callback_wrapper, ctx);
}

/// Register event callback
/// Level: 0=info, 1=warn, 2=error
/// Returns 0 on success, negative on error
export fn softether_client_set_event_callback(
    handle: ?*SoftEtherClientContext,
    cb: SoftEtherEventCallback,
    user: ?*anyopaque,
) c_int {
    const ctx = handle orelse return -1;
    ctx.event_callback = cb;
    ctx.user_data_event = user;

    // Register wrapper with adapter
    return zig_adapter_set_event_callback(ctx.adapter, zig_event_callback_wrapper, ctx);
}

/// Get client version string
export fn softether_client_version() [*:0]const u8 {
    return "SoftEtherClient-Zig v1.0.0";
}

/// Free strings allocated by this library
export fn softether_string_free(str: ?[*:0]u8) void {
    if (str) |s| {
        const len = std.mem.len(s);
        const slice = s[0..len];
        std.heap.c_allocator.free(slice);
    }
}

/// Get and clear last error message
/// Returns null if no error. Caller must free with softether_string_free
export fn softether_client_last_error(handle: ?*SoftEtherClientContext) ?[*:0]u8 {
    const ctx = handle orelse return null;

    // Check adapter error first
    if (zig_adapter_get_error(ctx.adapter)) |adapter_err| {
        const len = std.mem.len(adapter_err);
        const owned = std.heap.c_allocator.dupeZ(u8, adapter_err[0..len]) catch return null;
        return owned.ptr;
    }

    // Check context error
    if (ctx.last_error) |err| {
        const owned = std.heap.c_allocator.dupeZ(u8, err) catch return null;
        ctx.allocator.free(err);
        ctx.last_error = null;
        return owned.ptr;
    }

    return null;
}

/// Get network settings as JSON
/// Returns JSON string or null. Caller must free with softether_string_free
export fn softether_client_get_network_settings_json(handle: ?*SoftEtherClientContext) ?[*:0]u8 {
    const ctx = handle orelse return null;
    return zig_adapter_get_network_settings_json(ctx.adapter);
}

/// Get client's source MAC address
/// Writes 6 bytes to out_mac. Returns 0 on success, negative on error
export fn softether_client_get_mac(handle: ?*SoftEtherClientContext, out_mac: [*]u8) c_int {
    const ctx = handle orelse return -1;
    return zig_adapter_get_mac(ctx.adapter, out_mac);
}

/// Base64 decode utility
/// Returns number of decoded bytes, or negative on error
export fn softether_b64_decode(b64: [*:0]const u8, out_buf: [*]u8, out_cap: c_uint) c_int {
    const input_len = std.mem.len(b64);
    const input_slice = b64[0..input_len];

    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(input_slice) catch return -1;

    if (decoded_len > out_cap) {
        return -2; // Buffer too small
    }

    const output_slice = out_buf[0..out_cap];
    decoder.decode(output_slice[0..decoded_len], input_slice) catch return -1;

    return @intCast(decoded_len);
}

// ============================================================================
// Version and Build Info
// ============================================================================

export fn softether_client_get_build_info() [*:0]const u8 {
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

    const info = std.fmt.comptimePrint(
        "SoftEtherClient-Zig | Platform: {s} | Arch: {s} | Zig: {s}",
        .{ platform, arch, builtin.zig_version_string },
    );

    return info;
}

// ============================================================================
// Test/Debug Helpers
// ============================================================================

export fn softether_client_is_valid_handle(handle: ?*SoftEtherClientContext) bool {
    return handle != null;
}

export fn softether_client_get_adapter_ptr(handle: ?*SoftEtherClientContext) ?*ZigPacketAdapter {
    const ctx = handle orelse return null;
    return ctx.adapter;
}
