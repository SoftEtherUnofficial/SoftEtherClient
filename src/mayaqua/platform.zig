//! Platform Utilities
//!
//! Safe wrappers around Mayaqua platform FFI functions.

const std = @import("std");
const mayaqua = @import("../mayaqua.zig");
const c = mayaqua.c;
const MayaquaError = mayaqua.MayaquaError;
const checkResult = mayaqua.checkResult;

/// Get system directory path
///
/// ## Parameters
/// - `allocator`: Allocator for the returned string
///
/// ## Returns
/// - System directory path (caller must free)
///
/// ## Example
/// ```zig
/// const path = try platform.getSystemDir(allocator);
/// defer allocator.free(path);
/// ```
pub fn getSystemDir(allocator: std.mem.Allocator) MayaquaError![]u8 {
    var path_ptr: [*c]u8 = null;

    const result = c.mayaqua_get_system_dir(@ptrCast(&path_ptr));
    try checkResult(result);

    if (path_ptr == null) {
        return MayaquaError.NullPointer;
    }

    // Copy from Rust allocation
    const path_len = std.mem.len(path_ptr);
    const path = try allocator.dupe(u8, path_ptr[0..path_len]);

    // Free Rust allocation
    c.mayaqua_free_string(path_ptr);

    return path;
}

/// Get config directory path
///
/// ## Parameters
/// - `allocator`: Allocator for the returned string
///
/// ## Returns
/// - Config directory path (caller must free)
///
/// ## Example
/// ```zig
/// const path = try platform.getConfigDir(allocator);
/// defer allocator.free(path);
/// ```
pub fn getConfigDir(allocator: std.mem.Allocator) MayaquaError![]u8 {
    var path_ptr: [*c]u8 = null;

    const result = c.mayaqua_get_config_dir(@ptrCast(&path_ptr));
    try checkResult(result);

    if (path_ptr == null) {
        return MayaquaError.NullPointer;
    }

    // Copy from Rust allocation
    const path_len = std.mem.len(path_ptr);
    const path = try allocator.dupe(u8, path_ptr[0..path_len]);

    // Free Rust allocation
    c.mayaqua_free_string(path_ptr);

    return path;
}

/// Get list of network interfaces
///
/// ## Parameters
/// - `allocator`: Allocator for the returned array
///
/// ## Returns
/// - Array of interface names (caller must free)
///
/// ## Example
/// ```zig
/// const interfaces = try platform.getInterfaces(allocator);
/// defer {
///     for (interfaces) |iface| allocator.free(iface);
///     allocator.free(interfaces);
/// }
/// ```
pub fn getInterfaces(allocator: std.mem.Allocator) MayaquaError![][]u8 {
    var array_ptr: [*c][*c]u8 = undefined;
    var count: c_uint = 0;

    const result = c.mayaqua_get_interfaces(
        @ptrCast(&array_ptr),
        &count,
    );
    try checkResult(result);

    if (count == 0) {
        return &[_][]u8{};
    }

    // Allocate Zig array
    const interfaces = try allocator.alloc([]u8, count);
    errdefer allocator.free(interfaces);

    // Copy each string from Rust allocation
    var i: usize = 0;
    errdefer {
        for (interfaces[0..i]) |iface| allocator.free(iface);
    }

    while (i < count) : (i += 1) {
        const str_ptr = array_ptr[i];
        const str_len = std.mem.len(str_ptr);
        interfaces[i] = try allocator.dupe(u8, str_ptr[0..str_len]);
    }

    // Free Rust allocation
    c.mayaqua_free_string_array(array_ptr, count);

    return interfaces;
}

// ============================================================================
// Tests
// ============================================================================

test "get system dir" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const path = try getSystemDir(allocator);
    defer allocator.free(path);

    try testing.expect(path.len > 0);
}

test "get config dir" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const path = try getConfigDir(allocator);
    defer allocator.free(path);

    try testing.expect(path.len > 0);
}

test "get interfaces" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const interfaces = try getInterfaces(allocator);
    defer {
        for (interfaces) |iface| allocator.free(iface);
        allocator.free(interfaces);
    }

    // Should have at least one interface (loopback)
    try testing.expect(interfaces.len > 0);
}
