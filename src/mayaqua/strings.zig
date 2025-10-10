//! String Utilities
//!
//! Safe wrappers around Mayaqua string FFI functions.

const std = @import("std");
const mayaqua = @import("../mayaqua.zig");
const c = mayaqua.c;
const MayaquaError = mayaqua.MayaquaError;
const checkResult = mayaqua.checkResult;

/// Convert UTF-8 string to UTF-16
///
/// ## Parameters
/// - `allocator`: Allocator for the returned buffer
/// - `input`: UTF-8 string to convert
///
/// ## Returns
/// - Owned slice of UTF-16 code units (caller must free)
///
/// ## Example
/// ```zig
/// const utf16 = try strings.utf8ToUtf16(allocator, "Hello, 世界");
/// defer allocator.free(utf16);
/// ```
pub fn utf8ToUtf16(allocator: std.mem.Allocator, input: []const u8) MayaquaError![]u16 {
    var input_buf: [4096]u8 = undefined;
    if (input.len >= input_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(input_buf[0..input.len], input);
    input_buf[input.len] = 0;

    var output_ptr: [*c]u16 = null;
    var output_len: c_uint = 0;

    const result = c.mayaqua_utf8_to_utf16(
        @ptrCast(&input_buf),
        @ptrCast(&output_ptr),
        &output_len,
    );
    try checkResult(result);

    if (output_ptr == null or output_len == 0) {
        return MayaquaError.NullPointer;
    }

    // Copy from Rust-allocated buffer to Zig allocator
    const data = try allocator.alloc(u16, output_len);
    errdefer allocator.free(data);

    @memcpy(data, output_ptr[0..output_len]);

    // Free Rust allocation
    c.mayaqua_free_utf16(output_ptr, output_len);

    return data;
}

/// Convert UTF-16 string to UTF-8
///
/// ## Parameters
/// - `allocator`: Allocator for the returned buffer
/// - `input`: UTF-16 string to convert
///
/// ## Returns
/// - Owned UTF-8 string slice (caller must free)
///
/// ## Example
/// ```zig
/// const utf8 = try strings.utf16ToUtf8(allocator, utf16_data);
/// defer allocator.free(utf8);
/// ```
pub fn utf16ToUtf8(allocator: std.mem.Allocator, input: []const u16) MayaquaError![]u8 {
    var output_ptr: [*c]u8 = null;

    const result = c.mayaqua_utf16_to_utf8(
        input.ptr,
        @intCast(input.len),
        @ptrCast(&output_ptr),
    );
    try checkResult(result);

    if (output_ptr == null) {
        return MayaquaError.NullPointer;
    }

    // Calculate string length
    const len = std.mem.len(output_ptr);

    // Copy from Rust-allocated buffer to Zig allocator
    const data = try allocator.alloc(u8, len);
    errdefer allocator.free(data);

    @memcpy(data, output_ptr[0..len]);

    // Free Rust allocation
    c.mayaqua_free_string(output_ptr);

    return data;
}

/// Convert binary data to hex string
///
/// ## Parameters
/// - `allocator`: Allocator for the returned buffer
/// - `data`: Binary data to convert
///
/// ## Returns
/// - Owned hex string (caller must free)
///
/// ## Example
/// ```zig
/// const hex = try strings.binToStr(allocator, &[_]u8{0xDE, 0xAD, 0xBE, 0xEF});
/// defer allocator.free(hex);
/// // hex == "deadbeef"
/// ```
pub fn binToStr(allocator: std.mem.Allocator, data: []const u8) MayaquaError![]u8 {
    var output_ptr: [*c]u8 = null;
    const output_size: usize = (data.len * 2) + 1; // Hex string is 2x + null terminator
    output_ptr = @ptrCast(std.c.malloc(output_size));
    if (output_ptr == null) {
        return MayaquaError.OutOfMemory;
    }
    defer std.c.free(output_ptr);

    _ = c.mayaqua_bin_to_str(
        data.ptr,
        @intCast(data.len),
        @ptrCast(&output_ptr),
    );

    // Find null terminator
    const len = std.mem.len(output_ptr);

    return try allocator.dupe(u8, output_ptr[0..len]);
}

/// Convert hex string to binary data
///
/// ## Parameters
/// - `allocator`: Allocator for the returned buffer
/// - `hex`: Hex string to convert
///
/// ## Returns
/// - Owned binary data (caller must free)
///
/// ## Example
/// ```zig
/// const bin = try strings.strToBin(allocator, "deadbeef");
/// defer allocator.free(bin);
/// // bin == [0xDE, 0xAD, 0xBE, 0xEF]
/// ```
pub fn strToBin(allocator: std.mem.Allocator, hex: []const u8) MayaquaError![]u8 {
    var hex_buf: [4096]u8 = undefined;
    if (hex.len >= hex_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(hex_buf[0..hex.len], hex);
    hex_buf[hex.len] = 0;

    var output_ptr: ?*anyopaque = null;
    var output_len: c_uint = 0;

    const result = c.mayaqua_str_to_bin(
        @ptrCast(&hex_buf),
        @ptrCast(&output_ptr),
        &output_len,
    );
    try checkResult(result);

    if (output_ptr == null or output_len == 0) {
        return MayaquaError.NullPointer;
    }

    // Copy from Rust-allocated buffer
    const src_ptr: [*]u8 = @ptrCast(output_ptr.?);
    const data = try allocator.dupe(u8, src_ptr[0..output_len]);

    // Free Rust allocation
    c.mayaqua_free_buffer(@ptrCast(output_ptr.?), output_len);

    return data;
}

/// Convert MAC address to string
///
/// ## Parameters
/// - `mac`: 6-byte MAC address
///
/// ## Returns
/// - Formatted MAC address string (e.g., "00:11:22:33:44:55")
///
/// ## Example
/// ```zig
/// const mac_str = try strings.macToStr(&[_]u8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
/// // mac_str == "00:11:22:33:44:55"
/// ```
pub fn macToStr(mac: *const [6]u8) MayaquaError![17]u8 {
    var output_buf: [18]u8 = undefined;

    const result = c.mayaqua_mac_to_str(
        mac.ptr,
        &output_buf,
    );
    try checkResult(result);

    var result_str: [17]u8 = undefined;
    @memcpy(&result_str, output_buf[0..17]);

    return result_str;
}

/// Convert string to MAC address
///
/// ## Parameters
/// - `str`: MAC address string (e.g., "00:11:22:33:44:55")
///
/// ## Returns
/// - 6-byte MAC address
///
/// ## Example
/// ```zig
/// const mac = try strings.strToMac("00:11:22:33:44:55");
/// // mac == [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
/// ```
pub fn strToMac(str: []const u8) MayaquaError![6]u8 {
    var str_buf: [32]u8 = undefined;
    if (str.len >= str_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(str_buf[0..str.len], str);
    str_buf[str.len] = 0;

    var output: [6]u8 = undefined;

    const result = c.mayaqua_str_to_mac(
        @ptrCast(&str_buf),
        &output,
    );
    try checkResult(result);

    return output;
}

// ============================================================================
// Tests
// ============================================================================

test "utf8 to utf16" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const utf16 = try utf8ToUtf16(allocator, "Hello");
    defer allocator.free(utf16);

    try testing.expect(utf16.len > 0);
}

test "utf16 to utf8 roundtrip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const original = "Hello, World!";

    const utf16 = try utf8ToUtf16(allocator, original);
    defer allocator.free(utf16);

    const utf8 = try utf16ToUtf8(allocator, utf16);
    defer allocator.free(utf8);

    try testing.expectEqualSlices(u8, original, utf8);
}

test "bin to hex" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const bin = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const hex = try binToStr(allocator, &bin);
    defer allocator.free(hex);

    try testing.expectEqualSlices(u8, "deadbeef", hex);
}

test "hex to bin roundtrip" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const original = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

    const hex = try binToStr(allocator, &original);
    defer allocator.free(hex);

    const bin = try strToBin(allocator, hex);
    defer allocator.free(bin);

    try testing.expectEqualSlices(u8, &original, bin);
}

test "mac to string" {
    const testing = std.testing;

    const mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const str = try macToStr(&mac);

    try testing.expectEqualSlices(u8, "00:11:22:33:44:55", &str);
}

test "string to mac roundtrip" {
    const testing = std.testing;

    const original = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    const str = try macToStr(&original);
    const mac = try strToMac(&str);

    try testing.expectEqualSlices(u8, &original, &mac);
}
