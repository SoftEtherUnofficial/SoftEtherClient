//! SoftEther String Utilities Module
//!
//! This module provides string manipulation, parsing, and formatting utilities
//! used throughout the SoftEther VPN codebase. Ported from SoftEther C implementation
//! with Zig idioms and safety.
//!
//! Key Features:
//! - Safe string operations with bounds checking
//! - Token parsing and splitting
//! - Case conversion and comparison
//! - String search and replace
//! - Hex/binary conversion
//! - MAC address formatting
//! - Trimming and normalization
//!
//! Usage:
//! ```zig
//! const str = @import("mayaqua/str.zig");
//! const allocator = std.heap.page_allocator;
//!
//! // Parse tokens
//! const tokens = try str.parseToken(allocator, "host:port:user", ":");
//! defer tokens.deinit(allocator);
//!
//! // Case-insensitive compare
//! if (str.eqlIgnoreCase("Hello", "hello")) { ... }
//!
//! // MAC address formatting
//! var mac_str: [18]u8 = undefined;
//! str.macToStr(&mac_str, &[_]u8{0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
//! // Result: "00:11:22:33:44:55"
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

/// Token list - parsed string tokens
pub const TokenList = struct {
    tokens: [][]const u8,
    allocator: Allocator,

    /// Free all token memory
    pub fn deinit(self: *TokenList, allocator: Allocator) void {
        for (self.tokens) |token| {
            allocator.free(token);
        }
        allocator.free(self.tokens);
    }

    /// Check if a string is in the token list
    pub fn contains(self: *const TokenList, target: []const u8) bool {
        for (self.tokens) |token| {
            if (mem.eql(u8, token, target)) {
                return true;
            }
        }
        return false;
    }

    /// Check if a string is in the token list (case-insensitive)
    pub fn containsIgnoreCase(self: *const TokenList, target: []const u8) bool {
        for (self.tokens) |token| {
            if (eqlIgnoreCase(token, target)) {
                return true;
            }
        }
        return false;
    }
};

/// Parse a string into tokens using delimiter
pub fn parseToken(allocator: Allocator, src: []const u8, delimiter: []const u8) !TokenList {
    var tokens = try ArrayList([]const u8).initCapacity(allocator, 8);
    errdefer {
        for (tokens.items) |token| {
            allocator.free(token);
        }
        tokens.deinit(allocator);
    }

    if (src.len == 0) {
        const empty = try tokens.toOwnedSlice(allocator);
        return TokenList{ .tokens = empty, .allocator = allocator };
    }

    var iter = mem.splitSequence(u8, src, delimiter);
    while (iter.next()) |token| {
        // Skip empty tokens
        if (token.len > 0) {
            const owned = try allocator.dupe(u8, token);
            try tokens.append(allocator, owned);
        }
    }

    const result = try tokens.toOwnedSlice(allocator);
    return TokenList{ .tokens = result, .allocator = allocator };
}

/// Parse tokens but keep empty strings
pub fn parseTokenWithEmpty(allocator: Allocator, src: []const u8, delimiter: []const u8) !TokenList {
    var tokens = try ArrayList([]const u8).initCapacity(allocator, 8);
    errdefer {
        for (tokens.items) |token| {
            allocator.free(token);
        }
        tokens.deinit(allocator);
    }

    var iter = mem.splitSequence(u8, src, delimiter);
    while (iter.next()) |token| {
        const owned = try allocator.dupe(u8, token);
        try tokens.append(allocator, owned);
    }

    const result = try tokens.toOwnedSlice(allocator);
    return TokenList{ .tokens = result, .allocator = allocator };
}

/// Case-insensitive string comparison
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;

    for (a, b) |char_a, char_b| {
        if (toLower(char_a) != toLower(char_b)) {
            return false;
        }
    }
    return true;
}

/// Convert character to lowercase
pub fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

/// Convert character to uppercase
pub fn toUpper(c: u8) u8 {
    if (c >= 'a' and c <= 'z') {
        return c - ('a' - 'A');
    }
    return c;
}

/// Convert string to lowercase (in-place)
pub fn strLower(str: []u8) void {
    for (str) |*c| {
        c.* = toLower(c.*);
    }
}

/// Convert string to uppercase (in-place)
pub fn strUpper(str: []u8) void {
    for (str) |*c| {
        c.* = toUpper(c.*);
    }
}

/// Check if string starts with prefix
pub fn startsWith(str: []const u8, prefix: []const u8) bool {
    if (prefix.len > str.len) return false;
    return mem.eql(u8, str[0..prefix.len], prefix);
}

/// Check if string starts with prefix (case-insensitive)
pub fn startsWithIgnoreCase(str: []const u8, prefix: []const u8) bool {
    if (prefix.len > str.len) return false;
    return eqlIgnoreCase(str[0..prefix.len], prefix);
}

/// Check if string ends with suffix
pub fn endsWith(str: []const u8, suffix: []const u8) bool {
    if (suffix.len > str.len) return false;
    const start = str.len - suffix.len;
    return mem.eql(u8, str[start..], suffix);
}

/// Check if string ends with suffix (case-insensitive)
pub fn endsWithIgnoreCase(str: []const u8, suffix: []const u8) bool {
    if (suffix.len > str.len) return false;
    const start = str.len - suffix.len;
    return eqlIgnoreCase(str[start..], suffix);
}

/// Trim whitespace from both ends
pub fn trim(str: []const u8) []const u8 {
    return mem.trim(u8, str, " \t\r\n");
}

/// Trim whitespace from left
pub fn trimLeft(str: []const u8) []const u8 {
    return mem.trimLeft(u8, str, " \t\r\n");
}

/// Trim whitespace from right
pub fn trimRight(str: []const u8) []const u8 {
    return mem.trimRight(u8, str, " \t\r\n");
}

/// Check if character is in string
pub fn contains(haystack: []const u8, needle: u8) bool {
    return mem.indexOfScalar(u8, haystack, needle) != null;
}

/// Find substring in string (case-sensitive)
pub fn indexOf(haystack: []const u8, needle: []const u8) ?usize {
    return mem.indexOf(u8, haystack, needle);
}

/// Find substring in string (case-insensitive)
pub fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len > haystack.len) return null;

    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        if (eqlIgnoreCase(haystack[i .. i + needle.len], needle)) {
            return i;
        }
    }
    return null;
}

/// Check if string contains substring
pub fn containsStr(haystack: []const u8, needle: []const u8) bool {
    return indexOf(haystack, needle) != null;
}

/// Check if string contains substring (case-insensitive)
pub fn containsStrIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return indexOfIgnoreCase(haystack, needle) != null;
}

/// Replace all occurrences of old with new
pub fn replace(allocator: Allocator, input: []const u8, old: []const u8, new: []const u8) ![]u8 {
    if (old.len == 0) return allocator.dupe(u8, input);

    var result = try ArrayList(u8).initCapacity(allocator, input.len);
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < input.len) {
        if (i + old.len <= input.len and mem.eql(u8, input[i .. i + old.len], old)) {
            try result.appendSlice(allocator, new);
            i += old.len;
        } else {
            try result.append(allocator, input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Convert binary data to hex string
pub fn binToHex(allocator: Allocator, data: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var result = try allocator.alloc(u8, data.len * 2);

    for (data, 0..) |byte, i| {
        result[i * 2] = hex_chars[byte >> 4];
        result[i * 2 + 1] = hex_chars[byte & 0x0F];
    }

    return result;
}

/// Convert hex string to binary data
pub fn hexToBin(allocator: Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidHexString;

    var result = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(result);

    for (0..result.len) |i| {
        const high = try hexCharToNibble(hex[i * 2]);
        const low = try hexCharToNibble(hex[i * 2 + 1]);
        result[i] = (high << 4) | low;
    }

    return result;
}

/// Convert hex character to nibble (4 bits)
fn hexCharToNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexChar,
    };
}

/// Format MAC address as string (e.g., "00:11:22:33:44:55")
pub fn macToStr(buf: []u8, mac: []const u8) !void {
    if (mac.len != 6) return error.InvalidMacAddress;
    if (buf.len < 17) return error.BufferTooSmall;

    const hex_chars = "0123456789abcdef";
    for (mac, 0..) |byte, i| {
        buf[i * 3] = hex_chars[byte >> 4];
        buf[i * 3 + 1] = hex_chars[byte & 0x0F];
        if (i < 5) {
            buf[i * 3 + 2] = ':';
        }
    }
}

/// Parse MAC address from string (e.g., "00:11:22:33:44:55")
pub fn strToMac(mac: []u8, str: []const u8) !void {
    if (mac.len != 6) return error.InvalidMacBuffer;

    // Remove separators (: or -)
    var hex_digits: [12]u8 = undefined;
    var digit_count: usize = 0;

    for (str) |c| {
        if ((c >= '0' and c <= '9') or
            (c >= 'a' and c <= 'f') or
            (c >= 'A' and c <= 'F'))
        {
            if (digit_count >= 12) return error.InvalidMacString;
            hex_digits[digit_count] = c;
            digit_count += 1;
        } else if (c != ':' and c != '-' and c != ' ') {
            return error.InvalidMacString;
        }
    }

    if (digit_count != 12) return error.InvalidMacString;

    for (0..6) |i| {
        const high = try hexCharToNibble(hex_digits[i * 2]);
        const low = try hexCharToNibble(hex_digits[i * 2 + 1]);
        mac[i] = (high << 4) | low;
    }
}

/// Check if string is empty or only whitespace
pub fn isEmpty(str: []const u8) bool {
    return trim(str).len == 0;
}

/// Check if string is filled (not empty and not only whitespace)
pub fn isFilled(str: []const u8) bool {
    return !isEmpty(str);
}

/// Check if all characters are digits
pub fn isNumeric(str: []const u8) bool {
    if (str.len == 0) return false;

    for (str) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

/// Check if all characters are alphabetic
pub fn isAlpha(str: []const u8) bool {
    if (str.len == 0) return false;

    for (str) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z'))) {
            return false;
        }
    }
    return true;
}

/// Check if all characters are alphanumeric
pub fn isAlphanumeric(str: []const u8) bool {
    if (str.len == 0) return false;

    for (str) |c| {
        if (!((c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9')))
        {
            return false;
        }
    }
    return true;
}

/// Check if character is printable ASCII
pub fn isPrintableAscii(c: u8) bool {
    return c >= 32 and c <= 126;
}

/// Check if string contains only printable ASCII characters
pub fn isPrintableAsciiStr(str: []const u8) bool {
    for (str) |c| {
        if (!isPrintableAscii(c)) return false;
    }
    return true;
}

/// Parse integer from string
pub fn parseInt(comptime T: type, str: []const u8) !T {
    const trimmed = trim(str);
    if (trimmed.len == 0) return error.InvalidInteger;
    return std.fmt.parseInt(T, trimmed, 10);
}

/// Parse hex integer from string
pub fn parseHex(comptime T: type, str: []const u8) !T {
    const trimmed = trim(str);
    if (trimmed.len == 0) return error.InvalidHexInteger;

    // Handle 0x prefix
    const hex_str = if (startsWith(trimmed, "0x") or startsWith(trimmed, "0X"))
        trimmed[2..]
    else
        trimmed;

    return std.fmt.parseInt(T, hex_str, 16);
}

/// Format bytes with units (B, KB, MB, GB)
pub fn formatBytes(allocator: Allocator, bytes: u64) ![]u8 {
    const kb: u64 = 1024;
    const mb: u64 = kb * 1024;
    const gb: u64 = mb * 1024;
    const tb: u64 = gb * 1024;

    if (bytes >= tb) {
        return try std.fmt.allocPrint(allocator, "{d:.2} TB", .{@as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(tb))});
    } else if (bytes >= gb) {
        return try std.fmt.allocPrint(allocator, "{d:.2} GB", .{@as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(gb))});
    } else if (bytes >= mb) {
        return try std.fmt.allocPrint(allocator, "{d:.2} MB", .{@as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(mb))});
    } else if (bytes >= kb) {
        return try std.fmt.allocPrint(allocator, "{d:.2} KB", .{@as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(kb))});
    } else {
        return try std.fmt.allocPrint(allocator, "{d} B", .{bytes});
    }
}

//
// Tests
//

test "parseToken - basic splitting" {
    const allocator = std.testing.allocator;

    var tokens = try parseToken(allocator, "hello:world:test", ":");
    defer tokens.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), tokens.tokens.len);
    try std.testing.expectEqualStrings("hello", tokens.tokens[0]);
    try std.testing.expectEqualStrings("world", tokens.tokens[1]);
    try std.testing.expectEqualStrings("test", tokens.tokens[2]);
}

test "parseToken - empty tokens skipped" {
    const allocator = std.testing.allocator;

    var tokens = try parseToken(allocator, "a::b:::c", ":");
    defer tokens.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), tokens.tokens.len);
    try std.testing.expectEqualStrings("a", tokens.tokens[0]);
    try std.testing.expectEqualStrings("b", tokens.tokens[1]);
    try std.testing.expectEqualStrings("c", tokens.tokens[2]);
}

test "eqlIgnoreCase" {
    try std.testing.expect(eqlIgnoreCase("Hello", "hello"));
    try std.testing.expect(eqlIgnoreCase("WORLD", "world"));
    try std.testing.expect(eqlIgnoreCase("TeSt", "tEsT"));
    try std.testing.expect(!eqlIgnoreCase("hello", "world"));
    try std.testing.expect(!eqlIgnoreCase("test", "testing"));
}

test "startsWith and endsWith" {
    try std.testing.expect(startsWith("hello world", "hello"));
    try std.testing.expect(endsWith("hello world", "world"));
    try std.testing.expect(startsWithIgnoreCase("Hello World", "hello"));
    try std.testing.expect(endsWithIgnoreCase("Hello World", "WORLD"));
    try std.testing.expect(!startsWith("hello", "world"));
    try std.testing.expect(!endsWith("hello", "world"));
}

test "trim functions" {
    try std.testing.expectEqualStrings("hello", trim("  hello  "));
    try std.testing.expectEqualStrings("world", trim("\t\nworld\r\n"));
    try std.testing.expectEqualStrings("hello  ", trimLeft("  hello  "));
    try std.testing.expectEqualStrings("  hello", trimRight("  hello  "));
}

test "binToHex and hexToBin" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 0x12, 0x34, 0xAB, 0xCD };
    const hex = try binToHex(allocator, &data);
    defer allocator.free(hex);

    try std.testing.expectEqualStrings("1234abcd", hex);

    const bin = try hexToBin(allocator, hex);
    defer allocator.free(bin);

    try std.testing.expectEqualSlices(u8, &data, bin);
}

test "macToStr and strToMac" {
    var buf: [18]u8 = undefined;
    const mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    try macToStr(&buf, &mac);
    try std.testing.expectEqualStrings("00:11:22:33:44:55", buf[0..17]);

    var parsed_mac: [6]u8 = undefined;
    try strToMac(&parsed_mac, "00:11:22:33:44:55");
    try std.testing.expectEqualSlices(u8, &mac, &parsed_mac);

    // Test with different separators
    try strToMac(&parsed_mac, "00-11-22-33-44-55");
    try std.testing.expectEqualSlices(u8, &mac, &parsed_mac);
}

test "string validation functions" {
    try std.testing.expect(isEmpty(""));
    try std.testing.expect(isEmpty("   "));
    try std.testing.expect(!isEmpty("hello"));
    try std.testing.expect(isFilled("hello"));

    try std.testing.expect(isNumeric("12345"));
    try std.testing.expect(!isNumeric("123abc"));

    try std.testing.expect(isAlpha("hello"));
    try std.testing.expect(!isAlpha("hello123"));

    try std.testing.expect(isAlphanumeric("hello123"));
    try std.testing.expect(!isAlphanumeric("hello-123"));
}

test "parseInt and parseHex" {
    try std.testing.expectEqual(@as(u32, 12345), try parseInt(u32, "12345"));
    try std.testing.expectEqual(@as(i32, -42), try parseInt(i32, "-42"));

    try std.testing.expectEqual(@as(u32, 0x1234), try parseHex(u32, "1234"));
    try std.testing.expectEqual(@as(u32, 0xABCD), try parseHex(u32, "0xABCD"));
    try std.testing.expectEqual(@as(u32, 0xFF), try parseHex(u32, "0xFF"));
}

test "formatBytes" {
    const allocator = std.testing.allocator;

    const b = try formatBytes(allocator, 512);
    defer allocator.free(b);
    try std.testing.expectEqualStrings("512 B", b);

    const kb = try formatBytes(allocator, 2048);
    defer allocator.free(kb);
    try std.testing.expectEqualStrings("2.00 KB", kb);

    const mb = try formatBytes(allocator, 1024 * 1024 * 5);
    defer allocator.free(mb);
    try std.testing.expectEqualStrings("5.00 MB", mb);
}

test "replace" {
    const allocator = std.testing.allocator;

    const result = try replace(allocator, "hello world hello", "hello", "hi");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("hi world hi", result);
}

test "contains and indexOf" {
    try std.testing.expect(contains("hello world", 'o'));
    try std.testing.expect(!contains("hello", 'x'));

    try std.testing.expectEqual(@as(?usize, 6), indexOf("hello world", "world"));
    try std.testing.expectEqual(@as(?usize, null), indexOf("hello", "xyz"));

    try std.testing.expectEqual(@as(?usize, 6), indexOfIgnoreCase("hello WORLD", "world"));
}
