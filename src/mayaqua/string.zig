//! String Utilities Module
//!
//! This module provides a Zig replacement for Mayaqua/Str.c.
//! Key improvements over C version:
//! - UTF-8 native (Zig strings are UTF-8 by default)
//! - Slice-based (no null-terminator bugs)
//! - Type-safe conversions
//! - Compile-time string literals
//! - Zero-copy where possible
//!
//! Only ports functions actually used by the VPN client.
//! Original Str.c has 5,933 lines - we need only ~500 lines.

const std = @import("std");
const mem = @import("memory.zig");

/// String length (UTF-8 aware)
/// Replacement for StrLen()
pub fn len(s: []const u8) usize {
    return s.len;
}

/// Null-terminated string length
pub fn lenZ(s: [*:0]const u8) usize {
    return std.mem.len(s);
}

/// Copy string (with size limit for safety)
/// Replacement for StrCpy(dest, sizeof(dest), src)
pub fn copy(dest: []u8, src: []const u8) !void {
    if (src.len > dest.len) {
        return error.BufferTooSmall;
    }
    @memcpy(dest[0..src.len], src);

    // Null-terminate if there's room
    if (src.len < dest.len) {
        dest[src.len] = 0;
    }
}

/// Copy null-terminated string
pub fn copyZ(dest: []u8, src: [*:0]const u8) !void {
    const src_len = lenZ(src);
    if (src_len >= dest.len) {
        return error.BufferTooSmall;
    }
    @memcpy(dest[0..src_len], src[0..src_len]);
    dest[src_len] = 0;
}

/// Concatenate strings (with size limit)
/// Replacement for StrCat(dest, sizeof(dest), src)
pub fn cat(dest: []u8, src: []const u8) !void {
    // Find current length (look for null terminator)
    var dest_len: usize = 0;
    while (dest_len < dest.len and dest[dest_len] != 0) : (dest_len += 1) {}

    if (dest_len + src.len >= dest.len) {
        return error.BufferTooSmall;
    }

    @memcpy(dest[dest_len..][0..src.len], src);
    dest[dest_len + src.len] = 0;
}

/// Compare strings (case-sensitive)
/// Replacement for StrCmp()
/// Returns: 0 if equal, <0 if a<b, >0 if a>b
pub fn cmp(a: []const u8, b: []const u8) i32 {
    const min_len = @min(a.len, b.len);

    for (0..min_len) |i| {
        if (a[i] != b[i]) {
            return @as(i32, a[i]) - @as(i32, b[i]);
        }
    }

    // If all bytes match, shorter string is "less than"
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// Compare strings (case-insensitive)
/// Replacement for StrCmpi()
pub fn cmpi(a: []const u8, b: []const u8) i32 {
    const min_len = @min(a.len, b.len);

    for (0..min_len) |i| {
        const a_lower = std.ascii.toLower(a[i]);
        const b_lower = std.ascii.toLower(b[i]);
        if (a_lower != b_lower) {
            return @as(i32, a_lower) - @as(i32, b_lower);
        }
    }

    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// Check if strings are equal (case-sensitive)
pub fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Check if strings are equal (case-insensitive)
pub fn eqli(a: []const u8, b: []const u8) bool {
    return cmpi(a, b) == 0;
}

/// Check if string starts with prefix
pub fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    return eql(s[0..prefix.len], prefix);
}

/// Check if string ends with suffix
pub fn endsWith(s: []const u8, suffix: []const u8) bool {
    if (s.len < suffix.len) return false;
    return eql(s[s.len - suffix.len ..], suffix);
}

/// Find substring (returns index or null)
/// Replacement for SearchStr()
pub fn find(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;

    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        if (eql(haystack[i..][0..needle.len], needle)) {
            return i;
        }
    }
    return null;
}

/// Check if string contains substring
pub fn contains(haystack: []const u8, needle: []const u8) bool {
    return find(haystack, needle) != null;
}

/// Duplicate string using allocator
/// Replacement for CopyStr()
pub fn duplicate(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    return mem.clone(allocator, s);
}

/// Duplicate null-terminated string
pub fn duplicateZ(allocator: std.mem.Allocator, s: [*:0]const u8) ![:0]u8 {
    return mem.cloneString(allocator, s);
}

/// Format string (like sprintf)
/// Uses Zig's std.fmt
pub fn format(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) ![]u8 {
    return try std.fmt.allocPrint(allocator, fmt, args);
}

/// Format into fixed buffer
pub fn formatBuf(buf: []u8, comptime fmt: []const u8, args: anytype) ![]u8 {
    return try std.fmt.bufPrint(buf, fmt, args);
}

/// Trim whitespace from both ends
pub fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, &std.ascii.whitespace);
}

/// Trim whitespace from start
pub fn trimLeft(s: []const u8) []const u8 {
    return std.mem.trimLeft(u8, s, &std.ascii.whitespace);
}

/// Trim whitespace from end
pub fn trimRight(s: []const u8) []const u8 {
    return std.mem.trimRight(u8, s, &std.ascii.whitespace);
}

/// Split string by delimiter (returns iterator)
pub fn split(s: []const u8, delimiter: []const u8) std.mem.SplitIterator(u8, .sequence) {
    return std.mem.splitSequence(u8, s, delimiter);
}

/// Split string by single character
pub fn splitScalar(s: []const u8, delimiter: u8) std.mem.SplitIterator(u8, .scalar) {
    return std.mem.splitScalar(u8, s, delimiter);
}

/// Replace all occurrences (allocates new string)
pub fn replace(allocator: std.mem.Allocator, s: []const u8, old: []const u8, new: []const u8) ![]u8 {
    if (old.len == 0) return try duplicate(allocator, s);

    // Count occurrences
    var count: usize = 0;
    var pos: usize = 0;
    while (find(s[pos..], old)) |idx| {
        count += 1;
        pos += idx + old.len;
    }

    if (count == 0) return try duplicate(allocator, s);

    // Calculate result length (handle both grow and shrink cases)
    const result_len = if (new.len >= old.len)
        s.len + count * (new.len - old.len)
    else
        s.len - count * (old.len - new.len);

    var result = try allocator.alloc(u8, result_len);

    // Build result
    var src_pos: usize = 0;
    var dst_pos: usize = 0;
    while (find(s[src_pos..], old)) |idx| {
        // Copy before match
        @memcpy(result[dst_pos..][0..idx], s[src_pos..][0..idx]);
        dst_pos += idx;
        src_pos += idx;

        // Copy replacement
        @memcpy(result[dst_pos..][0..new.len], new);
        dst_pos += new.len;
        src_pos += old.len;
    }

    // Copy remainder
    const remaining = s.len - src_pos;
    if (remaining > 0) {
        @memcpy(result[dst_pos..][0..remaining], s[src_pos..][0..remaining]);
    }

    return result;
}

/// Convert string to integer
pub fn parseInt(s: []const u8, base: u8) !i64 {
    return try std.fmt.parseInt(i64, s, base);
}

/// Convert string to unsigned integer
pub fn parseUInt(s: []const u8, base: u8) !u64 {
    return try std.fmt.parseUnsigned(u64, s, base);
}

/// Convert string to float
pub fn parseFloat(s: []const u8) !f64 {
    return try std.fmt.parseFloat(f64, s);
}

/// Convert string to lowercase (allocates)
pub fn toLower(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var result = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        result[i] = std.ascii.toLower(c);
    }
    return result;
}

/// Convert string to uppercase (allocates)
pub fn toUpper(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    var result = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| {
        result[i] = std.ascii.toUpper(c);
    }
    return result;
}

/// Convert string to lowercase in-place
pub fn toLowerInPlace(s: []u8) void {
    for (s, 0..) |c, i| {
        s[i] = std.ascii.toLower(c);
    }
}

/// Convert string to uppercase in-place
pub fn toUpperInPlace(s: []u8) void {
    for (s, 0..) |c, i| {
        s[i] = std.ascii.toUpper(c);
    }
}

/// Check if string is empty
pub fn isEmpty(s: []const u8) bool {
    return s.len == 0;
}

/// Check if string contains only whitespace
pub fn isWhitespace(s: []const u8) bool {
    if (s.len == 0) return true;
    for (s) |c| {
        if (!std.ascii.isWhitespace(c)) return false;
    }
    return true;
}

/// Check if string is valid UTF-8
pub fn isValidUtf8(s: []const u8) bool {
    return std.unicode.utf8ValidateSlice(s);
}

/// C-compatible FFI functions (for gradual migration)
export fn zig_strLen(str: [*:0]const u8) callconv(.c) c_uint {
    return @intCast(lenZ(str));
}

export fn zig_strCpy(dest: [*]u8, dest_size: c_uint, src: [*:0]const u8) callconv(.c) void {
    const dest_slice = dest[0..dest_size];
    copyZ(dest_slice, src) catch return;
}

export fn zig_strCat(dest: [*]u8, dest_size: c_uint, src: [*:0]const u8) callconv(.c) void {
    const dest_slice = dest[0..dest_size];
    const src_len = lenZ(src);
    const src_slice = src[0..src_len];
    cat(dest_slice, src_slice) catch return;
}

export fn zig_strCmp(a: [*:0]const u8, b: [*:0]const u8) callconv(.c) c_int {
    const a_len = lenZ(a);
    const b_len = lenZ(b);
    return cmp(a[0..a_len], b[0..b_len]);
}

export fn zig_strCmpi(a: [*:0]const u8, b: [*:0]const u8) callconv(.c) c_int {
    const a_len = lenZ(a);
    const b_len = lenZ(b);
    return cmpi(a[0..a_len], b[0..b_len]);
}

// Tests

test "string length" {
    try std.testing.expectEqual(@as(usize, 0), len(""));
    try std.testing.expectEqual(@as(usize, 5), len("hello"));
    try std.testing.expectEqual(@as(usize, 13), len("Hello, World!"));
}

test "string copy" {
    var buf: [20]u8 = undefined;

    try copy(&buf, "hello");
    try std.testing.expectEqualStrings("hello", buf[0..5]);
    try std.testing.expectEqual(@as(u8, 0), buf[5]);
}

test "string copy too long" {
    var buf: [5]u8 = undefined;

    const result = copy(&buf, "hello world");
    try std.testing.expectError(error.BufferTooSmall, result);
}

test "string concatenate" {
    var buf: [20]u8 = undefined;
    @memset(&buf, 0);

    try copy(&buf, "hello");
    try cat(&buf, " world");

    var i: usize = 0;
    while (i < buf.len and buf[i] != 0) : (i += 1) {}
    try std.testing.expectEqualStrings("hello world", buf[0..i]);
}

test "string compare" {
    try std.testing.expectEqual(@as(i32, 0), cmp("hello", "hello"));
    try std.testing.expect(cmp("hello", "world") < 0);
    try std.testing.expect(cmp("world", "hello") > 0);
    try std.testing.expect(cmp("hel", "hello") < 0);
}

test "string compare case insensitive" {
    try std.testing.expectEqual(@as(i32, 0), cmpi("hello", "HELLO"));
    try std.testing.expectEqual(@as(i32, 0), cmpi("Hello", "hELLo"));
    try std.testing.expect(cmpi("hello", "WORLD") < 0);
}

test "string equality" {
    try std.testing.expect(eql("hello", "hello"));
    try std.testing.expect(!eql("hello", "world"));
    try std.testing.expect(eqli("hello", "HELLO"));
}

test "string starts with" {
    try std.testing.expect(startsWith("hello world", "hello"));
    try std.testing.expect(!startsWith("hello world", "world"));
    try std.testing.expect(startsWith("test", ""));
}

test "string ends with" {
    try std.testing.expect(endsWith("hello world", "world"));
    try std.testing.expect(!endsWith("hello world", "hello"));
    try std.testing.expect(endsWith("test", ""));
}

test "string find" {
    try std.testing.expectEqual(@as(?usize, 0), find("hello world", "hello"));
    try std.testing.expectEqual(@as(?usize, 6), find("hello world", "world"));
    try std.testing.expectEqual(@as(?usize, null), find("hello world", "xyz"));
}

test "string contains" {
    try std.testing.expect(contains("hello world", "hello"));
    try std.testing.expect(contains("hello world", "world"));
    try std.testing.expect(!contains("hello world", "xyz"));
}

test "string duplicate" {
    const allocator = std.testing.allocator;

    const original = "hello world";
    const copy_str = try duplicate(allocator, original);
    defer allocator.free(copy_str);

    try std.testing.expectEqualStrings(original, copy_str);
}

test "string format" {
    const allocator = std.testing.allocator;

    const result = try format(allocator, "Hello, {s}! You are {d} years old.", .{ "Alice", 30 });
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Hello, Alice! You are 30 years old.", result);
}

test "string trim" {
    try std.testing.expectEqualStrings("hello", trim("  hello  "));
    try std.testing.expectEqualStrings("hello", trim("hello"));
    try std.testing.expectEqualStrings("", trim("   "));
}

test "string split" {
    var it = split("one,two,three", ",");

    try std.testing.expectEqualStrings("one", it.next().?);
    try std.testing.expectEqualStrings("two", it.next().?);
    try std.testing.expectEqualStrings("three", it.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), it.next());
}

test "string replace" {
    const allocator = std.testing.allocator;

    const result = try replace(allocator, "hello world", "world", "Zig");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("hello Zig", result);
}

test "string to lowercase" {
    const allocator = std.testing.allocator;

    const result = try toLower(allocator, "Hello WORLD");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("hello world", result);
}

test "string to uppercase" {
    const allocator = std.testing.allocator;

    const result = try toUpper(allocator, "Hello world");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("HELLO WORLD", result);
}

test "string parse int" {
    try std.testing.expectEqual(@as(i64, 42), try parseInt("42", 10));
    try std.testing.expectEqual(@as(i64, -42), try parseInt("-42", 10));
    try std.testing.expectEqual(@as(i64, 255), try parseInt("FF", 16));
}

test "string is empty" {
    try std.testing.expect(isEmpty(""));
    try std.testing.expect(!isEmpty("hello"));
}

test "string is whitespace" {
    try std.testing.expect(isWhitespace(""));
    try std.testing.expect(isWhitespace("   "));
    try std.testing.expect(!isWhitespace("hello"));
}
