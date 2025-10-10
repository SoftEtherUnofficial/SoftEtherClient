//! Filesystem Operations
//!
//! Safe wrappers around Mayaqua filesystem FFI functions.

const std = @import("std");
const mayaqua = @import("../mayaqua.zig");
const c = mayaqua.c;
const MayaquaError = mayaqua.MayaquaError;
const checkResult = mayaqua.checkResult;

/// Ensure directory exists (creates if needed, including parents)
///
/// ## Parameters
/// - `path`: Directory path to create
///
/// ## Example
/// ```zig
/// try fs.ensureDir("/path/to/my/dir");
/// ```
pub fn ensureDir(path: []const u8) MayaquaError!void {
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const result = c.mayaqua_ensure_dir(@ptrCast(&path_buf));
    try checkResult(result);
}

/// Read entire file into memory
///
/// ## Parameters
/// - `allocator`: Allocator for the returned buffer
/// - `path`: File path to read
///
/// ## Returns
/// - Owned slice containing file contents (caller must free)
///
/// ## Example
/// ```zig
/// const data = try fs.readFile(allocator, "/path/to/file.txt");
/// defer allocator.free(data);
/// ```
pub fn readFile(allocator: std.mem.Allocator, path: []const u8) MayaquaError![]u8 {
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    var output_ptr: [*c]u8 = null;
    var output_len: c_uint = 0;

    const result = c.mayaqua_read_file(
        @ptrCast(&path_buf),
        @ptrCast(&output_ptr),
        &output_len,
    );
    try checkResult(result);

    if (output_ptr == null or output_len == 0) {
        return MayaquaError.NullPointer;
    }

    // Copy from Rust-allocated buffer to Zig allocator
    const data = try allocator.alloc(u8, output_len);
    errdefer allocator.free(data);

    @memcpy(data, output_ptr[0..output_len]);

    // Free Rust allocation
    c.mayaqua_free_buffer(output_ptr, output_len);

    return data;
}

/// Write data to file atomically
///
/// ## Parameters
/// - `path`: File path to write
/// - `data`: Data to write
///
/// ## Example
/// ```zig
/// try fs.writeFile("/path/to/file.txt", "Hello, world!");
/// ```
pub fn writeFile(path: []const u8, data: []const u8) MayaquaError!void {
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const result = c.mayaqua_write_file(
        @ptrCast(&path_buf),
        data.ptr,
        @intCast(data.len),
    );
    try checkResult(result);
}

/// Set file permissions to user read/write only (0600)
///
/// ## Parameters
/// - `path`: File path to set permissions
///
/// ## Example
/// ```zig
/// try fs.setUserRwOnly("/path/to/sensitive/file");
/// ```
pub fn setUserRwOnly(path: []const u8) MayaquaError!void {
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) {
        return MayaquaError.InvalidParameter;
    }

    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    _ = c.mayaqua_set_user_rw_only(@ptrCast(&path_buf));
}

// ============================================================================
// Tests
// ============================================================================

test "ensure dir" {
    const tmp_dir = "/tmp/mayaqua_test_dir";

    try ensureDir(tmp_dir);

    // Should succeed even if already exists
    try ensureDir(tmp_dir);

    // Clean up
    std.fs.deleteTreeAbsolute(tmp_dir) catch {};
}

test "write and read file" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const tmp_file = "/tmp/mayaqua_test_file.txt";
    const content = "Hello, Zig wrapper!";

    // Write file
    try writeFile(tmp_file, content);
    defer std.fs.deleteFileAbsolute(tmp_file) catch {};

    // Read file back
    const data = try readFile(allocator, tmp_file);
    defer allocator.free(data);

    try testing.expectEqualSlices(u8, content, data);
}

test "set user rw only" {
    const testing = std.testing;

    const tmp_file = "/tmp/mayaqua_test_perms.txt";

    try writeFile(tmp_file, "test");
    defer std.fs.deleteFileAbsolute(tmp_file) catch {};

    try setUserRwOnly(tmp_file);

    // Verify permissions (Unix-specific)
    const file = try std.fs.openFileAbsolute(tmp_file, .{});
    defer file.close();

    const stat = try file.stat();
    const mode = stat.mode & 0o777;

    try testing.expectEqual(@as(u32, 0o600), mode);
}
