//! Compression utilities for Pack protocol
//! Wraps zlib compression functions for efficient Pack serialization

const std = @import("std");
const c = @cImport({
    @cInclude("zlib.h");
});

/// Compression error type
pub const CompressionError = error{
    CompressionFailed,
    DecompressionFailed,
    BufferTooSmall,
    InvalidData,
};

/// Calculate the maximum size needed for compressed data
pub fn calcCompressedSize(src_size: usize) usize {
    return src_size * 2 + 256;
}

/// Compress data using zlib
/// Returns the actual compressed size
pub fn compress(dst: []u8, src: []const u8, level: i32) CompressionError!usize {
    if (dst.len == 0 or src.len == 0) {
        return error.InvalidData;
    }

    var dst_len: c_ulong = dst.len;
    const result = c.compress2(
        dst.ptr,
        &dst_len,
        src.ptr,
        @intCast(src.len),
        level,
    );

    if (result != c.Z_OK) {
        return error.CompressionFailed;
    }

    return @intCast(dst_len);
}

/// Compress data using default compression level
pub fn compressDefault(dst: []u8, src: []const u8) CompressionError!usize {
    return compress(dst, src, c.Z_DEFAULT_COMPRESSION);
}

/// Decompress data using zlib
/// Returns the actual decompressed size
pub fn decompress(dst: []u8, src: []const u8) CompressionError!usize {
    if (dst.len == 0 or src.len == 0) {
        return error.InvalidData;
    }

    var dst_len: c_ulong = dst.len;
    const result = c.uncompress(
        dst.ptr,
        &dst_len,
        src.ptr,
        @intCast(src.len),
    );

    if (result != c.Z_OK) {
        return error.DecompressionFailed;
    }

    return @intCast(dst_len);
}

/// Compress data and allocate output buffer
/// Caller owns returned memory
pub fn compressAlloc(allocator: std.mem.Allocator, src: []const u8, level: i32) ![]u8 {
    const max_size = calcCompressedSize(src.len);
    const dst = try allocator.alloc(u8, max_size);
    errdefer allocator.free(dst);

    const actual_size = try compress(dst, src, level);

    // Shrink to actual size
    if (actual_size < max_size) {
        return allocator.realloc(dst, actual_size);
    }

    return dst;
}

/// Compress data and allocate output buffer (default compression level)
pub fn compressAllocDefault(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    return compressAlloc(allocator, src, c.Z_DEFAULT_COMPRESSION);
}

/// Decompress data and allocate output buffer
/// Caller owns returned memory
/// original_size must be known (stored separately)
pub fn decompressAlloc(allocator: std.mem.Allocator, src: []const u8, original_size: usize) ![]u8 {
    const dst = try allocator.alloc(u8, original_size);
    errdefer allocator.free(dst);

    const actual_size = try decompress(dst, src);

    if (actual_size != original_size) {
        return error.DecompressionFailed;
    }

    return dst;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Compression: compress and decompress simple data" {
    const original = "Hello, World! This is a test of compression. " ** 5; // Repeat for better compression

    // Compress
    const max_compressed = calcCompressedSize(original.len);
    var compressed = try testing.allocator.alloc(u8, max_compressed);
    defer testing.allocator.free(compressed);

    const compressed_size = try compressDefault(compressed, original);
    try testing.expect(compressed_size > 0);
    try testing.expect(compressed_size < original.len); // Should be smaller

    // Decompress
    const decompressed = try testing.allocator.alloc(u8, original.len);
    defer testing.allocator.free(decompressed);

    const decompressed_size = try decompress(decompressed, compressed[0..compressed_size]);
    try testing.expectEqual(original.len, decompressed_size);
    try testing.expectEqualStrings(original, decompressed);
}
test "Compression: compressAlloc and decompressAlloc" {
    const original = "The quick brown fox jumps over the lazy dog. " ** 10;

    // Compress with allocation
    const compressed = try compressAllocDefault(testing.allocator, original);
    defer testing.allocator.free(compressed);

    try testing.expect(compressed.len > 0);
    try testing.expect(compressed.len < original.len);

    // Decompress with allocation
    const decompressed = try decompressAlloc(testing.allocator, compressed, original.len);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualStrings(original, decompressed);
}

test "Compression: large data" {
    // Create 10KB of repetitive data (should compress well)
    const size = 10 * 1024;
    const original = try testing.allocator.alloc(u8, size);
    defer testing.allocator.free(original);

    // Fill with pattern
    for (original, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    // Compress
    const compressed = try compressAllocDefault(testing.allocator, original);
    defer testing.allocator.free(compressed);

    try testing.expect(compressed.len > 0);
    try testing.expect(compressed.len < original.len);

    const ratio = @as(f64, @floatFromInt(compressed.len)) / @as(f64, @floatFromInt(original.len));
    std.debug.print("Compression ratio: {d:.2}%\n", .{ratio * 100});

    // Decompress
    const decompressed = try decompressAlloc(testing.allocator, compressed, original.len);
    defer testing.allocator.free(decompressed);

    try testing.expectEqualSlices(u8, original, decompressed);
}

test "Compression: different compression levels" {
    const original = "abcdefghijklmnopqrstuvwxyz" ** 100;

    // Test different levels
    const levels = [_]i32{ c.Z_BEST_SPEED, c.Z_DEFAULT_COMPRESSION, c.Z_BEST_COMPRESSION };

    for (levels) |level| {
        const compressed = try compressAlloc(testing.allocator, original, level);
        defer testing.allocator.free(compressed);

        try testing.expect(compressed.len > 0);

        const decompressed = try decompressAlloc(testing.allocator, compressed, original.len);
        defer testing.allocator.free(decompressed);

        try testing.expectEqualStrings(original, decompressed);
    }
}

test "Compression: empty data error" {
    var buf: [100]u8 = undefined;
    try testing.expectError(error.InvalidData, compressDefault(&buf, &[_]u8{}));
    try testing.expectError(error.InvalidData, decompress(&buf, &[_]u8{}));
}

test "Compression: calcCompressedSize" {
    try testing.expectEqual(@as(usize, 256), calcCompressedSize(0));
    try testing.expectEqual(@as(usize, 2256), calcCompressedSize(1000));
    try testing.expectEqual(@as(usize, 20736), calcCompressedSize(10240));
}
