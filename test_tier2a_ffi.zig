const std = @import("std");
const c = @cImport({
    @cInclude("mayaqua_ffi.h");
});

test "compress and decompress with Mayaqua FFI" {
    // Test data - use longer string to ensure compression
    const original = "Hello, World! This is a test of zlib compression from Zig! " ** 5;
    const data: [*c]const u8 = @ptrCast(original);
    const data_len: c_uint = @intCast(original.len);

    // Compress
    var compressed_len: c_uint = 0;
    const compressed = c.mayaqua_compress_deflate(data, data_len, &compressed_len);
    defer c.mayaqua_free(@ptrCast(compressed), compressed_len);

    try std.testing.expect(compressed != null);
    try std.testing.expect(compressed_len > 0);
    // Note: For short strings, compression may not reduce size due to overhead
    // So we just verify we got some output

    std.debug.print("Original size: {}, Compressed size: {}\n", .{ data_len, compressed_len });

    // Decompress
    var decompressed_len: c_uint = 0;
    const decompressed = c.mayaqua_decompress_deflate(compressed, compressed_len, &decompressed_len);
    defer c.mayaqua_free(@ptrCast(decompressed), decompressed_len);

    try std.testing.expect(decompressed != null);
    try std.testing.expectEqual(data_len, decompressed_len);

    // Verify data matches
    const decompressed_slice = decompressed[0..decompressed_len];
    try std.testing.expectEqualSlices(u8, original, decompressed_slice);

    std.debug.print("✅ Compression roundtrip successful!\n", .{});
}

test "HTTP request creation and serialization with Mayaqua FFI" {
    // Create HTTP request
    const method = "GET";
    const path = "/api/test";

    const request = c.mayaqua_http_request_new(method, path);
    defer c.mayaqua_http_request_free(request);

    try std.testing.expect(request != null);

    // Add headers
    const result1 = c.mayaqua_http_request_add_header(request, "Host", "example.com");
    try std.testing.expect(result1);

    const result2 = c.mayaqua_http_request_add_header(request, "User-Agent", "Mayaqua-Zig/1.0");
    try std.testing.expect(result2);

    // Set body
    const body = "test=data";
    const result3 = c.mayaqua_http_request_set_body(request, @ptrCast(body), @intCast(body.len));
    try std.testing.expect(result3);

    // Serialize to bytes
    var bytes_len: c_uint = 0;
    const bytes = c.mayaqua_http_request_to_bytes(request, &bytes_len);
    defer c.mayaqua_free(@ptrCast(bytes), bytes_len);

    try std.testing.expect(bytes != null);
    try std.testing.expect(bytes_len > 0);

    // Print the HTTP request
    const request_str = bytes[0..bytes_len];
    std.debug.print("\n--- HTTP Request ---\n{s}\n--- End Request ---\n", .{request_str});

    // Verify it contains expected elements
    try std.testing.expect(std.mem.indexOf(u8, request_str, "GET /api/test HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "Host: example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "User-Agent: Mayaqua-Zig/1.0") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_str, "test=data") != null);

    std.debug.print("✅ HTTP request creation successful!\n", .{});
}

test "memory allocation with Mayaqua FFI" {
    // Test basic memory operations
    const ptr = c.mayaqua_malloc(1024);
    defer c.mayaqua_free(ptr, 1024);

    try std.testing.expect(ptr != null);

    // Test zero-initialized memory
    const zero_ptr = c.mayaqua_zero_malloc(512);
    defer c.mayaqua_free(zero_ptr, 512);

    try std.testing.expect(zero_ptr != null);

    // Verify it's zeroed
    const zero_slice: [*c]u8 = @ptrCast(zero_ptr);
    for (0..512) |i| {
        try std.testing.expectEqual(@as(u8, 0), zero_slice[i]);
    }

    std.debug.print("✅ Memory allocation successful!\n", .{});
}

test "buffer operations with Mayaqua FFI" {
    const buf = c.mayaqua_buf_new();
    defer c.mayaqua_buf_free(buf);

    try std.testing.expect(buf != null);

    // Write data
    const data = "Hello from Zig!";
    const written = c.mayaqua_buf_write(buf, @ptrCast(data), @intCast(data.len));
    try std.testing.expectEqual(@as(c_uint, @intCast(data.len)), written);

    // Check size
    const size = c.mayaqua_buf_size(buf);
    try std.testing.expectEqual(@as(c_uint, @intCast(data.len)), size);

    // Seek back to beginning before reading
    c.mayaqua_buf_seek(buf, 0);

    // Read data back - read exactly the amount we wrote
    var read_buf: [128]u8 = undefined;
    const read_count = c.mayaqua_buf_read(buf, @ptrCast(&read_buf), @intCast(data.len) // Read only what we wrote, not the whole buffer
    );
    try std.testing.expectEqual(@as(c_uint, @intCast(data.len)), read_count);

    const read_slice = read_buf[0..data.len];
    try std.testing.expectEqualSlices(u8, data, read_slice);

    std.debug.print("✅ Buffer operations successful!\n", .{});
}
