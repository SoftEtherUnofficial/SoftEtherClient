//! Test Mayaqua FFI integration from Zig
//!
//! This demonstrates using the Rust Mayaqua library from Zig code.

const std = @import("std");

const c = @cImport({
    @cInclude("mayaqua_ffi.h");
});

pub fn main() !void {
    std.debug.print("=== Mayaqua-Rust FFI Integration Test ===\n\n", .{});

    // Initialize library
    const init_result = c.mayaqua_init();
    std.debug.print("Library initialized: {}\n", .{init_result});

    // Get version
    const version = c.mayaqua_version();
    const version_str = std.mem.span(@as([*:0]const u8, @ptrCast(version)));
    std.debug.print("Version: {s}\n\n", .{version_str});

    // Test 1: Memory allocation
    std.debug.print("Test 1: Memory Allocation\n", .{});
    const size: c_uint = 1024;
    const ptr = c.mayaqua_malloc(size);
    if (ptr != null) {
        std.debug.print("  ✅ Allocated {} bytes\n", .{size});
        c.mayaqua_free(ptr, size);
        std.debug.print("  ✅ Freed memory\n", .{});
    } else {
        std.debug.print("  ❌ Allocation failed\n", .{});
    }

    // Test 2: Zero malloc
    std.debug.print("\nTest 2: Zero-Initialized Allocation\n", .{});
    const zero_ptr = c.mayaqua_zero_malloc(size);
    if (zero_ptr != null) {
        std.debug.print("  ✅ Allocated {} bytes (zeroed)\n", .{size});

        // Verify it's zeroed
        const bytes = @as([*]u8, @ptrCast(zero_ptr));
        var is_zeroed = true;
        var i: usize = 0;
        while (i < size) : (i += 1) {
            if (bytes[i] != 0) {
                is_zeroed = false;
                break;
            }
        }

        if (is_zeroed) {
            std.debug.print("  ✅ Memory is zeroed\n", .{});
        } else {
            std.debug.print("  ❌ Memory not zeroed\n", .{});
        }

        c.mayaqua_free(zero_ptr, size);
    }

    // Test 3: Buffer operations
    std.debug.print("\nTest 3: Buffer Operations\n", .{});
    const buf = c.mayaqua_buf_new();
    if (buf != null) {
        std.debug.print("  ✅ Created buffer\n", .{});

        // Write data
        const data = "Hello from Zig via Rust-Mayaqua!";
        const written = c.mayaqua_buf_write(buf, data.ptr, data.len);
        std.debug.print("  ✅ Written {} bytes\n", .{written});

        // Check size
        const buf_size = c.mayaqua_buf_size(buf);
        std.debug.print("  ✅ Buffer size: {} bytes\n", .{buf_size});

        if (buf_size == data.len) {
            std.debug.print("  ✅ Size matches written data\n", .{});
        }

        // Get buffer data pointer
        const buf_data = c.mayaqua_buf_data(buf);
        if (buf_data != null) {
            const buf_bytes = @as([*]const u8, @ptrCast(buf_data));
            const buf_slice = buf_bytes[0..buf_size];
            std.debug.print("  ✅ Buffer contents: {s}\n", .{buf_slice});
        }

        // Test seek
        c.mayaqua_buf_seek(buf, 0);
        const pos = c.mayaqua_buf_position(buf);
        std.debug.print("  ✅ Seek to position: {}\n", .{pos});

        // Read data back
        var read_buffer: [256]u8 = undefined;
        const read_count = c.mayaqua_buf_read(buf, &read_buffer, data.len);
        std.debug.print("  ✅ Read {} bytes back\n", .{read_count});

        if (read_count == data.len) {
            const read_slice = read_buffer[0..read_count];
            if (std.mem.eql(u8, read_slice, data)) {
                std.debug.print("  ✅ Read data matches written data\n", .{});
            }
        }

        // Clear buffer
        c.mayaqua_buf_clear(buf);
        const cleared_size = c.mayaqua_buf_size(buf);
        std.debug.print("  ✅ Cleared buffer, size now: {}\n", .{cleared_size});

        // Free buffer
        c.mayaqua_buf_free(buf);
        std.debug.print("  ✅ Freed buffer\n", .{});
    }

    // Test 4: Memory copy
    std.debug.print("\nTest 4: Memory Copy\n", .{});
    const src_data = "Copy this data!";
    var dst_buffer: [256]u8 = undefined;

    c.mayaqua_copy(&dst_buffer, src_data.ptr, src_data.len);
    const dst_slice = dst_buffer[0..src_data.len];

    if (std.mem.eql(u8, dst_slice, src_data)) {
        std.debug.print("  ✅ Memory copied correctly\n", .{});
    } else {
        std.debug.print("  ❌ Memory copy mismatch\n", .{});
    }

    // Test 5: Memory zeroing
    std.debug.print("\nTest 5: Memory Zeroing\n", .{});
    var test_buffer: [64]u8 = undefined;
    @memset(&test_buffer, 0xFF); // Fill with 0xFF

    c.mayaqua_zero(&test_buffer, test_buffer.len);

    var all_zero = true;
    for (test_buffer) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }

    if (all_zero) {
        std.debug.print("  ✅ Memory zeroed correctly\n", .{});
    } else {
        std.debug.print("  ❌ Memory not fully zeroed\n", .{});
    }

    // Cleanup
    c.mayaqua_free_library();

    std.debug.print("\n=== All Tests Completed Successfully! ===\n", .{});
}
