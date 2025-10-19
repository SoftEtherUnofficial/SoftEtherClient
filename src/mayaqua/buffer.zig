//! SoftEther Buffer Management Module
//!
//! This module provides dynamic buffer operations for reading and writing binary data.
//! It's used throughout the SoftEther VPN codebase for packet construction, data
//! serialization, and stream handling.
//!
//! Key Features:
//! - Dynamic buffer allocation with automatic growth
//! - Read/write operations with cursor tracking
//! - Seek operations (SEEK_SET, SEEK_CUR, SEEK_END)
//! - Zero-copy operations where possible
//! - Memory-efficient buffer management
//!
//! Usage:
//! ```zig
//! const buffer = @import("mayaqua/buffer.zig");
//! const allocator = std.heap.page_allocator;
//!
//! // Create a buffer
//! var buf = try buffer.Buffer.init(allocator);
//! defer buf.deinit();
//!
//! // Write data
//! try buf.write(&[_]u8{1, 2, 3, 4});
//! try buf.writeInt(u32, 0x12345678);
//!
//! // Read data back
//! buf.seekSet(0);
//! var data: [4]u8 = undefined;
//! _ = try buf.read(&data);
//! const value = try buf.readInt(u32);
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;

/// Seek modes (compatible with C SEEK_* constants)
pub const SeekMode = enum(u8) {
    set = 0, // SEEK_SET: absolute position
    cur = 1, // SEEK_CUR: relative to current
    end = 2, // SEEK_END: relative to end
};

/// Dynamic buffer for read/write operations
pub const Buffer = struct {
    data: []u8, // Actual data
    size: usize, // Used size
    capacity: usize, // Allocated capacity
    position: usize, // Current read/write position
    allocator: Allocator,

    /// Initial capacity for new buffers
    const INITIAL_CAPACITY: usize = 4096;

    /// Initialize an empty buffer
    pub fn init(allocator: Allocator) !*Buffer {
        const self = try allocator.create(Buffer);
        const data = try allocator.alloc(u8, INITIAL_CAPACITY);

        self.* = .{
            .data = data,
            .size = 0,
            .capacity = INITIAL_CAPACITY,
            .position = 0,
            .allocator = allocator,
        };

        return self;
    }

    /// Initialize buffer with specific capacity
    pub fn initCapacity(allocator: Allocator, capacity: usize) !*Buffer {
        const self = try allocator.create(Buffer);
        const data = try allocator.alloc(u8, capacity);

        self.* = .{
            .data = data,
            .size = 0,
            .capacity = capacity,
            .position = 0,
            .allocator = allocator,
        };

        return self;
    }

    /// Initialize buffer from existing data (copies the data)
    pub fn fromSlice(allocator: Allocator, source: []const u8) !*Buffer {
        const self = try allocator.create(Buffer);
        const data = try allocator.dupe(u8, source);

        self.* = .{
            .data = data,
            .size = source.len,
            .capacity = source.len,
            .position = 0,
            .allocator = allocator,
        };

        return self;
    }

    /// Free buffer memory
    pub fn deinit(self: *Buffer) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }

    /// Clear buffer (reset size and position, keep capacity)
    pub fn clear(self: *Buffer) void {
        self.size = 0;
        self.position = 0;
    }

    /// Ensure buffer has enough capacity
    fn ensureCapacity(self: *Buffer, required: usize) !void {
        if (required <= self.capacity) return;

        // Grow by 2x or to required size, whichever is larger
        var new_capacity = self.capacity * 2;
        while (new_capacity < required) {
            new_capacity *= 2;
        }

        const new_data = try self.allocator.realloc(self.data, new_capacity);
        self.data = new_data;
        self.capacity = new_capacity;
    }

    /// Write data to buffer at current position
    pub fn write(self: *Buffer, data: []const u8) !void {
        if (data.len == 0) return;

        const end_pos = self.position + data.len;
        try self.ensureCapacity(end_pos);

        @memcpy(self.data[self.position..][0..data.len], data);
        self.position = end_pos;

        if (end_pos > self.size) {
            self.size = end_pos;
        }
    }

    /// Write another buffer's data
    pub fn writeBuffer(self: *Buffer, other: *const Buffer) !void {
        try self.write(other.data[0..other.size]);
    }

    /// Write a single byte
    pub fn writeByte(self: *Buffer, byte: u8) !void {
        try self.write(&[_]u8{byte});
    }

    /// Write an integer (native endian)
    pub fn writeInt(self: *Buffer, comptime T: type, value: T) !void {
        const bytes = mem.toBytes(value);
        try self.write(&bytes);
    }

    /// Write an integer (big endian)
    pub fn writeIntBig(self: *Buffer, comptime T: type, value: T) !void {
        var buf: [@sizeOf(T)]u8 = undefined;
        mem.writeInt(T, &buf, value, .big);
        try self.write(&buf);
    }

    /// Write an integer (little endian)
    pub fn writeIntLittle(self: *Buffer, comptime T: type, value: T) !void {
        var buf: [@sizeOf(T)]u8 = undefined;
        mem.writeInt(T, &buf, value, .little);
        try self.write(&buf);
    }

    /// Read data from buffer at current position
    pub fn read(self: *Buffer, dest: []u8) !usize {
        const available = self.size - self.position;
        const to_read = @min(dest.len, available);

        if (to_read == 0) return 0;

        @memcpy(dest[0..to_read], self.data[self.position..][0..to_read]);
        self.position += to_read;

        return to_read;
    }

    /// Read a single byte
    pub fn readByte(self: *Buffer) !u8 {
        if (self.position >= self.size) return error.EndOfBuffer;

        const byte = self.data[self.position];
        self.position += 1;
        return byte;
    }

    /// Read an integer (native endian)
    pub fn readInt(self: *Buffer, comptime T: type) !T {
        const size = @sizeOf(T);
        if (self.position + size > self.size) return error.EndOfBuffer;

        const value = mem.bytesToValue(T, self.data[self.position..][0..size]);
        self.position += size;
        return value;
    }

    /// Read an integer (big endian)
    pub fn readIntBig(self: *Buffer, comptime T: type) !T {
        const size = @sizeOf(T);
        if (self.position + size > self.size) return error.EndOfBuffer;

        const value = mem.readInt(T, self.data[self.position..][0..size], .big);
        self.position += size;
        return value;
    }

    /// Read an integer (little endian)
    pub fn readIntLittle(self: *Buffer, comptime T: type) !T {
        const size = @sizeOf(T);
        if (self.position + size > self.size) return error.EndOfBuffer;

        const value = mem.readInt(T, self.data[self.position..][0..size], .little);
        self.position += size;
        return value;
    }

    /// Read all remaining data
    pub fn readRemaining(self: *Buffer, allocator: Allocator) ![]u8 {
        const remaining_bytes = self.size - self.position;
        if (remaining_bytes == 0) return &[_]u8{};

        const data = try allocator.dupe(u8, self.data[self.position..self.size]);
        self.position = self.size;
        return data;
    }

    /// Peek at data without advancing position
    pub fn peek(self: *const Buffer, dest: []u8) !usize {
        const available = self.size - self.position;
        const to_read = @min(dest.len, available);

        if (to_read == 0) return 0;

        @memcpy(dest[0..to_read], self.data[self.position..][0..to_read]);
        return to_read;
    }

    /// Seek to absolute position
    pub fn seekSet(self: *Buffer, offset: usize) void {
        self.position = @min(offset, self.size);
    }

    /// Seek relative to current position
    pub fn seekCur(self: *Buffer, offset: isize) void {
        if (offset < 0) {
            const abs_offset = @as(usize, @intCast(-offset));
            if (abs_offset > self.position) {
                self.position = 0;
            } else {
                self.position -= abs_offset;
            }
        } else {
            const new_pos = self.position + @as(usize, @intCast(offset));
            self.position = @min(new_pos, self.size);
        }
    }

    /// Seek relative to end
    pub fn seekEnd(self: *Buffer, offset: isize) void {
        if (offset <= 0) {
            const abs_offset = @as(usize, @intCast(-offset));
            if (abs_offset > self.size) {
                self.position = 0;
            } else {
                self.position = self.size - abs_offset;
            }
        } else {
            self.position = self.size;
        }
    }

    /// Generic seek operation
    pub fn seek(self: *Buffer, offset: isize, mode: SeekMode) void {
        switch (mode) {
            .set => self.seekSet(@intCast(if (offset < 0) 0 else offset)),
            .cur => self.seekCur(offset),
            .end => self.seekEnd(offset),
        }
    }

    /// Get current position
    pub fn tell(self: *const Buffer) usize {
        return self.position;
    }

    /// Get used size
    pub fn getSize(self: *const Buffer) usize {
        return self.size;
    }

    /// Get remaining bytes from current position
    pub fn remaining(self: *const Buffer) usize {
        return self.size - self.position;
    }

    /// Check if at end of buffer
    pub fn isEof(self: *const Buffer) bool {
        return self.position >= self.size;
    }

    /// Get slice of current data (zero-copy)
    pub fn getSlice(self: *const Buffer) []const u8 {
        return self.data[0..self.size];
    }

    /// Get slice of remaining data (zero-copy)
    pub fn getRemainingSlice(self: *const Buffer) []const u8 {
        return self.data[self.position..self.size];
    }

    /// Clone buffer (creates new copy)
    pub fn clone(self: *const Buffer, allocator: Allocator) !*Buffer {
        return fromSlice(allocator, self.data[0..self.size]);
    }

    /// Compare two buffers
    pub fn eql(self: *const Buffer, other: *const Buffer) bool {
        if (self.size != other.size) return false;
        return mem.eql(u8, self.data[0..self.size], other.data[0..other.size]);
    }

    /// Resize buffer to exact size (truncate or extend)
    pub fn resize(self: *Buffer, new_size: usize) !void {
        try self.ensureCapacity(new_size);
        self.size = new_size;
        if (self.position > self.size) {
            self.position = self.size;
        }
    }

    /// Get mutable slice of data (for zero-copy operations)
    pub fn getMutableSlice(self: *Buffer) []u8 {
        return self.data[0..self.size];
    }
};

//
// Tests
//

test "Buffer - basic write and read" {
    const allocator = std.testing.allocator;

    var buf = try Buffer.init(allocator);
    defer buf.deinit();

    // Write some data
    try buf.write(&[_]u8{ 1, 2, 3, 4, 5 });
    try std.testing.expectEqual(@as(usize, 5), buf.getSize());
    try std.testing.expectEqual(@as(usize, 5), buf.tell());

    // Seek to start and read
    buf.seekSet(0);
    var data: [5]u8 = undefined;
    const read_count = try buf.read(&data);

    try std.testing.expectEqual(@as(usize, 5), read_count);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5 }, &data);
}

test "Buffer - integer operations" {
    const allocator = std.testing.allocator;

    var buf = try Buffer.init(allocator);
    defer buf.deinit();

    // Write integers
    try buf.writeIntBig(u32, 0x12345678);
    try buf.writeIntLittle(u16, 0xABCD);

    try std.testing.expectEqual(@as(usize, 6), buf.getSize());

    // Read back
    buf.seekSet(0);
    const val1 = try buf.readIntBig(u32);
    const val2 = try buf.readIntLittle(u16);

    try std.testing.expectEqual(@as(u32, 0x12345678), val1);
    try std.testing.expectEqual(@as(u16, 0xABCD), val2);
}

test "Buffer - seek operations" {
    const allocator = std.testing.allocator;

    var buf = try Buffer.init(allocator);
    defer buf.deinit();

    try buf.write(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });

    // Seek absolute
    buf.seekSet(5);
    try std.testing.expectEqual(@as(usize, 5), buf.tell());

    // Seek relative
    buf.seekCur(2);
    try std.testing.expectEqual(@as(usize, 7), buf.tell());

    buf.seekCur(-3);
    try std.testing.expectEqual(@as(usize, 4), buf.tell());

    // Seek from end
    buf.seekEnd(-2);
    try std.testing.expectEqual(@as(usize, 8), buf.tell());
}

test "Buffer - auto growth" {
    const allocator = std.testing.allocator;

    var buf = try Buffer.initCapacity(allocator, 4);
    defer buf.deinit();

    // Write more than initial capacity
    try buf.write(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });

    try std.testing.expectEqual(@as(usize, 8), buf.getSize());
    try std.testing.expect(buf.capacity >= 8);
}

test "Buffer - fromSlice" {
    const allocator = std.testing.allocator;

    const data = [_]u8{ 10, 20, 30, 40, 50 };
    var buf = try Buffer.fromSlice(allocator, &data);
    defer buf.deinit();

    try std.testing.expectEqual(@as(usize, 5), buf.getSize());

    var read_data: [5]u8 = undefined;
    _ = try buf.read(&read_data);
    try std.testing.expectEqualSlices(u8, &data, &read_data);
}

test "Buffer - clone and compare" {
    const allocator = std.testing.allocator;

    var buf1 = try Buffer.init(allocator);
    defer buf1.deinit();

    try buf1.write(&[_]u8{ 1, 2, 3, 4, 5 });

    var buf2 = try buf1.clone(allocator);
    defer buf2.deinit();

    try std.testing.expect(buf1.eql(buf2));

    // Modify buf2
    try buf2.writeByte(6);
    try std.testing.expect(!buf1.eql(buf2));
}

test "Buffer - remaining data" {
    const allocator = std.testing.allocator;

    var buf = try Buffer.init(allocator);
    defer buf.deinit();

    try buf.write(&[_]u8{ 1, 2, 3, 4, 5 });
    buf.seekSet(2);

    try std.testing.expectEqual(@as(usize, 3), buf.remaining());
    try std.testing.expect(!buf.isEof());

    buf.seekSet(5);
    try std.testing.expect(buf.isEof());
}

test "Buffer - peek" {
    const allocator = std.testing.allocator;

    var buf = try Buffer.init(allocator);
    defer buf.deinit();

    try buf.write(&[_]u8{ 1, 2, 3, 4, 5 });
    buf.seekSet(0);

    // Peek doesn't advance position
    var peek_data: [3]u8 = undefined;
    _ = try buf.peek(&peek_data);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, &peek_data);
    try std.testing.expectEqual(@as(usize, 0), buf.tell());

    // Read does advance position
    var read_data: [3]u8 = undefined;
    _ = try buf.read(&read_data);
    try std.testing.expectEqual(@as(usize, 3), buf.tell());
}

test "Buffer - clear" {
    const allocator = std.testing.allocator;

    var buf = try Buffer.init(allocator);
    defer buf.deinit();

    try buf.write(&[_]u8{ 1, 2, 3, 4, 5 });
    const old_capacity = buf.capacity;

    buf.clear();

    try std.testing.expectEqual(@as(usize, 0), buf.getSize());
    try std.testing.expectEqual(@as(usize, 0), buf.tell());
    try std.testing.expectEqual(old_capacity, buf.capacity); // Capacity preserved
}
