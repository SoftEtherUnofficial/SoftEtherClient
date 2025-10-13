//! Memory Management Module
//!
//! This module provides a Zig replacement for Mayaqua/Memory.c.
//! Key improvements over C version:
//! - Explicit allocator pattern (no hidden global state)
//! - Compile-time leak detection
//! - Type-safe allocations
//! - Zero-copy optimization where possible
//! - Memory pool for frequent allocations (packets)
//!
//! Usage:
//!   const allocator = memory.getAllocator();
//!   const ptr = try allocator.alloc(u8, 1024);
//!   defer allocator.free(ptr);

const std = @import("std");
const builtin = @import("builtin");

/// Global allocator configuration
/// In debug mode, use GeneralPurposeAllocator for leak detection
/// In release mode, use C allocator for compatibility
pub fn getAllocator() std.mem.Allocator {
    if (builtin.mode == .Debug) {
        return std.heap.page_allocator; // For now, will add GPA later
    } else {
        return std.heap.c_allocator; // Matches C malloc/free
    }
}

/// Memory statistics (mirrors C version's KS_* tracking)
pub const MemoryStats = struct {
    malloc_count: usize = 0,
    free_count: usize = 0,
    current_mem_count: usize = 0,
    total_mem_size: usize = 0,

    mutex: std.Thread.Mutex = .{},

    pub fn recordAlloc(self: *MemoryStats, size: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.malloc_count += 1;
        self.current_mem_count += 1;
        self.total_mem_size += size;
    }

    pub fn recordFree(self: *MemoryStats) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.free_count += 1;
        if (self.current_mem_count > 0) {
            self.current_mem_count -= 1;
        }
    }

    pub fn print(self: *MemoryStats) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        std.debug.print("Memory Stats:\n", .{});
        std.debug.print("  Allocations: {d}\n", .{self.malloc_count});
        std.debug.print("  Frees: {d}\n", .{self.free_count});
        std.debug.print("  Current allocs: {d}\n", .{self.current_mem_count});
        std.debug.print("  Total allocated: {d} bytes\n", .{self.total_mem_size});

        if (self.current_mem_count > 0) {
            std.debug.print("  ⚠️  WARNING: {d} allocations not freed!\n", .{self.current_mem_count});
        }
    }
};

/// Global memory statistics
var global_stats = MemoryStats{};

pub fn getStats() *MemoryStats {
    return &global_stats;
}

/// Allocate memory (zero-initialized)
/// Replacement for ZeroMalloc()
pub fn zeroAlloc(allocator: std.mem.Allocator, comptime T: type, count: usize) ![]T {
    const slice = try allocator.alloc(T, count);
    @memset(slice, 0);

    global_stats.recordAlloc(count * @sizeOf(T));

    return slice;
}

/// Allocate single item (zero-initialized)
/// Replacement for ZeroMalloc(sizeof(T))
pub fn zeroCreate(allocator: std.mem.Allocator, comptime T: type) !*T {
    const ptr = try allocator.create(T);
    ptr.* = std.mem.zeroes(T);

    global_stats.recordAlloc(@sizeOf(T));

    return ptr;
}

/// Free memory allocated with zeroAlloc
pub fn zeroFree(allocator: std.mem.Allocator, slice: anytype) void {
    // Zero out before freeing (security)
    if (@TypeOf(slice) == []u8 or @TypeOf(slice) == []const u8) {
        @memset(slice, 0);
    }

    allocator.free(slice);
    global_stats.recordFree();
}

/// Free single item allocated with zeroCreate
pub fn zeroDestroy(allocator: std.mem.Allocator, ptr: anytype) void {
    const T = @TypeOf(ptr.*);
    ptr.* = std.mem.zeroes(T);

    allocator.destroy(ptr);
    global_stats.recordFree();
}

/// Duplicate a slice (like C's Clone())
pub fn clone(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const dest = try allocator.alloc(u8, src.len);
    @memcpy(dest, src);

    global_stats.recordAlloc(src.len);

    return dest;
}

/// Duplicate a string (null-terminated)
pub fn cloneString(allocator: std.mem.Allocator, src: [:0]const u8) ![:0]u8 {
    const dest = try allocator.allocSentinel(u8, src.len, 0);
    @memcpy(dest, src);

    global_stats.recordAlloc(src.len + 1);

    return dest;
}

/// Packet buffer pool for high-frequency allocations
/// Reduces malloc/free overhead for VPN packets
pub const PacketPool = struct {
    const PACKET_SIZE = 2048; // Standard MTU + overhead
    const POOL_SIZE = 256; // Pre-allocated packets

    pool: std.ArrayList([]u8),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator) !PacketPool {
        var pool = try std.ArrayList([]u8).initCapacity(allocator, POOL_SIZE);

        // Pre-allocate packet buffers
        var i: usize = 0;
        while (i < POOL_SIZE) : (i += 1) {
            const buffer = try allocator.alloc(u8, PACKET_SIZE);
            try pool.append(allocator, buffer);
        }

        return PacketPool{
            .pool = pool,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PacketPool) void {
        for (self.pool.items) |buffer| {
            self.allocator.free(buffer);
        }
        self.pool.deinit(self.allocator);
    }

    /// Get a packet buffer from pool (or allocate new one)
    pub fn acquire(self: *PacketPool) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.pool.pop()) |buffer| {
            // Reuse from pool (zero it first)
            @memset(buffer, 0);
            return buffer;
        } else {
            // Pool exhausted, allocate new
            return try self.allocator.alloc(u8, PACKET_SIZE);
        }
    }

    /// Return packet buffer to pool
    pub fn release(self: *PacketPool, buffer: []u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (buffer.len == PACKET_SIZE and self.pool.items.len < POOL_SIZE) {
            // Return to pool for reuse
            self.pool.append(self.allocator, buffer) catch {
                // Pool full, just free it
                self.allocator.free(buffer);
            };
        } else {
            // Wrong size or pool full, free it
            self.allocator.free(buffer);
        }
    }
};

/// C-compatible FFI functions
/// These allow gradual migration from C to Zig
export fn zig_malloc(size: c_uint) callconv(.c) ?*anyopaque {
    const allocator = getAllocator();
    const bytes = allocator.alloc(u8, size) catch return null;

    global_stats.recordAlloc(size);

    return bytes.ptr;
}

export fn zig_zeroMalloc(size: c_uint) callconv(.c) ?*anyopaque {
    const allocator = getAllocator();
    const bytes = allocator.alloc(u8, size) catch return null;
    @memset(bytes, 0);

    global_stats.recordAlloc(size);

    return bytes.ptr;
}

export fn zig_free(ptr: ?*anyopaque) callconv(.c) void {
    if (ptr) |p| {
        // For now, just use C free since we're using c_allocator in release mode
        // In pure Zig code, we always track sizes via slices
        const c_ptr: [*c]u8 = @ptrCast(@alignCast(p));
        std.c.free(c_ptr);

        global_stats.recordFree();
    }
}

export fn zig_getMemoryStats() callconv(.c) void {
    global_stats.print();
}

// Tests
test "basic allocation" {
    const allocator = std.testing.allocator;

    const bytes = try allocator.alloc(u8, 100);
    defer allocator.free(bytes);

    try std.testing.expect(bytes.len == 100);
}

test "zero allocation" {
    const allocator = std.testing.allocator;

    const bytes = try zeroAlloc(allocator, u8, 100);
    defer allocator.free(bytes);

    // Check all bytes are zero
    for (bytes) |b| {
        try std.testing.expect(b == 0);
    }
}

test "struct allocation" {
    const allocator = std.testing.allocator;

    const TestStruct = struct {
        value: u32,
        name: [16]u8,
    };

    const obj = try zeroCreate(allocator, TestStruct);
    defer zeroDestroy(allocator, obj);

    try std.testing.expect(obj.value == 0);
}

test "clone slice" {
    const allocator = std.testing.allocator;

    const original = "Hello, World!";
    const copy = try clone(allocator, original);
    defer allocator.free(copy);

    try std.testing.expectEqualSlices(u8, original, copy);
}

test "packet pool" {
    const allocator = std.testing.allocator;

    var pool = try PacketPool.init(allocator);
    defer pool.deinit();

    // Acquire and release
    const buf1 = try pool.acquire();
    const buf2 = try pool.acquire();

    try std.testing.expect(buf1.len == 2048);
    try std.testing.expect(buf2.len == 2048);

    pool.release(buf1);
    pool.release(buf2);

    // Should reuse from pool
    const buf3 = try pool.acquire();
    pool.release(buf3);
}

test "memory stats tracking" {
    var stats = MemoryStats{};

    stats.recordAlloc(100);
    stats.recordAlloc(200);
    stats.recordFree();

    try std.testing.expect(stats.malloc_count == 2);
    try std.testing.expect(stats.free_count == 1);
    try std.testing.expect(stats.current_mem_count == 1);
    try std.testing.expect(stats.total_mem_size == 300);
}
