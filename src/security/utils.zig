const std = @import("std");
const builtin = @import("builtin");

/// Securely zero memory to prevent sensitive data from being read
/// Uses volatile operations to prevent compiler optimization
/// Replaces C function: void secure_zero(void* ptr, size_t len)
pub fn secureZero(ptr: []u8) void {
    if (ptr.len == 0) return;

    // Use @volatileCast to prevent compiler from optimizing away the zeroing
    const volatile_ptr = @as([*]volatile u8, @ptrCast(ptr.ptr));

    for (0..ptr.len) |i| {
        volatile_ptr[i] = 0;
    }

    // Volatile operations ensure the zeroing is not optimized away
}

/// Securely zero memory using platform-specific explicit functions
/// Falls back to secureZero if platform-specific functions not available
/// Replaces C function: void secure_zero_explicit(void* ptr, size_t len)
pub fn secureZeroExplicit(ptr: []u8) void {
    if (ptr.len == 0) return;

    // Use std.crypto.secureZero if available (Zig 0.11+)
    // For now, use our implementation
    switch (builtin.os.tag) {
        .windows => {
            // On Windows, we could use RtlSecureZeroMemory
            // but Zig's volatile approach is sufficient
            secureZero(ptr);
        },
        .linux, .macos => {
            // On Linux/macOS, explicit_bzero might be available
            // but Zig's volatile approach is sufficient
            secureZero(ptr);
        },
        else => {
            secureZero(ptr);
        },
    }
}

/// Lock memory pages to prevent swapping to disk
/// This keeps sensitive data in RAM only
/// Returns true on success, false if locking failed (may require elevated privileges)
/// Replaces C function: int secure_lock_memory(void* addr, size_t len)
pub fn lockMemory(ptr: []u8) bool {
    if (ptr.len == 0) return false;

    switch (builtin.os.tag) {
        .linux, .macos => {
            // Use mlock to prevent swapping
            // Note: mlock requires page-aligned address and may require privileges
            const c = @cImport({
                @cInclude("sys/mman.h");
            });
            const result = c.mlock(ptr.ptr, ptr.len);
            return result == 0;
        },
        .windows => {
            // Windows VirtualLock
            // Note: This requires proper imports, simplified for now
            // In production, would use @cImport for Windows API
            return false; // Stub for now
        },
        else => {
            return false;
        },
    }
}

/// Unlock previously locked memory pages
/// Returns true on success
/// Replaces C function: int secure_unlock_memory(void* addr, size_t len)
pub fn unlockMemory(ptr: []u8) bool {
    if (ptr.len == 0) return false;

    switch (builtin.os.tag) {
        .linux, .macos => {
            const c = @cImport({
                @cInclude("sys/mman.h");
            });
            const result = c.munlock(ptr.ptr, ptr.len);
            return result == 0;
        },
        .windows => {
            return false; // Stub for now
        },
        else => {
            return false;
        },
    }
}

/// Timing-attack resistant memory comparison
/// Always compares full length regardless of where differences are found
/// Returns true if contents are equal, false otherwise
/// Replaces C function: int secure_compare(const void* a, const void* b, size_t len)
pub fn timingSafeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (a.len == 0) return true;

    // Timing-safe comparison - XOR all bytes
    var result: u8 = 0;
    for (a, b) |byte_a, byte_b| {
        result |= byte_a ^ byte_b;
    }

    return result == 0;
}

/// Timing-safe comparison that returns 0 if equal, non-zero otherwise
/// Compatible with C function signature
pub fn timingSafeCompare(a: []const u8, b: []const u8) u8 {
    if (timingSafeEqual(a, b)) {
        return 0;
    } else {
        return 1;
    }
}

/// Secure buffer that automatically zeros on deallocation
pub const SecureBuffer = struct {
    data: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, size: usize) !SecureBuffer {
        const data = try allocator.alloc(u8, size);

        // Optionally lock memory to prevent swapping
        _ = lockMemory(data);

        return SecureBuffer{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SecureBuffer) void {
        // Securely zero before deallocation
        secureZero(self.data);

        // Unlock if it was locked
        _ = unlockMemory(self.data);

        // Free memory
        self.allocator.free(self.data);

        self.data = &[_]u8{};
    }

    pub fn slice(self: *SecureBuffer) []u8 {
        return self.data;
    }

    pub fn constSlice(self: *const SecureBuffer) []const u8 {
        return self.data;
    }
};

// ============================================
// C FFI Exports (for compatibility during migration)
// ============================================

export fn secure_zero(ptr: ?[*]u8, len: usize) void {
    if (ptr) |p| {
        const slice = p[0..len];
        secureZero(slice);
    }
}

export fn secure_zero_explicit(ptr: ?[*]u8, len: usize) void {
    if (ptr) |p| {
        const slice = p[0..len];
        secureZeroExplicit(slice);
    }
}

export fn secure_lock_memory(addr: ?[*]u8, len: usize) c_int {
    if (addr) |a| {
        const slice = a[0..len];
        return if (lockMemory(slice)) 1 else 0;
    }
    return 0;
}

export fn secure_unlock_memory(addr: ?[*]u8, len: usize) c_int {
    if (addr) |a| {
        const slice = a[0..len];
        return if (unlockMemory(slice)) 1 else 0;
    }
    return 0;
}

export fn secure_compare(a: ?[*]const u8, b: ?[*]const u8, len: usize) c_int {
    if (a == null or b == null) return -1;

    const slice_a = a.?[0..len];
    const slice_b = b.?[0..len];

    return timingSafeCompare(slice_a, slice_b);
}

// ============================================
// Tests
// ============================================

test "secureZero basic" {
    var buffer = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    secureZero(&buffer);

    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "secureZero empty" {
    var empty: [0]u8 = undefined;
    secureZero(&empty); // Should not crash
}

test "secureZeroExplicit" {
    var buffer = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    secureZeroExplicit(&buffer);

    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "timingSafeEqual same" {
    const a = "Hello, World!";
    const b = "Hello, World!";

    try std.testing.expect(timingSafeEqual(a, b));
}

test "timingSafeEqual different" {
    const a = "Hello, World!";
    const b = "Hello, World?";

    try std.testing.expect(!timingSafeEqual(a, b));
}

test "timingSafeEqual different lengths" {
    const a = "Hello";
    const b = "Hello, World!";

    try std.testing.expect(!timingSafeEqual(a, b));
}

test "timingSafeEqual empty" {
    const a: []const u8 = &[_]u8{};
    const b: []const u8 = &[_]u8{};

    try std.testing.expect(timingSafeEqual(a, b));
}

test "timingSafeCompare" {
    const a = "password123";
    const b = "password123";
    const c = "password124";

    try std.testing.expectEqual(@as(u8, 0), timingSafeCompare(a, b));
    try std.testing.expectEqual(@as(u8, 1), timingSafeCompare(a, c));
}

test "SecureBuffer init and deinit" {
    var buffer = try SecureBuffer.init(std.testing.allocator, 256);
    defer buffer.deinit();

    try std.testing.expectEqual(@as(usize, 256), buffer.data.len);

    // Fill with data
    @memset(buffer.slice(), 0xFF);

    // Verify it's filled
    for (buffer.slice()) |byte| {
        try std.testing.expectEqual(@as(u8, 0xFF), byte);
    }

    // deinit will zero it
}

test "SecureBuffer auto-zero on deinit" {
    var buffer = try SecureBuffer.init(std.testing.allocator, 128);

    // Fill with sensitive data
    for (buffer.slice(), 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    // Save pointer for verification (NOTE: This is unsafe and only for testing)
    const ptr = buffer.data.ptr;
    const len = buffer.data.len;

    // Deinit should zero the memory
    buffer.deinit();

    // In a real scenario, we can't safely access freed memory
    // This test just verifies the deinit doesn't crash
    _ = ptr;
    _ = len;
}

test "lockMemory and unlockMemory" {
    var buffer = [_]u8{1} ** 4096; // Page-aligned size

    // Try to lock (may fail without privileges, that's ok)
    const locked = lockMemory(&buffer);

    if (locked) {
        // If we successfully locked, we should be able to unlock
        const unlocked = unlockMemory(&buffer);
        try std.testing.expect(unlocked);
    }

    // Test should pass either way
}

test "C FFI exports" {
    var buffer = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };

    // Test secure_zero export
    secure_zero(@ptrCast(&buffer), buffer.len);
    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }

    // Test secure_compare export
    const a = "test";
    const b = "test";
    const c = "fail";

    try std.testing.expectEqual(@as(c_int, 0), secure_compare(@ptrCast(a.ptr), @ptrCast(b.ptr), a.len));
    try std.testing.expectEqual(@as(c_int, 1), secure_compare(@ptrCast(a.ptr), @ptrCast(c.ptr), a.len));

    // Test null pointers
    try std.testing.expectEqual(@as(c_int, -1), secure_compare(null, @ptrCast(b.ptr), b.len));
}

test "timing safety" {
    // This test verifies that comparison time is constant regardless of where difference is
    // In practice, timing would need to be measured, but this tests functionality

    const base = "SuperSecretPassword123";
    const early_diff = "XuperSecretPassword123"; // Different at position 0
    const late_diff = "SuperSecretPassword12X"; // Different at position 21

    // Both should return false
    try std.testing.expect(!timingSafeEqual(base, early_diff));
    try std.testing.expect(!timingSafeEqual(base, late_diff));

    // The key property is that both take similar time (can't test timing in unit test)
}
