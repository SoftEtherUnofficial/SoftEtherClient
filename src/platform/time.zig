const std = @import("std");
const builtin = @import("builtin");

/// High-resolution timer state
var timer_state: TimerState = .{};
var timer_init_flag = std.atomic.Value(bool).init(false);
var timer_mutex = std.Thread.Mutex{};

const TimerState = struct {
    start_time: i128 = 0,
    frequency: u64 = 1,
};

/// Initialize the timer (called once automatically)
fn initTimer() void {
    timer_mutex.lock();
    defer timer_mutex.unlock();

    if (!timer_init_flag.load(.acquire)) {
        timer_state.start_time = std.time.nanoTimestamp();
        timer_state.frequency = std.time.ns_per_ms; // 1,000,000 ns per ms
        timer_init_flag.store(true, .release);
    }
}

/// Returns milliseconds since program start
/// Replaces C function: UINT64 Tick64(void)
pub fn tick64() u64 {
    if (!timer_init_flag.load(.acquire)) {
        initTimer();
    }

    const now = std.time.nanoTimestamp();
    const elapsed_ns = now - timer_state.start_time;

    // Convert to milliseconds
    return @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
}

/// High-resolution tick (milliseconds)
/// Replaces C function: UINT64 TickHighres64(void)
pub fn tickHighres64() u64 {
    return tick64(); // Same implementation for Zig
}

/// Nanosecond resolution tick
/// Replaces C function: UINT64 TickHighresNano64(void)
pub fn tickHighresNano64() u64 {
    if (!timer_init_flag.load(.acquire)) {
        initTimer();
    }

    const now = std.time.nanoTimestamp();
    const elapsed_ns = now - timer_state.start_time;

    return @intCast(elapsed_ns);
}

/// Convert tick to Unix timestamp (milliseconds since epoch)
/// Replaces C function: void Tick64ToTime64(UINT64 tick, void *time64)
pub fn tick64ToTime64(tick: u64) u64 {
    // Get current Unix timestamp in milliseconds
    const now_ms = std.time.milliTimestamp();
    const program_uptime_ms = tick64();

    // Calculate the timestamp when the program started
    const program_start_ms = now_ms - @as(i64, @intCast(program_uptime_ms));

    // Add the tick offset to get the absolute timestamp
    return @intCast(program_start_ms + @as(i64, @intCast(tick)));
}

/// Sleep for specified milliseconds
pub fn sleepMs(milliseconds: u64) void {
    std.Thread.sleep(milliseconds * std.time.ns_per_ms);
}

/// Sleep for specified microseconds
pub fn sleepUs(microseconds: u64) void {
    std.Thread.sleep(microseconds * std.time.ns_per_us);
}

/// Get current Unix timestamp in milliseconds
pub fn currentTimeMs() i64 {
    return std.time.milliTimestamp();
}

/// Get current Unix timestamp in seconds
pub fn currentTimeSec() i64 {
    return @divTrunc(std.time.milliTimestamp(), 1000);
}

/// Format duration in human-readable format
pub fn formatDuration(allocator: std.mem.Allocator, milliseconds: u64) ![]const u8 {
    const seconds = milliseconds / 1000;
    const minutes = seconds / 60;
    const hours = minutes / 60;
    const days = hours / 24;

    if (days > 0) {
        return try std.fmt.allocPrint(allocator, "{d}d {d}h {d}m {d}s", .{
            days,
            hours % 24,
            minutes % 60,
            seconds % 60,
        });
    } else if (hours > 0) {
        return try std.fmt.allocPrint(allocator, "{d}h {d}m {d}s", .{
            hours,
            minutes % 60,
            seconds % 60,
        });
    } else if (minutes > 0) {
        return try std.fmt.allocPrint(allocator, "{d}m {d}s", .{
            minutes,
            seconds % 60,
        });
    } else if (seconds > 0) {
        return try std.fmt.allocPrint(allocator, "{d}s {d}ms", .{
            seconds,
            milliseconds % 1000,
        });
    } else {
        return try std.fmt.allocPrint(allocator, "{d}ms", .{milliseconds});
    }
}

// ============================================
// C FFI Exports (for compatibility during migration)
// ============================================

export fn Tick64() u64 {
    return tick64();
}

export fn TickHighres64() u64 {
    return tickHighres64();
}

export fn TickHighresNano64() u64 {
    return tickHighresNano64();
}

export fn Tick64ToTime64(tick: u64, time64_ptr: ?*u64) void {
    if (time64_ptr) |ptr| {
        ptr.* = tick64ToTime64(tick);
    }
}

export fn TickToTime(time_struct: ?*anyopaque, tick: u64) void {
    _ = time_struct;
    _ = tick;
    // Stub for compatibility
}

export fn FreeTick64() void {
    // No-op, nothing to free in Zig implementation
}

// ============================================
// Tests
// ============================================

test "tick64 basic" {
    const t1 = tick64();
    std.Thread.sleep(10 * std.time.ns_per_ms);
    const t2 = tick64();

    try std.testing.expect(t2 >= t1);
    try std.testing.expect(t2 - t1 >= 10);
}

test "tick64 monotonic" {
    var prev = tick64();
    for (0..100) |_| {
        const current = tick64();
        try std.testing.expect(current >= prev);
        prev = current;
    }
}

test "tickHighres64" {
    const t1 = tickHighres64();
    std.Thread.sleep(5 * std.time.ns_per_ms);
    const t2 = tickHighres64();

    try std.testing.expect(t2 >= t1);
}

test "tickHighresNano64" {
    const t1 = tickHighresNano64();
    std.Thread.sleep(1 * std.time.ns_per_ms);
    const t2 = tickHighresNano64();

    try std.testing.expect(t2 > t1);
    try std.testing.expect(t2 - t1 >= 1_000_000); // At least 1ms in nanoseconds
}

test "tick64ToTime64" {
    const tick = tick64();
    const time64 = tick64ToTime64(tick);

    // time64 should be a reasonable Unix timestamp (after year 2020)
    try std.testing.expect(time64 > 1600000000000); // Sept 2020
}

test "currentTimeMs" {
    const now = currentTimeMs();
    try std.testing.expect(now > 1600000000000); // After Sept 2020
}

test "currentTimeSec" {
    const now_sec = currentTimeSec();
    try std.testing.expect(now_sec > 1600000000); // After Sept 2020
}

test "sleepMs" {
    const start = tick64();
    sleepMs(50);
    const end = tick64();

    const elapsed = end - start;
    try std.testing.expect(elapsed >= 50);
    try std.testing.expect(elapsed < 100); // Should not take too long
}

test "formatDuration milliseconds" {
    const allocator = std.testing.allocator;
    const str = try formatDuration(allocator, 500);
    defer allocator.free(str);

    try std.testing.expectEqualStrings("500ms", str);
}

test "formatDuration seconds" {
    const allocator = std.testing.allocator;
    const str = try formatDuration(allocator, 5500);
    defer allocator.free(str);

    try std.testing.expectEqualStrings("5s 500ms", str);
}

test "formatDuration minutes" {
    const allocator = std.testing.allocator;
    const str = try formatDuration(allocator, 125000); // 2m 5s
    defer allocator.free(str);

    try std.testing.expectEqualStrings("2m 5s", str);
}

test "formatDuration hours" {
    const allocator = std.testing.allocator;
    const str = try formatDuration(allocator, 3665000); // 1h 1m 5s
    defer allocator.free(str);

    try std.testing.expectEqualStrings("1h 1m 5s", str);
}

test "formatDuration days" {
    const allocator = std.testing.allocator;
    const str = try formatDuration(allocator, 90061000); // 1d 1h 1m 1s
    defer allocator.free(str);

    try std.testing.expectEqualStrings("1d 1h 1m 1s", str);
}

test "C FFI exports" {
    const t1 = Tick64();
    std.Thread.sleep(5 * std.time.ns_per_ms);
    const t2 = Tick64();

    try std.testing.expect(t2 >= t1);

    // Test TickHighres64
    _ = TickHighres64();

    // Test TickHighresNano64
    const nano1 = TickHighresNano64();
    const nano2 = TickHighresNano64();
    try std.testing.expect(nano2 >= nano1);

    // Test Tick64ToTime64
    var time64: u64 = 0;
    Tick64ToTime64(t1, &time64);
    try std.testing.expect(time64 > 0);

    // Test FreeTick64 (should not crash)
    FreeTick64();
}
