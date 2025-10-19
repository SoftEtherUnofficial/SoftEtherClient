//! Time utilities for SoftEther VPN - Zig implementation
//!
//! High-resolution timing functions compatible with SoftEther C and Rust implementations.
//! This provides Unix epoch-based timestamps (absolute time), unlike platform/time.zig
//! which provides program-relative time.
//!
//! Ported from: SoftEtherRust/libs/mayaqua/src/time.rs

const std = @import("std");

/// 64-bit millisecond timestamp since Unix epoch (equivalent to C Tick64)
pub const Tick64 = u64;

/// Get current time as 64-bit millisecond timestamp since Unix epoch
///
/// This is equivalent to the C implementation's Tick64() function when measuring
/// absolute time, and the Rust implementation's get_tick64().
///
/// Returns milliseconds since January 1, 1970 00:00:00 UTC
pub fn getTick64() Tick64 {
    return @intCast(std.time.milliTimestamp());
}

/// Get current time as seconds since Unix epoch
///
/// Returns seconds since January 1, 1970 00:00:00 UTC
pub fn getTime() u64 {
    return @intCast(@divFloor(std.time.milliTimestamp(), 1000));
}

/// Check if enough time has passed since last tick
///
/// Example:
/// ```zig
/// const last_keepalive = getTick64();
/// // ... later ...
/// if (isIntervalElapsed(last_keepalive, KEEPALIVE_INTERVAL)) {
///     // Send keepalive
/// }
/// ```
pub fn isIntervalElapsed(last_tick: Tick64, interval_ms: u64) bool {
    const current = getTick64();
    return current -| last_tick >= interval_ms; // Saturating subtraction
}

/// Calculate time remaining until interval elapses
///
/// Returns 0 if interval has already elapsed, otherwise returns milliseconds remaining
pub fn getTimeRemaining(last_tick: Tick64, interval_ms: u64) u64 {
    const current = getTick64();
    const elapsed = current -| last_tick;

    if (elapsed >= interval_ms) {
        return 0;
    }
    return interval_ms - elapsed;
}

/// Sleep for specified milliseconds
pub fn sleepMillis(millis: u64) void {
    std.Thread.sleep(millis * std.time.ns_per_ms);
}

/// Sleep for specified seconds
pub fn sleepSecs(secs: u64) void {
    std.Thread.sleep(secs * std.time.ns_per_s);
}

/// Sleep for specified microseconds
pub fn sleepMicros(micros: u64) void {
    std.Thread.sleep(micros * std.time.ns_per_us);
}

// ============================================
// Constants from SoftEther C implementation
// ============================================

/// Traffic monitoring check interval (1 second)
pub const TRAFFIC_CHECK_SPAN: u64 = 1000;

/// Keep-alive packet interval (30 seconds)
pub const KEEPALIVE_INTERVAL: u64 = 30000;

/// Session timeout (60 seconds)
pub const SESSION_TIMEOUT: u64 = 60000;

/// Minimum timeout value (5 seconds)
pub const TIMEOUT_MIN: u64 = 5 * 1000;

/// Maximum timeout value (60 seconds)
pub const TIMEOUT_MAX: u64 = 60 * 1000;

/// Default timeout value (30 seconds)
pub const TIMEOUT_DEFAULT: u64 = 30 * 1000;

/// Connecting timeout (15 seconds)
pub const CONNECTING_TIMEOUT: u64 = 15 * 1000;

/// TCP keep-alive timeout (1 second)
pub const KEEP_TCP_TIMEOUT: u64 = 1000;

// ============================================
// Utility Functions
// ============================================

/// Format a Tick64 timestamp as ISO8601 string
///
/// Example: "2025-10-18T12:34:56Z"
pub fn formatTick64(allocator: std.mem.Allocator, tick: Tick64) ![]u8 {
    const timestamp_secs: i64 = @intCast(@divFloor(@as(i64, @intCast(tick)), 1000));
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp_secs) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

/// Clamp a timeout value to valid range
pub fn clampTimeout(timeout_ms: u64) u64 {
    if (timeout_ms < TIMEOUT_MIN) return TIMEOUT_MIN;
    if (timeout_ms > TIMEOUT_MAX) return TIMEOUT_MAX;
    return timeout_ms;
}

/// Calculate exponential backoff with jitter
///
/// Used for retry logic with increasing delays
pub fn exponentialBackoff(attempt: u32, base_ms: u64, max_ms: u64) u64 {
    if (attempt == 0) return base_ms;

    // Calculate 2^attempt * base_ms, with overflow protection
    const max_shift: u6 = 63; // u64 max shift
    const shift_amount: u6 = if (attempt > max_shift) max_shift else @intCast(attempt);
    const multiplier = @as(u64, 1) << shift_amount;

    // Multiply with overflow check
    const backoff = if (multiplier > max_ms / base_ms)
        max_ms
    else
        base_ms * multiplier;

    // Add jitter (±25%)
    var prng = std.Random.DefaultPrng.init(@intCast(getTick64()));
    const random = prng.random();
    const jitter_range = backoff / 4; // 25%
    const jitter = random.uintLessThan(u64, jitter_range * 2);
    const with_jitter = backoff -| (jitter_range) + jitter;

    return @min(with_jitter, max_ms);
} // ============================================
// Tests
// ============================================

test "getTick64 returns increasing values" {
    const tick1 = getTick64();
    sleepMillis(10);
    const tick2 = getTick64();

    try std.testing.expect(tick2 > tick1);
    try std.testing.expect(tick2 - tick1 >= 10);
}

test "getTime returns seconds" {
    const time1 = getTime();
    const time2 = getTime();

    // Time should be moving forward (or equal if very fast)
    try std.testing.expect(time2 >= time1);

    // Should be a reasonable Unix timestamp (after year 2020)
    try std.testing.expect(time1 > 1577836800); // Jan 1, 2020
}

test "isIntervalElapsed works correctly" {
    const now = getTick64();

    // Interval should not be elapsed immediately
    try std.testing.expect(!isIntervalElapsed(now, 1000));

    // Interval should be elapsed if we use an old timestamp
    const old_tick = now -| 2000;
    try std.testing.expect(isIntervalElapsed(old_tick, 1000));
}

test "getTimeRemaining calculates correctly" {
    const now = getTick64();

    // Full interval remaining
    try std.testing.expectEqual(@as(u64, 1000), getTimeRemaining(now, 1000));

    // No time remaining for old tick
    const old_tick = now -| 2000;
    try std.testing.expectEqual(@as(u64, 0), getTimeRemaining(old_tick, 1000));
}

test "constants have correct values" {
    try std.testing.expectEqual(@as(u64, 5000), TIMEOUT_MIN);
    try std.testing.expectEqual(@as(u64, 30000), TIMEOUT_DEFAULT);
    try std.testing.expectEqual(@as(u64, 60000), TIMEOUT_MAX);
    try std.testing.expectEqual(@as(u64, 30000), KEEPALIVE_INTERVAL);
}

test "clampTimeout works" {
    try std.testing.expectEqual(TIMEOUT_MIN, clampTimeout(0));
    try std.testing.expectEqual(TIMEOUT_MIN, clampTimeout(1000));
    try std.testing.expectEqual(@as(u64, 10000), clampTimeout(10000));
    try std.testing.expectEqual(TIMEOUT_MAX, clampTimeout(100000));
}

test "exponentialBackoff increases" {
    const base = 1000;
    const max = 60000;

    const backoff0 = exponentialBackoff(0, base, max);
    const backoff1 = exponentialBackoff(1, base, max);
    const backoff2 = exponentialBackoff(2, base, max);

    // Should increase
    try std.testing.expect(backoff1 > backoff0);
    try std.testing.expect(backoff2 > backoff1);

    // Should respect max
    const backoff_large = exponentialBackoff(20, base, max);
    try std.testing.expect(backoff_large <= max);
}

test "formatTick64 produces valid ISO8601" {
    const allocator = std.testing.allocator;

    // Test with a known timestamp: 2025-10-18 12:00:00 UTC = 1729252800000 ms
    const tick: Tick64 = 1729252800000;
    const formatted = try formatTick64(allocator, tick);
    defer allocator.free(formatted);

    // Should have format YYYY-MM-DDTHH:MM:SSZ
    try std.testing.expectEqual(@as(usize, 20), formatted.len);
    try std.testing.expect(formatted[4] == '-');
    try std.testing.expect(formatted[7] == '-');
    try std.testing.expect(formatted[10] == 'T');
    try std.testing.expect(formatted[13] == ':');
    try std.testing.expect(formatted[16] == ':');
    try std.testing.expect(formatted[19] == 'Z');
}

test "sleepMillis actually sleeps" {
    const start = getTick64();
    sleepMillis(20);
    const end = getTick64();

    // Should have slept at least 20ms (with some tolerance)
    try std.testing.expect(end - start >= 18);
}
