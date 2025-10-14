//! Keep-Alive Handler for VPN Connections
//!
//! Prevents server-side timeouts by periodically sending packets.
//! Maintains connection health monitoring and automatic recovery.

const std = @import("std");
const log = std.log.scoped(.keepalive);

/// Keep-alive packet manager
pub const KeepAlive = struct {
    /// Last time a keep-alive packet was sent (milliseconds)
    last_sent_ms: i64 = 0,

    /// Interval between keep-alive packets (milliseconds)
    interval_ms: i64 = 5000, // 5 seconds

    /// Whether keep-alive is enabled
    enabled: bool = true,

    /// Total number of keep-alive packets sent
    packets_sent: u64 = 0,

    /// Last time any packet was received (for health check)
    last_recv_ms: i64 = 0,

    /// Timeout threshold (if no packets received in this time, connection is dead)
    timeout_ms: i64 = 30000, // 30 seconds

    /// Initialize a new keep-alive handler
    pub fn init() KeepAlive {
        return .{
            .last_sent_ms = 0,
            .last_recv_ms = std.time.milliTimestamp(),
        };
    }

    /// Check if a keep-alive packet should be sent now
    pub fn shouldSend(self: *KeepAlive) bool {
        if (!self.enabled) return false;

        const now = std.time.milliTimestamp();
        const elapsed = now - self.last_sent_ms;

        return elapsed >= self.interval_ms;
    }

    /// Mark that a keep-alive packet was just sent
    pub fn markSent(self: *KeepAlive) void {
        self.last_sent_ms = std.time.milliTimestamp();
        self.packets_sent += 1;

        log.debug("Keep-alive packet #{d} sent", .{self.packets_sent});
    }

    /// Update the last received packet timestamp
    pub fn markReceived(self: *KeepAlive) void {
        self.last_recv_ms = std.time.milliTimestamp();
    }

    /// Check if connection appears to be dead (no packets received recently)
    pub fn isDead(self: *KeepAlive) bool {
        if (self.last_recv_ms == 0) return false; // Not connected yet

        const now = std.time.milliTimestamp();
        const silence_duration = now - self.last_recv_ms;

        if (silence_duration > self.timeout_ms) {
            log.warn("Connection appears dead: {d}ms since last packet (threshold: {d}ms)", .{ silence_duration, self.timeout_ms });
            return true;
        }

        return false;
    }

    /// Get human-readable status
    pub fn getStatus(self: *KeepAlive) Status {
        const now = std.time.milliTimestamp();
        const time_since_last_recv = if (self.last_recv_ms > 0)
            now - self.last_recv_ms
        else
            0;

        return .{
            .enabled = self.enabled,
            .packets_sent = self.packets_sent,
            .time_since_last_send_ms = now - self.last_sent_ms,
            .time_since_last_recv_ms = time_since_last_recv,
            .is_healthy = !self.isDead(),
        };
    }

    pub const Status = struct {
        enabled: bool,
        packets_sent: u64,
        time_since_last_send_ms: i64,
        time_since_last_recv_ms: i64,
        is_healthy: bool,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "KeepAlive - init" {
    const ka = KeepAlive.init();
    try std.testing.expect(ka.enabled);
    try std.testing.expectEqual(@as(u64, 0), ka.packets_sent);
    try std.testing.expect(ka.last_recv_ms > 0); // Should be initialized to current time
}

test "KeepAlive - shouldSend after interval" {
    var ka = KeepAlive.init();
    ka.interval_ms = 100; // 100ms for testing

    // Should not send immediately after init
    ka.last_sent_ms = std.time.milliTimestamp();
    try std.testing.expect(!ka.shouldSend());

    // Wait for interval
    std.Thread.sleep(150 * std.time.ns_per_ms);

    // Should send now
    try std.testing.expect(ka.shouldSend());
}

test "KeepAlive - markSent increments counter" {
    var ka = KeepAlive.init();

    try std.testing.expectEqual(@as(u64, 0), ka.packets_sent);
    ka.markSent();
    try std.testing.expectEqual(@as(u64, 1), ka.packets_sent);
    ka.markSent();
    try std.testing.expectEqual(@as(u64, 2), ka.packets_sent);
}

test "KeepAlive - isDead detection" {
    var ka = KeepAlive.init();
    ka.timeout_ms = 100; // 100ms timeout for testing

    // Should be alive initially
    try std.testing.expect(!ka.isDead());

    // Mark as received
    ka.markReceived();
    try std.testing.expect(!ka.isDead());

    // Wait past timeout
    std.Thread.sleep(150 * std.time.ns_per_ms);

    // Should be dead now
    try std.testing.expect(ka.isDead());
}

test "KeepAlive - disabled should not send" {
    var ka = KeepAlive.init();
    ka.enabled = false;
    ka.interval_ms = 0; // Would normally trigger immediately

    try std.testing.expect(!ka.shouldSend());
}

test "KeepAlive - getStatus" {
    var ka = KeepAlive.init();
    ka.markSent();
    ka.markReceived();

    const status = ka.getStatus();
    try std.testing.expect(status.enabled);
    try std.testing.expectEqual(@as(u64, 1), status.packets_sent);
    try std.testing.expect(status.is_healthy);
}
