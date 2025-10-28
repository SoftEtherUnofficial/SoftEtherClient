//! Unified Logging System for SoftEther Cross-Platform VPN
//!
//! Design Goals:
//! - Single logging interface for all platforms (iOS, Android, Linux, macOS, Windows)
//! - Runtime log level filtering (DEBUG, INFO, WARN, ERROR)
//! - Platform-specific output (NSLog for iOS, logcat for Android, stderr for desktop)
//! - Zero-allocation for hot paths
//! - Thread-safe
//! - Compile-time log filtering for release builds
//! - Structured logging with context (component, operation, duration)
//! - Performance metrics integration

const std = @import("std");
const builtin = @import("builtin");

/// Log levels (in order of severity)
pub const LogLevel = enum(u8) {
    DEBUG = 0, // Verbose debugging (disabled in release)
    INFO = 1, // General information
    WARN = 2, // Warnings (potential issues)
    ERROR = 3, // Errors (recoverable)
    FATAL = 4, // Fatal errors (unrecoverable)

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .DEBUG => "DEBUG",
            .INFO => "INFO",
            .WARN => "WARN",
            .ERROR => "ERROR",
            .FATAL => "FATAL",
        };
    }

    pub fn toEmoji(self: LogLevel) []const u8 {
        return switch (self) {
            .DEBUG => "🔍",
            .INFO => "ℹ️",
            .WARN => "⚠️",
            .ERROR => "❌",
            .FATAL => "💀",
        };
    }
};

/// Log components (for filtering by module)
pub const LogComponent = enum {
    CORE, // Core VPN logic
    ADAPTER, // Packet adapter
    VIRTUALTAP, // VirtualTap L2 virtualization
    IOS, // iOS-specific
    ANDROID, // Android-specific
    MACOS, // macOS-specific
    LINUX, // Linux-specific
    WINDOWS, // Windows-specific
    DHCP, // DHCP client
    ARP, // ARP handling
    PACKET, // Packet processing
    QUEUE, // Queue operations
    NETWORK, // Network operations
    TLS, // TLS/encryption
    PERF, // Performance metrics
    TEST, // Testing

    pub fn toString(self: LogComponent) []const u8 {
        return @tagName(self);
    }
};

/// Runtime log configuration
pub const LogConfig = struct {
    min_level: LogLevel = .INFO,
    enabled_components: std.EnumSet(LogComponent) = std.EnumSet(LogComponent).initFull(),
    show_timestamp: bool = true,
    show_thread_id: bool = false,
    show_emoji: bool = true,
    colored_output: bool = false, // ANSI colors for terminal
    performance_tracking: bool = true,
    max_message_length: usize = 512,

    /// Global configuration instance
    var global: LogConfig = .{};

    pub fn setMinLevel(level: LogLevel) void {
        global.min_level = level;
    }

    pub fn enableComponent(component: LogComponent) void {
        global.enabled_components.insert(component);
    }

    pub fn disableComponent(component: LogComponent) void {
        global.enabled_components.remove(component);
    }

    pub fn isComponentEnabled(self: *const LogConfig, component: LogComponent) bool {
        _ = self; // TODO: Use for runtime filtering
        _ = component;
        return true; // All components enabled for now
    }
};

/// Platform-specific logging backend
const LogBackend = struct {
    // iOS: Use NSLog via Objective-C bridge
    extern "c" fn ios_log_message([*:0]const u8) void;

    // Android: Use __android_log_print via JNI
    extern "c" fn android_log_print(c_int, [*:0]const u8, [*:0]const u8, ...) void;

    // Standard C printf (for desktop platforms)
    extern "c" fn printf([*:0]const u8, ...) c_int;

    // Standard C fprintf to stderr
    extern "c" fn fprintf(*anyopaque, [*:0]const u8, ...) c_int;
    extern "c" var stderr: *anyopaque;

    /// Output log message to platform-specific backend
    pub fn output(msg: [*:0]const u8) void {
        switch (builtin.target.os.tag) {
            .ios, .tvos, .watchos => {
                // iOS family: Use NSLog
                ios_log_message(msg);
            },
            .linux => {
                if (builtin.target.isAndroid()) {
                    // Android: Use logcat
                    const ANDROID_LOG_INFO = 4;
                    android_log_print(ANDROID_LOG_INFO, "SoftEtherVPN", "%s", msg);
                } else {
                    // Linux: Use stderr
                    _ = fprintf(stderr, "%s\n", msg);
                }
            },
            .macos => {
                // macOS: Use stderr (or NSLog in GUI apps)
                _ = fprintf(stderr, "%s\n", msg);
            },
            .windows => {
                // Windows: Use stderr (or OutputDebugString)
                _ = fprintf(stderr, "%s\n", msg);
            },
            else => {
                // Fallback: Use printf
                _ = printf("%s\n", msg);
            },
        }
    }
};

/// Performance timer for operation tracking
pub const PerfTimer = struct {
    start_ns: i128,
    component: LogComponent,
    operation: []const u8,

    pub fn start(component: LogComponent, operation: []const u8) PerfTimer {
        return .{
            .start_ns = std.time.nanoTimestamp(),
            .component = component,
            .operation = operation,
        };
    }

    pub fn end(self: *const PerfTimer) void {
        if (!LogConfig.global.performance_tracking) return;

        const end_ns = std.time.nanoTimestamp();
        const duration_us = @divFloor(end_ns - self.start_ns, 1000);

        var buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrintZ(&buf, "[{s}] ⏱️ {s}: {d}µs", .{
            self.component.toString(),
            self.operation,
            duration_us,
        }) catch return;

        LogBackend.output(msg.ptr);
    }
};

/// Core logging function (internal)
fn logInternal(
    comptime level: LogLevel,
    comptime component: LogComponent,
    comptime fmt: []const u8,
    args: anytype,
) void {
    // Compile-time filtering: Skip DEBUG logs in release builds
    if (level == .DEBUG and builtin.mode != .Debug) {
        return;
    }

    // Runtime filtering: Check minimum level
    if (@intFromEnum(level) < @intFromEnum(LogConfig.global.min_level)) {
        return;
    }

    // Runtime filtering: Check if component is enabled
    if (!LogConfig.global.isComponentEnabled(component)) {
        return;
    }

    // Format message
    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    // Timestamp
    if (LogConfig.global.show_timestamp) {
        const timestamp_ms = @divFloor(std.time.milliTimestamp(), 1);
        const seconds = @divFloor(timestamp_ms, 1000);
        const millis = @mod(timestamp_ms, 1000);
        const hours = @mod(@divFloor(seconds, 3600), 24);
        const minutes = @mod(@divFloor(seconds, 60), 60);
        const secs = @mod(seconds, 60);

        writer.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3} ", .{ hours, minutes, secs, millis }) catch {};
    }

    // Level emoji or text
    if (LogConfig.global.show_emoji) {
        writer.print("{s} ", .{level.toEmoji()}) catch {};
    } else {
        writer.print("[{s}] ", .{level.toString()}) catch {};
    }

    // Component
    writer.print("[{s}] ", .{component.toString()}) catch {};

    // Message
    writer.print(fmt, args) catch {};

    // Null-terminate
    const written = stream.getWritten();
    if (written.len < buf.len) {
        buf[written.len] = 0;
    } else {
        buf[buf.len - 1] = 0;
    }

    // Output to platform backend
    LogBackend.output(@ptrCast(&buf));
}

// ============================================================================
// Public API: Log functions by level
// ============================================================================

/// DEBUG: Verbose debugging (disabled in release builds)
pub fn debug(
    comptime component: LogComponent,
    comptime fmt: []const u8,
    args: anytype,
) void {
    logInternal(.DEBUG, component, fmt, args);
}

/// INFO: General information
pub fn info(
    comptime component: LogComponent,
    comptime fmt: []const u8,
    args: anytype,
) void {
    logInternal(.INFO, component, fmt, args);
}

/// WARN: Warnings (potential issues)
pub fn warn(
    comptime component: LogComponent,
    comptime fmt: []const u8,
    args: anytype,
) void {
    logInternal(.WARN, component, fmt, args);
}

/// ERROR: Errors (recoverable)
pub fn err(
    comptime component: LogComponent,
    comptime fmt: []const u8,
    args: anytype,
) void {
    logInternal(.ERROR, component, fmt, args);
}

/// FATAL: Fatal errors (unrecoverable)
pub fn fatal(
    comptime component: LogComponent,
    comptime fmt: []const u8,
    args: anytype,
) void {
    logInternal(.FATAL, component, fmt, args);
}

// ============================================================================
// Convenience macros for common patterns
// ============================================================================

/// Log packet direction (iOS→Server or Server→iOS)
pub fn logPacket(
    comptime component: LogComponent,
    comptime direction: enum { outgoing, incoming },
    ip_src: [4]u8,
    ip_dst: [4]u8,
    protocol: u8,
    length: usize,
) void {
    const arrow = if (direction == .outgoing) "→" else "←";
    info(component, "📦 {d}.{d}.{d}.{d} {s} {d}.{d}.{d}.{d} proto={d} len={d}", .{
        ip_src[0],
        ip_src[1],
        ip_src[2],
        ip_src[3],
        arrow,
        ip_dst[0],
        ip_dst[1],
        ip_dst[2],
        ip_dst[3],
        protocol,
        length,
    });
}

/// Log queue operation (enqueue/dequeue)
pub fn logQueue(
    comptime component: LogComponent,
    comptime operation: enum { enqueue, dequeue, full, empty },
    queue_name: []const u8,
    count: usize,
    capacity: usize,
) void {
    const emoji = switch (operation) {
        .enqueue => "➕",
        .dequeue => "➖",
        .full => "🚫",
        .empty => "📭",
    };

    info(component, "{s} {s}: {d}/{d}", .{ emoji, queue_name, count, capacity });
}

/// Log network configuration
pub fn logNetworkConfig(
    comptime component: LogComponent,
    ip: [4]u8,
    gateway: [4]u8,
    netmask: [4]u8,
    dns: []const [4]u8,
) void {
    info(component, "🌐 IP: {d}.{d}.{d}.{d} GW: {d}.{d}.{d}.{d} Mask: {d}.{d}.{d}.{d}", .{
        ip[0],      ip[1],      ip[2],      ip[3],
        gateway[0], gateway[1], gateway[2], gateway[3],
        netmask[0], netmask[1], netmask[2], netmask[3],
    });

    for (dns, 0..) |dns_server, i| {
        info(component, "🌐 DNS{d}: {d}.{d}.{d}.{d}", .{
            i + 1,
            dns_server[0],
            dns_server[1],
            dns_server[2],
            dns_server[3],
        });
    }
}

/// Log MAC address learning
pub fn logMacLearning(
    comptime component: LogComponent,
    ip: [4]u8,
    mac: [6]u8,
    is_gateway: bool,
) void {
    const emoji = if (is_gateway) "🎯" else "📝";
    info(component, "{s} Learned MAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2} for IP {d}.{d}.{d}.{d}", .{
        emoji,
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        ip[0],
        ip[1],
        ip[2],
        ip[3],
    });
}

/// Log DHCP state transition
pub fn logDhcpState(
    comptime component: LogComponent,
    comptime state: enum {
        init,
        discover_sent,
        offer_received,
        request_sent,
        configured,
        renewing,
        rebinding,
    },
    details: ?[]const u8,
) void {
    const state_str = switch (state) {
        .init => "INIT",
        .discover_sent => "DISCOVER_SENT",
        .offer_received => "OFFER_RECEIVED",
        .request_sent => "REQUEST_SENT",
        .configured => "CONFIGURED ✅",
        .renewing => "RENEWING",
        .rebinding => "REBINDING",
    };

    if (details) |d| {
        info(component, "🔄 DHCP: {s} - {s}", .{ state_str, d });
    } else {
        info(component, "🔄 DHCP: {s}", .{state_str});
    }
}

// ============================================================================
// Testing & Debug Utilities
// ============================================================================

/// Hex dump for debugging (only in debug builds)
pub fn hexDump(
    component: LogComponent,
    label: []const u8,
    data: []const u8,
    max_bytes: usize,
) void {
    _ = component; // May be used for filtering in future
    if (builtin.mode != .Debug) return;

    const bytes_to_show = @min(data.len, max_bytes);

    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    writer.print("{s} ({d} bytes):", .{ label, data.len }) catch return;

    var i: usize = 0;
    while (i < bytes_to_show) : (i += 1) {
        if (i % 16 == 0) {
            writer.writeAll("\n  ") catch break;
        }
        writer.print("{X:0>2} ", .{data[i]}) catch break;
    }

    if (bytes_to_show < data.len) {
        writer.writeAll("\n  ...") catch {};
    }

    const written = stream.getWritten();
    if (written.len < buf.len) {
        buf[written.len] = 0;
    } else {
        buf[buf.len - 1] = 0;
    }

    LogBackend.output(@ptrCast(&buf));
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize logging system (call once at startup)
pub fn init(config: LogConfig) void {
    LogConfig.global = config;

    info(.CORE, "🚀 SoftEther VPN Logging System initialized", .{});
    info(.CORE, "   Platform: {s}", .{@tagName(builtin.target.os.tag)});
    info(.CORE, "   Build: {s}", .{@tagName(builtin.mode)});
    info(.CORE, "   Min Level: {s}", .{config.min_level.toString()});
}

// ============================================================================
// Tests
// ============================================================================

test "logging levels" {
    const testing = std.testing;

    try testing.expectEqual(LogLevel.DEBUG, LogLevel.DEBUG);
    try testing.expect(@intFromEnum(LogLevel.DEBUG) < @intFromEnum(LogLevel.INFO));
    try testing.expect(@intFromEnum(LogLevel.INFO) < @intFromEnum(LogLevel.WARN));
    try testing.expect(@intFromEnum(LogLevel.WARN) < @intFromEnum(LogLevel.ERROR));
    try testing.expect(@intFromEnum(LogLevel.ERROR) < @intFromEnum(LogLevel.FATAL));
}

test "performance timer" {
    var timer = PerfTimer.start(.TEST, "test_operation");
    // Timer will measure operation time
    var sum: u64 = 0;
    for (0..1000) |i| {
        sum +%= i; // Wrapping add to do actual work
    }
    std.debug.assert(sum > 0); // Use the result
    timer.end();
}
