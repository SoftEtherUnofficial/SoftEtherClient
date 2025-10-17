const std = @import("std");

/// Log levels matching SoftEther's logging system
pub const LogLevel = enum(u8) {
    trace = 0, // Very verbose, packet-level detail
    debug = 1, // Detailed diagnostic information
    info = 2, // Normal operational messages
    warn = 3, // Warning conditions
    err = 4, // Error conditions
    fatal = 5, // Fatal errors

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .trace => "TRACE",
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
            .fatal => "FATAL",
        };
    }

    pub fn toColor(self: LogLevel) []const u8 {
        return switch (self) {
            .trace => "\x1b[90m", // Dark gray
            .debug => "\x1b[36m", // Cyan
            .info => "\x1b[32m", // Green
            .warn => "\x1b[33m", // Yellow
            .err => "\x1b[31m", // Red
            .fatal => "\x1b[35m", // Magenta
        };
    }

    pub fn fromString(str: []const u8) ?LogLevel {
        if (std.mem.eql(u8, str, "TRACE") or std.mem.eql(u8, str, "trace")) return .trace;
        if (std.mem.eql(u8, str, "DEBUG") or std.mem.eql(u8, str, "debug")) return .debug;
        if (std.mem.eql(u8, str, "INFO") or std.mem.eql(u8, str, "info")) return .info;
        if (std.mem.eql(u8, str, "WARN") or std.mem.eql(u8, str, "warn")) return .warn;
        if (std.mem.eql(u8, str, "ERROR") or std.mem.eql(u8, str, "error")) return .err;
        if (std.mem.eql(u8, str, "FATAL") or std.mem.eql(u8, str, "fatal")) return .fatal;
        return null;
    }
};

/// Log categories for better organization
pub const LogCategory = enum {
    general,
    network,
    protocol,
    packet,
    session,
    tunnel,
    auth,
    crypto,
    memory,
    performance,
    bridge,
    adapter,

    pub fn toString(self: LogCategory) []const u8 {
        return switch (self) {
            .general => "GEN",
            .network => "NET",
            .protocol => "PRO",
            .packet => "PKT",
            .session => "SES",
            .tunnel => "TUN",
            .auth => "AUT",
            .crypto => "CRY",
            .memory => "MEM",
            .performance => "PRF",
            .bridge => "BRG",
            .adapter => "ADP",
        };
    }
};

/// Global logger configuration
pub const LoggerConfig = struct {
    level: LogLevel = .info,
    use_colors: bool = true,
    show_timestamps: bool = true,
    show_category: bool = true,
    show_file_location: bool = false,
    output_file: ?std.fs.File = null,
    mutex: std.Thread.Mutex = .{},

    /// Category-specific log level overrides
    category_levels: std.AutoHashMap(LogCategory, LogLevel) = undefined,
    allocator: ?std.mem.Allocator = null,
};

/// Global logger instance
var global_config: LoggerConfig = .{};
var config_initialized: bool = false;

/// Initialize logger with configuration from environment variables
pub fn initFromEnv(allocator: std.mem.Allocator) !void {
    global_config.allocator = allocator;
    global_config.category_levels = std.AutoHashMap(LogCategory, LogLevel).init(allocator);
    config_initialized = true;

    // Check LOG_LEVEL environment variable
    if (std.process.getEnvVarOwned(allocator, "LOG_LEVEL")) |level_str| {
        defer allocator.free(level_str);
        if (LogLevel.fromString(level_str)) |level| {
            global_config.level = level;
        }
    } else |_| {
        // Default to INFO level
        global_config.level = .info;
    }

    // Check LOG_COLORS environment variable
    if (std.process.getEnvVarOwned(allocator, "LOG_COLORS")) |colors_str| {
        defer allocator.free(colors_str);
        global_config.use_colors = std.mem.eql(u8, colors_str, "1") or
            std.mem.eql(u8, colors_str, "true") or
            std.mem.eql(u8, colors_str, "yes");
    } else |_| {}

    // Check LOG_TIMESTAMPS environment variable
    if (std.process.getEnvVarOwned(allocator, "LOG_TIMESTAMPS")) |ts_str| {
        defer allocator.free(ts_str);
        global_config.show_timestamps = std.mem.eql(u8, ts_str, "1") or
            std.mem.eql(u8, ts_str, "true") or
            std.mem.eql(u8, ts_str, "yes");
    } else |_| {}
}

/// Initialize logger with manual configuration
pub fn initConfig(config: LoggerConfig) void {
    global_config = config;
    config_initialized = true;
}

/// Deinitialize logger and free resources
pub fn deinit() void {
    if (config_initialized and global_config.allocator != null) {
        global_config.category_levels.deinit();
        config_initialized = false;
    }
}

/// Initialize logger with configuration
pub fn init(config: LoggerConfig) void {
    global_config = config;
}

/// Set minimum log level
pub fn setLevel(level: LogLevel) void {
    global_config.mutex.lock();
    defer global_config.mutex.unlock();
    global_config.level = level;
}

/// Set minimum log level for a specific category
pub fn setCategoryLevel(category: LogCategory, level: LogLevel) void {
    global_config.mutex.lock();
    defer global_config.mutex.unlock();
    if (config_initialized and global_config.allocator != null) {
        global_config.category_levels.put(category, level) catch {};
    }
}

/// Enable/disable colors
pub fn setColors(enabled: bool) void {
    global_config.mutex.lock();
    defer global_config.mutex.unlock();
    global_config.use_colors = enabled;
}

/// Set output file for logging
pub fn setOutputFile(file: ?std.fs.File) void {
    global_config.mutex.lock();
    defer global_config.mutex.unlock();
    global_config.output_file = file;
}

/// Format timestamp
fn formatTimestamp(writer: anytype) !void {
    const timestamp = std.time.milliTimestamp();
    const seconds = @divTrunc(timestamp, 1000);
    const millis = @mod(timestamp, 1000);

    // Simple epoch time format (can be enhanced later)
    try writer.print("[{d}.{d:0>3}] ", .{ seconds, millis });
}

/// Core logging function
fn logMessage(
    comptime level: LogLevel,
    category: LogCategory,
    comptime fmt: []const u8,
    args: anytype,
    src: std.builtin.SourceLocation,
) void {
    global_config.mutex.lock();
    defer global_config.mutex.unlock();

    // Check global minimum log level first
    if (@intFromEnum(level) < @intFromEnum(global_config.level)) {
        return;
    }

    // Check category-specific log level override
    if (config_initialized and global_config.allocator != null) {
        if (global_config.category_levels.get(category)) |cat_level| {
            if (@intFromEnum(level) < @intFromEnum(cat_level)) {
                return;
            }
        }
    }

    // For tests, use a buffer instead of stderr
    const is_test = @import("builtin").is_test;
    if (is_test) {
        // Silent in tests to avoid output clutter
        return;
    }

    // Build log message in buffer
    var buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    // Build log message
    if (global_config.use_colors) {
        writer.print("{s}", .{level.toColor()}) catch return;
    }

    if (global_config.show_timestamps) {
        formatTimestamp(writer) catch return;
    }

    // Level and category
    writer.print("[{s}]", .{level.toString()}) catch return;

    if (global_config.show_category) {
        writer.print("[{s}]", .{category.toString()}) catch return;
    }

    // File location (optional, useful for debugging)
    if (global_config.show_file_location) {
        const file_name = std.fs.path.basename(src.file);
        writer.print(" {s}:{d}", .{ file_name, src.line }) catch return;
    }

    // Message
    writer.print(" ", .{}) catch return;
    writer.print(fmt, args) catch return;

    if (global_config.use_colors) {
        writer.print("\x1b[0m", .{}) catch return; // Reset color
    }

    writer.print("\n", .{}) catch return;

    // Output using std.debug.print (works in all contexts)
    const message = fbs.getWritten();
    std.debug.print("{s}", .{message});

    // Also write to file if configured
    if (global_config.output_file) |file| {
        file.writeAll(message) catch return;
    }
}

/// Convenience logging functions
pub fn trace(category: LogCategory, comptime fmt: []const u8, args: anytype) void {
    logMessage(.trace, category, fmt, args, @src());
}

pub fn debug(category: LogCategory, comptime fmt: []const u8, args: anytype) void {
    logMessage(.debug, category, fmt, args, @src());
}

pub fn info(category: LogCategory, comptime fmt: []const u8, args: anytype) void {
    logMessage(.info, category, fmt, args, @src());
}

pub fn warn(category: LogCategory, comptime fmt: []const u8, args: anytype) void {
    logMessage(.warn, category, fmt, args, @src());
}

pub fn err(category: LogCategory, comptime fmt: []const u8, args: anytype) void {
    logMessage(.err, category, fmt, args, @src());
}

pub fn fatal(category: LogCategory, comptime fmt: []const u8, args: anytype) void {
    logMessage(.fatal, category, fmt, args, @src());
}

/// Scoped logger for specific modules
pub fn Scoped(comptime default_category: LogCategory) type {
    return struct {
        pub fn trace(comptime fmt: []const u8, args: anytype) void {
            logMessage(.trace, default_category, fmt, args, @src());
        }

        pub fn debug(comptime fmt: []const u8, args: anytype) void {
            logMessage(.debug, default_category, fmt, args, @src());
        }

        pub fn info(comptime fmt: []const u8, args: anytype) void {
            logMessage(.info, default_category, fmt, args, @src());
        }

        pub fn warn(comptime fmt: []const u8, args: anytype) void {
            logMessage(.warn, default_category, fmt, args, @src());
        }

        pub fn err(comptime fmt: []const u8, args: anytype) void {
            logMessage(.err, default_category, fmt, args, @src());
        }

        pub fn fatal(comptime fmt: []const u8, args: anytype) void {
            logMessage(.fatal, default_category, fmt, args, @src());
        }
    };
}

/// Performance timing helper
pub const Timer = struct {
    start_time: i64,
    name: []const u8,
    category: LogCategory,

    pub fn start(name: []const u8, category: LogCategory) Timer {
        return .{
            .start_time = std.time.milliTimestamp(),
            .name = name,
            .category = category,
        };
    }

    pub fn lap(self: *Timer, comptime fmt: []const u8, args: anytype) void {
        const now = std.time.milliTimestamp();
        const elapsed = now - self.start_time;

        var buf: [512]u8 = undefined;
        var buf2: [256]u8 = undefined;
        const inner_msg = std.fmt.bufPrint(&buf2, fmt, args) catch "format error";
        const msg = std.fmt.bufPrint(&buf, "{s}: {s} ({d}ms)", .{
            self.name,
            inner_msg,
            elapsed,
        }) catch return;

        logMessage(.debug, self.category, "{s}", .{msg}, @src());
        self.start_time = now; // Reset for next lap
    }

    pub fn end(self: *Timer) void {
        const elapsed = std.time.milliTimestamp() - self.start_time;
        logMessage(.debug, self.category, "{s}: completed in {d}ms", .{ self.name, elapsed }, @src());
    }
};

/// Hex dump utility for debugging packets (only at TRACE level)
pub fn hexDump(
    category: LogCategory,
    data: []const u8,
    prefix: []const u8,
) void {
    global_config.mutex.lock();
    defer global_config.mutex.unlock();

    // Only show hex dumps at TRACE level
    if (@intFromEnum(LogLevel.trace) < @intFromEnum(global_config.level)) {
        return;
    }

    // Check category-specific log level override
    if (config_initialized and global_config.allocator != null) {
        if (global_config.category_levels.get(category)) |cat_level| {
            if (@intFromEnum(LogLevel.trace) < @intFromEnum(cat_level)) {
                return;
            }
        }
    }

    const is_test = @import("builtin").is_test;
    if (is_test) {
        return; // Silent in tests
    }

    std.debug.print("{s}Hex dump ({d} bytes):\n", .{ prefix, data.len });
    var i: usize = 0;
    while (i < data.len) : (i += 16) {
        // Offset
        std.debug.print("  {X:0>4}: ", .{i});

        // Hex values
        var j: usize = 0;
        while (j < 16) : (j += 1) {
            if (i + j < data.len) {
                std.debug.print("{X:0>2} ", .{data[i + j]});
            } else {
                std.debug.print("   ", .{});
            }
            if (j == 7) std.debug.print(" ", .{});
        }

        // ASCII representation
        std.debug.print(" |", .{});
        j = 0;
        while (j < 16 and i + j < data.len) : (j += 1) {
            const c = data[i + j];
            if (c >= 32 and c <= 126) {
                std.debug.print("{c}", .{c});
            } else {
                std.debug.print(".", .{});
            }
        }
        std.debug.print("|\n", .{});
    }
}

// Tests
test "log levels" {
    try std.testing.expectEqual(LogLevel.debug, .debug);
    try std.testing.expectEqual(LogLevel.info, .info);
    try std.testing.expectEqual(LogLevel.warn, .warn);
    try std.testing.expectEqual(LogLevel.err, .err);
    try std.testing.expectEqual(LogLevel.fatal, .fatal);
}

test "log level ordering" {
    try std.testing.expect(@intFromEnum(LogLevel.debug) < @intFromEnum(LogLevel.info));
    try std.testing.expect(@intFromEnum(LogLevel.info) < @intFromEnum(LogLevel.warn));
    try std.testing.expect(@intFromEnum(LogLevel.warn) < @intFromEnum(LogLevel.err));
    try std.testing.expect(@intFromEnum(LogLevel.err) < @intFromEnum(LogLevel.fatal));
}

test "category strings" {
    try std.testing.expectEqualStrings("NET", LogCategory.network.toString());
    try std.testing.expectEqualStrings("PKT", LogCategory.packet.toString());
    try std.testing.expectEqualStrings("SES", LogCategory.session.toString());
}

test "scoped logger" {
    const log = Scoped(.network);

    // Should not crash (just prints to stderr)
    log.info("Test message: {d}", .{42});
    log.debug("Debug info", .{});
}

test "timer" {
    var timer = Timer.start("test_operation", .performance);
    // Sleep not available in test context
    // Just test that timer compiles and runs
    timer.end();
}
