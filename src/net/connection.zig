// Connection Management Implementation
// Pure Zig implementation for VPN client
// Phase 2: Network Layer - Task 3

const std = @import("std");
const socket = @import("socket.zig");
const http = @import("http.zig");
const TcpSocket = socket.TcpSocket;
const HttpClient = http.HttpClient;
const HttpResponse = http.HttpResponse;

/// Connection state
pub const ConnectionState = enum {
    disconnected,
    connecting,
    connected,
    disconnecting,
    error_state,

    pub fn isActive(self: ConnectionState) bool {
        return self == .connected or self == .connecting;
    }
};

/// Connection statistics
pub const ConnectionStats = struct {
    connect_attempts: u64 = 0,
    successful_connects: u64 = 0,
    failed_connects: u64 = 0,
    disconnects: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    last_connect_time: i64 = 0,
    last_disconnect_time: i64 = 0,
    total_connection_time_ms: u64 = 0,
    retry_count: u64 = 0,

    pub fn init() ConnectionStats {
        return ConnectionStats{};
    }

    pub fn recordConnectAttempt(self: *ConnectionStats) void {
        self.connect_attempts += 1;
    }

    pub fn recordConnectSuccess(self: *ConnectionStats) void {
        self.successful_connects += 1;
        self.last_connect_time = std.time.milliTimestamp();
    }

    pub fn recordConnectFailure(self: *ConnectionStats) void {
        self.failed_connects += 1;
    }

    pub fn recordDisconnect(self: *ConnectionStats) void {
        self.disconnects += 1;
        self.last_disconnect_time = std.time.milliTimestamp();

        // Calculate connection duration
        if (self.last_connect_time > 0) {
            const duration = @as(u64, @intCast(self.last_disconnect_time - self.last_connect_time));
            self.total_connection_time_ms += duration;
        }
    }

    pub fn recordRetry(self: *ConnectionStats) void {
        self.retry_count += 1;
    }

    pub fn successRate(self: *const ConnectionStats) f64 {
        if (self.connect_attempts == 0) return 0.0;
        return @as(f64, @floatFromInt(self.successful_connects)) / @as(f64, @floatFromInt(self.connect_attempts));
    }

    pub fn averageConnectionTime(self: *const ConnectionStats) u64 {
        if (self.successful_connects == 0) return 0;
        return self.total_connection_time_ms / self.successful_connects;
    }
};

/// Retry policy configuration
pub const RetryPolicy = struct {
    max_retries: u8 = 3,
    initial_delay_ms: u64 = 1000, // 1 second
    max_delay_ms: u64 = 30000, // 30 seconds
    backoff_multiplier: f64 = 2.0, // Exponential backoff
    jitter: bool = true, // Add random jitter to prevent thundering herd

    pub fn calculateDelay(self: *const RetryPolicy, attempt: u8) u64 {
        if (attempt == 0) return self.initial_delay_ms;

        // Exponential backoff: delay = initial * multiplier^attempt
        const base_delay = @as(f64, @floatFromInt(self.initial_delay_ms)) *
            std.math.pow(f64, self.backoff_multiplier, @as(f64, @floatFromInt(attempt)));

        var delay = @min(@as(u64, @intFromFloat(base_delay)), self.max_delay_ms);

        // Add jitter (0-25% random variation)
        if (self.jitter) {
            var prng = std.Random.DefaultPrng.init(@as(u64, @intCast(std.time.milliTimestamp())));
            const random = prng.random();
            const jitter_percent = random.intRangeAtMost(u8, 0, 25);
            const jitter_amount = (delay * jitter_percent) / 100;
            delay += jitter_amount;
        }

        return delay;
    }
};

/// Keep-alive configuration
pub const KeepAliveConfig = struct {
    enabled: bool = true,
    idle_timeout_ms: u64 = 60000, // 60 seconds
    probe_interval_ms: u64 = 10000, // 10 seconds
    max_idle_connections: usize = 10,

    pub fn shouldKeepAlive(self: *const KeepAliveConfig, idle_time_ms: u64) bool {
        return self.enabled and idle_time_ms < self.idle_timeout_ms;
    }
};

/// Connection pool entry
pub const PooledConnection = struct {
    socket: ?TcpSocket,
    host: []const u8,
    port: u16,
    created_at: i64,
    last_used: i64,
    use_count: u64,
    state: ConnectionState,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !PooledConnection {
        const host_copy = try allocator.dupe(u8, host);
        const now = std.time.milliTimestamp();

        return PooledConnection{
            .socket = null,
            .host = host_copy,
            .port = port,
            .created_at = now,
            .last_used = now,
            .use_count = 0,
            .state = .disconnected,
        };
    }

    pub fn deinit(self: *PooledConnection, allocator: std.mem.Allocator) void {
        if (self.socket) |*sock| {
            sock.close();
        }
        allocator.free(self.host);
    }

    pub fn connect(self: *PooledConnection, allocator: std.mem.Allocator) !void {
        self.state = .connecting;
        self.socket = try TcpSocket.connect(allocator, self.host, self.port);
        self.state = .connected;
        self.last_used = std.time.milliTimestamp();
        self.use_count += 1;
    }

    pub fn disconnect(self: *PooledConnection) void {
        if (self.socket) |*sock| {
            sock.close();
            self.socket = null;
        }
        self.state = .disconnected;
    }

    pub fn isIdle(self: *const PooledConnection, timeout_ms: u64) bool {
        const now = std.time.milliTimestamp();
        const idle_time = @as(u64, @intCast(now - self.last_used));
        return idle_time > timeout_ms;
    }

    pub fn markUsed(self: *PooledConnection) void {
        self.last_used = std.time.milliTimestamp();
        self.use_count += 1;
    }
};

/// Connection pool for reusing connections
pub const ConnectionPool = struct {
    allocator: std.mem.Allocator,
    connections: std.ArrayList(PooledConnection),
    config: KeepAliveConfig,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, config: KeepAliveConfig) ConnectionPool {
        return ConnectionPool{
            .allocator = allocator,
            .connections = std.ArrayList(PooledConnection){},
            .config = config,
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.connections.items) |*conn| {
            conn.deinit(self.allocator);
        }
        self.connections.deinit(self.allocator);
    }

    /// Acquire a connection from the pool or create a new one
    pub fn acquire(self: *ConnectionPool, host: []const u8, port: u16) !*PooledConnection {
        self.mutex.lock();
        defer self.mutex.unlock();

        // First, try to find an existing idle connection
        for (self.connections.items) |*conn| {
            if (conn.state == .connected and
                std.mem.eql(u8, conn.host, host) and
                conn.port == port and
                !conn.isIdle(self.config.idle_timeout_ms))
            {
                conn.markUsed();
                return conn;
            }
        }

        // Clean up idle connections if at capacity
        if (self.connections.items.len >= self.config.max_idle_connections) {
            try self.cleanupIdleConnections();
        }

        // Create a new connection
        var new_conn = try PooledConnection.init(self.allocator, host, port);
        errdefer new_conn.deinit(self.allocator);

        try new_conn.connect(self.allocator);
        try self.connections.append(self.allocator, new_conn);

        return &self.connections.items[self.connections.items.len - 1];
    }

    /// Release a connection back to the pool
    pub fn release(self: *ConnectionPool, conn: *PooledConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.config.enabled) {
            conn.last_used = std.time.milliTimestamp();
        } else {
            conn.disconnect();
        }
    }

    /// Clean up idle connections
    fn cleanupIdleConnections(self: *ConnectionPool) !void {
        var i: usize = 0;
        while (i < self.connections.items.len) {
            const conn = &self.connections.items[i];
            if (conn.isIdle(self.config.idle_timeout_ms)) {
                conn.deinit(self.allocator);
                _ = self.connections.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Get pool statistics
    pub fn getStats(self: *ConnectionPool) PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        var stats = PoolStats{
            .total_connections = self.connections.items.len,
            .active_connections = 0,
            .idle_connections = 0,
        };

        for (self.connections.items) |*conn| {
            if (conn.state == .connected) {
                if (conn.isIdle(self.config.idle_timeout_ms)) {
                    stats.idle_connections += 1;
                } else {
                    stats.active_connections += 1;
                }
            }
        }

        return stats;
    }
};

/// Pool statistics
pub const PoolStats = struct {
    total_connections: usize,
    active_connections: usize,
    idle_connections: usize,
};

/// Connection manager - high-level API
pub const ConnectionManager = struct {
    allocator: std.mem.Allocator,
    pool: ConnectionPool,
    retry_policy: RetryPolicy,
    stats: ConnectionStats,
    timeout_ms: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        keepalive_config: KeepAliveConfig,
        retry_policy: RetryPolicy,
        timeout_ms: u64,
    ) ConnectionManager {
        return ConnectionManager{
            .allocator = allocator,
            .pool = ConnectionPool.init(allocator, keepalive_config),
            .retry_policy = retry_policy,
            .stats = ConnectionStats.init(),
            .timeout_ms = timeout_ms,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        self.pool.deinit();
    }

    /// Connect with automatic retry
    pub fn connect(self: *ConnectionManager, host: []const u8, port: u16) !*PooledConnection {
        var attempt: u8 = 0;

        while (attempt <= self.retry_policy.max_retries) : (attempt += 1) {
            self.stats.recordConnectAttempt();

            const conn = self.pool.acquire(host, port) catch |err| {
                self.stats.recordConnectFailure();

                if (attempt >= self.retry_policy.max_retries) {
                    return err;
                }

                // Calculate backoff delay
                const delay_ms = self.retry_policy.calculateDelay(attempt);
                self.stats.recordRetry();

                std.Thread.sleep(delay_ms * std.time.ns_per_ms);
                continue;
            };

            self.stats.recordConnectSuccess();
            return conn;
        }

        return error.MaxRetriesExceeded;
    }

    /// Disconnect and release connection
    pub fn disconnect(self: *ConnectionManager, conn: *PooledConnection) void {
        self.stats.recordDisconnect();
        self.pool.release(conn);
    }

    /// Get connection statistics
    pub fn getStats(self: *const ConnectionManager) ConnectionStats {
        return self.stats;
    }

    /// Get pool statistics
    pub fn getPoolStats(self: *ConnectionManager) PoolStats {
        return self.pool.getStats();
    }
};

// ============================================================================
// C FFI Exports for gradual migration
// ============================================================================

export fn zig_connection_manager_init(
    keepalive_timeout_ms: u64,
    max_idle_connections: usize,
    max_retries: u8,
    timeout_ms: u64,
) ?*ConnectionManager {
    const allocator = std.heap.c_allocator;

    const keepalive_config = KeepAliveConfig{
        .enabled = true,
        .idle_timeout_ms = keepalive_timeout_ms,
        .max_idle_connections = max_idle_connections,
    };

    const retry_policy = RetryPolicy{
        .max_retries = max_retries,
    };

    const manager = allocator.create(ConnectionManager) catch return null;
    manager.* = ConnectionManager.init(allocator, keepalive_config, retry_policy, timeout_ms);
    return manager;
}

export fn zig_connection_manager_destroy(manager: ?*ConnectionManager) void {
    if (manager) |m| {
        const allocator = std.heap.c_allocator;
        m.deinit();
        allocator.destroy(m);
    }
}

export fn zig_connection_manager_connect(
    manager: ?*ConnectionManager,
    host: [*:0]const u8,
    port: u16,
) ?*PooledConnection {
    const m = manager orelse return null;
    const host_slice = std.mem.span(host);

    return m.connect(host_slice, port) catch null;
}

export fn zig_connection_manager_disconnect(
    manager: ?*ConnectionManager,
    conn: ?*PooledConnection,
) void {
    const m = manager orelse return;
    const c = conn orelse return;
    m.disconnect(c);
}

export fn zig_connection_get_stats(
    manager: ?*ConnectionManager,
    stats_out: ?*ConnectionStats,
) void {
    const m = manager orelse return;
    const stats = stats_out orelse return;
    stats.* = m.getStats();
}

// ============================================================================
// Tests
// ============================================================================

test "Connection state transitions" {
    var state = ConnectionState.disconnected;
    try std.testing.expect(!state.isActive());

    state = .connected;
    try std.testing.expect(state.isActive());

    state = .error_state;
    try std.testing.expect(!state.isActive());
}

test "Connection stats tracking" {
    var stats = ConnectionStats.init();

    stats.recordConnectAttempt();
    stats.recordConnectSuccess();

    try std.testing.expectEqual(@as(u64, 1), stats.connect_attempts);
    try std.testing.expectEqual(@as(u64, 1), stats.successful_connects);
    try std.testing.expectEqual(@as(u64, 0), stats.failed_connects);

    try std.testing.expectEqual(@as(f64, 1.0), stats.successRate());
}

test "Retry policy exponential backoff" {
    const policy = RetryPolicy{
        .initial_delay_ms = 1000,
        .max_delay_ms = 10000,
        .backoff_multiplier = 2.0,
        .jitter = false,
    };

    try std.testing.expectEqual(@as(u64, 1000), policy.calculateDelay(0));
    try std.testing.expectEqual(@as(u64, 2000), policy.calculateDelay(1));
    try std.testing.expectEqual(@as(u64, 4000), policy.calculateDelay(2));
    try std.testing.expectEqual(@as(u64, 8000), policy.calculateDelay(3));
    try std.testing.expectEqual(@as(u64, 10000), policy.calculateDelay(4)); // capped at max
}

test "Retry policy with jitter" {
    const policy = RetryPolicy{
        .initial_delay_ms = 1000,
        .max_delay_ms = 10000,
        .backoff_multiplier = 2.0,
        .jitter = true,
    };

    const delay1 = policy.calculateDelay(1);
    const delay2 = policy.calculateDelay(1);

    // Both should be around 2000ms but with jitter they might differ
    try std.testing.expect(delay1 >= 2000 and delay1 <= 2500);
    // Note: delay2 might equal delay1 due to PRNG, but we just check it's in range
    try std.testing.expect(delay2 >= 2000 and delay2 <= 2500);
}

test "Keep-alive configuration" {
    const config = KeepAliveConfig{
        .enabled = true,
        .idle_timeout_ms = 60000,
    };

    try std.testing.expect(config.shouldKeepAlive(30000)); // 30s < 60s
    try std.testing.expect(!config.shouldKeepAlive(70000)); // 70s > 60s
}

test "Pooled connection lifecycle" {
    const allocator = std.testing.allocator;

    var conn = try PooledConnection.init(allocator, "example.com", 443);
    defer conn.deinit(allocator);

    try std.testing.expectEqualStrings("example.com", conn.host);
    try std.testing.expectEqual(@as(u16, 443), conn.port);
    try std.testing.expectEqual(ConnectionState.disconnected, conn.state);
    try std.testing.expectEqual(@as(u64, 0), conn.use_count);
}

test "Connection pool initialization" {
    const allocator = std.testing.allocator;

    const config = KeepAliveConfig{
        .enabled = true,
        .idle_timeout_ms = 60000,
        .max_idle_connections = 5,
    };

    var pool = ConnectionPool.init(allocator, config);
    defer pool.deinit();

    const stats = pool.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.total_connections);
    try std.testing.expectEqual(@as(usize, 0), stats.active_connections);
}

test "Connection manager initialization" {
    const allocator = std.testing.allocator;

    const keepalive = KeepAliveConfig{};
    const retry = RetryPolicy{};

    var manager = ConnectionManager.init(allocator, keepalive, retry, 30000);
    defer manager.deinit();

    const stats = manager.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.connect_attempts);
}

test "Connection stats success rate" {
    var stats = ConnectionStats.init();

    stats.recordConnectAttempt();
    stats.recordConnectSuccess();

    stats.recordConnectAttempt();
    stats.recordConnectFailure();

    stats.recordConnectAttempt();
    stats.recordConnectSuccess();

    try std.testing.expectEqual(@as(u64, 3), stats.connect_attempts);
    try std.testing.expectEqual(@as(u64, 2), stats.successful_connects);
    try std.testing.expectEqual(@as(u64, 1), stats.failed_connects);

    const rate = stats.successRate();
    try std.testing.expect(rate > 0.66 and rate < 0.67); // 2/3 ≈ 0.666...
}

test "Pooled connection idle detection" {
    const allocator = std.testing.allocator;

    var conn = try PooledConnection.init(allocator, "example.com", 443);
    defer conn.deinit(allocator);

    // Just created, should not be idle
    try std.testing.expect(!conn.isIdle(1000));

    // Simulate time passing by setting last_used in the past
    conn.last_used = std.time.milliTimestamp() - 5000; // 5 seconds ago

    try std.testing.expect(conn.isIdle(1000)); // 5s > 1s threshold
    try std.testing.expect(!conn.isIdle(10000)); // 5s < 10s threshold
}

test "Connection manager stats tracking" {
    const allocator = std.testing.allocator;

    const keepalive = KeepAliveConfig{};
    const retry = RetryPolicy{ .max_retries = 0 }; // No retries for test

    var manager = ConnectionManager.init(allocator, keepalive, retry, 30000);
    defer manager.deinit();

    // Attempt connection to localhost (will likely fail, but that's OK for stats test)
    _ = manager.connect("127.0.0.1", 9999) catch {};

    const stats = manager.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.connect_attempts);
}
