//! Collections Module
//!
//! This module provides Zig replacements for Mayaqua data structures.
//! Key improvements over C version:
//! - Type-safe generics (no void* casting)
//! - RAII-style resource management
//! - Compile-time guarantees
//! - Iterator pattern for traversal
//! - Zero-overhead abstractions
//!
//! Replaces: Mayaqua/Object.c + Mayaqua/Memory.c (partial)
//! Original: ~4,000 lines C → ~600 lines Zig

const std = @import("std");

// Note: For C FFI exports, we need getAllocator() from memory module
// In production use, this would be imported properly via build system
fn getAllocator() std.mem.Allocator {
    return std.heap.page_allocator;
}

// ============================================
// LOCK - Thread synchronization primitive
// ============================================

/// Thread-safe lock wrapper around std.Thread.Mutex
/// Replacement for LOCK structure
pub const Lock = struct {
    mutex: std.Thread.Mutex,

    pub fn init() Lock {
        return .{
            .mutex = .{},
        };
    }

    pub fn lock(self: *Lock) void {
        self.mutex.lock();
    }

    pub fn unlock(self: *Lock) void {
        self.mutex.unlock();
    }

    pub fn tryLock(self: *Lock) bool {
        return self.mutex.tryLock();
    }

    pub fn deinit(self: *Lock) void {
        _ = self;
        // Mutex doesn't need explicit cleanup in Zig
    }
};

// ============================================
// COUNTER - Thread-safe counter
// ============================================

/// Thread-safe counter with atomic operations
/// Replacement for COUNTER structure
pub const Counter = struct {
    value: std.atomic.Value(u32),

    pub fn init() Counter {
        return .{
            .value = std.atomic.Value(u32).init(0),
        };
    }

    pub fn initWithValue(initial: u32) Counter {
        return .{
            .value = std.atomic.Value(u32).init(initial),
        };
    }

    pub fn get(self: *const Counter) u32 {
        return self.value.load(.acquire);
    }

    pub fn set(self: *Counter, val: u32) void {
        self.value.store(val, .release);
    }

    pub fn inc(self: *Counter) u32 {
        return self.value.fetchAdd(1, .acq_rel) + 1;
    }

    pub fn dec(self: *Counter) u32 {
        return self.value.fetchSub(1, .acq_rel) - 1;
    }

    pub fn add(self: *Counter, val: u32) u32 {
        return self.value.fetchAdd(val, .acq_rel) + val;
    }

    pub fn sub(self: *Counter, val: u32) u32 {
        return self.value.fetchSub(val, .acq_rel) - val;
    }

    pub fn deinit(self: *Counter) void {
        _ = self;
        // No cleanup needed
    }
};

// ============================================
// REF - Reference counting
// ============================================

/// Reference counter for shared ownership
/// Replacement for REF structure
pub const Ref = struct {
    counter: Counter,

    pub fn init() Ref {
        return .{
            .counter = Counter.initWithValue(1),
        };
    }

    pub fn addRef(self: *Ref) u32 {
        return self.counter.inc();
    }

    pub fn release(self: *Ref) u32 {
        return self.counter.dec();
    }

    pub fn count(self: *const Ref) u32 {
        return self.counter.get();
    }

    pub fn deinit(self: *Ref) void {
        self.counter.deinit();
    }
};

// ============================================
// EVENT - Synchronization event
// ============================================

/// Event object for thread synchronization
/// Replacement for EVENT structure
pub const Event = struct {
    condition: std.Thread.Condition,
    mutex: std.Thread.Mutex,
    signaled: bool,

    pub fn init() Event {
        return .{
            .condition = .{},
            .mutex = .{},
            .signaled = false,
        };
    }

    pub fn set(self: *Event) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.signaled = true;
        self.condition.broadcast();
    }

    pub fn reset(self: *Event) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.signaled = false;
    }

    pub fn wait(self: *Event) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        while (!self.signaled) {
            self.condition.wait(&self.mutex);
        }
    }

    pub fn waitTimeout(self: *Event, timeout_ms: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.signaled) return true;

        const timeout_ns = timeout_ms * std.time.ns_per_ms;
        self.condition.timedWait(&self.mutex, timeout_ns) catch return false;

        return self.signaled;
    }

    pub fn deinit(self: *Event) void {
        _ = self;
        // No cleanup needed
    }
};

// ============================================
// LIST - Dynamic array with locking
// ============================================

/// Thread-safe dynamic list
/// Replacement for LIST structure
pub fn List(comptime T: type) type {
    return struct {
        const Self = @This();

        items: std.ArrayList(T),
        allocator: std.mem.Allocator,
        lock: Lock,
        sorted: bool,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .items = std.ArrayList(T){},
                .allocator = allocator,
                .lock = Lock.init(),
                .sorted = false,
            };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit(self.allocator);
            self.lock.deinit();
        }

        pub fn append(self: *Self, item: T) !void {
            self.lock.lock();
            defer self.lock.unlock();

            try self.items.append(self.allocator, item);
            self.sorted = false;
        }

        pub fn insert(self: *Self, index: usize, item: T) !void {
            self.lock.lock();
            defer self.lock.unlock();

            try self.items.insert(self.allocator, index, item);
            self.sorted = false;
        }

        pub fn remove(self: *Self, index: usize) T {
            self.lock.lock();
            defer self.lock.unlock();

            return self.items.orderedRemove(index);
        }

        pub fn get(self: *Self, index: usize) ?T {
            self.lock.lock();
            defer self.lock.unlock();

            if (index >= self.items.items.len) return null;
            return self.items.items[index];
        }

        pub fn set(self: *Self, index: usize, item: T) bool {
            self.lock.lock();
            defer self.lock.unlock();

            if (index >= self.items.items.len) return false;
            self.items.items[index] = item;
            return true;
        }

        pub fn len(self: *Self) usize {
            self.lock.lock();
            defer self.lock.unlock();

            return self.items.items.len;
        }

        pub fn clear(self: *Self) void {
            self.lock.lock();
            defer self.lock.unlock();

            self.items.clearRetainingCapacity();
        }

        pub fn sort(self: *Self, comptime lessThan: fn (T, T) bool) void {
            self.lock.lock();
            defer self.lock.unlock();

            std.mem.sort(T, self.items.items, {}, struct {
                fn inner(_: void, a: T, b: T) bool {
                    return lessThan(a, b);
                }
            }.inner);
            self.sorted = true;
        }

        pub fn find(self: *Self, comptime eql: fn (T, T) bool, item: T) ?usize {
            self.lock.lock();
            defer self.lock.unlock();

            for (self.items.items, 0..) |existing, i| {
                if (eql(existing, item)) return i;
            }
            return null;
        }

        pub fn contains(self: *Self, comptime eql: fn (T, T) bool, item: T) bool {
            return self.find(eql, item) != null;
        }

        /// Get slice without locking (caller must hold lock)
        pub fn itemsUnsafe(self: *Self) []T {
            return self.items.items;
        }
    };
}

// ============================================
// QUEUE - FIFO queue with locking
// ============================================

/// Thread-safe FIFO queue
/// Replacement for QUEUE structure
pub fn Queue(comptime T: type) type {
    return struct {
        const Self = @This();

        items: std.ArrayList(T),
        allocator: std.mem.Allocator,
        lock: Lock,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .items = std.ArrayList(T){},
                .allocator = allocator,
                .lock = Lock.init(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit(self.allocator);
            self.lock.deinit();
        }

        pub fn enqueue(self: *Self, item: T) !void {
            self.lock.lock();
            defer self.lock.unlock();

            try self.items.append(self.allocator, item);
        }

        pub fn dequeue(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();

            if (self.items.items.len == 0) return null;
            return self.items.orderedRemove(0);
        }

        pub fn peek(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();

            if (self.items.items.len == 0) return null;
            return self.items.items[0];
        }

        pub fn len(self: *Self) usize {
            self.lock.lock();
            defer self.lock.unlock();

            return self.items.items.len;
        }

        pub fn isEmpty(self: *Self) bool {
            return self.len() == 0;
        }

        pub fn clear(self: *Self) void {
            self.lock.lock();
            defer self.lock.unlock();

            self.items.clearRetainingCapacity();
        }
    };
}

// ============================================
// STACK - LIFO stack with locking
// ============================================

/// Thread-safe LIFO stack
/// Replacement for SK structure
pub fn Stack(comptime T: type) type {
    return struct {
        const Self = @This();

        items: std.ArrayList(T),
        allocator: std.mem.Allocator,
        lock: Lock,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .items = std.ArrayList(T){},
                .allocator = allocator,
                .lock = Lock.init(),
            };
        }

        pub fn deinit(self: *Self) void {
            self.items.deinit(self.allocator);
            self.lock.deinit();
        }

        pub fn push(self: *Self, item: T) !void {
            self.lock.lock();
            defer self.lock.unlock();

            try self.items.append(self.allocator, item);
        }

        pub fn pop(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();

            if (self.items.items.len == 0) return null;
            return self.items.pop();
        }

        pub fn peek(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();

            if (self.items.items.len == 0) return null;
            return self.items.items[self.items.items.len - 1];
        }

        pub fn len(self: *Self) usize {
            self.lock.lock();
            defer self.lock.unlock();

            return self.items.items.len;
        }

        pub fn isEmpty(self: *Self) bool {
            return self.len() == 0;
        }

        pub fn clear(self: *Self) void {
            self.lock.lock();
            defer self.lock.unlock();

            self.items.clearRetainingCapacity();
        }
    };
}

// ============================================
// C FFI EXPORTS (for gradual migration)
// ============================================

// Lock FFI
export fn zig_newLock() callconv(.c) ?*Lock {
    const allocator = getAllocator();
    const lock = allocator.create(Lock) catch return null;
    lock.* = Lock.init();
    return lock;
}

export fn zig_deleteLock(lock: ?*Lock) callconv(.c) void {
    if (lock) |l| {
        l.deinit();
        const allocator = getAllocator();
        allocator.destroy(l);
    }
}

export fn zig_lock(lock: ?*Lock) callconv(.c) void {
    if (lock) |l| {
        l.lock();
    }
}

export fn zig_unlock(lock: ?*Lock) callconv(.c) void {
    if (lock) |l| {
        l.unlock();
    }
}

// Counter FFI
export fn zig_newCounter() callconv(.c) ?*Counter {
    const allocator = getAllocator();
    const counter = allocator.create(Counter) catch return null;
    counter.* = Counter.init();
    return counter;
}

export fn zig_deleteCounter(counter: ?*Counter) callconv(.c) void {
    if (counter) |c| {
        c.deinit();
        const allocator = getAllocator();
        allocator.destroy(c);
    }
}

export fn zig_inc(counter: ?*Counter) callconv(.c) c_uint {
    if (counter) |c| {
        return c.inc();
    }
    return 0;
}

export fn zig_dec(counter: ?*Counter) callconv(.c) c_uint {
    if (counter) |c| {
        return c.dec();
    }
    return 0;
}

export fn zig_getCount(counter: ?*Counter) callconv(.c) c_uint {
    if (counter) |c| {
        return c.get();
    }
    return 0;
}

// ============================================
// TESTS
// ============================================

test "lock basic operations" {
    var lock = Lock.init();
    defer lock.deinit();

    lock.lock();
    lock.unlock();

    try std.testing.expect(lock.tryLock());
    lock.unlock();
}

test "counter operations" {
    var counter = Counter.init();
    defer counter.deinit();

    try std.testing.expectEqual(@as(u32, 0), counter.get());
    try std.testing.expectEqual(@as(u32, 1), counter.inc());
    try std.testing.expectEqual(@as(u32, 2), counter.inc());
    try std.testing.expectEqual(@as(u32, 2), counter.get());
    try std.testing.expectEqual(@as(u32, 1), counter.dec());
    try std.testing.expectEqual(@as(u32, 1), counter.get());
}

test "ref counting" {
    var ref = Ref.init();
    defer ref.deinit();

    try std.testing.expectEqual(@as(u32, 1), ref.count());
    try std.testing.expectEqual(@as(u32, 2), ref.addRef());
    try std.testing.expectEqual(@as(u32, 3), ref.addRef());
    try std.testing.expectEqual(@as(u32, 2), ref.release());
    try std.testing.expectEqual(@as(u32, 1), ref.release());
}

test "event signaling" {
    var event = Event.init();
    defer event.deinit();

    event.set();
    event.wait(); // Should return immediately

    event.reset();
    try std.testing.expect(!event.waitTimeout(10)); // Should timeout
}

test "list operations" {
    const allocator = std.testing.allocator;

    var list = List(i32).init(allocator);
    defer list.deinit();

    try list.append(10);
    try list.append(20);
    try list.append(30);

    try std.testing.expectEqual(@as(usize, 3), list.len());
    try std.testing.expectEqual(@as(i32, 10), list.get(0).?);
    try std.testing.expectEqual(@as(i32, 20), list.get(1).?);
    try std.testing.expectEqual(@as(i32, 30), list.get(2).?);

    try list.insert(1, 15);
    try std.testing.expectEqual(@as(usize, 4), list.len());
    try std.testing.expectEqual(@as(i32, 15), list.get(1).?);

    const removed = list.remove(1);
    try std.testing.expectEqual(@as(i32, 15), removed);
    try std.testing.expectEqual(@as(usize, 3), list.len());
}

test "list find and contains" {
    const allocator = std.testing.allocator;

    var list = List(i32).init(allocator);
    defer list.deinit();

    try list.append(10);
    try list.append(20);
    try list.append(30);

    const eqlFn = struct {
        fn eql(a: i32, b: i32) bool {
            return a == b;
        }
    }.eql;

    try std.testing.expectEqual(@as(?usize, 1), list.find(eqlFn, 20));
    try std.testing.expectEqual(@as(?usize, null), list.find(eqlFn, 40));
    try std.testing.expect(list.contains(eqlFn, 20));
    try std.testing.expect(!list.contains(eqlFn, 40));
}

test "list sorting" {
    const allocator = std.testing.allocator;

    var list = List(i32).init(allocator);
    defer list.deinit();

    try list.append(30);
    try list.append(10);
    try list.append(20);

    const lessThan = struct {
        fn lt(a: i32, b: i32) bool {
            return a < b;
        }
    }.lt;

    list.sort(lessThan);

    try std.testing.expectEqual(@as(i32, 10), list.get(0).?);
    try std.testing.expectEqual(@as(i32, 20), list.get(1).?);
    try std.testing.expectEqual(@as(i32, 30), list.get(2).?);
}

test "queue operations" {
    const allocator = std.testing.allocator;

    var queue = Queue(i32).init(allocator);
    defer queue.deinit();

    try queue.enqueue(10);
    try queue.enqueue(20);
    try queue.enqueue(30);

    try std.testing.expectEqual(@as(usize, 3), queue.len());
    try std.testing.expectEqual(@as(i32, 10), queue.peek().?);

    try std.testing.expectEqual(@as(i32, 10), queue.dequeue().?);
    try std.testing.expectEqual(@as(i32, 20), queue.dequeue().?);
    try std.testing.expectEqual(@as(usize, 1), queue.len());

    try std.testing.expectEqual(@as(i32, 30), queue.dequeue().?);
    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(?i32, null), queue.dequeue());
}

test "stack operations" {
    const allocator = std.testing.allocator;

    var stack = Stack(i32).init(allocator);
    defer stack.deinit();

    try stack.push(10);
    try stack.push(20);
    try stack.push(30);

    try std.testing.expectEqual(@as(usize, 3), stack.len());
    try std.testing.expectEqual(@as(i32, 30), stack.peek().?);

    try std.testing.expectEqual(@as(i32, 30), stack.pop().?);
    try std.testing.expectEqual(@as(i32, 20), stack.pop().?);
    try std.testing.expectEqual(@as(usize, 1), stack.len());

    try std.testing.expectEqual(@as(i32, 10), stack.pop().?);
    try std.testing.expect(stack.isEmpty());
    try std.testing.expectEqual(@as(?i32, null), stack.pop());
}

test "thread safety - counter" {
    var counter = Counter.init();
    defer counter.deinit();

    const ThreadContext = struct {
        counter_ptr: *Counter,

        fn worker(ctx: @This()) void {
            var i: usize = 0;
            while (i < 1000) : (i += 1) {
                _ = ctx.counter_ptr.inc();
            }
        }
    };

    var threads: [10]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, ThreadContext.worker, .{ThreadContext{ .counter_ptr = &counter }});
    }

    for (threads) |thread| {
        thread.join();
    }

    try std.testing.expectEqual(@as(u32, 10000), counter.get());
}

test "thread safety - list" {
    const allocator = std.testing.allocator;

    var list = List(i32).init(allocator);
    defer list.deinit();

    const ThreadContext = struct {
        list_ptr: *List(i32),
        start: i32,

        fn worker(ctx: @This()) !void {
            var i: i32 = 0;
            while (i < 100) : (i += 1) {
                try ctx.list_ptr.append(ctx.start + i);
            }
        }
    };

    var threads: [10]std.Thread = undefined;
    for (&threads, 0..) |*thread, idx| {
        thread.* = try std.Thread.spawn(.{}, ThreadContext.worker, .{ThreadContext{ .list_ptr = &list, .start = @as(i32, @intCast(idx)) * 100 }});
    }

    for (threads) |thread| {
        thread.join();
    }

    try std.testing.expectEqual(@as(usize, 1000), list.len());
}
