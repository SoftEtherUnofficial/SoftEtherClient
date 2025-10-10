//! Data Structures
//!
//! Safe wrappers around Mayaqua table FFI functions.
//! Provides generic List, Queue, and Table (HashMap) with type-safe wrappers.

const std = @import("std");
const mayaqua = @import("../mayaqua.zig");
const c = mayaqua.c;
const MayaquaError = mayaqua.MayaquaError;
const checkResult = mayaqua.checkResult;

/// Generic List for storing pointers
pub const List = struct {
    handle: *c.MayaquaList,

    /// Create new list
    pub fn new() List {
        const handle = c.mayaqua_list_new();
        return .{ .handle = handle };
    }

    /// Add item to list
    pub fn add(self: List, item: *anyopaque) void {
        c.mayaqua_list_add(self.handle, item);
    }

    /// Get item at index
    pub fn get(self: List, index: u32) ?*anyopaque {
        const ptr = c.mayaqua_list_get(self.handle, @intCast(index));
        if (ptr == null) return null;
        return ptr;
    }

    /// Remove item at index
    pub fn remove(self: List, index: u32) ?*anyopaque {
        const ptr = c.mayaqua_list_remove(self.handle, @intCast(index));
        if (ptr == null) return null;
        return ptr;
    }

    /// Get list length
    pub fn len(self: List) usize {
        return @intCast(c.mayaqua_list_len(self.handle));
    }

    /// Clear all items (does not free items themselves)
    pub fn clear(self: List) void {
        c.mayaqua_list_clear(self.handle);
    }

    /// Free list (does not free items themselves)
    pub fn free(self: List) void {
        c.mayaqua_list_free(self.handle);
    }
};

/// Generic Queue (FIFO) for storing pointers
pub const Queue = struct {
    handle: *c.MayaquaQueue,

    /// Create new queue
    pub fn new() Queue {
        const handle = c.mayaqua_queue_new();
        return .{ .handle = handle };
    }

    /// Push item to queue (enqueue)
    pub fn push(self: Queue, item: *anyopaque) void {
        c.mayaqua_queue_push(self.handle, item);
    }

    /// Pop item from queue (dequeue)
    pub fn pop(self: Queue) ?*anyopaque {
        const ptr = c.mayaqua_queue_pop(self.handle);
        if (ptr == null) return null;
        return ptr;
    }

    /// Get queue length
    pub fn len(self: Queue) usize {
        return @intCast(c.mayaqua_queue_len(self.handle));
    }

    /// Free queue (does not free items themselves)
    pub fn free(self: Queue) void {
        c.mayaqua_queue_free(self.handle);
    }
};

/// Generic Table/HashMap (string keys to pointers)
pub const Table = struct {
    handle: *c.MayaquaTable,

    /// Create new table
    pub fn new() Table {
        const handle = c.mayaqua_table_new();
        return .{ .handle = handle };
    }

    /// Insert key-value pair
    pub fn insert(self: Table, key: []const u8, value: *anyopaque) MayaquaError!void {
        var key_buf: [256]u8 = undefined;
        if (key.len >= key_buf.len) {
            return MayaquaError.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        const result = c.mayaqua_table_insert(
            self.handle,
            @ptrCast(&key_buf),
            value,
        );
        try checkResult(result);
    }

    /// Get value by key
    pub fn get(self: Table, key: []const u8) MayaquaError!?*anyopaque {
        var key_buf: [256]u8 = undefined;
        if (key.len >= key_buf.len) {
            return MayaquaError.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        const ptr = c.mayaqua_table_get(
            self.handle,
            @ptrCast(&key_buf),
        );
        if (ptr == null) return null;
        return ptr;
    }

    /// Remove key-value pair
    pub fn removeKey(self: Table, key: []const u8) MayaquaError!?*anyopaque {
        var key_buf: [256]u8 = undefined;
        if (key.len >= key_buf.len) {
            return MayaquaError.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        const ptr = c.mayaqua_table_remove(
            self.handle,
            @ptrCast(&key_buf),
        );
        if (ptr == null) return null;
        return ptr;
    }

    /// Check if table contains key
    pub fn contains(self: Table, key: []const u8) MayaquaError!bool {
        var key_buf: [256]u8 = undefined;
        if (key.len >= key_buf.len) {
            return MayaquaError.InvalidParameter;
        }

        @memcpy(key_buf[0..key.len], key);
        key_buf[key.len] = 0;

        return c.mayaqua_table_contains(
            self.handle,
            @ptrCast(&key_buf),
        );
    }

    /// Get table size
    pub fn len(self: Table) usize {
        return @intCast(c.mayaqua_table_len(self.handle));
    }

    /// Free table (does not free values themselves)
    pub fn free(self: Table) void {
        c.mayaqua_table_free(self.handle);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "list operations" {
    const testing = std.testing;

    var list = List.new();
    defer list.free();

    // Create some test data
    var value1: u32 = 42;
    var value2: u32 = 100;

    list.add(@ptrCast(&value1));
    list.add(@ptrCast(&value2));

    try testing.expectEqual(@as(usize, 2), list.len());

    const ptr1 = list.get(0).?;
    const retrieved1: *u32 = @ptrCast(@alignCast(ptr1));
    try testing.expectEqual(@as(u32, 42), retrieved1.*);

    list.clear();
    try testing.expectEqual(@as(usize, 0), list.len());
}

test "queue operations" {
    const testing = std.testing;

    var queue = Queue.new();
    defer queue.free();

    var value1: u32 = 1;
    var value2: u32 = 2;
    var value3: u32 = 3;

    queue.push(@ptrCast(&value1));
    queue.push(@ptrCast(&value2));
    queue.push(@ptrCast(&value3));

    try testing.expectEqual(@as(usize, 3), queue.len());

    const ptr1 = queue.pop().?;
    const retrieved1: *u32 = @ptrCast(@alignCast(ptr1));
    try testing.expectEqual(@as(u32, 1), retrieved1.*);

    try testing.expectEqual(@as(usize, 2), queue.len());
}

test "table operations" {
    const testing = std.testing;

    var table = Table.new();
    defer table.free();

    var value1: u32 = 42;
    var value2: u32 = 100;

    try table.insert("key1", @ptrCast(&value1));
    try table.insert("key2", @ptrCast(&value2));

    try testing.expectEqual(@as(usize, 2), table.len());
    try testing.expect(try table.contains("key1"));
    try testing.expect(try table.contains("key2"));
    try testing.expect(!try table.contains("key3"));

    const ptr1 = (try table.get("key1")).?;
    const retrieved1: *u32 = @ptrCast(@alignCast(ptr1));
    try testing.expectEqual(@as(u32, 42), retrieved1.*);
}
