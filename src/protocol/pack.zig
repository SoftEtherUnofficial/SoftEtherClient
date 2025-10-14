// SoftEther PACK Serialization
// Pure Zig implementation of SoftEther's PACK protocol for key-value data structures
const std = @import("std");
const Allocator = std.mem.Allocator;

/// SoftEther PACK value types
pub const PackValue = union(enum) {
    int: i32,
    int64: i64,
    string: []const u8,
    data: []const u8,
    bool_val: bool,

    pub fn deinit(self: *PackValue, allocator: Allocator) void {
        switch (self.*) {
            .string => |s| allocator.free(s),
            .data => |d| allocator.free(d),
            else => {},
        }
    }
};

/// SoftEther PACK structure - key-value packet for protocol communication
pub const Pack = struct {
    fields: std.StringHashMap(PackValue),
    allocator: Allocator,

    pub fn init(allocator: Allocator) !*Pack {
        const pack = try allocator.create(Pack);
        pack.* = .{
            .fields = std.StringHashMap(PackValue).init(allocator),
            .allocator = allocator,
        };
        return pack;
    }

    pub fn deinit(self: *Pack) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var value = entry.value_ptr.*;
            value.deinit(self.allocator);
        }
        self.fields.deinit();
        self.allocator.destroy(self);
    }

    // ========================================================================
    // Add Field Methods
    // ========================================================================

    pub fn addInt(self: *Pack, name: []const u8, value: i32) !void {
        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        try self.fields.put(key, .{ .int = value });
    }

    pub fn addInt64(self: *Pack, name: []const u8, value: i64) !void {
        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        try self.fields.put(key, .{ .int64 = value });
    }

    pub fn addString(self: *Pack, name: []const u8, value: []const u8) !void {
        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(val);
        try self.fields.put(key, .{ .string = val });
    }

    pub fn addData(self: *Pack, name: []const u8, data: []const u8) !void {
        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        const val = try self.allocator.dupe(u8, data);
        errdefer self.allocator.free(val);
        try self.fields.put(key, .{ .data = val });
    }

    pub fn addBool(self: *Pack, name: []const u8, value: bool) !void {
        const key = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(key);
        try self.fields.put(key, .{ .bool_val = value });
    }

    // ========================================================================
    // Get Field Methods
    // ========================================================================

    pub fn getInt(self: *const Pack, name: []const u8) ?i32 {
        const value = self.fields.get(name) orelse return null;
        return switch (value) {
            .int => |v| v,
            else => null,
        };
    }

    pub fn getInt64(self: *const Pack, name: []const u8) ?i64 {
        const value = self.fields.get(name) orelse return null;
        return switch (value) {
            .int64 => |v| v,
            else => null,
        };
    }

    pub fn getString(self: *const Pack, name: []const u8) ?[]const u8 {
        const value = self.fields.get(name) orelse return null;
        return switch (value) {
            .string => |v| v,
            else => null,
        };
    }

    pub fn getData(self: *const Pack, name: []const u8) ?[]const u8 {
        const value = self.fields.get(name) orelse return null;
        return switch (value) {
            .data => |v| v,
            else => null,
        };
    }

    pub fn getBool(self: *const Pack, name: []const u8) ?bool {
        const value = self.fields.get(name) orelse return null;
        return switch (value) {
            .bool_val => |v| v,
            else => null,
        };
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Serialize to SoftEther PACK binary format
    pub fn serialize(self: *const Pack, writer: anytype) !void {
        // Write field count
        const count: u32 = @intCast(self.fields.count());
        try writer.writeInt(u32, count, .little);

        // Write each field
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const value = entry.value_ptr.*;

            // Write field name length and name
            const name_len: u32 = @intCast(name.len);
            try writer.writeInt(u32, name_len, .little);
            try writer.writeAll(name);

            // Write value type and value
            switch (value) {
                .int => |v| {
                    try writer.writeByte(0); // Type: int
                    try writer.writeInt(i32, v, .little);
                },
                .int64 => |v| {
                    try writer.writeByte(1); // Type: int64
                    try writer.writeInt(i64, v, .little);
                },
                .string => |v| {
                    try writer.writeByte(2); // Type: string
                    const len: u32 = @intCast(v.len);
                    try writer.writeInt(u32, len, .little);
                    try writer.writeAll(v);
                },
                .data => |v| {
                    try writer.writeByte(3); // Type: data
                    const len: u32 = @intCast(v.len);
                    try writer.writeInt(u32, len, .little);
                    try writer.writeAll(v);
                },
                .bool_val => |v| {
                    try writer.writeByte(4); // Type: bool
                    try writer.writeByte(if (v) 1 else 0);
                },
            }
        }
    }

    /// Deserialize from SoftEther PACK binary format
    pub fn deserialize(reader: anytype, allocator: Allocator) !*Pack {
        const pack = try Pack.init(allocator);
        errdefer pack.deinit();

        // Read field count
        const count = try reader.readInt(u32, .little);

        // Read each field
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            // Read field name
            const name_len = try reader.readInt(u32, .little);
            const name = try allocator.alloc(u8, name_len);
            errdefer allocator.free(name);
            _ = try reader.readAll(name);

            // Read value type
            const value_type = try reader.readByte();

            // Read value based on type
            switch (value_type) {
                0 => { // int
                    const value = try reader.readInt(i32, .little);
                    try pack.fields.put(name, .{ .int = value });
                },
                1 => { // int64
                    const value = try reader.readInt(i64, .little);
                    try pack.fields.put(name, .{ .int64 = value });
                },
                2 => { // string
                    const len = try reader.readInt(u32, .little);
                    const value = try allocator.alloc(u8, len);
                    errdefer allocator.free(value);
                    _ = try reader.readAll(value);
                    try pack.fields.put(name, .{ .string = value });
                },
                3 => { // data
                    const len = try reader.readInt(u32, .little);
                    const value = try allocator.alloc(u8, len);
                    errdefer allocator.free(value);
                    _ = try reader.readAll(value);
                    try pack.fields.put(name, .{ .data = value });
                },
                4 => { // bool
                    const value = (try reader.readByte()) != 0;
                    try pack.fields.put(name, .{ .bool_val = value });
                },
                else => return error.InvalidPackValueType,
            }
        }

        return pack;
    }

    /// Serialize to byte array
    pub fn toBytes(self: *const Pack) ![]u8 {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(self.allocator);
        try self.serialize(list.writer(self.allocator));
        return try list.toOwnedSlice(self.allocator);
    }

    /// Deserialize from byte array
    pub fn fromBytes(data: []const u8, allocator: Allocator) !*Pack {
        var stream = std.io.fixedBufferStream(data);
        return try deserialize(stream.reader(), allocator);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Pack: create and destroy" {
    const allocator = std.testing.allocator;
    const pack = try Pack.init(allocator);
    defer pack.deinit();
}

test "Pack: add and get int" {
    const allocator = std.testing.allocator;
    const pack = try Pack.init(allocator);
    defer pack.deinit();

    try pack.addInt("test", 42);
    const value = pack.getInt("test");
    try std.testing.expectEqual(@as(i32, 42), value.?);
}

test "Pack: add and get string" {
    const allocator = std.testing.allocator;
    const pack = try Pack.init(allocator);
    defer pack.deinit();

    try pack.addString("name", "SoftEtherZig");
    const value = pack.getString("name");
    try std.testing.expectEqualStrings("SoftEtherZig", value.?);
}

test "Pack: add and get bool" {
    const allocator = std.testing.allocator;
    const pack = try Pack.init(allocator);
    defer pack.deinit();

    try pack.addBool("enabled", true);
    const value = pack.getBool("enabled");
    try std.testing.expect(value.?);
}

test "Pack: serialize and deserialize" {
    const allocator = std.testing.allocator;

    // Create pack
    const pack1 = try Pack.init(allocator);
    defer pack1.deinit();
    try pack1.addInt("version", 502);
    try pack1.addString("client", "SoftEtherZig");
    try pack1.addBool("test", true);

    // Serialize
    const bytes = try pack1.toBytes();
    defer allocator.free(bytes);

    // Deserialize
    const pack2 = try Pack.fromBytes(bytes, allocator);
    defer pack2.deinit();

    // Verify
    try std.testing.expectEqual(@as(i32, 502), pack2.getInt("version").?);
    try std.testing.expectEqualStrings("SoftEtherZig", pack2.getString("client").?);
    try std.testing.expect(pack2.getBool("test").?);
}

test "Pack: multiple data types" {
    const allocator = std.testing.allocator;
    const pack = try Pack.init(allocator);
    defer pack.deinit();

    try pack.addInt("int_val", -100);
    try pack.addInt64("int64_val", 9999999999);
    try pack.addString("str_val", "test");
    try pack.addData("data_val", &[_]u8{ 1, 2, 3, 4 });
    try pack.addBool("bool_val", false);

    try std.testing.expectEqual(@as(i32, -100), pack.getInt("int_val").?);
    try std.testing.expectEqual(@as(i64, 9999999999), pack.getInt64("int64_val").?);
    try std.testing.expectEqualStrings("test", pack.getString("str_val").?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, pack.getData("data_val").?);
    try std.testing.expect(!pack.getBool("bool_val").?);
}
