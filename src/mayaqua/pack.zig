//! Pack system for SoftEther VPN protocol - Zig implementation
//!
//! Binary serialization format compatible with the C and Rust implementations.
//! Uses big-endian byte order for scalar fields per SoftEther wire format.
//!
//! Ported from: SoftEtherRust/libs/mayaqua/src/pack.rs

const std = @import("std");
const Allocator = std.mem.Allocator;

// Constants from SoftEther protocol
pub const MAX_ELEMENT_NAME_LEN: usize = 63;
pub const MAX_VALUE_NUM: usize = 16384;
pub const MAX_ELEMENT_NUM: usize = 16384;
pub const MAX_VALUE_SIZE: usize = 67108864; // 64MB
pub const MAX_PACK_SIZE: usize = 134217728; // 128MB

/// Errors that can occur during pack operations
pub const PackError = error{
    InvalidPack,
    SizeOver,
    InvalidParameter,
    InvalidUtf8,
    EndOfStream,
    OutOfMemory,
};

/// Value types in the pack system (from C Pack.h)
pub const ValueType = enum(u32) {
    int = 0, // 32-bit integer
    data = 1, // Binary data blob
    str = 2, // ANSI string
    uni_str = 3, // Unicode string (UTF-8)
    int64 = 4, // 64-bit integer

    pub fn fromU32(value: u32) PackError!ValueType {
        return switch (value) {
            0 => .int,
            1 => .data,
            2 => .str,
            3 => .uni_str,
            4 => .int64,
            else => PackError.InvalidPack,
        };
    }
};

/// A value in the pack system
pub const Value = struct {
    int_value: u32,
    int64_value: u64,
    data: []u8, // Owned slice
    str_value: []u8, // Owned slice
    uni_str: []u8, // Owned slice
    allocator: Allocator,
    /// For int values: use little-endian encoding instead of big-endian
    /// This is needed for OutRpcNodeInfo fields (ClientPort, ClientProductVer, etc.)
    use_little_endian: bool = false,

    pub fn initInt(allocator: Allocator, value: u32) !*Value {
        return initIntWithEndian(allocator, value, false);
    }

    pub fn initIntLittleEndian(allocator: Allocator, value: u32) !*Value {
        return initIntWithEndian(allocator, value, true);
    }

    fn initIntWithEndian(allocator: Allocator, value: u32, little_endian: bool) !*Value {
        const self = try allocator.create(Value);
        self.* = .{
            .int_value = value,
            .int64_value = 0,
            .data = &[_]u8{},
            .str_value = &[_]u8{},
            .uni_str = &[_]u8{},
            .allocator = allocator,
            .use_little_endian = little_endian,
        };
        return self;
    }

    pub fn initInt64(allocator: Allocator, value: u64) !*Value {
        const self = try allocator.create(Value);
        self.* = .{
            .int_value = 0,
            .int64_value = value,
            .data = &[_]u8{},
            .str_value = &[_]u8{},
            .uni_str = &[_]u8{},
            .allocator = allocator,
        };
        return self;
    }

    pub fn initData(allocator: Allocator, data: []const u8) !*Value {
        const self = try allocator.create(Value);
        const data_copy = try allocator.dupe(u8, data);
        self.* = .{
            .int_value = 0,
            .int64_value = 0,
            .data = data_copy,
            .str_value = &[_]u8{},
            .uni_str = &[_]u8{},
            .allocator = allocator,
        };
        return self;
    }

    pub fn initStr(allocator: Allocator, s: []const u8) !*Value {
        const self = try allocator.create(Value);
        const str_copy = try allocator.dupe(u8, s);
        self.* = .{
            .int_value = 0,
            .int64_value = 0,
            .data = &[_]u8{},
            .str_value = str_copy,
            .uni_str = &[_]u8{},
            .allocator = allocator,
        };
        return self;
    }

    pub fn initUniStr(allocator: Allocator, s: []const u8) !*Value {
        const self = try allocator.create(Value);
        const str_copy = try allocator.dupe(u8, s);
        self.* = .{
            .int_value = 0,
            .int64_value = 0,
            .data = &[_]u8{},
            .str_value = &[_]u8{},
            .uni_str = str_copy,
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(self: *Value) void {
        if (self.data.len > 0) self.allocator.free(self.data);
        if (self.str_value.len > 0) self.allocator.free(self.str_value);
        if (self.uni_str.len > 0) self.allocator.free(self.uni_str);
        self.allocator.destroy(self);
    }

    /// Write value to buffer using big-endian byte order (or little-endian for OutRpcNodeInfo fields)
    pub fn writeToBuffer(self: *const Value, writer: anytype, value_type: ValueType) !void {
        switch (value_type) {
            .int => {
                // OutRpcNodeInfo fields use little-endian, regular Pack ints use big-endian
                const byte_order: std.builtin.Endian = if (self.use_little_endian) .little else .big;
                try writer.writeInt(u32, self.int_value, byte_order);
            },
            .int64 => {
                try writer.writeInt(u64, self.int64_value, .big);
            },
            .data => {
                try writer.writeInt(u32, @intCast(self.data.len), .big);
                try writer.writeAll(self.data);
            },
            .str => {
                try writer.writeInt(u32, @intCast(self.str_value.len), .big);
                try writer.writeAll(self.str_value);
            },
            .uni_str => {
                try writer.writeInt(u32, @intCast(self.uni_str.len), .big);
                try writer.writeAll(self.uni_str);
            },
        }
    }

    /// Read value from buffer based on type (big-endian)
    pub fn readFromBuffer(allocator: Allocator, reader: anytype, value_type: ValueType) !*Value {
        switch (value_type) {
            .int => {
                const int_val = try reader.readInt(u32, .big);
                return try initInt(allocator, int_val);
            },
            .int64 => {
                const int64_val = try reader.readInt(u64, .big);
                return try initInt64(allocator, int64_val);
            },
            .data => {
                const len = try reader.readInt(u32, .big);
                if (len > MAX_VALUE_SIZE) return PackError.SizeOver;

                const data = try allocator.alloc(u8, len);
                defer allocator.free(data); // Free after initData dupes it

                try reader.readNoEof(data);

                return try initData(allocator, data);
            },
            .str => {
                const len = try reader.readInt(u32, .big);
                if (len > MAX_VALUE_SIZE) return PackError.SizeOver;

                const str_data = try allocator.alloc(u8, len);
                defer allocator.free(str_data); // Free after initStr dupes it

                try reader.readNoEof(str_data);

                // Validate UTF-8
                if (!std.unicode.utf8ValidateSlice(str_data)) {
                    return PackError.InvalidUtf8;
                }

                return try initStr(allocator, str_data);
            },
            .uni_str => {
                const len = try reader.readInt(u32, .big);
                if (len > MAX_VALUE_SIZE) return PackError.SizeOver;

                const str_data = try allocator.alloc(u8, len);
                defer allocator.free(str_data); // Free after initUniStr dupes it

                try reader.readNoEof(str_data);

                // Validate UTF-8
                if (!std.unicode.utf8ValidateSlice(str_data)) {
                    return PackError.InvalidUtf8;
                }

                return try initUniStr(allocator, str_data);
            },
        }
    }
};

/// An element in the pack system
pub const Element = struct {
    name: []u8, // Owned slice (max 63 chars)
    value_type: ValueType,
    values: std.ArrayList(*Value),
    allocator: Allocator,

    // JSON conversion hints (for future use)
    json_hint_is_array: bool = false,
    json_hint_is_bool: bool = false,
    json_hint_is_datetime: bool = false,
    json_hint_is_ip: bool = false,
    json_hint_group_name: []u8 = &[_]u8{},

    pub fn init(allocator: Allocator, name: []const u8, value_type: ValueType) !*Element {
        if (name.len > MAX_ELEMENT_NAME_LEN) {
            return PackError.InvalidParameter;
        }

        const self = try allocator.create(Element);
        const name_copy = try allocator.dupe(u8, name);
        errdefer allocator.free(name_copy);

        var values_list = try std.ArrayList(*Value).initCapacity(allocator, 4);
        errdefer values_list.deinit(allocator);

        self.* = .{
            .name = name_copy,
            .value_type = value_type,
            .values = values_list,
            .allocator = allocator,
        };

        return self;
    }

    pub fn deinit(self: *Element) void {
        for (self.values.items) |value| {
            value.deinit();
        }
        self.values.deinit(self.allocator);
        self.allocator.free(self.name);
        if (self.json_hint_group_name.len > 0) {
            self.allocator.free(self.json_hint_group_name);
        }
        self.allocator.destroy(self);
    }

    pub fn addValue(self: *Element, value: *Value) !void {
        if (self.values.items.len >= MAX_VALUE_NUM) {
            return PackError.SizeOver;
        }
        try self.values.append(self.allocator, value);
    }

    /// Write element to buffer: name_len (BE, includes virtual null), name bytes (no NUL),
    /// value_type (BE), value_count (BE), then values.
    pub fn writeToBuffer(self: *const Element, writer: anytype) !void {
        // SoftEther writes length = (len + 1) including a virtual null terminator,
        // but does NOT write the null byte itself.
        const stored_len: u32 = @intCast(self.name.len + 1);
        if (stored_len > MAX_ELEMENT_NAME_LEN + 1) {
            return PackError.SizeOver;
        }

        try writer.writeInt(u32, stored_len, .big);
        try writer.writeAll(self.name); // no trailing NUL

        // value type (big-endian)
        try writer.writeInt(u32, @intFromEnum(self.value_type), .big);

        // value count (big-endian)
        try writer.writeInt(u32, @intCast(self.values.items.len), .big);

        // values
        for (self.values.items) |value| {
            try value.writeToBuffer(writer, self.value_type);
        }
    }

    /// Read element from buffer using BE name length
    pub fn readFromBuffer(allocator: Allocator, reader: anytype) !*Element {
        const name_len_with_null = try reader.readInt(u32, .big);
        if (name_len_with_null == 0 or name_len_with_null - 1 > MAX_ELEMENT_NAME_LEN) {
            return PackError.InvalidPack;
        }

        const name_len = name_len_with_null - 1;
        const raw_name_bytes = try allocator.alloc(u8, name_len);
        defer allocator.free(raw_name_bytes); // Free after use since Element.init will dupe

        try reader.readNoEof(raw_name_bytes);

        // Check for null bytes in name
        if (std.mem.indexOfScalar(u8, raw_name_bytes, 0) != null) {
            return PackError.InvalidPack;
        }

        // Validate UTF-8
        if (!std.unicode.utf8ValidateSlice(raw_name_bytes)) {
            return PackError.InvalidUtf8;
        }

        // value type
        const value_type_raw = try reader.readInt(u32, .big);
        const value_type = try ValueType.fromU32(value_type_raw);

        // value count
        const value_count = try reader.readInt(u32, .big);
        if (value_count > MAX_VALUE_NUM) {
            return PackError.SizeOver;
        }

        const element = try init(allocator, raw_name_bytes, value_type);
        errdefer element.deinit();

        // Read values
        var i: usize = 0;
        while (i < value_count) : (i += 1) {
            const value = try Value.readFromBuffer(allocator, reader, value_type);
            errdefer value.deinit();
            try element.addValue(value);
        }

        return element;
    }
};

/// The main Pack structure for SoftEther protocol
pub const Pack = struct {
    elements: std.ArrayList(*Element),
    allocator: Allocator,

    // JSON metadata (for future use)
    json_subitem_names: std.ArrayList([]u8),
    current_json_hint_group_name: []u8,

    pub fn init(allocator: Allocator) !*Pack {
        const self = try allocator.create(Pack);

        var elements_list = try std.ArrayList(*Element).initCapacity(allocator, 16);
        errdefer elements_list.deinit(allocator);

        var json_names = try std.ArrayList([]u8).initCapacity(allocator, 4);
        errdefer json_names.deinit(allocator);

        self.* = .{
            .elements = elements_list,
            .allocator = allocator,
            .json_subitem_names = json_names,
            .current_json_hint_group_name = &[_]u8{},
        };
        return self;
    }

    pub fn deinit(self: *Pack) void {
        for (self.elements.items) |element| {
            element.deinit();
        }
        self.elements.deinit(self.allocator);

        for (self.json_subitem_names.items) |name| {
            self.allocator.free(name);
        }
        self.json_subitem_names.deinit(self.allocator);

        if (self.current_json_hint_group_name.len > 0) {
            self.allocator.free(self.current_json_hint_group_name);
        }

        self.allocator.destroy(self);
    }

    pub fn addElement(self: *Pack, element: *Element) !void {
        if (self.elements.items.len >= MAX_ELEMENT_NUM) {
            return PackError.SizeOver;
        }
        try self.elements.append(self.allocator, element);
    }

    /// Find element by name
    pub fn findElement(self: *const Pack, name: []const u8) ?*Element {
        for (self.elements.items) |element| {
            if (std.mem.eql(u8, element.name, name)) {
                return element;
            }
        }
        return null;
    }

    /// Serialize pack to binary buffer (SoftEther format - big-endian)
    pub fn toBuffer(self: *const Pack, allocator: Allocator) ![]u8 {
        var buffer = try std.ArrayList(u8).initCapacity(allocator, 1024);
        errdefer buffer.deinit(allocator);

        const writer = buffer.writer(allocator);

        // CRITICAL: Sort elements alphabetically by name (matches C ComparePackName)
        // C implementation uses sorted list, so we must sort before serialization
        const sorted_elements = try allocator.alloc(*Element, self.elements.items.len);
        defer allocator.free(sorted_elements);
        @memcpy(sorted_elements, self.elements.items);

        // Sort using CASE-INSENSITIVE element name comparison (matches C StrCmpi)
        std.mem.sort(*Element, sorted_elements, {}, struct {
            fn lessThan(_: void, a: *Element, b: *Element) bool {
                // Case-insensitive ASCII comparison using ToUpper (matches C's StrCmpi)
                const len = @min(a.name.len, b.name.len);
                for (0..len) |i| {
                    const a_upper = std.ascii.toUpper(a.name[i]);
                    const b_upper = std.ascii.toUpper(b.name[i]);
                    if (a_upper < b_upper) return true;
                    if (a_upper > b_upper) return false;
                }
                return a.name.len < b.name.len;
            }
        }.lessThan);

        // Write element count (big-endian)
        try writer.writeInt(u32, @intCast(sorted_elements.len), .big);

        // Write each element in sorted order
        for (sorted_elements) |element| {
            try element.writeToBuffer(writer);
        }

        // Check total size limit
        if (buffer.items.len > MAX_PACK_SIZE) {
            return PackError.SizeOver;
        }

        const result = try buffer.toOwnedSlice(allocator);

        // DEBUG: Dump Pack binary for comparison with C bridge
        {
            const file = std.fs.cwd().createFile("/tmp/pure_zig_auth_pack.bin", .{}) catch |err| {
                std.log.debug("Failed to create debug dump file: {}", .{err});
                return result;
            };
            defer file.close();
            file.writeAll(result) catch |err| {
                std.log.debug("Failed to write debug dump: {}", .{err});
            };
            std.log.debug("Pure Zig Pack dumped: {} bytes to /tmp/pure_zig_auth_pack.bin", .{result.len});
        }

        return result;
    }

    /// Deserialize pack from binary buffer (big-endian)
    pub fn fromBuffer(allocator: Allocator, data: []const u8) !*Pack {
        if (data.len > MAX_PACK_SIZE) {
            return PackError.SizeOver;
        }

        var stream = std.io.fixedBufferStream(data);
        const reader = stream.reader();

        // Read element count (big-endian)
        const element_count = try reader.readInt(u32, .big);
        if (element_count > MAX_ELEMENT_NUM) {
            return PackError.SizeOver;
        }

        const pack = try init(allocator);
        errdefer pack.deinit();

        // Read each element
        var i: usize = 0;
        while (i < element_count) : (i += 1) {
            const element = try Element.readFromBuffer(allocator, reader);
            errdefer element.deinit();
            try pack.addElement(element);
        }

        return pack;
    }
};

// Helper functions for common operations

/// Add int value to pack (big-endian encoding)
pub fn packAddInt(pack: *Pack, name: []const u8, value: u32) !void {
    const element = try Element.init(pack.allocator, name, .int);
    errdefer element.deinit();

    const val = try Value.initInt(pack.allocator, value);
    errdefer val.deinit();

    try element.addValue(val);
    try pack.addElement(element);
}

/// Add int value to pack with LITTLE-endian encoding
/// Used for OutRpcNodeInfo fields (ClientPort, ClientProductVer, ClientProductBuild, etc.)
pub fn packAddIntLittleEndian(pack: *Pack, name: []const u8, value: u32) !void {
    const element = try Element.init(pack.allocator, name, .int);
    errdefer element.deinit();

    const val = try Value.initIntLittleEndian(pack.allocator, value);
    errdefer val.deinit();

    try element.addValue(val);
    try pack.addElement(element);
}

/// Add int64 value to pack
pub fn packAddInt64(pack: *Pack, name: []const u8, value: u64) !void {
    const element = try Element.init(pack.allocator, name, .int64);
    errdefer element.deinit();

    const val = try Value.initInt64(pack.allocator, value);
    errdefer val.deinit();

    try element.addValue(val);
    try pack.addElement(element);
}

/// Add string value to pack
pub fn packAddStr(pack: *Pack, name: []const u8, value: []const u8) !void {
    const element = try Element.init(pack.allocator, name, .str);
    errdefer element.deinit();

    const val = try Value.initStr(pack.allocator, value);
    errdefer val.deinit();

    try element.addValue(val);
    try pack.addElement(element);
}

/// Add data value to pack
pub fn packAddData(pack: *Pack, name: []const u8, value: []const u8) !void {
    const element = try Element.init(pack.allocator, name, .data);
    errdefer element.deinit();

    const val = try Value.initData(pack.allocator, value);
    errdefer val.deinit();

    try element.addValue(val);
    try pack.addElement(element);
}

/// Get int value from pack
pub fn packGetInt(pack: *const Pack, name: []const u8) ?u32 {
    if (pack.findElement(name)) |element| {
        if (element.value_type == .int and element.values.items.len > 0) {
            return element.values.items[0].int_value;
        }
    }
    return null;
}

/// Get int64 value from pack
pub fn packGetInt64(pack: *const Pack, name: []const u8) ?u64 {
    if (pack.findElement(name)) |element| {
        if (element.value_type == .int64 and element.values.items.len > 0) {
            return element.values.items[0].int64_value;
        }
    }
    return null;
}

/// Get string value from pack
pub fn packGetStr(pack: *const Pack, name: []const u8) ?[]const u8 {
    if (pack.findElement(name)) |element| {
        if (element.value_type == .str and element.values.items.len > 0) {
            return element.values.items[0].str_value;
        }
    }
    return null;
}

/// Get data value from pack
pub fn packGetData(pack: *const Pack, name: []const u8) ?[]const u8 {
    if (pack.findElement(name)) |element| {
        if (element.value_type == .data and element.values.items.len > 0) {
            return element.values.items[0].data;
        }
    }
    return null;
}

/// Add IPv4 address with IPv6 metadata fields (matches C PackAddIp32/PackAddIp)
/// This adds 4 elements total:
/// - {name}@ipv6_array: 16 zero bytes for IPv4
/// - {name}@ipv6_bool: false (0) for IPv4
/// - {name}@ipv6_scope_id: 0 for IPv4
/// - {name}: the IPv4 address as u32 (added last to match C order)
pub fn packAddIpv4(pack: *Pack, name: []const u8, ipv4: u32) !void {
    var name_buf: [128]u8 = undefined;

    // Add @ipv6_array = 16 zero bytes (added FIRST)
    const ipv6_array_name = try std.fmt.bufPrint(&name_buf, "{s}@ipv6_array", .{name});
    var zero_ipv6: [16]u8 = undefined;
    @memset(&zero_ipv6, 0);
    try packAddData(pack, ipv6_array_name, &zero_ipv6);

    // Add @ipv6_bool = false (0)
    const ipv6_bool_name = try std.fmt.bufPrint(&name_buf, "{s}@ipv6_bool", .{name});
    try packAddInt(pack, ipv6_bool_name, 0);

    // Add @ipv6_scope_id = 0
    const ipv6_scope_name = try std.fmt.bufPrint(&name_buf, "{s}@ipv6_scope_id", .{name});
    try packAddInt(pack, ipv6_scope_name, 0);

    // Add main IP address field LAST (matches C PackAddIp order)
    try packAddInt(pack, name, ipv4);
}
