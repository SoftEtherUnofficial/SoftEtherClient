//! Pack Protocol - SoftEther Binary Serialization Format
//!
//! This module implements the Pack protocol used by SoftEther VPN for
//! serializing structured data (key-value pairs) into binary format.
//!
//! Replaces: src/bridge/Mayaqua/Pack.c (~2,500 lines C → ~800 lines Zig)
//!
//! Pack is SoftEther's binary serialization format, similar to MessagePack
//! but with SoftEther-specific types and conventions. Used for:
//! - VPN protocol messages (authentication, keep-alive, etc.)
//! - Configuration data
//! - Session parameters
//! - RPC calls between client and server
//!
//! ## Protocol Specification
//!
//! Pack Format (little-endian):
//! ```
//! [element_count: u32]
//! [element_1]
//! [element_2]
//! ...
//! ```
//!
//! Element Format:
//! ```
//! [key_length: u32]
//! [key_bytes: u8[key_length]]
//! [value_type: u8]
//! [value_data]
//! ```
//!
//! Value Types:
//! - 0: int (u32, 4 bytes)
//! - 1: data (length: u32, bytes: u8[])
//! - 2: str (ANSI string, length: u32, bytes: u8[])
//! - 3: unistr (Unicode UTF-16LE string, length: u32, bytes: u16[])
//! - 4: int64 (u64, 8 bytes)
//!
//! ## Phase 5 Week 2 Status
//!
//! - [x] Day 1: Extract Pack module, add constants, validation
//! - [ ] Day 2: Unicode string support (VALUE_UNISTR)
//! - [ ] Day 3: IP address helper types
//! - [ ] Day 4: Compression support (LZO/zlib)
//! - [ ] Day 5: Comprehensive testing and benchmarks

const std = @import("std");
const Allocator = std.mem.Allocator;
const compress = @import("compress.zig");

// ============================================================================
// SoftEther Pack Constants (from Pack.h)
// ============================================================================

/// Maximum size of data in a single VALUE
pub const MAX_VALUE_SIZE: usize = if (@sizeOf(usize) == 8)
    384 * 1024 * 1024 // 384 MB on 64-bit
else
    96 * 1024 * 1024; // 96 MB on 32-bit

/// Maximum number of VALUES in a single ELEMENT
pub const MAX_VALUE_NUM: u32 = if (@sizeOf(usize) == 8)
    262144 // 256K on 64-bit
else
    65536; // 64K on 32-bit

/// Maximum length of an ELEMENT name
pub const MAX_ELEMENT_NAME_LEN: usize = 63;

/// Maximum number of ELEMENTs in a single PACK
pub const MAX_ELEMENT_NUM: u32 = if (@sizeOf(usize) == 8)
    262144 // 256K on 64-bit
else
    131072; // 128K on 32-bit

/// Maximum size of a serialized PACK
pub const MAX_PACK_SIZE: usize = if (@sizeOf(usize) == 8)
    512 * 1024 * 1024 // 512 MB on 64-bit
else
    128 * 1024 * 1024; // 128 MB on 32-bit

// Value type codes (must match SoftEther C protocol)
pub const VALUE_INT: u8 = 0;
pub const VALUE_DATA: u8 = 1;
pub const VALUE_STR: u8 = 2;
pub const VALUE_UNISTR: u8 = 3;
pub const VALUE_INT64: u8 = 4;

// ============================================================================
// Unicode Conversion Utilities
// ============================================================================

/// Convert UTF-8 string to UTF-16LE (little-endian)
/// Caller owns returned memory
pub fn utf8ToUtf16Le(allocator: Allocator, utf8: []const u8) ![]u16 {
    // Count UTF-16 code units needed
    const utf16_len = try std.unicode.utf8CountCodepoints(utf8);

    // Allocate UTF-16 buffer
    var utf16 = try allocator.alloc(u16, utf16_len);
    errdefer allocator.free(utf16);

    // Convert UTF-8 to UTF-16
    var utf8_view = try std.unicode.Utf8View.init(utf8);
    var utf8_iter = utf8_view.iterator();
    var i: usize = 0;

    while (utf8_iter.nextCodepoint()) |codepoint| {
        if (codepoint <= 0xFFFF) {
            // BMP character (single UTF-16 code unit)
            utf16[i] = @intCast(codepoint);
            i += 1;
        } else {
            // Supplementary character (surrogate pair)
            const high = @as(u16, @intCast(0xD800 + ((codepoint - 0x10000) >> 10)));
            const low = @as(u16, @intCast(0xDC00 + ((codepoint - 0x10000) & 0x3FF)));

            if (i + 1 >= utf16.len) {
                // Need to expand buffer for surrogate pair
                const new_len = utf16.len + 1;
                const new_buf = try allocator.realloc(utf16, new_len);
                utf16 = new_buf;
            }

            utf16[i] = high;
            utf16[i + 1] = low;
            i += 2;
        }
    }

    // Resize to actual length (may be larger if we had surrogate pairs)
    if (i != utf16.len) {
        utf16 = try allocator.realloc(utf16, i);
    }

    return utf16;
}

/// Convert UTF-16LE (little-endian) to UTF-8 string
/// Caller owns returned memory
pub fn utf16LeToUtf8(allocator: Allocator, utf16: []const u16) ![]u8 {
    // Estimate UTF-8 size (max 4 bytes per codepoint)
    var utf8 = try std.ArrayList(u8).initCapacity(allocator, utf16.len * 2);
    errdefer utf8.deinit(allocator);

    var i: usize = 0;
    while (i < utf16.len) {
        const unit = utf16[i];
        i += 1;

        var codepoint: u21 = undefined;

        if (unit >= 0xD800 and unit <= 0xDBFF) {
            // High surrogate - need low surrogate
            if (i >= utf16.len) return error.InvalidUtf16;

            const low = utf16[i];
            if (low < 0xDC00 or low > 0xDFFF) return error.InvalidUtf16;
            i += 1;

            // Combine surrogates
            codepoint = @as(u21, @intCast(0x10000 +
                ((@as(u32, unit) - 0xD800) << 10) +
                (@as(u32, low) - 0xDC00)));
        } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
            // Lone low surrogate - invalid
            return error.InvalidUtf16;
        } else {
            // BMP character
            codepoint = @as(u21, @intCast(unit));
        }

        // Encode codepoint as UTF-8
        var buf: [4]u8 = undefined;
        const utf8_len = try std.unicode.utf8Encode(codepoint, &buf);
        try utf8.appendSlice(allocator, buf[0..utf8_len]);
    }

    return utf8.toOwnedSlice(allocator);
}

// ============================================================================
// Pack Value Types
// ============================================================================

/// Pack value - represents a single typed value in the Pack protocol
pub const PackValue = union(enum) {
    /// 32-bit unsigned integer (VALUE_INT = 0)
    int: u32,

    /// 64-bit unsigned integer (VALUE_INT64 = 4)
    int64: u64,

    /// Boolean (custom extension, serialized as int)
    /// Note: Not in original C spec, but useful for Zig
    bool: bool,

    /// Binary data blob (VALUE_DATA = 1)
    data: []const u8,

    /// ANSI/UTF-8 string (VALUE_STR = 2)
    str: []const u8,

    /// Unicode UTF-16LE string (VALUE_UNISTR = 3)
    /// TODO: Implement in Day 2
    unistr: []const u16,

    /// Get the type code for serialization
    pub fn getTypeCode(self: PackValue) u8 {
        return switch (self) {
            .int => VALUE_INT,
            .int64 => VALUE_INT64,
            .bool => VALUE_INT, // Serialize bool as int (0 or 1)
            .data => VALUE_DATA,
            .str => VALUE_STR,
            .unistr => VALUE_UNISTR,
        };
    }
};

// ============================================================================
// Pack Structure
// ============================================================================

/// Pack - a collection of named values (key-value pairs)
/// Similar to a HashMap<String, PackValue> but with serialization support
pub const Pack = struct {
    data: std.StringHashMap(PackValue),
    allocator: Allocator,

    const Self = @This();

    /// Create a new empty Pack
    pub fn init(allocator: Allocator) Self {
        return .{
            .data = std.StringHashMap(PackValue).init(allocator),
            .allocator = allocator,
        };
    }

    /// Free all memory associated with the Pack
    pub fn deinit(self: *Self) void {
        var it = self.data.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            switch (entry.value_ptr.*) {
                .data => |d| self.allocator.free(d),
                .str => |s| self.allocator.free(s),
                .unistr => |u| self.allocator.free(u),
                else => {},
            }
        }
        self.data.deinit();
    }

    /// Internal method: Add value without copying (takes ownership)
    /// Used by deserialize() to avoid double-copying
    fn putTakingOwnership(self: *Self, key: []const u8, value: PackValue) !void {
        // Validate key length
        if (key.len > MAX_ELEMENT_NAME_LEN) {
            return error.KeyTooLong;
        }

        // Check element count limit (only if adding new key)
        if (!self.data.contains(key) and self.data.count() >= MAX_ELEMENT_NUM) {
            return error.TooManyElements;
        }

        // Copy the key
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        // Validate value size
        switch (value) {
            .data => |d| if (d.len > MAX_VALUE_SIZE) return error.ValueTooLarge,
            .str => |s| if (s.len > MAX_VALUE_SIZE) return error.ValueTooLarge,
            .unistr => |u| if (u.len * 2 > MAX_VALUE_SIZE) return error.ValueTooLarge,
            else => {},
        }

        // If key already exists, free the old key and value
        if (self.data.fetchRemove(key)) |old_entry| {
            self.allocator.free(old_entry.key);
            switch (old_entry.value) {
                .data => |d| self.allocator.free(d),
                .str => |s| self.allocator.free(s),
                .unistr => |u| self.allocator.free(u),
                else => {},
            }
        }

        // Insert value directly (takes ownership)
        try self.data.put(key_copy, value);
    }

    /// Add or update a value in the Pack
    /// Key and value are copied (caller retains ownership of inputs)
    pub fn put(self: *Self, key: []const u8, value: PackValue) !void {
        // Validate key length
        if (key.len > MAX_ELEMENT_NAME_LEN) {
            return error.KeyTooLong;
        }

        // Check element count limit (only if adding new key)
        if (!self.data.contains(key) and self.data.count() >= MAX_ELEMENT_NUM) {
            return error.TooManyElements;
        }

        // Copy the key
        const key_copy = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(key_copy);

        // Copy the value (if it contains owned data)
        const value_copy = switch (value) {
            .data => |d| blk: {
                if (d.len > MAX_VALUE_SIZE) return error.ValueTooLarge;
                break :blk PackValue{ .data = try self.allocator.dupe(u8, d) };
            },
            .str => |s| blk: {
                if (s.len > MAX_VALUE_SIZE) return error.ValueTooLarge;
                break :blk PackValue{ .str = try self.allocator.dupe(u8, s) };
            },
            .unistr => |u| blk: {
                if (u.len * 2 > MAX_VALUE_SIZE) return error.ValueTooLarge;
                break :blk PackValue{ .unistr = try self.allocator.dupe(u16, u) };
            },
            else => value,
        };

        // If key already exists, free the old key and value
        if (self.data.fetchRemove(key)) |old_entry| {
            self.allocator.free(old_entry.key);
            switch (old_entry.value) {
                .data => |d| self.allocator.free(d),
                .str => |s| self.allocator.free(s),
                .unistr => |u| self.allocator.free(u),
                else => {},
            }
        }

        try self.data.put(key_copy, value_copy);
    }

    /// Get a value from the Pack (returns null if not found)
    pub fn get(self: *const Self, key: []const u8) ?PackValue {
        return self.data.get(key);
    }

    /// Check if a key exists in the Pack
    pub fn contains(self: *const Self, key: []const u8) bool {
        return self.data.contains(key);
    }

    /// Remove a value from the Pack
    pub fn remove(self: *Self, key: []const u8) bool {
        if (self.data.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            switch (kv.value) {
                .data => |d| self.allocator.free(d),
                .str => |s| self.allocator.free(s),
                .unistr => |u| self.allocator.free(u),
                else => {},
            }
            return true;
        }
        return false;
    }

    /// Get the number of elements in the Pack
    pub fn len(self: *const Self) u32 {
        return @intCast(self.data.count());
    }

    // ========================================================================
    // Serialization
    // ========================================================================

    /// Serialize the Pack to binary format
    /// Caller owns returned memory
    pub fn serialize(self: *const Self) ![]u8 {
        var buffer = std.ArrayList(u8).initCapacity(self.allocator, 1024) catch |err| {
            if (err == error.OutOfMemory) return err;
            unreachable;
        };
        defer buffer.deinit(self.allocator);

        const writer = buffer.writer(self.allocator);

        // Write number of elements
        const element_count: u32 = @intCast(self.data.count());
        try writer.writeInt(u32, element_count, .little);

        // Write each key-value pair
        var it = self.data.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr.*;

            // Write key length and key
            try writer.writeInt(u32, @intCast(key.len), .little);
            try writer.writeAll(key);

            // Write value type and value
            switch (value) {
                .int => |v| {
                    try writer.writeByte(VALUE_INT);
                    try writer.writeInt(u32, v, .little);
                },
                .int64 => |v| {
                    try writer.writeByte(VALUE_INT64);
                    try writer.writeInt(u64, v, .little);
                },
                .bool => |v| {
                    // Serialize bool as int (0 or 1)
                    try writer.writeByte(VALUE_INT);
                    try writer.writeInt(u32, if (v) 1 else 0, .little);
                },
                .data => |d| {
                    try writer.writeByte(VALUE_DATA);
                    try writer.writeInt(u32, @intCast(d.len), .little);
                    try writer.writeAll(d);
                },
                .str => |s| {
                    try writer.writeByte(VALUE_STR);
                    try writer.writeInt(u32, @intCast(s.len), .little);
                    try writer.writeAll(s);
                },
                .unistr => |u| {
                    try writer.writeByte(VALUE_UNISTR);
                    // Write length in bytes (u16 count * 2)
                    try writer.writeInt(u32, @intCast(u.len * 2), .little);
                    // Write UTF-16LE code units
                    for (u) |code_unit| {
                        try writer.writeInt(u16, code_unit, .little);
                    }
                },
            }
        }

        const serialized = try buffer.toOwnedSlice(self.allocator);

        // Validate serialized size
        if (serialized.len > MAX_PACK_SIZE) {
            self.allocator.free(serialized);
            return error.PackTooLarge;
        }

        return serialized;
    }

    /// Deserialize a Pack from binary format
    pub fn deserialize(allocator: Allocator, data: []const u8) !Pack {
        // Validate input size
        if (data.len > MAX_PACK_SIZE) {
            return error.PackTooLarge;
        }
        if (data.len < 4) {
            return error.InvalidPack;
        }

        var pack = Pack.init(allocator);
        errdefer pack.deinit();

        var offset: usize = 0;

        // Read number of elements
        const count = std.mem.readInt(u32, data[offset..][0..4], .little);
        offset += 4;

        // Validate element count
        if (count > MAX_ELEMENT_NUM) {
            return error.TooManyElements;
        }

        // Read each key-value pair
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            // Read key
            if (offset + 4 > data.len) return error.InvalidPack;
            const key_len = std.mem.readInt(u32, data[offset..][0..4], .little);
            offset += 4;

            if (key_len > MAX_ELEMENT_NAME_LEN) return error.KeyTooLong;
            if (offset + key_len > data.len) return error.InvalidPack;

            const key = data[offset .. offset + key_len];
            offset += key_len;

            // Read value type
            if (offset >= data.len) return error.InvalidPack;
            const value_type = data[offset];
            offset += 1;

            // Read value based on type
            const value = switch (value_type) {
                VALUE_INT => blk: {
                    if (offset + 4 > data.len) return error.InvalidPack;
                    const v = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;
                    break :blk PackValue{ .int = v };
                },
                VALUE_INT64 => blk: {
                    if (offset + 8 > data.len) return error.InvalidPack;
                    const v = std.mem.readInt(u64, data[offset..][0..8], .little);
                    offset += 8;
                    break :blk PackValue{ .int64 = v };
                },
                VALUE_DATA => blk: {
                    if (offset + 4 > data.len) return error.InvalidPack;
                    const data_len = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;

                    if (data_len > MAX_VALUE_SIZE) return error.ValueTooLarge;
                    if (offset + data_len > data.len) return error.InvalidPack;

                    // Must copy data since serialized buffer will be freed
                    const d = try allocator.dupe(u8, data[offset .. offset + data_len]);
                    offset += data_len;
                    break :blk PackValue{ .data = d };
                },
                VALUE_STR => blk: {
                    if (offset + 4 > data.len) return error.InvalidPack;
                    const str_len = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;

                    if (str_len > MAX_VALUE_SIZE) return error.ValueTooLarge;
                    if (offset + str_len > data.len) return error.InvalidPack;

                    // Must copy string since serialized buffer will be freed
                    const s = try allocator.dupe(u8, data[offset .. offset + str_len]);
                    offset += str_len;
                    break :blk PackValue{ .str = s };
                },
                VALUE_UNISTR => blk: {
                    if (offset + 4 > data.len) return error.InvalidPack;
                    const byte_len = std.mem.readInt(u32, data[offset..][0..4], .little);
                    offset += 4;

                    if (byte_len > MAX_VALUE_SIZE) return error.ValueTooLarge;
                    if (byte_len % 2 != 0) return error.InvalidUtf16; // Must be even (u16 aligned)
                    if (offset + byte_len > data.len) return error.InvalidPack;

                    const utf16_len = byte_len / 2;

                    // Read UTF-16LE code units from binary data
                    const utf16_buf = try allocator.alloc(u16, utf16_len);
                    var j: usize = 0;
                    while (j < utf16_len) : (j += 1) {
                        const byte_offset = offset + (j * 2);
                        utf16_buf[j] = std.mem.readInt(u16, data[byte_offset..][0..2], .little);
                    }

                    offset += byte_len;
                    break :blk PackValue{ .unistr = utf16_buf };
                },
                else => return error.UnsupportedPackType,
            };

            try pack.putTakingOwnership(key, value);
        }

        return pack;
    }

    /// Serialize Pack with compression
    /// Format: [original_size: u32][compressed_data]
    /// Compression threshold: only compress if data > min_size (default 1KB)
    pub fn serializeCompressed(self: *const Self, min_size: usize) ![]u8 {
        const uncompressed = try self.serialize();
        errdefer self.allocator.free(uncompressed);

        // Don't compress if data is too small
        if (uncompressed.len < min_size) {
            return uncompressed;
        }

        // Try to compress
        const compressed_data = compress.compressAllocDefault(self.allocator, uncompressed) catch {
            // If compression fails, return uncompressed
            return uncompressed;
        };
        defer self.allocator.free(compressed_data);

        // Only use compression if it's actually smaller (plus 4-byte header)
        if (compressed_data.len + 4 >= uncompressed.len) {
            return uncompressed;
        }

        // Build compressed pack: [original_size: u32][compressed_data]
        const result = try self.allocator.alloc(u8, 4 + compressed_data.len);
        errdefer self.allocator.free(result);

        std.mem.writeInt(u32, result[0..4], @intCast(uncompressed.len), .little);
        @memcpy(result[4..], compressed_data);

        self.allocator.free(uncompressed);
        return result;
    }

    /// Deserialize Pack from compressed format
    /// Automatically detects if data is compressed or not
    /// Compressed format: [original_size: u32][compressed_data]
    pub fn deserializeCompressed(allocator: Allocator, data: []const u8) !Pack {
        // If data is too small to be compressed (< 4 byte header), deserialize directly
        if (data.len < 4) {
            return deserialize(allocator, data);
        }

        // Read potential original size
        const original_size = std.mem.readInt(u32, data[0..4], .little);

        // Heuristic: if original_size looks reasonable and data appears compressed,
        // try to decompress. Otherwise, treat as uncompressed.
        // Reasonable: original_size > data.len and original_size < MAX_PACK_SIZE
        const looks_compressed = original_size > data.len and
            original_size <= MAX_PACK_SIZE and
            original_size > 0;

        if (!looks_compressed) {
            // Treat as uncompressed
            return deserialize(allocator, data);
        }

        // Try to decompress
        const decompressed = compress.decompressAlloc(allocator, data[4..], original_size) catch {
            // If decompression fails, try treating as uncompressed
            return deserialize(allocator, data);
        };
        defer allocator.free(decompressed);

        return deserialize(allocator, decompressed);
    }

    // ========================================================================
    // Convenience Methods
    // ========================================================================

    /// Add an integer value
    pub fn putInt(self: *Self, key: []const u8, value: u32) !void {
        try self.put(key, PackValue{ .int = value });
    }

    /// Add a 64-bit integer value
    pub fn putInt64(self: *Self, key: []const u8, value: u64) !void {
        try self.put(key, PackValue{ .int64 = value });
    }

    /// Add a boolean value
    pub fn putBool(self: *Self, key: []const u8, value: bool) !void {
        try self.put(key, PackValue{ .bool = value });
    }

    /// Add a string value
    pub fn putStr(self: *Self, key: []const u8, value: []const u8) !void {
        try self.put(key, PackValue{ .str = value });
    }

    /// Add a data value
    pub fn putData(self: *Self, key: []const u8, value: []const u8) !void {
        try self.put(key, PackValue{ .data = value });
    }

    /// Add a unicode string value (UTF-8 input, stored as UTF-16LE)
    pub fn putUniStr(self: *Self, key: []const u8, utf8_value: []const u8) !void {
        // Convert UTF-8 to UTF-16LE
        const utf16 = try utf8ToUtf16Le(self.allocator, utf8_value);
        errdefer self.allocator.free(utf16);

        // put() will make a copy of utf16, so we need to free our temporary copy
        try self.put(key, PackValue{ .unistr = utf16 });

        // Free the temporary UTF-16 buffer (put() made its own copy)
        self.allocator.free(utf16);
    }

    /// Get an integer value (returns null if not found or wrong type)
    pub fn getInt(self: *const Self, key: []const u8) ?u32 {
        if (self.get(key)) |value| {
            return switch (value) {
                .int => |v| v,
                .bool => |b| if (b) 1 else 0,
                else => null,
            };
        }
        return null;
    }

    /// Get a 64-bit integer value (returns null if not found or wrong type)
    pub fn getInt64(self: *const Self, key: []const u8) ?u64 {
        if (self.get(key)) |value| {
            return switch (value) {
                .int64 => |v| v,
                .int => |v| @as(u64, v), // Auto-promote u32 to u64
                else => null,
            };
        }
        return null;
    }

    /// Get a boolean value (returns null if not found or wrong type)
    pub fn getBool(self: *const Self, key: []const u8) ?bool {
        if (self.get(key)) |value| {
            return switch (value) {
                .bool => |b| b,
                .int => |v| v != 0,
                else => null,
            };
        }
        return null;
    }

    /// Get a string value (returns null if not found or wrong type)
    pub fn getStr(self: *const Self, key: []const u8) ?[]const u8 {
        if (self.get(key)) |value| {
            return switch (value) {
                .str => |s| s,
                else => null,
            };
        }
        return null;
    }

    /// Get a data value (returns null if not found or wrong type)
    pub fn getData(self: *const Self, key: []const u8) ?[]const u8 {
        if (self.get(key)) |value| {
            return switch (value) {
                .data => |d| d,
                else => null,
            };
        }
        return null;
    }

    /// Get a unicode string value as UTF-8 (converts from UTF-16LE)
    /// Caller owns returned memory (must be freed)
    pub fn getUniStr(self: *const Self, allocator: Allocator, key: []const u8) !?[]u8 {
        if (self.get(key)) |value| {
            return switch (value) {
                .unistr => |u| try utf16LeToUtf8(allocator, u),
                else => null,
            };
        }
        return null;
    }

    /// Get raw UTF-16LE data (returns null if not found or wrong type)
    pub fn getUniStrRaw(self: *const Self, key: []const u8) ?[]const u16 {
        if (self.get(key)) |value| {
            return switch (value) {
                .unistr => |u| u,
                else => null,
            };
        }
        return null;
    }

    /// Put an IPv4 address (stored as 4-byte VALUE_DATA)
    pub fn putIp(self: *Self, key: []const u8, ip: [4]u8) !void {
        try self.putData(key, &ip);
    }

    /// Get an IPv4 address (returns null if not found, wrong type, or wrong size)
    pub fn getIp(self: *const Self, key: []const u8) ?[4]u8 {
        if (self.getData(key)) |data| {
            if (data.len == 4) {
                var result: [4]u8 = undefined;
                @memcpy(&result, data);
                return result;
            }
        }
        return null;
    }

    /// Put an IPv6 address (stored as 16-byte VALUE_DATA)
    pub fn putIp6(self: *Self, key: []const u8, ip: [16]u8) !void {
        try self.putData(key, &ip);
    }

    /// Get an IPv6 address (returns null if not found, wrong type, or wrong size)
    pub fn getIp6(self: *const Self, key: []const u8) ?[16]u8 {
        if (self.getData(key)) |data| {
            if (data.len == 16) {
                var result: [16]u8 = undefined;
                @memcpy(&result, data);
                return result;
            }
        }
        return null;
    }
};

// ============================================================================
// IP Address Utilities
// ============================================================================

/// Parse an IPv4 address string (e.g., "192.168.1.1") into 4 bytes
pub fn parseIpv4(str: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var octets: usize = 0;
    var current_octet: u32 = 0;
    var has_digit = false;

    for (str) |c| {
        if (c == '.') {
            if (!has_digit or octets >= 3) return error.InvalidIpv4;
            if (current_octet > 255) return error.InvalidIpv4;
            result[octets] = @intCast(current_octet);
            octets += 1;
            current_octet = 0;
            has_digit = false;
        } else if (c >= '0' and c <= '9') {
            current_octet = current_octet * 10 + (c - '0');
            has_digit = true;
        } else {
            return error.InvalidIpv4;
        }
    }

    // Handle last octet
    if (!has_digit or octets != 3) return error.InvalidIpv4;
    if (current_octet > 255) return error.InvalidIpv4;
    result[octets] = @intCast(current_octet);

    return result;
}

/// Format an IPv4 address (4 bytes) into a string (e.g., "192.168.1.1")
/// Caller owns returned memory
pub fn formatIpv4(allocator: Allocator, ip: [4]u8) ![]u8 {
    // Maximum length: "255.255.255.255" = 15 chars + null terminator
    return std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
}

/// Parse an IPv6 address string (e.g., "::1", "2001:db8::1") into 16 bytes
pub fn parseIpv6(str: []const u8) ![16]u8 {
    // Use std.net for robust IPv6 parsing
    const addr = std.net.Address.parseIp6(str, 0) catch return error.InvalidIpv6;
    return addr.in6.sa.addr;
}

/// Format an IPv6 address (16 bytes) into a string (e.g., "::1", "2001:db8::1")
/// Caller owns returned memory
pub fn formatIpv6(allocator: Allocator, ip: [16]u8) ![]u8 {
    // Convert 16 bytes to 8 groups of 16-bit values
    var groups: [8]u16 = undefined;
    for (0..8) |i| {
        groups[i] = (@as(u16, ip[i * 2]) << 8) | ip[i * 2 + 1];
    }

    // Find longest sequence of zeros for compression (::)
    var best_start: ?usize = null;
    var best_len: usize = 0;
    var cur_start: ?usize = null;
    var cur_len: usize = 0;

    for (groups, 0..) |group, i| {
        if (group == 0) {
            if (cur_start == null) {
                cur_start = i;
                cur_len = 1;
            } else {
                cur_len += 1;
            }
            if (cur_len > best_len) {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_start = null;
            cur_len = 0;
        }
    }

    // Format using compression if we have at least 2 consecutive zeros
    var buf: [40]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    var i: usize = 0;
    var used_compression = false;

    while (i < 8) {
        if (best_len >= 2 and best_start != null and i == best_start.? and !used_compression) {
            try writer.writeAll("::");
            used_compression = true;
            i += best_len;
        } else {
            if (i > 0 and !(best_len >= 2 and best_start != null and i == best_start.? + best_len)) {
                try writer.writeByte(':');
            }
            if (i < 8) {
                try writer.print("{x}", .{groups[i]});
                i += 1;
            }
        }
    }

    return allocator.dupe(u8, stream.getWritten());
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Pack: init and deinit" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try testing.expectEqual(@as(u32, 0), pack.len());
}

test "Pack: put and get int" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("test_key", 42);

    try testing.expectEqual(@as(u32, 1), pack.len());
    try testing.expect(pack.contains("test_key"));

    const value = pack.getInt("test_key");
    try testing.expectEqual(@as(u32, 42), value.?);
}

test "Pack: put and get int64" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const large_value: u64 = 0x123456789ABCDEF0;
    try pack.putInt64("large", large_value);

    const value = pack.getInt64("large");
    try testing.expectEqual(large_value, value.?);
}

test "Pack: put and get bool" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putBool("flag1", true);
    try pack.putBool("flag2", false);

    try testing.expectEqual(true, pack.getBool("flag1").?);
    try testing.expectEqual(false, pack.getBool("flag2").?);
}

test "Pack: put and get string" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putStr("message", "Hello, SoftEther!");

    const value = pack.getStr("message");
    try testing.expectEqualStrings("Hello, SoftEther!", value.?);
}

test "Pack: put and get data" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const binary_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    try pack.putData("binary", &binary_data);

    const value = pack.getData("binary");
    try testing.expectEqualSlices(u8, &binary_data, value.?);
}

test "Pack: serialize and deserialize empty" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 0), pack2.len());
}

test "Pack: serialize and deserialize with int" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("version", 1);
    try pack.putInt("build", 5180);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 1), pack2.getInt("version").?);
    try testing.expectEqual(@as(u32, 5180), pack2.getInt("build").?);
}

test "Pack: serialize and deserialize with string" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putStr("hello", "world");
    try pack.putStr("vpn", "SoftEther");

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqualStrings("world", pack2.getStr("hello").?);
    try testing.expectEqualStrings("SoftEther", pack2.getStr("vpn").?);
}

test "Pack: serialize and deserialize mixed types" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("num", 42);
    try pack.putInt64("big", 0xDEADBEEFCAFEBABE);
    try pack.putStr("text", "test");
    try pack.putBool("flag", true);
    const data = [_]u8{ 1, 2, 3, 4, 5 };
    try pack.putData("bytes", &data);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 42), pack2.getInt("num").?);
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFEBABE), pack2.getInt64("big").?);
    try testing.expectEqualStrings("test", pack2.getStr("text").?);
    try testing.expectEqual(true, pack2.getBool("flag").?);
    try testing.expectEqualSlices(u8, &data, pack2.getData("bytes").?);
}

test "Pack: key too long error" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Create a key longer than MAX_ELEMENT_NAME_LEN (63)
    const long_key = "a" ** 64;

    const result = pack.putInt(long_key, 42);
    try testing.expectError(error.KeyTooLong, result);
}

test "Pack: remove element" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("test", 42);
    try testing.expectEqual(@as(u32, 1), pack.len());

    const removed = pack.remove("test");
    try testing.expect(removed);
    try testing.expectEqual(@as(u32, 0), pack.len());

    const removed_again = pack.remove("test");
    try testing.expect(!removed_again);
}

test "Pack: update existing value" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("counter", 1);
    try testing.expectEqual(@as(u32, 1), pack.getInt("counter").?);

    try pack.putInt("counter", 2);
    try testing.expectEqual(@as(u32, 1), pack.len()); // Still 1 element
    try testing.expectEqual(@as(u32, 2), pack.getInt("counter").?);
}

test "Pack: int64 auto-promotion" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("small", 42);

    // getInt64 should auto-promote u32 to u64
    const value = pack.getInt64("small");
    try testing.expectEqual(@as(u64, 42), value.?);
}

test "Pack: bool as int serialization" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putBool("true_val", true);
    try pack.putBool("false_val", false);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    // Bool should be deserialized as int (1 or 0)
    try testing.expectEqual(@as(u32, 1), pack2.getInt("true_val").?);
    try testing.expectEqual(@as(u32, 0), pack2.getInt("false_val").?);

    // getBool should still work
    try testing.expectEqual(true, pack2.getBool("true_val").?);
    try testing.expectEqual(false, pack2.getBool("false_val").?);
}

// ============================================================================
// Unicode String Tests
// ============================================================================

test "Unicode: UTF-8 to UTF-16LE conversion (ASCII)" {
    const utf8 = "Hello, World!";
    const utf16 = try utf8ToUtf16Le(testing.allocator, utf8);
    defer testing.allocator.free(utf16);

    // ASCII characters should be single UTF-16 code units
    try testing.expectEqual(@as(usize, 13), utf16.len);
    try testing.expectEqual(@as(u16, 'H'), utf16[0]);
    try testing.expectEqual(@as(u16, 'e'), utf16[1]);
    try testing.expectEqual(@as(u16, '!'), utf16[12]);
}

test "Unicode: UTF-8 to UTF-16LE conversion (Japanese)" {
    const utf8 = "こんにちは"; // "Hello" in Japanese (5 characters)
    const utf16 = try utf8ToUtf16Le(testing.allocator, utf8);
    defer testing.allocator.free(utf16);

    try testing.expectEqual(@as(usize, 5), utf16.len);
    try testing.expectEqual(@as(u16, 0x3053), utf16[0]); // こ
    try testing.expectEqual(@as(u16, 0x3093), utf16[1]); // ん
}

test "Unicode: UTF-8 to UTF-16LE conversion (Emoji)" {
    const utf8 = "👍"; // Thumbs up emoji (U+1F44D, requires surrogate pair)
    const utf16 = try utf8ToUtf16Le(testing.allocator, utf8);
    defer testing.allocator.free(utf16);

    // Emoji requires surrogate pair (2 UTF-16 code units)
    try testing.expectEqual(@as(usize, 2), utf16.len);
    try testing.expectEqual(@as(u16, 0xD83D), utf16[0]); // High surrogate
    try testing.expectEqual(@as(u16, 0xDC4D), utf16[1]); // Low surrogate
}

test "Unicode: UTF-16LE to UTF-8 conversion (ASCII)" {
    const utf16 = [_]u16{ 'H', 'e', 'l', 'l', 'o' };
    const utf8 = try utf16LeToUtf8(testing.allocator, &utf16);
    defer testing.allocator.free(utf8);

    try testing.expectEqualStrings("Hello", utf8);
}

test "Unicode: UTF-16LE to UTF-8 conversion (Japanese)" {
    const utf16 = [_]u16{ 0x3053, 0x3093, 0x306B, 0x3061, 0x306F }; // こんにちは
    const utf8 = try utf16LeToUtf8(testing.allocator, &utf16);
    defer testing.allocator.free(utf8);

    try testing.expectEqualStrings("こんにちは", utf8);
}

test "Unicode: UTF-16LE to UTF-8 conversion (Emoji)" {
    const utf16 = [_]u16{ 0xD83D, 0xDC4D }; // 👍 (surrogate pair)
    const utf8 = try utf16LeToUtf8(testing.allocator, &utf16);
    defer testing.allocator.free(utf8);

    try testing.expectEqualStrings("👍", utf8);
}

test "Unicode: Round-trip conversion (mixed)" {
    const original = "Hello 世界 🌍"; // English + Chinese + Emoji
    const utf16 = try utf8ToUtf16Le(testing.allocator, original);
    defer testing.allocator.free(utf16);

    const utf8 = try utf16LeToUtf8(testing.allocator, utf16);
    defer testing.allocator.free(utf8);

    try testing.expectEqualStrings(original, utf8);
}

test "Pack: putUniStr and getUniStr" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putUniStr("greeting", "Hello, 世界!");

    const value = try pack.getUniStr(testing.allocator, "greeting");
    defer if (value) |v| testing.allocator.free(v);

    try testing.expectEqualStrings("Hello, 世界!", value.?);
}

test "Pack: serialize and deserialize unicode string" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putUniStr("message", "こんにちは 世界 👍");

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    const value = try pack2.getUniStr(testing.allocator, "message");
    defer if (value) |v| testing.allocator.free(v);

    try testing.expectEqualStrings("こんにちは 世界 👍", value.?);
}

test "Pack: mixed types with unicode" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("version", 1);
    try pack.putStr("server", "vpn.example.com");
    try pack.putUniStr("username", "ユーザー名"); // "Username" in Japanese
    try pack.putBool("secure", true);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 1), pack2.getInt("version").?);
    try testing.expectEqualStrings("vpn.example.com", pack2.getStr("server").?);

    const username = try pack2.getUniStr(testing.allocator, "username");
    defer if (username) |u| testing.allocator.free(u);
    try testing.expectEqualStrings("ユーザー名", username.?);

    try testing.expectEqual(true, pack2.getBool("secure").?);
}

test "Pack: empty unicode string" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putUniStr("empty", "");

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    const value = try pack2.getUniStr(testing.allocator, "empty");
    defer if (value) |v| testing.allocator.free(v);

    try testing.expectEqualStrings("", value.?);
}

// ============================================================================
// IP Address Tests
// ============================================================================

test "IP: parseIpv4 valid addresses" {
    const ip1 = try parseIpv4("192.168.1.1");
    try testing.expectEqual(@as(u8, 192), ip1[0]);
    try testing.expectEqual(@as(u8, 168), ip1[1]);
    try testing.expectEqual(@as(u8, 1), ip1[2]);
    try testing.expectEqual(@as(u8, 1), ip1[3]);

    const ip2 = try parseIpv4("10.0.0.1");
    try testing.expectEqual(@as(u8, 10), ip2[0]);
    try testing.expectEqual(@as(u8, 0), ip2[1]);
    try testing.expectEqual(@as(u8, 0), ip2[2]);
    try testing.expectEqual(@as(u8, 1), ip2[3]);

    const ip3 = try parseIpv4("255.255.255.255");
    try testing.expectEqual(@as(u8, 255), ip3[0]);
    try testing.expectEqual(@as(u8, 255), ip3[1]);
    try testing.expectEqual(@as(u8, 255), ip3[2]);
    try testing.expectEqual(@as(u8, 255), ip3[3]);
}

test "IP: parseIpv4 invalid addresses" {
    try testing.expectError(error.InvalidIpv4, parseIpv4("256.1.1.1")); // Octet > 255
    try testing.expectError(error.InvalidIpv4, parseIpv4("192.168.1")); // Too few octets
    try testing.expectError(error.InvalidIpv4, parseIpv4("192.168.1.1.1")); // Too many octets
    try testing.expectError(error.InvalidIpv4, parseIpv4("192.168.1.a")); // Invalid character
    try testing.expectError(error.InvalidIpv4, parseIpv4("192..168.1.1")); // Empty octet
}

test "IP: formatIpv4" {
    const ip = [4]u8{ 192, 168, 1, 1 };
    const str = try formatIpv4(testing.allocator, ip);
    defer testing.allocator.free(str);

    try testing.expectEqualStrings("192.168.1.1", str);
}

test "IP: IPv4 round-trip" {
    const original = "10.20.30.40";
    const ip = try parseIpv4(original);
    const formatted = try formatIpv4(testing.allocator, ip);
    defer testing.allocator.free(formatted);

    try testing.expectEqualStrings(original, formatted);
}

test "IP: parseIpv6 valid addresses" {
    const ip1 = try parseIpv6("::1"); // Loopback
    try testing.expectEqual(@as(u8, 0), ip1[0]);
    try testing.expectEqual(@as(u8, 0), ip1[1]);
    try testing.expectEqual(@as(u8, 1), ip1[15]); // Last byte is 1

    const ip2 = try parseIpv6("2001:db8::1"); // Documentation prefix
    try testing.expectEqual(@as(u8, 0x20), ip2[0]);
    try testing.expectEqual(@as(u8, 0x01), ip2[1]);
    try testing.expectEqual(@as(u8, 0x0d), ip2[2]);
    try testing.expectEqual(@as(u8, 0xb8), ip2[3]);
}

test "IP: formatIpv6" {
    const ip = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }; // ::1
    const str = try formatIpv6(testing.allocator, ip);
    defer testing.allocator.free(str);

    // Should format as compressed notation
    try testing.expect(std.mem.indexOf(u8, str, "::1") != null or std.mem.indexOf(u8, str, "::0.0.0.1") != null);
}

test "Pack: putIp and getIp" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const ip = [4]u8{ 192, 168, 1, 1 };
    try pack.putIp("server_ip", ip);

    const retrieved = pack.getIp("server_ip");
    try testing.expect(retrieved != null);
    try testing.expectEqualSlices(u8, &ip, &retrieved.?);
}

test "Pack: putIp6 and getIp6" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const ip6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try pack.putIp6("server_ip6", ip6);

    const retrieved = pack.getIp6("server_ip6");
    try testing.expect(retrieved != null);
    try testing.expectEqualSlices(u8, &ip6, &retrieved.?);
}

test "Pack: serialize and deserialize IPv4" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const ip = [4]u8{ 10, 0, 0, 1 };
    try pack.putIp("gateway", ip);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    const retrieved = pack2.getIp("gateway");
    try testing.expect(retrieved != null);
    try testing.expectEqualSlices(u8, &ip, &retrieved.?);
}

test "Pack: serialize and deserialize IPv6" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const ip6 = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }; // ::1
    try pack.putIp6("local_ip6", ip6);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    const retrieved = pack2.getIp6("local_ip6");
    try testing.expect(retrieved != null);
    try testing.expectEqualSlices(u8, &ip6, &retrieved.?);
}

test "Pack: getIp returns null for wrong size" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Put 5-byte data (not valid IPv4)
    try pack.putData("invalid", &[5]u8{ 1, 2, 3, 4, 5 });

    const ip = pack.getIp("invalid");
    try testing.expect(ip == null); // Should return null for wrong size
}

test "Pack: getIp6 returns null for wrong size" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Put 4-byte data (not valid IPv6)
    try pack.putData("invalid", &[4]u8{ 1, 2, 3, 4 });

    const ip6 = pack.getIp6("invalid");
    try testing.expect(ip6 == null); // Should return null for wrong size
}

// ============================================================================
// Compression Tests
// ============================================================================

test "Pack: serializeCompressed small pack (no compression)" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("value", 42);
    try pack.putStr("name", "test");

    // Serialize with compression (but pack is too small, min_size=1024)
    const serialized = try pack.serializeCompressed(1024);
    defer testing.allocator.free(serialized);

    // Should be uncompressed (no 4-byte header)
    var pack2 = try Pack.deserializeCompressed(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 42), pack2.getInt("value").?);
    try testing.expectEqualStrings("test", pack2.getStr("name").?);
}

test "Pack: serializeCompressed large pack (with compression)" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Add repetitive data (should compress well)
    try pack.putStr("data1", "Hello World! " ** 100);
    try pack.putStr("data2", "The quick brown fox " ** 100);
    try pack.putStr("data3", "Lorem ipsum dolor sit amet " ** 100);
    try pack.putInt("count", 300);

    // Serialize with compression (min_size=100 bytes)
    const compressed = try pack.serializeCompressed(100);
    defer testing.allocator.free(compressed);

    // Should be smaller than uncompressed
    const uncompressed = try pack.serialize();
    defer testing.allocator.free(uncompressed);

    try testing.expect(compressed.len < uncompressed.len);

    const ratio = @as(f64, @floatFromInt(compressed.len)) / @as(f64, @floatFromInt(uncompressed.len));
    std.debug.print("Pack compression ratio: {d:.2}%\n", .{ratio * 100});

    // Verify decompression
    var pack2 = try Pack.deserializeCompressed(testing.allocator, compressed);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 300), pack2.getInt("count").?);
    try testing.expectEqualStrings("Hello World! " ** 100, pack2.getStr("data1").?);
}

test "Pack: deserializeCompressed uncompressed data" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("value", 12345);
    try pack.putStr("text", "uncompressed");

    // Serialize without compression
    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    // Deserialize with decompression detection (should detect uncompressed)
    var pack2 = try Pack.deserializeCompressed(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 12345), pack2.getInt("value").?);
    try testing.expectEqualStrings("uncompressed", pack2.getStr("text").?);
}

test "Pack: compression round-trip with unicode and IPs" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Mixed data types
    try pack.putUniStr("username", "田中太郎");
    try pack.putIp("server", try parseIpv4("192.168.1.100"));
    try pack.putIp6("server_v6", try parseIpv6("2001:db8::1"));
    try pack.putStr("repeated_data", "abcdefgh" ** 200); // Compressible
    try pack.putInt64("session_id", 0x123456789ABCDEF0);

    // Compress
    const compressed = try pack.serializeCompressed(100);
    defer testing.allocator.free(compressed);

    // Decompress
    var pack2 = try Pack.deserializeCompressed(testing.allocator, compressed);
    defer pack2.deinit();

    // Verify all values
    const username = try pack2.getUniStr(testing.allocator, "username");
    defer testing.allocator.free(username.?);
    try testing.expectEqualStrings("田中太郎", username.?);

    const ip = pack2.getIp("server").?;
    try testing.expectEqual(@as(u8, 192), ip[0]);
    try testing.expectEqual(@as(u8, 168), ip[1]);

    const ip6 = pack2.getIp6("server_v6").?;
    try testing.expectEqual(@as(u8, 0x20), ip6[0]);
    try testing.expectEqual(@as(u8, 0x01), ip6[1]);

    try testing.expectEqualStrings("abcdefgh" ** 200, pack2.getStr("repeated_data").?);
    try testing.expectEqual(@as(u64, 0x123456789ABCDEF0), pack2.getInt64("session_id").?);
}

test "Pack: compression benchmark" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Create a realistic VPN packet with mixed data
    try pack.putStr("method", "vpn_connect");
    try pack.putUniStr("hub_name", "MyVPN");
    try pack.putUniStr("username", "user@example.com");
    try pack.putIp("client_ip", try parseIpv4("10.0.0.50"));
    try pack.putIp("gateway", try parseIpv4("10.0.0.1"));
    try pack.putInt("mtu", 1500);
    try pack.putInt64("timestamp", 1697500000000);

    // Add some larger data
    try pack.putData("session_key", &([_]u8{0xAB} ** 256));
    try pack.putStr("capabilities", "compression,encryption,ipv6" ** 20);

    const uncompressed = try pack.serialize();
    defer testing.allocator.free(uncompressed);

    const compressed = try pack.serializeCompressed(100);
    defer testing.allocator.free(compressed);

    const ratio = @as(f64, @floatFromInt(compressed.len)) / @as(f64, @floatFromInt(uncompressed.len));
    std.debug.print("VPN packet: {d} bytes → {d} bytes (ratio: {d:.2}%)\n", .{ uncompressed.len, compressed.len, ratio * 100 });

    // Verify correctness
    var pack2 = try Pack.deserializeCompressed(testing.allocator, compressed);
    defer pack2.deinit();

    try testing.expectEqualStrings("vpn_connect", pack2.getStr("method").?);
    try testing.expectEqual(@as(u32, 1500), pack2.getInt("mtu").?);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

test "Pack: maximum elements" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Add many elements (but under MAX_ELEMENT_NUM)
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        const key = try std.fmt.allocPrint(testing.allocator, "key_{d}", .{i});
        defer testing.allocator.free(key);
        try pack.putInt(key, i);
    }

    try testing.expectEqual(@as(u32, 100), pack.len());

    // Serialize and deserialize
    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 100), pack2.len());
}

test "Pack: large data value" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Create large data (100KB)
    const large_data = try testing.allocator.alloc(u8, 100 * 1024);
    defer testing.allocator.free(large_data);

    // Fill with pattern
    for (large_data, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    try pack.putData("large", large_data);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    const retrieved = pack2.getData("large").?;
    try testing.expectEqual(large_data.len, retrieved.len);
    try testing.expectEqualSlices(u8, large_data, retrieved);
}

test "Pack: empty key error" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Empty key should work (no restriction in current implementation)
    try pack.putInt("", 42);
    try testing.expectEqual(@as(u32, 42), pack.getInt("").?);
}

test "Pack: duplicate key replacement" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("key", 1);
    try testing.expectEqual(@as(u32, 1), pack.getInt("key").?);

    try pack.putInt("key", 2);
    try testing.expectEqual(@as(u32, 2), pack.getInt("key").?);

    // Should only have one element
    try testing.expectEqual(@as(u32, 1), pack.len());
}

test "Pack: mixed type replacement" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("value", 42);
    try testing.expectEqual(@as(u32, 42), pack.getInt("value").?);

    // Replace with different type
    try pack.putStr("value", "hello");
    try testing.expect(pack.getInt("value") == null);
    try testing.expectEqualStrings("hello", pack.getStr("value").?);
}

test "Pack: null value retrieval" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try testing.expect(pack.getInt("nonexistent") == null);
    try testing.expect(pack.getStr("nonexistent") == null);
    try testing.expect(pack.getData("nonexistent") == null);
    try testing.expect(pack.getInt64("nonexistent") == null);
    try testing.expect(pack.getIp("nonexistent") == null);
    try testing.expect(pack.getIp6("nonexistent") == null);
}

test "Pack: serialize empty pack" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    // Should be just element count (4 bytes = 0)
    try testing.expectEqual(@as(usize, 4), serialized.len);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    try testing.expectEqual(@as(u32, 0), pack2.len());
}

test "Pack: deserialize malformed data (too short)" {
    // Less than 4 bytes
    const bad_data = [_]u8{ 0x01, 0x02 };
    try testing.expectError(error.InvalidPack, Pack.deserialize(testing.allocator, &bad_data));
}

test "Pack: very long unicode string" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Create long unicode string with Japanese characters (repeated 100 times)
    const base = "こんにちは世界！";
    const long_str = base ** 100; // Compile-time repetition

    try pack.putUniStr("long_text", long_str);

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    const retrieved = try pack2.getUniStr(testing.allocator, "long_text");
    defer testing.allocator.free(retrieved.?);

    try testing.expectEqualStrings(long_str, retrieved.?);
}

test "Pack: multiple IP addresses" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Add multiple IPs
    try pack.putIp("server1", try parseIpv4("192.168.1.1"));
    try pack.putIp("server2", try parseIpv4("10.0.0.1"));
    try pack.putIp("gateway", try parseIpv4("192.168.1.254"));
    try pack.putIp6("dns_v6", try parseIpv6("2001:4860:4860::8888"));

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    var pack2 = try Pack.deserialize(testing.allocator, serialized);
    defer pack2.deinit();

    const server1 = pack2.getIp("server1").?;
    try testing.expectEqual(@as(u8, 192), server1[0]);

    const dns_v6 = pack2.getIp6("dns_v6").?;
    try testing.expectEqual(@as(u8, 0x20), dns_v6[0]);
    try testing.expectEqual(@as(u8, 0x01), dns_v6[1]);
}

// ============================================================================
// Benchmark Tests
// ============================================================================

test "Benchmark: small pack serialization" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putInt("count", 42);
    try pack.putStr("name", "test");
    try pack.putBool("active", true);

    const iterations: usize = 1000;
    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const serialized = try pack.serialize();
        testing.allocator.free(serialized);
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns = end - start;
    const per_op_us = @divTrunc(elapsed_ns, @as(i64, @intCast(iterations)) * 1000);

    std.debug.print("Small pack serialize: {d} µs/op ({d} ops)\n", .{ per_op_us, iterations });
}

test "Benchmark: medium pack serialization" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Medium-sized VPN packet
    try pack.putStr("method", "vpn_data");
    try pack.putInt64("session_id", 0x123456789ABCDEF0);
    try pack.putUniStr("username", "user@example.com");
    try pack.putIp("client_ip", try parseIpv4("10.0.0.50"));
    try pack.putIp("server_ip", try parseIpv4("203.0.113.1"));
    try pack.putData("payload", &([_]u8{0x55} ** 500));
    try pack.putInt("sequence", 12345);

    const iterations: usize = 1000;
    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const serialized = try pack.serialize();
        testing.allocator.free(serialized);
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns = end - start;
    const per_op_us = @divTrunc(elapsed_ns, @as(i64, @intCast(iterations)) * 1000);

    std.debug.print("Medium pack serialize: {d} µs/op ({d} ops)\n", .{ per_op_us, iterations });
}

test "Benchmark: large pack serialization" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Large pack with many elements
    var j: u32 = 0;
    while (j < 50) : (j += 1) {
        const key = try std.fmt.allocPrint(testing.allocator, "field_{d}", .{j});
        defer testing.allocator.free(key);
        try pack.putInt(key, j);
    }

    try pack.putData("large_payload", &([_]u8{0xAB} ** 10000));

    const iterations: usize = 100;
    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const serialized = try pack.serialize();
        testing.allocator.free(serialized);
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns = end - start;
    const per_op_us = @divTrunc(elapsed_ns, @as(i64, @intCast(iterations)) * 1000);

    std.debug.print("Large pack serialize: {d} µs/op ({d} ops)\n", .{ per_op_us, iterations });
}

test "Benchmark: deserialization" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    try pack.putStr("method", "test");
    try pack.putInt("value", 42);
    try pack.putInt64("timestamp", 1697500000000);
    try pack.putIp("ip", try parseIpv4("192.168.1.1"));

    const serialized = try pack.serialize();
    defer testing.allocator.free(serialized);

    const iterations: usize = 1000;
    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var pack2 = try Pack.deserialize(testing.allocator, serialized);
        pack2.deinit();
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns = end - start;
    const per_op_us = @divTrunc(elapsed_ns, @as(i64, @intCast(iterations)) * 1000);

    std.debug.print("Pack deserialize: {d} µs/op ({d} ops)\n", .{ per_op_us, iterations });
}

test "Benchmark: compression vs uncompressed" {
    var pack = Pack.init(testing.allocator);
    defer pack.deinit();

    // Create compressible data
    try pack.putStr("data1", "Hello World!" ** 100);
    try pack.putStr("data2", "The quick brown fox" ** 100);
    try pack.putStr("data3", "Lorem ipsum" ** 100);

    const iterations: usize = 100;

    // Benchmark uncompressed
    const start_uncompressed = std.time.nanoTimestamp();
    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        const serialized = try pack.serialize();
        testing.allocator.free(serialized);
    }
    const end_uncompressed = std.time.nanoTimestamp();

    // Benchmark compressed
    const start_compressed = std.time.nanoTimestamp();
    i = 0;
    while (i < iterations) : (i += 1) {
        const serialized = try pack.serializeCompressed(100);
        testing.allocator.free(serialized);
    }
    const end_compressed = std.time.nanoTimestamp();

    const uncompressed_us = @divTrunc(end_uncompressed - start_uncompressed, @as(i64, @intCast(iterations)) * 1000);
    const compressed_us = @divTrunc(end_compressed - start_compressed, @as(i64, @intCast(iterations)) * 1000);

    std.debug.print("Uncompressed: {d} µs/op, Compressed: {d} µs/op (overhead: {d}x)\n", .{ uncompressed_us, compressed_us, @as(f64, @floatFromInt(compressed_us)) / @as(f64, @floatFromInt(uncompressed_us)) });
}
