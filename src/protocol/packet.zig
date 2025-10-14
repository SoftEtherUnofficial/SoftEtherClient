// Packet Handling Module
// Provides packet encapsulation, fragmentation, and compression for VPN protocol
const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

// ============================================================================
// Constants
// ============================================================================

pub const MAX_PACKET_SIZE: usize = 65535;
pub const MIN_PACKET_SIZE: usize = 20;
pub const HEADER_SIZE: usize = 24;
pub const MAX_FRAGMENT_SIZE: usize = 1400; // MTU-safe size
pub const MAGIC_NUMBER: u32 = 0x5345_5650; // 'SEVP' in hex

// ============================================================================
// Packet Types
// ============================================================================

pub const PacketType = enum(u8) {
    data = 0x01,
    control = 0x02,
    keepalive = 0x03,
    auth = 0x04,
    disconnect = 0x05,
    fragment = 0x06,
    ack = 0x07,
    nack = 0x08,

    pub fn toString(self: PacketType) []const u8 {
        return switch (self) {
            .data => "DATA",
            .control => "CONTROL",
            .keepalive => "KEEPALIVE",
            .auth => "AUTH",
            .disconnect => "DISCONNECT",
            .fragment => "FRAGMENT",
            .ack => "ACK",
            .nack => "NACK",
        };
    }
};

pub const PacketFlags = packed struct(u8) {
    compressed: bool = false,
    encrypted: bool = false,
    fragmented: bool = false,
    requires_ack: bool = false,
    _reserved: u4 = 0,

    pub fn toU8(self: PacketFlags) u8 {
        return @bitCast(self);
    }

    pub fn fromU8(value: u8) PacketFlags {
        return @bitCast(value);
    }
};

// ============================================================================
// Packet Header
// ============================================================================

pub const PacketHeader = packed struct {
    magic: u32, // Magic number (0x5345_5650)
    version: u8, // Protocol version
    packet_type: PacketType, // Type of packet
    flags: PacketFlags, // Packet flags
    _reserved: u8, // Reserved for future use
    sequence: u32, // Sequence number
    ack_number: u32, // Acknowledgment number
    payload_length: u32, // Length of payload
    checksum: u32, // CRC32 checksum

    pub fn init(packet_type: PacketType, sequence: u32, payload_len: u32) PacketHeader {
        return .{
            .magic = MAGIC_NUMBER,
            .version = 1,
            .packet_type = packet_type,
            .flags = .{},
            .sequence = sequence,
            .ack_number = 0,
            .payload_length = payload_len,
            .checksum = 0,
            ._reserved = 0,
        };
    }

    pub fn validate(self: *const PacketHeader) bool {
        if (self.magic != MAGIC_NUMBER) return false;
        if (self.version != 1) return false;
        if (self.payload_length > MAX_PACKET_SIZE) return false;
        return true;
    }

    pub fn calculateChecksum(self: *PacketHeader, payload: []const u8) void {
        self.checksum = 0;
        var crc = std.hash.Crc32.init();

        // Hash header (excluding checksum field)
        const header_bytes: []const u8 = std.mem.asBytes(self);
        crc.update(header_bytes[0..20]); // Up to checksum field

        // Hash payload
        crc.update(payload);

        self.checksum = crc.final();
    }

    pub fn verifyChecksum(self: *const PacketHeader, payload: []const u8) bool {
        var temp_header = self.*;
        const stored_checksum = self.checksum;
        temp_header.calculateChecksum(payload);
        return temp_header.checksum == stored_checksum;
    }
};

// ============================================================================
// Packet Structure
// ============================================================================

pub const Packet = struct {
    header: PacketHeader,
    payload: []u8,
    allocator: Allocator,
    owned: bool,

    pub fn init(allocator: Allocator, packet_type: PacketType, sequence: u32, payload: []const u8) !Packet {
        const owned_payload = try allocator.dupe(u8, payload);
        var header = PacketHeader.init(packet_type, sequence, @intCast(payload.len));
        header.calculateChecksum(owned_payload);

        return .{
            .header = header,
            .payload = owned_payload,
            .allocator = allocator,
            .owned = true,
        };
    }

    pub fn deinit(self: *Packet) void {
        if (self.owned) {
            self.allocator.free(self.payload);
        }
    }

    pub fn serialize(self: *const Packet, allocator: Allocator) ![]u8 {
        const header_size = @sizeOf(PacketHeader);
        const total_size = header_size + self.payload.len;
        var buffer = try allocator.alloc(u8, total_size);

        // Copy header
        const header_bytes: *const [header_size]u8 = @ptrCast(&self.header);
        @memcpy(buffer[0..header_size], header_bytes);

        // Copy payload
        @memcpy(buffer[header_size..], self.payload);

        return buffer;
    }

    pub fn deserialize(allocator: Allocator, data: []const u8) !Packet {
        const header_size = @sizeOf(PacketHeader);
        if (data.len < header_size) return error.PacketTooSmall;

        // Parse header
        const header: *const PacketHeader = @ptrCast(@alignCast(data.ptr));
        if (!header.validate()) return error.InvalidPacket;

        // Extract payload
        const payload_start = header_size;
        const payload_end = header_size + header.payload_length;
        if (payload_end > data.len) return error.InvalidPayloadLength;

        const payload = data[payload_start..payload_end];

        // Verify checksum
        if (!header.verifyChecksum(payload)) return error.ChecksumMismatch;

        // Copy payload
        const owned_payload = try allocator.dupe(u8, payload);

        return .{
            .header = header.*,
            .payload = owned_payload,
            .allocator = allocator,
            .owned = true,
        };
    }

    pub fn getType(self: *const Packet) PacketType {
        return self.header.packet_type;
    }

    pub fn getSequence(self: *const Packet) u32 {
        return self.header.sequence;
    }

    pub fn setFlags(self: *Packet, flags: PacketFlags) void {
        self.header.flags = flags;
        self.header.calculateChecksum(self.payload);
    }
};

// ============================================================================
// Packet Fragmentation
// ============================================================================

pub const FragmentInfo = struct {
    packet_id: u32, // Original packet ID
    fragment_index: u16, // Index of this fragment
    total_fragments: u16, // Total number of fragments
    fragment_size: u32, // Size of this fragment

    pub fn serialize(self: *const FragmentInfo, allocator: Allocator) ![]u8 {
        var buffer = try allocator.alloc(u8, 12);
        std.mem.writeInt(u32, buffer[0..4], self.packet_id, .little);
        std.mem.writeInt(u16, buffer[4..6], self.fragment_index, .little);
        std.mem.writeInt(u16, buffer[6..8], self.total_fragments, .little);
        std.mem.writeInt(u32, buffer[8..12], self.fragment_size, .little);
        return buffer;
    }

    pub fn deserialize(data: []const u8) !FragmentInfo {
        if (data.len < 12) return error.InvalidFragmentInfo;

        return .{
            .packet_id = std.mem.readInt(u32, data[0..4], .little),
            .fragment_index = std.mem.readInt(u16, data[4..6], .little),
            .total_fragments = std.mem.readInt(u16, data[6..8], .little),
            .fragment_size = std.mem.readInt(u32, data[8..12], .little),
        };
    }
};

pub const PacketFragmenter = struct {
    allocator: Allocator,
    max_fragment_size: usize,
    next_packet_id: u32,

    pub fn init(allocator: Allocator, max_size: usize) PacketFragmenter {
        return .{
            .allocator = allocator,
            .max_fragment_size = max_size,
            .next_packet_id = 1,
        };
    }

    pub fn needsFragmentation(self: *const PacketFragmenter, packet: *const Packet) bool {
        return packet.payload.len > self.max_fragment_size;
    }

    pub fn fragment(self: *PacketFragmenter, packet: *const Packet, sequence_start: u32) !ArrayList(Packet) {
        var fragments = ArrayList(Packet){};
        errdefer {
            for (fragments.items) |*frag| frag.deinit();
            fragments.deinit(self.allocator);
        }

        const payload_data = packet.payload;
        const total_size = payload_data.len;
        const num_fragments = (total_size + self.max_fragment_size - 1) / self.max_fragment_size;

        const packet_id = self.next_packet_id;
        self.next_packet_id += 1;

        var offset: usize = 0;
        var frag_idx: u16 = 0;

        while (offset < total_size) {
            const remaining = total_size - offset;
            const frag_size = @min(remaining, self.max_fragment_size);
            const fragment_data = payload_data[offset .. offset + frag_size];

            // Create fragment info
            const frag_info = FragmentInfo{
                .packet_id = packet_id,
                .fragment_index = frag_idx,
                .total_fragments = @intCast(num_fragments),
                .fragment_size = @intCast(frag_size),
            };

            // Serialize fragment info + data
            const frag_info_bytes = try frag_info.serialize(self.allocator);
            defer self.allocator.free(frag_info_bytes);

            var frag_payload = try self.allocator.alloc(u8, frag_info_bytes.len + fragment_data.len);
            @memcpy(frag_payload[0..frag_info_bytes.len], frag_info_bytes);
            @memcpy(frag_payload[frag_info_bytes.len..], fragment_data);

            // Create fragment packet
            const sequence = sequence_start + frag_idx;
            var frag_packet = Packet{
                .header = PacketHeader.init(.fragment, sequence, @intCast(frag_payload.len)),
                .payload = frag_payload,
                .allocator = self.allocator,
                .owned = true,
            };

            var flags = frag_packet.header.flags;
            flags.fragmented = true;
            flags.requires_ack = true;
            frag_packet.setFlags(flags);

            try fragments.append(self.allocator, frag_packet);

            offset += frag_size;
            frag_idx += 1;
        }

        return fragments;
    }
};

pub const PacketReassembler = struct {
    allocator: Allocator,
    fragments: std.AutoHashMap(u32, ArrayList(Packet)),
    timeout_ms: u64,

    pub fn init(allocator: Allocator, timeout: u64) PacketReassembler {
        return .{
            .allocator = allocator,
            .fragments = std.AutoHashMap(u32, ArrayList(Packet)).init(allocator),
            .timeout_ms = timeout,
        };
    }

    pub fn deinit(self: *PacketReassembler) void {
        var it = self.fragments.valueIterator();
        while (it.next()) |frag_list| {
            for (frag_list.items) |*frag| frag.deinit();
            frag_list.deinit(self.allocator);
        }
        self.fragments.deinit();
    }

    pub fn addFragment(self: *PacketReassembler, fragment: Packet) !?Packet {
        // Parse fragment info
        const frag_info = try FragmentInfo.deserialize(fragment.payload[0..12]);
        const packet_id = frag_info.packet_id;

        // Get or create fragment list
        const result = try self.fragments.getOrPut(packet_id);
        if (!result.found_existing) {
            result.value_ptr.* = ArrayList(Packet){};
        }

        try result.value_ptr.append(self.allocator, fragment);

        // Check if we have all fragments
        if (result.value_ptr.items.len == frag_info.total_fragments) {
            return try self.reassemble(packet_id);
        }

        return null;
    }

    fn reassemble(self: *PacketReassembler, packet_id: u32) !Packet {
        var fragments = self.fragments.get(packet_id) orelse return error.FragmentsNotFound;
        defer {
            for (fragments.items) |*frag| frag.deinit();
            fragments.deinit(self.allocator);
            _ = self.fragments.remove(packet_id);
        }

        // Sort fragments by index
        std.mem.sort(Packet, fragments.items, {}, struct {
            fn lessThan(_: void, a: Packet, b: Packet) bool {
                const info_a = FragmentInfo.deserialize(a.payload[0..12]) catch return false;
                const info_b = FragmentInfo.deserialize(b.payload[0..12]) catch return false;
                return info_a.fragment_index < info_b.fragment_index;
            }
        }.lessThan);

        // Calculate total payload size
        var total_size: usize = 0;
        for (fragments.items) |*frag| {
            const info = try FragmentInfo.deserialize(frag.payload[0..12]);
            total_size += info.fragment_size;
        }

        // Reassemble payload
        var payload = try self.allocator.alloc(u8, total_size);
        var offset: usize = 0;

        for (fragments.items) |*frag| {
            const info = try FragmentInfo.deserialize(frag.payload[0..12]);
            const data_start: usize = 12;
            const data_end = data_start + info.fragment_size;
            const fragment_data = frag.payload[data_start..data_end];

            @memcpy(payload[offset .. offset + fragment_data.len], fragment_data);
            offset += fragment_data.len;
        }

        // Create reassembled packet
        const first_frag = &fragments.items[0];
        var packet = Packet{
            .header = PacketHeader.init(.data, first_frag.header.sequence, @intCast(payload.len)),
            .payload = payload,
            .allocator = self.allocator,
            .owned = true,
        };

        packet.header.calculateChecksum(payload);

        return packet;
    }
};

// ============================================================================
// Packet Compression
// ============================================================================

pub const CompressionType = enum(u8) {
    none = 0,
    zlib = 1,
    gzip = 2,
    lz4 = 3,
};

pub const PacketCompressor = struct {
    allocator: Allocator,
    compression_type: CompressionType,
    min_size: usize, // Minimum size to compress

    pub fn init(allocator: Allocator, comp_type: CompressionType, min_size: usize) PacketCompressor {
        return .{
            .allocator = allocator,
            .compression_type = comp_type,
            .min_size = min_size,
        };
    }

    pub fn shouldCompress(self: *const PacketCompressor, data: []const u8) bool {
        return data.len >= self.min_size and self.compression_type != .none;
    }

    pub fn compress(self: *const PacketCompressor, data: []const u8) ![]u8 {
        if (!self.shouldCompress(data)) {
            return try self.allocator.dupe(u8, data);
        }

        // For now, return a simple mock compression (prefix with type + size)
        // In production, integrate with std.compress or external library
        const header_size = 5; // 1 byte type + 4 bytes original size
        var compressed = try self.allocator.alloc(u8, header_size + data.len);

        compressed[0] = @intFromEnum(self.compression_type);
        std.mem.writeInt(u32, compressed[1..5], @intCast(data.len), .little);
        @memcpy(compressed[header_size..], data);

        return compressed;
    }

    pub fn decompress(self: *const PacketCompressor, data: []const u8) ![]u8 {
        if (data.len < 5) {
            return try self.allocator.dupe(u8, data);
        }

        const comp_type: CompressionType = @enumFromInt(data[0]);
        if (comp_type == .none) {
            return try self.allocator.dupe(u8, data);
        }

        const original_size = std.mem.readInt(u32, data[1..5], .little);
        const compressed_data = data[5..];

        // Mock decompression - in production use actual decompression
        const decompressed = try self.allocator.alloc(u8, original_size);
        @memcpy(decompressed, compressed_data[0..@min(compressed_data.len, original_size)]);

        return decompressed;
    }
};

// ============================================================================
// Packet Queue
// ============================================================================

pub const PacketQueue = struct {
    allocator: Allocator,
    packets: ArrayList(Packet),
    max_size: usize,

    pub fn init(allocator: Allocator, max_size: usize) PacketQueue {
        return .{
            .allocator = allocator,
            .packets = ArrayList(Packet){},
            .max_size = max_size,
        };
    }

    pub fn deinit(self: *PacketQueue) void {
        for (self.packets.items) |*pkt| pkt.deinit();
        self.packets.deinit(self.allocator);
    }

    pub fn enqueue(self: *PacketQueue, packet: Packet) !void {
        if (self.packets.items.len >= self.max_size) {
            return error.QueueFull;
        }
        try self.packets.append(self.allocator, packet);
    }

    pub fn dequeue(self: *PacketQueue) ?Packet {
        if (self.packets.items.len == 0) return null;
        return self.packets.orderedRemove(0);
    }

    pub fn peek(self: *const PacketQueue) ?*const Packet {
        if (self.packets.items.len == 0) return null;
        return &self.packets.items[0];
    }

    pub fn size(self: *const PacketQueue) usize {
        return self.packets.items.len;
    }

    pub fn isFull(self: *const PacketQueue) bool {
        return self.packets.items.len >= self.max_size;
    }

    pub fn isEmpty(self: *const PacketQueue) bool {
        return self.packets.items.len == 0;
    }

    pub fn clear(self: *PacketQueue) void {
        for (self.packets.items) |*pkt| pkt.deinit();
        self.packets.clearRetainingCapacity();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "packet header initialization" {
    const header = PacketHeader.init(.data, 123, 456);
    try std.testing.expectEqual(MAGIC_NUMBER, header.magic);
    try std.testing.expectEqual(@as(u8, 1), header.version);
    try std.testing.expectEqual(PacketType.data, header.packet_type);
    try std.testing.expectEqual(@as(u32, 123), header.sequence);
    try std.testing.expectEqual(@as(u32, 456), header.payload_length);
}

test "packet header validation" {
    var header = PacketHeader.init(.control, 1, 100);
    try std.testing.expect(header.validate());

    header.magic = 0xDEADBEEF;
    try std.testing.expect(!header.validate());
}

test "packet header checksum" {
    const allocator = std.testing.allocator;
    const payload = "Hello, World!";

    var header = PacketHeader.init(.data, 1, payload.len);
    header.calculateChecksum(payload);

    try std.testing.expect(header.checksum != 0);
    try std.testing.expect(header.verifyChecksum(payload));

    // Corrupt payload
    var corrupted = try allocator.dupe(u8, payload);
    defer allocator.free(corrupted);
    corrupted[0] = 'X';

    try std.testing.expect(!header.verifyChecksum(corrupted));
}

test "packet creation and serialization" {
    const allocator = std.testing.allocator;
    const payload = "Test payload data";

    var packet = try Packet.init(allocator, .data, 42, payload);
    defer packet.deinit();

    try std.testing.expectEqual(PacketType.data, packet.getType());
    try std.testing.expectEqual(@as(u32, 42), packet.getSequence());
    try std.testing.expectEqualSlices(u8, payload, packet.payload);

    const serialized = try packet.serialize(allocator);
    defer allocator.free(serialized);

    try std.testing.expect(serialized.len >= HEADER_SIZE + payload.len);
}

test "packet deserialization" {
    const allocator = std.testing.allocator;
    const payload = "Deserialize test";

    var packet = try Packet.init(allocator, .control, 99, payload);
    defer packet.deinit();

    const serialized = try packet.serialize(allocator);
    defer allocator.free(serialized);

    var deserialized = try Packet.deserialize(allocator, serialized);
    defer deserialized.deinit();

    try std.testing.expectEqual(packet.header.packet_type, deserialized.header.packet_type);
    try std.testing.expectEqual(packet.header.sequence, deserialized.header.sequence);
    try std.testing.expectEqualSlices(u8, packet.payload, deserialized.payload);
}

test "packet flags" {
    var flags = PacketFlags{};
    try std.testing.expect(!flags.compressed);
    try std.testing.expect(!flags.encrypted);

    flags.compressed = true;
    flags.encrypted = true;

    const value = flags.toU8();
    const restored = PacketFlags.fromU8(value);

    try std.testing.expect(restored.compressed);
    try std.testing.expect(restored.encrypted);
}

test "fragment info serialization" {
    const allocator = std.testing.allocator;

    const info = FragmentInfo{
        .packet_id = 12345,
        .fragment_index = 2,
        .total_fragments = 5,
        .fragment_size = 1024,
    };

    const serialized = try info.serialize(allocator);
    defer allocator.free(serialized);

    const deserialized = try FragmentInfo.deserialize(serialized);

    try std.testing.expectEqual(info.packet_id, deserialized.packet_id);
    try std.testing.expectEqual(info.fragment_index, deserialized.fragment_index);
    try std.testing.expectEqual(info.total_fragments, deserialized.total_fragments);
    try std.testing.expectEqual(info.fragment_size, deserialized.fragment_size);
}

test "packet fragmentation" {
    const allocator = std.testing.allocator;

    // Create large payload that needs fragmentation
    const large_payload = try allocator.alloc(u8, 3000);
    defer allocator.free(large_payload);
    for (large_payload, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    var packet = try Packet.init(allocator, .data, 100, large_payload);
    defer packet.deinit();

    var fragmenter = PacketFragmenter.init(allocator, 1000);
    try std.testing.expect(fragmenter.needsFragmentation(&packet));

    var fragments = try fragmenter.fragment(&packet, 100);
    defer {
        for (fragments.items) |*frag| frag.deinit();
        fragments.deinit(allocator);
    }

    try std.testing.expect(fragments.items.len >= 3);

    for (fragments.items) |*frag| {
        try std.testing.expect(frag.header.flags.fragmented);
    }
}

test "packet reassembly" {
    const allocator = std.testing.allocator;

    const payload = try allocator.alloc(u8, 2500);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| {
        byte.* = @intCast(i % 256);
    }

    var packet = try Packet.init(allocator, .data, 200, payload);
    defer packet.deinit();

    var fragmenter = PacketFragmenter.init(allocator, 1000);
    var fragments = try fragmenter.fragment(&packet, 200);
    defer fragments.deinit(allocator);

    var reassembler = PacketReassembler.init(allocator, 30000);
    defer reassembler.deinit();

    // Add fragments one by one
    for (fragments.items) |frag| {
        const result = try reassembler.addFragment(frag);

        // Last fragment should return reassembled packet
        if (frag.header.sequence == fragments.items[fragments.items.len - 1].header.sequence) {
            try std.testing.expect(result != null);
            var reassembled = result.?;
            defer reassembled.deinit();

            try std.testing.expectEqualSlices(u8, payload, reassembled.payload);
        }
    }
}

test "packet compression" {
    const allocator = std.testing.allocator;

    const compressor = PacketCompressor.init(allocator, .zlib, 50);
    const data = "This is some data to compress that exceeds the minimum size threshold for compression to be applied";

    try std.testing.expect(compressor.shouldCompress(data));

    const compressed = try compressor.compress(data);
    defer allocator.free(compressed);

    try std.testing.expect(compressed.len > 0);

    const decompressed = try compressor.decompress(compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualSlices(u8, data, decompressed);
}

test "packet queue operations" {
    const allocator = std.testing.allocator;

    var queue = PacketQueue.init(allocator, 5);
    defer queue.deinit();

    try std.testing.expect(queue.isEmpty());
    try std.testing.expectEqual(@as(usize, 0), queue.size());

    // Enqueue packets
    const packet1 = try Packet.init(allocator, .data, 1, "First");
    try queue.enqueue(packet1);

    const packet2 = try Packet.init(allocator, .data, 2, "Second");
    try queue.enqueue(packet2);

    try std.testing.expectEqual(@as(usize, 2), queue.size());
    try std.testing.expect(!queue.isEmpty());

    // Peek
    const peeked = queue.peek();
    try std.testing.expect(peeked != null);
    try std.testing.expectEqual(@as(u32, 1), peeked.?.getSequence());

    // Dequeue
    var dequeued1 = queue.dequeue().?;
    defer dequeued1.deinit();
    try std.testing.expectEqual(@as(u32, 1), dequeued1.getSequence());

    var dequeued2 = queue.dequeue().?;
    defer dequeued2.deinit();
    try std.testing.expectEqual(@as(u32, 2), dequeued2.getSequence());

    try std.testing.expect(queue.isEmpty());
}

test "packet queue full" {
    const allocator = std.testing.allocator;

    var queue = PacketQueue.init(allocator, 2);
    defer queue.deinit();

    const packet1 = try Packet.init(allocator, .data, 1, "First");
    try queue.enqueue(packet1);

    const packet2 = try Packet.init(allocator, .data, 2, "Second");
    try queue.enqueue(packet2);

    try std.testing.expect(queue.isFull());

    const packet3 = try Packet.init(allocator, .data, 3, "Third");
    const result = queue.enqueue(packet3);
    try std.testing.expectError(error.QueueFull, result);

    // Clean up packet3 since it wasn't added
    var p3 = packet3;
    p3.deinit();
}

test "packet type to string" {
    try std.testing.expectEqualStrings("DATA", PacketType.data.toString());
    try std.testing.expectEqualStrings("CONTROL", PacketType.control.toString());
    try std.testing.expectEqualStrings("KEEPALIVE", PacketType.keepalive.toString());
}
