//! ARP (Address Resolution Protocol) Handler
//!
//! Handles ARP requests and replies for L2↔L3 translation.

const std = @import("std");

pub const ArpHandler = struct {
    allocator: std.mem.Allocator,
    our_mac: [6]u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, our_mac: [6]u8) !Self {
        return Self{
            .allocator = allocator,
            .our_mac = our_mac,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Build ARP reply packet
    pub fn buildArpReply(
        self: *Self,
        our_ip: u32,
        target_mac: [6]u8,
        target_ip: u32,
    ) ![]const u8 {
        const packet = try self.allocator.alloc(u8, 42); // Ethernet + ARP
        errdefer self.allocator.free(packet);

        var pos: usize = 0;

        // Ethernet header (14 bytes)
        @memcpy(packet[pos..][0..6], &target_mac); // Dest MAC
        pos += 6;
        @memcpy(packet[pos..][0..6], &self.our_mac); // Src MAC
        pos += 6;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0806, .big); // EtherType: ARP
        pos += 2;

        // ARP packet (28 bytes)
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0001, .big); // Hardware type: Ethernet
        pos += 2;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0800, .big); // Protocol type: IPv4
        pos += 2;
        packet[pos] = 6; // Hardware size
        pos += 1;
        packet[pos] = 4; // Protocol size
        pos += 1;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0002, .big); // Opcode: Reply
        pos += 2;

        // Sender (us)
        @memcpy(packet[pos..][0..6], &self.our_mac); // Sender MAC
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], our_ip, .big); // Sender IP
        pos += 4;

        // Target
        @memcpy(packet[pos..][0..6], &target_mac); // Target MAC
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], target_ip, .big); // Target IP
        pos += 4;

        return packet;
    }

    /// Build ARP request packet
    pub fn buildArpRequest(
        self: *Self,
        our_ip: u32,
        target_ip: u32,
    ) ![]const u8 {
        const packet = try self.allocator.alloc(u8, 42);
        errdefer self.allocator.free(packet);

        var pos: usize = 0;

        // Ethernet header - broadcast
        @memset(packet[pos..][0..6], 0xFF); // Broadcast MAC
        pos += 6;
        @memcpy(packet[pos..][0..6], &self.our_mac); // Src MAC
        pos += 6;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0806, .big); // EtherType: ARP
        pos += 2;

        // ARP packet
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0001, .big); // Hardware type
        pos += 2;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0800, .big); // Protocol type
        pos += 2;
        packet[pos] = 6; // Hardware size
        pos += 1;
        packet[pos] = 4; // Protocol size
        pos += 1;
        std.mem.writeInt(u16, packet[pos..][0..2], 0x0001, .big); // Opcode: Request
        pos += 2;

        // Sender (us)
        @memcpy(packet[pos..][0..6], &self.our_mac);
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], our_ip, .big);
        pos += 4;

        // Target (unknown MAC)
        @memset(packet[pos..][0..6], 0x00);
        pos += 6;
        std.mem.writeInt(u32, packet[pos..][0..4], target_ip, .big);
        pos += 4;

        return packet;
    }
};

test "ArpHandler basic" {
    const allocator = std.testing.allocator;

    var handler = try ArpHandler.init(allocator, [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 });
    defer handler.deinit();

    const reply = try handler.buildArpReply(
        0x0A150001, // 10.21.0.1
        [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
        0x0A150064, // 10.21.0.100
    );
    defer allocator.free(reply);

    try std.testing.expectEqual(@as(usize, 42), reply.len);
    try std.testing.expectEqual(@as(u16, 0x0806), std.mem.readInt(u16, reply[12..14], .big));
}
