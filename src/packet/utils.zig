// SoftEther VPN Zig Client - Packet Utilities
// Common packet building and parsing functions for all platforms
// Ported from packet_utils.c (920 lines) to pure Zig

const std = @import("std");

// ============================================================================
// Type Definitions
// ============================================================================

/// MAC address (6 bytes)
pub const MacAddr = [6]u8;

/// IPv4 address (4 bytes, network byte order)
pub const Ipv4Addr = u32;

/// IPv6 address (16 bytes)
pub const Ipv6Addr = [16]u8;

// ============================================================================
// IPv6 Packet Building
// ============================================================================

/// Build an IPv6 Router Solicitation packet (RFC 4861)
/// Used to discover routers on the network
pub fn buildRouterSolicitation(my_mac: MacAddr, allocator: std.mem.Allocator) ![]u8 {
    var packet = try allocator.alloc(u8, 86); // Fixed size
    var pos: usize = 0;

    // Ethernet header (14 bytes)
    // Destination: IPv6 all-routers multicast (33:33:00:00:00:02)
    packet[pos] = 0x33;
    packet[pos + 1] = 0x33;
    packet[pos + 2] = 0x00;
    packet[pos + 3] = 0x00;
    packet[pos + 4] = 0x00;
    packet[pos + 5] = 0x02;
    pos += 6;

    // Source MAC
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: IPv6 (0x86DD)
    packet[pos] = 0x86;
    packet[pos + 1] = 0xDD;
    pos += 2;

    // IPv6 header (40 bytes)
    packet[pos] = 0x60; // Version 6, traffic class 0
    packet[pos + 1] = 0x00;
    packet[pos + 2] = 0x00;
    packet[pos + 3] = 0x00; // Flow label
    pos += 4;

    // Payload length: 8 bytes (ICMPv6 Router Solicitation)
    const payload_len: u16 = 8;
    packet[pos] = @intCast(payload_len >> 8);
    packet[pos + 1] = @intCast(payload_len & 0xFF);
    pos += 2;

    packet[pos] = 58; // Next header: ICMPv6
    packet[pos + 1] = 255; // Hop limit
    pos += 2;

    // Source: IPv6 link-local address (fe80::)
    packet[pos] = 0xFE;
    packet[pos + 1] = 0x80;
    pos += 2;
    @memset(packet[pos..][0..6], 0); // Zeros
    pos += 6;

    // Generate EUI-64 from MAC
    packet[pos] = my_mac[0] ^ 0x02; // Flip universal/local bit
    packet[pos + 1] = my_mac[1];
    packet[pos + 2] = my_mac[2];
    packet[pos + 3] = 0xFF;
    packet[pos + 4] = 0xFE;
    packet[pos + 5] = my_mac[3];
    packet[pos + 6] = my_mac[4];
    packet[pos + 7] = my_mac[5];
    pos += 8;

    // Destination: ff02::2 (all-routers multicast)
    packet[pos] = 0xFF;
    packet[pos + 1] = 0x02;
    pos += 2;
    @memset(packet[pos..][0..12], 0);
    pos += 12;
    packet[pos] = 0x00;
    packet[pos + 1] = 0x02;
    pos += 2;

    // ICMPv6 Router Solicitation (8 bytes)
    packet[pos] = 133; // Type: Router Solicitation
    packet[pos + 1] = 0; // Code
    packet[pos + 2] = 0x00; // Checksum (simplified)
    packet[pos + 3] = 0x00;
    packet[pos + 4] = 0x00; // Reserved
    packet[pos + 5] = 0x00;
    packet[pos + 6] = 0x00;
    packet[pos + 7] = 0x00;
    pos += 8;

    return packet;
}

/// Build an IPv6 Neighbor Advertisement packet (RFC 4861)
pub fn buildNeighborAdvertisement(my_mac: MacAddr, allocator: std.mem.Allocator) ![]u8 {
    var packet = try allocator.alloc(u8, 86); // Fixed size
    var pos: usize = 0;

    // Ethernet header (14 bytes)
    // Destination: IPv6 all-nodes multicast (33:33:00:00:00:01)
    packet[pos] = 0x33;
    packet[pos + 1] = 0x33;
    packet[pos + 2] = 0x00;
    packet[pos + 3] = 0x00;
    packet[pos + 4] = 0x00;
    packet[pos + 5] = 0x01;
    pos += 6;

    // Source MAC
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: IPv6 (0x86DD)
    packet[pos] = 0x86;
    packet[pos + 1] = 0xDD;
    pos += 2;

    // IPv6 header (40 bytes)
    packet[pos] = 0x60; // Version 6
    packet[pos + 1] = 0x00;
    packet[pos + 2] = 0x00;
    packet[pos + 3] = 0x00;
    pos += 4;

    // Payload length: 8 bytes
    const payload_len: u16 = 8;
    packet[pos] = @intCast(payload_len >> 8);
    packet[pos + 1] = @intCast(payload_len & 0xFF);
    pos += 2;

    packet[pos] = 58; // ICMPv6
    packet[pos + 1] = 255; // Hop limit
    pos += 2;

    // Source: link-local from MAC
    packet[pos] = 0xFE;
    packet[pos + 1] = 0x80;
    pos += 2;
    @memset(packet[pos..][0..6], 0);
    pos += 6;
    packet[pos] = my_mac[0] ^ 0x02;
    packet[pos + 1] = my_mac[1];
    packet[pos + 2] = my_mac[2];
    packet[pos + 3] = 0xFF;
    packet[pos + 4] = 0xFE;
    packet[pos + 5] = my_mac[3];
    packet[pos + 6] = my_mac[4];
    packet[pos + 7] = my_mac[5];
    pos += 8;

    // Destination: all-nodes multicast
    packet[pos] = 0xFF;
    packet[pos + 1] = 0x02;
    pos += 2;
    @memset(packet[pos..][0..12], 0);
    pos += 12;
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01;
    pos += 2;

    // ICMPv6 Neighbor Advertisement
    packet[pos] = 136; // Type
    packet[pos + 1] = 0; // Code
    packet[pos + 2] = 0x00; // Checksum
    packet[pos + 3] = 0x00;
    packet[pos + 4] = 0x00; // Flags
    packet[pos + 5] = 0x00;
    packet[pos + 6] = 0x00;
    packet[pos + 7] = 0x00;
    pos += 8;

    return packet;
}

// ============================================================================
// ARP Packet Building
// ============================================================================

/// Build a Gratuitous ARP packet (announce our IP/MAC to the network)
/// Used to detect IP conflicts and announce our presence
pub fn buildGratuitousArp(my_mac: MacAddr, my_ip: Ipv4Addr, allocator: std.mem.Allocator) ![]u8 {
    var packet = try allocator.alloc(u8, 42); // Fixed ARP size
    var pos: usize = 0;

    // Ethernet header (14 bytes)
    // Broadcast destination
    @memset(packet[pos..][0..6], 0xFF);
    pos += 6;

    // Source MAC
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: ARP (0x0806)
    packet[pos] = 0x08;
    packet[pos + 1] = 0x06;
    pos += 2;

    // ARP packet (28 bytes)
    // Hardware type: Ethernet (1)
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01;
    pos += 2;

    // Protocol type: IPv4 (0x0800)
    packet[pos] = 0x08;
    packet[pos + 1] = 0x00;
    pos += 2;

    packet[pos] = 6; // Hardware size (MAC = 6 bytes)
    packet[pos + 1] = 4; // Protocol size (IPv4 = 4 bytes)
    pos += 2;

    // Opcode: Reply (2) for gratuitous ARP
    packet[pos] = 0x00;
    packet[pos + 1] = 0x02;
    pos += 2;

    // Sender MAC
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // Sender IP (network byte order)
    std.mem.writeInt(u32, packet[pos..][0..4], my_ip, .big);
    pos += 4;

    // Target MAC (broadcast for gratuitous)
    @memset(packet[pos..][0..6], 0xFF);
    pos += 6;

    // Target IP (same as sender for gratuitous)
    std.mem.writeInt(u32, packet[pos..][0..4], my_ip, .big);
    pos += 4;

    return packet;
}

/// Build an ARP Reply packet
pub fn buildArpReply(
    my_mac: MacAddr,
    my_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
    allocator: std.mem.Allocator,
) ![]u8 {
    var packet = try allocator.alloc(u8, 42);
    var pos: usize = 0;

    // Ethernet header: unicast to target
    @memcpy(packet[pos..][0..6], &target_mac);
    pos += 6;
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: ARP
    packet[pos] = 0x08;
    packet[pos + 1] = 0x06;
    pos += 2;

    // ARP header
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01; // Ethernet
    pos += 2;
    packet[pos] = 0x08;
    packet[pos + 1] = 0x00; // IPv4
    pos += 2;
    packet[pos] = 6; // Hardware size
    packet[pos + 1] = 4; // Protocol size
    pos += 2;

    // Opcode: Reply (2)
    packet[pos] = 0x00;
    packet[pos + 1] = 0x02;
    pos += 2;

    // Sender (us)
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;
    std.mem.writeInt(u32, packet[pos..][0..4], my_ip, .big);
    pos += 4;

    // Target
    @memcpy(packet[pos..][0..6], &target_mac);
    pos += 6;
    std.mem.writeInt(u32, packet[pos..][0..4], target_ip, .big);
    pos += 4;

    return packet;
}

/// Build an ARP Request packet (ask "who has target_ip?")
pub fn buildArpRequest(
    my_mac: MacAddr,
    my_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    allocator: std.mem.Allocator,
) ![]u8 {
    var packet = try allocator.alloc(u8, 42);
    var pos: usize = 0;

    // Ethernet broadcast
    @memset(packet[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: ARP
    packet[pos] = 0x08;
    packet[pos + 1] = 0x06;
    pos += 2;

    // ARP header
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01;
    pos += 2;
    packet[pos] = 0x08;
    packet[pos + 1] = 0x00;
    pos += 2;
    packet[pos] = 6;
    packet[pos + 1] = 4;
    pos += 2;

    // Opcode: Request (1)
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01;
    pos += 2;

    // Sender
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;
    std.mem.writeInt(u32, packet[pos..][0..4], my_ip, .big);
    pos += 4;

    // Target (unknown MAC)
    @memset(packet[pos..][0..6], 0x00);
    pos += 6;
    std.mem.writeInt(u32, packet[pos..][0..4], target_ip, .big);
    pos += 4;

    return packet;
}

/// Build an ARP Probe packet (check if IP is already in use)
/// Used during DHCP to detect conflicts
pub fn buildArpProbe(
    my_mac: MacAddr,
    target_ip: Ipv4Addr,
    allocator: std.mem.Allocator,
) ![]u8 {
    var packet = try allocator.alloc(u8, 42);
    var pos: usize = 0;

    // Ethernet broadcast
    @memset(packet[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: ARP
    packet[pos] = 0x08;
    packet[pos + 1] = 0x06;
    pos += 2;

    // ARP header
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01;
    pos += 2;
    packet[pos] = 0x08;
    packet[pos + 1] = 0x00;
    pos += 2;
    packet[pos] = 6;
    packet[pos + 1] = 4;
    pos += 2;

    // Opcode: Request (1)
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01;
    pos += 2;

    // Sender MAC (ours)
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // Sender IP: 0.0.0.0 (probe)
    std.mem.writeInt(u32, packet[pos..][0..4], 0, .big);
    pos += 4;

    // Target MAC: all zeros
    @memset(packet[pos..][0..6], 0x00);
    pos += 6;

    // Target IP: the IP we're probing
    std.mem.writeInt(u32, packet[pos..][0..4], target_ip, .big);
    pos += 4;

    return packet;
}

// ============================================================================
// DHCP Packet Building
// ============================================================================

/// DHCP Magic Cookie (RFC 2131)
const DHCP_MAGIC_COOKIE: u32 = 0x63825363;

/// Build a DHCP Discover packet
pub fn buildDhcpDiscover(
    my_mac: MacAddr,
    xid: u32,
    allocator: std.mem.Allocator,
) ![]u8 {
    // Ethernet (14) + IP (20) + UDP (8) + DHCP (300)
    var packet = try allocator.alloc(u8, 342);
    var pos: usize = 0;

    // Ethernet header: broadcast
    @memset(packet[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: IPv4
    packet[pos] = 0x08;
    packet[pos + 1] = 0x00;
    pos += 2;

    // IPv4 header (20 bytes)
    packet[pos] = 0x45; // Version 4, IHL 5
    packet[pos + 1] = 0x00; // DSCP/ECN
    pos += 2;

    // Total length: 328 bytes (IP header + UDP + DHCP)
    const ip_total_len: u16 = 328;
    std.mem.writeInt(u16, packet[pos..][0..2], ip_total_len, .big);
    pos += 2;

    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // ID
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // Flags/Fragment
    pos += 2;

    packet[pos] = 64; // TTL
    packet[pos + 1] = 17; // Protocol: UDP
    pos += 2;

    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // Checksum (will calculate)
    pos += 2;

    // Source: 0.0.0.0
    std.mem.writeInt(u32, packet[pos..][0..4], 0, .big);
    pos += 4;

    // Dest: 255.255.255.255
    std.mem.writeInt(u32, packet[pos..][0..4], 0xFFFFFFFF, .big);
    pos += 4;

    // Calculate and set IPv4 checksum
    const ip_checksum = calculateIpv4Checksum(packet[14..34]);
    std.mem.writeInt(u16, packet[24..26], ip_checksum, .big);

    // UDP header (8 bytes)
    std.mem.writeInt(u16, packet[pos..][0..2], 68, .big); // Source port: DHCP client
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 67, .big); // Dest port: DHCP server
    pos += 2;

    // UDP length: 308 bytes (UDP header + DHCP)
    const udp_len: u16 = 308;
    std.mem.writeInt(u16, packet[pos..][0..2], udp_len, .big);
    pos += 2;

    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // UDP checksum (optional for IPv4)
    pos += 2;

    // DHCP packet (300 bytes minimum)
    packet[pos] = 1; // op: BOOTREQUEST
    packet[pos + 1] = 1; // htype: Ethernet
    packet[pos + 2] = 6; // hlen: 6 bytes
    packet[pos + 3] = 0; // hops
    pos += 4;

    std.mem.writeInt(u32, packet[pos..][0..4], xid, .big); // Transaction ID
    pos += 4;

    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // secs
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0x8000, .big); // flags: broadcast
    pos += 2;

    // ciaddr, yiaddr, siaddr, giaddr (all zeros)
    @memset(packet[pos..][0..16], 0);
    pos += 16;

    // chaddr: our MAC
    @memcpy(packet[pos..][0..6], &my_mac);
    @memset(packet[pos + 6 ..][0..10], 0); // Pad to 16 bytes
    pos += 16;

    // sname and file (192 bytes, all zeros)
    @memset(packet[pos..][0..192], 0);
    pos += 192;

    // DHCP magic cookie
    std.mem.writeInt(u32, packet[pos..][0..4], DHCP_MAGIC_COOKIE, .big);
    pos += 4;

    // DHCP options
    // Option 53: DHCP Message Type = DISCOVER (1)
    packet[pos] = 53;
    packet[pos + 1] = 1;
    packet[pos + 2] = 1; // DHCPDISCOVER
    pos += 3;

    // Option 55: Parameter Request List
    packet[pos] = 55;
    packet[pos + 1] = 4;
    packet[pos + 2] = 1; // Subnet mask
    packet[pos + 3] = 3; // Router
    packet[pos + 4] = 6; // DNS
    packet[pos + 5] = 15; // Domain name
    pos += 6;

    // Option 255: End
    packet[pos] = 255;
    pos += 1;

    // Pad to minimum size
    while (pos < 342) {
        packet[pos] = 0;
        pos += 1;
    }

    return packet;
}

/// Build a DHCP Request packet
pub fn buildDhcpRequest(
    my_mac: MacAddr,
    xid: u32,
    requested_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    allocator: std.mem.Allocator,
) ![]u8 {
    // Similar structure to DISCOVER but with requested IP
    var packet = try allocator.alloc(u8, 354);
    var pos: usize = 0;

    // Ethernet header: broadcast
    @memset(packet[pos..][0..6], 0xFF);
    pos += 6;
    @memcpy(packet[pos..][0..6], &my_mac);
    pos += 6;

    // EtherType: IPv4
    packet[pos] = 0x08;
    packet[pos + 1] = 0x00;
    pos += 2;

    // IPv4 header
    packet[pos] = 0x45;
    packet[pos + 1] = 0x00;
    pos += 2;

    // Total length: 340 bytes
    const ip_total_len: u16 = 340;
    std.mem.writeInt(u16, packet[pos..][0..2], ip_total_len, .big);
    pos += 2;

    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // ID
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // Flags
    pos += 2;

    packet[pos] = 64; // TTL
    packet[pos + 1] = 17; // UDP
    pos += 2;

    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // Checksum placeholder
    pos += 2;

    std.mem.writeInt(u32, packet[pos..][0..4], 0, .big); // Source: 0.0.0.0
    pos += 4;
    std.mem.writeInt(u32, packet[pos..][0..4], 0xFFFFFFFF, .big); // Dest: broadcast
    pos += 4;

    // Calculate IP checksum
    const ip_checksum = calculateIpv4Checksum(packet[14..34]);
    std.mem.writeInt(u16, packet[24..26], ip_checksum, .big);

    // UDP header
    std.mem.writeInt(u16, packet[pos..][0..2], 68, .big); // Client port
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 67, .big); // Server port
    pos += 2;

    const udp_len: u16 = 320;
    std.mem.writeInt(u16, packet[pos..][0..2], udp_len, .big);
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // Checksum
    pos += 2;

    // DHCP packet
    packet[pos] = 1; // BOOTREQUEST
    packet[pos + 1] = 1; // Ethernet
    packet[pos + 2] = 6;
    packet[pos + 3] = 0;
    pos += 4;

    std.mem.writeInt(u32, packet[pos..][0..4], xid, .big);
    pos += 4;

    std.mem.writeInt(u16, packet[pos..][0..2], 0, .big); // secs
    pos += 2;
    std.mem.writeInt(u16, packet[pos..][0..2], 0x8000, .big); // broadcast flag
    pos += 2;

    // ciaddr, yiaddr, siaddr, giaddr
    @memset(packet[pos..][0..16], 0);
    pos += 16;

    // chaddr
    @memcpy(packet[pos..][0..6], &my_mac);
    @memset(packet[pos + 6 ..][0..10], 0);
    pos += 16;

    // sname, file
    @memset(packet[pos..][0..192], 0);
    pos += 192;

    // Magic cookie
    std.mem.writeInt(u32, packet[pos..][0..4], DHCP_MAGIC_COOKIE, .big);
    pos += 4;

    // Option 53: DHCP Message Type = REQUEST (3)
    packet[pos] = 53;
    packet[pos + 1] = 1;
    packet[pos + 2] = 3; // DHCPREQUEST
    pos += 3;

    // Option 50: Requested IP Address
    packet[pos] = 50;
    packet[pos + 1] = 4;
    std.mem.writeInt(u32, packet[pos + 2 ..][0..4], requested_ip, .big);
    pos += 6;

    // Option 54: Server Identifier
    packet[pos] = 54;
    packet[pos + 1] = 4;
    std.mem.writeInt(u32, packet[pos + 2 ..][0..4], server_ip, .big);
    pos += 6;

    // Option 55: Parameter Request List
    packet[pos] = 55;
    packet[pos + 1] = 4;
    packet[pos + 2] = 1; // Subnet
    packet[pos + 3] = 3; // Router
    packet[pos + 4] = 6; // DNS
    packet[pos + 5] = 15; // Domain
    pos += 6;

    // Option 255: End
    packet[pos] = 255;
    pos += 1;

    // Pad
    while (pos < 354) {
        packet[pos] = 0;
        pos += 1;
    }

    return packet;
}

// ============================================================================
// DHCP Packet Parsing
// ============================================================================

/// DHCP message types
pub const DhcpMessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
};

/// Parse a DHCP Offer packet
pub fn parseDhcpOffer(
    data: []const u8,
    expected_xid: u32,
) ?struct {
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    server: Ipv4Addr,
    dns1: ?Ipv4Addr,
    dns2: ?Ipv4Addr,
} {
    // Need at least Ethernet(14) + IP(20) + UDP(8) + DHCP(236 min)
    if (data.len < 278) return null;

    // Skip Ethernet(14) + IP(20) + UDP(8) = 42 bytes
    const dhcp_start: usize = 42;
    const dhcp = data[dhcp_start..];

    // Verify BOOTREPLY (op = 2)
    if (dhcp[0] != 2) return null;

    // Check transaction ID
    const xid_received = std.mem.readInt(u32, dhcp[4..8], .big);
    if (xid_received != expected_xid) return null;

    // Get offered IP (yiaddr field at offset 16)
    const offered_ip = std.mem.readInt(u32, dhcp[16..20], .big);

    // Verify magic cookie
    const magic = std.mem.readInt(u32, dhcp[236..240], .big);
    if (magic != DHCP_MAGIC_COOKIE) return null;

    // Parse options
    var pos: usize = 240; // Start of options
    var msg_type: ?DhcpMessageType = null;
    var subnet_mask: ?Ipv4Addr = null;
    var router: ?Ipv4Addr = null;
    var dhcp_server: ?Ipv4Addr = null;
    var dns1: ?Ipv4Addr = null;
    var dns2: ?Ipv4Addr = null;

    while (pos + 2 <= dhcp.len) {
        const option = dhcp[pos];
        if (option == 255) break; // End option
        if (option == 0) { // Pad option
            pos += 1;
            continue;
        }

        pos += 1;
        const len = dhcp[pos];
        pos += 1;

        if (pos + len > dhcp.len) break;

        switch (option) {
            53 => { // DHCP Message Type
                if (len == 1) {
                    msg_type = @enumFromInt(dhcp[pos]);
                }
            },
            1 => { // Subnet Mask
                if (len == 4) {
                    subnet_mask = std.mem.readInt(u32, dhcp[pos..][0..4], .big);
                }
            },
            3 => { // Router
                if (len >= 4) {
                    router = std.mem.readInt(u32, dhcp[pos..][0..4], .big);
                }
            },
            54 => { // DHCP Server Identifier
                if (len == 4) {
                    dhcp_server = std.mem.readInt(u32, dhcp[pos..][0..4], .big);
                }
            },
            6 => { // DNS Servers
                if (len >= 4) {
                    dns1 = std.mem.readInt(u32, dhcp[pos..][0..4], .big);
                }
                if (len >= 8) {
                    dns2 = std.mem.readInt(u32, dhcp[pos + 4 ..][0..4], .big);
                }
            },
            else => {},
        }

        pos += len;
    }

    // Verify this is an OFFER
    if (msg_type != .offer) return null;

    return .{
        .ip = offered_ip,
        .mask = subnet_mask orelse 0xFFFFFF00, // Default: 255.255.255.0
        .gateway = router orelse 0,
        .server = dhcp_server orelse 0,
        .dns1 = dns1,
        .dns2 = dns2,
    };
}

/// Parse a DHCP ACK packet
pub fn parseDhcpAck(
    data: []const u8,
    expected_xid: u32,
) ?struct {
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
} {
    if (data.len < 278) return null;

    const dhcp_start: usize = 42;
    const dhcp = data[dhcp_start..];

    if (dhcp[0] != 2) return null;

    const xid_received = std.mem.readInt(u32, dhcp[4..8], .big);
    if (xid_received != expected_xid) return null;

    const assigned_ip = std.mem.readInt(u32, dhcp[16..20], .big);

    const magic = std.mem.readInt(u32, dhcp[236..240], .big);
    if (magic != DHCP_MAGIC_COOKIE) return null;

    var pos: usize = 240;
    var msg_type: ?DhcpMessageType = null;
    var subnet_mask: ?Ipv4Addr = null;
    var router: ?Ipv4Addr = null;

    while (pos + 2 <= dhcp.len) {
        const option = dhcp[pos];
        if (option == 255) break;
        if (option == 0) {
            pos += 1;
            continue;
        }

        pos += 1;
        const len = dhcp[pos];
        pos += 1;

        if (pos + len > dhcp.len) break;

        switch (option) {
            53 => {
                if (len == 1) {
                    msg_type = @enumFromInt(dhcp[pos]);
                }
            },
            1 => {
                if (len == 4) {
                    subnet_mask = std.mem.readInt(u32, dhcp[pos..][0..4], .big);
                }
            },
            3 => {
                if (len >= 4) {
                    router = std.mem.readInt(u32, dhcp[pos..][0..4], .big);
                }
            },
            else => {},
        }

        pos += len;
    }

    if (msg_type != .ack) return null;

    return .{
        .ip = assigned_ip,
        .mask = subnet_mask orelse 0xFFFFFF00,
        .gateway = router orelse 0,
    };
}

// ============================================================================
// Checksum Utilities
// ============================================================================

/// Calculate IPv4 header checksum (RFC 791)
pub fn calculateIpv4Checksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Sum all 16-bit words
    while (i + 1 < data.len) : (i += 2) {
        const word = std.mem.readInt(u16, data[i..][0..2], .big);
        sum += word;
    }

    // Add carry bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    return @truncate(~sum);
}

/// Calculate UDP checksum (RFC 768)
pub fn calculateUdpChecksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    udp_data: []const u8,
) u16 {
    var sum: u32 = 0;

    // Pseudo-header
    sum += (src_ip >> 16) & 0xFFFF;
    sum += src_ip & 0xFFFF;
    sum += (dst_ip >> 16) & 0xFFFF;
    sum += dst_ip & 0xFFFF;
    sum += 17; // Protocol: UDP
    sum += @as(u32, @intCast(udp_data.len));

    // UDP data
    var i: usize = 0;
    while (i + 1 < udp_data.len) : (i += 2) {
        const word = std.mem.readInt(u16, udp_data[i..][0..2], .big);
        sum += word;
    }

    // Handle odd byte
    if (i < udp_data.len) {
        sum += @as(u32, udp_data[i]) << 8;
    }

    // Add carry
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @truncate(~sum);
}

// ============================================================================
// C FFI Exports (for compatibility with existing C code)
// ============================================================================

export fn BuildGratuitousArp(my_mac: [*c]u8, my_ip: u32, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildGratuitousArp(mac, my_ip, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn BuildArpReply(my_mac: [*c]u8, my_ip: u32, target_mac: [*c]u8, target_ip: u32, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const tgt_mac: MacAddr = target_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildArpReply(mac, my_ip, tgt_mac, target_ip, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn BuildArpRequest(my_mac: [*c]u8, my_ip: u32, target_ip: u32, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildArpRequest(mac, my_ip, target_ip, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn BuildArpProbe(my_mac: [*c]u8, target_ip: u32, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildArpProbe(mac, target_ip, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn BuildDhcpDiscover(my_mac: [*c]u8, xid: u32, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildDhcpDiscover(mac, xid, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn BuildDhcpRequest(my_mac: [*c]u8, xid: u32, requested_ip: u32, server_ip: u32, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildDhcpRequest(mac, xid, requested_ip, server_ip, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn BuildRouterSolicitation(my_mac: [*c]u8, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildRouterSolicitation(mac, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn BuildNeighborAdvertisement(my_mac: [*c]u8, out_size: [*c]u32) callconv(.c) [*c]u8 {
    const mac: MacAddr = my_mac[0..6].*;
    const allocator = std.heap.c_allocator;

    const packet = buildNeighborAdvertisement(mac, allocator) catch return null;
    out_size.* = @intCast(packet.len);

    return packet.ptr;
}

export fn ParseDhcpOffer(
    data: [*c]u8,
    size: u32,
    expected_xid: u32,
    out_ip: [*c]u32,
    out_mask: [*c]u32,
    out_gw: [*c]u32,
    out_server: [*c]u32,
) callconv(.c) bool {
    const slice = data[0..size];
    const result = parseDhcpOffer(slice, expected_xid) orelse return false;

    out_ip.* = result.ip;
    out_mask.* = result.mask;
    out_gw.* = result.gateway;
    out_server.* = result.server;

    return true;
}

export fn ParseDhcpAck(
    data: [*c]u8,
    size: u32,
    expected_xid: u32,
    out_ip: [*c]u32,
    out_mask: [*c]u32,
    out_gw: [*c]u32,
) callconv(.c) bool {
    const slice = data[0..size];
    const result = parseDhcpAck(slice, expected_xid) orelse return false;

    out_ip.* = result.ip;
    out_mask.* = result.mask;
    out_gw.* = result.gateway;

    return true;
}

export fn CalculateIPv4Checksum(data: [*c]const u8, len: u32) callconv(.c) u16 {
    return calculateIpv4Checksum(data[0..len]);
}

export fn CalculateUDPChecksum(src_ip: u32, dst_ip: u32, udp_data: [*c]const u8, udp_len: u32) callconv(.c) u16 {
    return calculateUdpChecksum(src_ip, dst_ip, udp_data[0..udp_len]);
}

// ============================================================================
// Tests
// ============================================================================

test "build gratuitous ARP" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const my_mac: MacAddr = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const my_ip: Ipv4Addr = 0x0A000001; // 10.0.0.1 (big endian)

    const packet = try buildGratuitousArp(my_mac, my_ip, allocator);
    defer allocator.free(packet);

    try testing.expectEqual(@as(usize, 42), packet.len);

    // Check destination is broadcast
    try testing.expectEqual(@as(u8, 0xFF), packet[0]);
    try testing.expectEqual(@as(u8, 0xFF), packet[5]);

    // Check source MAC
    try testing.expectEqualSlices(u8, &my_mac, packet[6..12]);

    // Check EtherType is ARP
    try testing.expectEqual(@as(u8, 0x08), packet[12]);
    try testing.expectEqual(@as(u8, 0x06), packet[13]);

    // Check ARP opcode is Reply (2)
    try testing.expectEqual(@as(u8, 0x02), packet[21]);
}

test "build ARP request" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const my_mac: MacAddr = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const my_ip: Ipv4Addr = 0x0A000001;
    const target_ip: Ipv4Addr = 0x0A000002;

    const packet = try buildArpRequest(my_mac, my_ip, target_ip, allocator);
    defer allocator.free(packet);

    try testing.expectEqual(@as(usize, 42), packet.len);

    // Check opcode is Request (1)
    try testing.expectEqual(@as(u8, 0x01), packet[21]);
}

test "build DHCP discover" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const my_mac: MacAddr = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const xid: u32 = 0x12345678;

    const packet = try buildDhcpDiscover(my_mac, xid, allocator);
    defer allocator.free(packet);

    try testing.expectEqual(@as(usize, 342), packet.len);

    // Check it's a BOOTREQUEST
    try testing.expectEqual(@as(u8, 1), packet[42]);

    // Check XID
    const xid_in_packet = std.mem.readInt(u32, packet[46..50], .big);
    try testing.expectEqual(xid, xid_in_packet);
}

test "IPv4 checksum calculation" {
    const testing = std.testing;

    // Simple test case: IPv4 header with known checksum
    const header = [_]u8{
        0x45, 0x00, 0x00, 0x3c, // Version, IHL, DSCP, Total Length
        0x1c, 0x46, 0x40, 0x00, // Identification, Flags, Fragment Offset
        0x40, 0x06, 0x00, 0x00, // TTL, Protocol, Checksum (0 for calculation)
        0xac, 0x10, 0x0a, 0x63, // Source IP
        0xac, 0x10, 0x0a, 0x0c, // Dest IP
    };

    const checksum = calculateIpv4Checksum(&header);
    // The checksum should be non-zero
    try testing.expect(checksum != 0);
}

test "parse DHCP offer - invalid data" {
    const testing = std.testing;

    // Too short
    const short_data = [_]u8{0} ** 100;
    const result = parseDhcpOffer(&short_data, 0x12345678);
    try testing.expectEqual(@as(?@TypeOf(result.?), null), result);
}

test "build router solicitation" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const my_mac: MacAddr = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    const packet = try buildRouterSolicitation(my_mac, allocator);
    defer allocator.free(packet);

    try testing.expectEqual(@as(usize, 86), packet.len);

    // Check destination is all-routers multicast
    try testing.expectEqual(@as(u8, 0x33), packet[0]);
    try testing.expectEqual(@as(u8, 0x33), packet[1]);
    try testing.expectEqual(@as(u8, 0x02), packet[5]);

    // Check EtherType is IPv6
    try testing.expectEqual(@as(u8, 0x86), packet[12]);
    try testing.expectEqual(@as(u8, 0xDD), packet[13]);

    // Check ICMPv6 type is Router Solicitation (133)
    try testing.expectEqual(@as(u8, 133), packet[54]);
}
