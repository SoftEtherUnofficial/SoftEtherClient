//! L2↔L3 Protocol Translator
//!
//! Handles bidirectional conversion between Layer 2 (Ethernet frames) and Layer 3 (IP packets).
//! This is critical for using TUN devices (L3) with protocols that expect TAP devices (L2).
//!
//! IMPORTANT: This is protocol logic only - no platform dependencies!

const std = @import("std");
const ArpHandler = @import("arp.zig").ArpHandler;
const DhcpClient = @import("dhcp_client.zig").DhcpClient;
const DhcpPacket = @import("dhcp_client.zig").DhcpPacket;

/// Translator configuration options
pub const TranslatorOptions = struct {
    our_mac: [6]u8,
    learn_ip: bool = true,
    learn_gateway_mac: bool = true,
    handle_arp: bool = true,
    arp_timeout_ms: u32 = 60000,
    verbose: bool = false,
};

pub const L2L3Translator = struct {
    allocator: std.mem.Allocator,
    options: TranslatorOptions,

    // Learned network information
    our_ip: ?u32, // Our IP address (learned from outgoing packets)
    gateway_ip: ?u32, // Gateway IP address
    gateway_mac: ?[6]u8, // Gateway MAC address (learned from ARP)
    last_gateway_learn: i64, // Timestamp of last gateway MAC learn

    // ARP handling
    arp_handler: ArpHandler,

    // DHCP client (active - initiates DHCP discovery)
    dhcp_client: ?*DhcpClient,
    dhcp_packet_queue: std.ArrayList([]const u8), // Queue of DHCP packets to send
    dhcp_started: bool,
    offered_ip: ?[4]u8, // IP offered by DHCP server
    offered_server_id: ?[4]u8, // DHCP server ID

    // ARP reply queue (for replies that need to be sent back to VPN)
    arp_reply_queue: std.ArrayList([]const u8),
    pending_arp_ips: std.AutoHashMap(u32, void), // Track IPs with pending replies
    packets_translated_l2_to_l3: u64,
    packets_translated_l3_to_l2: u64,
    arp_requests_handled: u64,
    arp_replies_learned: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: TranslatorOptions) !Self {
        return .{
            .allocator = allocator,
            .options = options,
            .our_ip = null,
            .gateway_ip = null,
            .gateway_mac = null,
            .last_gateway_learn = 0,
            .arp_handler = try ArpHandler.init(allocator, options.our_mac),
            .dhcp_client = null,
            .dhcp_packet_queue = std.ArrayList([]const u8){},
            .dhcp_started = false,
            .offered_ip = null,
            .offered_server_id = null,
            .arp_reply_queue = std.ArrayList([]const u8){},
            .pending_arp_ips = std.AutoHashMap(u32, void).init(allocator),
            .packets_translated_l2_to_l3 = 0,
            .packets_translated_l3_to_l2 = 0,
            .arp_requests_handled = 0,
            .arp_replies_learned = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free DHCP client
        if (self.dhcp_client) |client| {
            if (client.lease) |*lease| {
                lease.deinit(self.allocator);
            }
            self.allocator.destroy(client);
        }
        // Free all queued DHCP packets
        for (self.dhcp_packet_queue.items) |packet| {
            self.allocator.free(packet);
        }
        self.dhcp_packet_queue.deinit(self.allocator);
        // Free all queued ARP replies
        for (self.arp_reply_queue.items) |reply| {
            self.allocator.free(reply);
        }
        self.arp_reply_queue.deinit(self.allocator);
        self.pending_arp_ips.deinit();
        self.arp_handler.deinit();
    }

    /// Convert IP packet (L3) to Ethernet frame (L2)
    /// Used when sending packets from TUN device to network/VPN that expects Ethernet frames
    ///
    /// **Memory Management:**
    /// This function allocates a new buffer for the Ethernet frame.
    /// The caller is responsible for freeing the returned slice using the same allocator.
    ///
    /// Example:
    /// ```zig
    /// const eth_frame = try translator.ipToEthernet(ip_packet);
    /// defer translator.allocator.free(eth_frame); // Caller must free!
    /// // ... use eth_frame ...
    /// ```
    ///
    /// Returns: Allocated Ethernet frame (14-byte header + IP packet)
    /// Errors: InvalidPacket if the IP packet is malformed
    pub fn ipToEthernet(self: *Self, ip_packet: []const u8) ![]const u8 {
        if (ip_packet.len == 0) return error.InvalidPacket;

        // Determine EtherType and destination MAC
        var ethertype: u16 = undefined;
        var dest_mac: [6]u8 = undefined;

        if (ip_packet.len > 0 and (ip_packet[0] & 0xF0) == 0x40) {
            // IPv4 packet
            ethertype = 0x0800;

            // Use learned gateway MAC if available, otherwise broadcast
            if (self.gateway_mac) |gw_mac| {
                dest_mac = gw_mac;
            } else {
                @memset(&dest_mac, 0xFF); // Broadcast
            }
        } else if (ip_packet.len > 0 and (ip_packet[0] & 0xF0) == 0x60) {
            // IPv6 packet
            ethertype = 0x86DD;
            @memset(&dest_mac, 0xFF); // Broadcast for IPv6
        } else {
            return error.InvalidPacket;
        }

        // Build Ethernet frame: [6 dest MAC][6 src MAC][2 EtherType][payload]
        const frame_size = 14 + ip_packet.len;
        const frame = try self.allocator.alloc(u8, frame_size);
        errdefer self.allocator.free(frame);

        @memcpy(frame[0..6], &dest_mac); // Destination MAC
        @memcpy(frame[6..12], &self.options.our_mac); // Source MAC
        std.mem.writeInt(u16, frame[12..14], ethertype, .big); // EtherType
        @memcpy(frame[14..], ip_packet); // IP packet

        self.packets_translated_l3_to_l2 += 1;

        // Verbose log removed - too noisy during normal operation
        // Each packet would generate a log line (hundreds per second)

        return frame;
    }

    /// Convert Ethernet frame (L2) to IP packet (L3)
    /// Used when receiving Ethernet frames from network/VPN to write to TUN device
    ///
    /// **Memory Management:**
    /// - Returns `null` if the frame was handled internally (e.g., ARP reply)
    /// - Returns an **allocated** IP packet slice if conversion succeeded
    /// - The caller is responsible for freeing the returned slice using the same allocator
    ///
    /// Example:
    /// ```zig
    /// if (try translator.ethernetToIp(eth_frame)) |ip_packet| {
    ///     defer translator.allocator.free(ip_packet); // Caller must free!
    ///     // ... use ip_packet ...
    /// } else {
    ///     // Frame was handled internally (e.g., ARP)
    /// }
    /// ```
    ///
    /// Returns: Optional allocated IP packet slice (null if handled internally)
    /// Errors: InvalidPacket if the Ethernet frame is malformed
    pub fn ethernetToIp(self: *Self, eth_frame: []const u8) !?[]const u8 {
        if (eth_frame.len < 14) return error.InvalidPacket;

        const ethertype = std.mem.readInt(u16, eth_frame[12..14], .big);

        // Handle ARP packets
        if (ethertype == 0x0806 and self.options.handle_arp) {
            return try self.handleArpFrame(eth_frame);
        }

        // Extract IP packet (strip 14-byte Ethernet header)
        var ip_packet: []const u8 = undefined;

        if (ethertype == 0x0800 or ethertype == 0x86DD) {
            // IPv4 or IPv6 - strip Ethernet header
            ip_packet = eth_frame[14..];

            // 🔥 FIX: Learn gateway MAC from ANY packet from gateway IP (not just ARP replies!)
            // Many VPN servers don't respond to ARP requests, but we can learn MAC from DHCP/ICMP/etc.
            if (ethertype == 0x0800 and ip_packet.len >= 20 and self.options.learn_gateway_mac) {
                const src_ip = std.mem.readInt(u32, ip_packet[12..16], .big);

                // If this packet is from our gateway, learn its MAC address
                if (self.gateway_ip) |gw_ip| {
                    if (src_ip == gw_ip) {
                        var new_mac: [6]u8 = undefined;
                        @memcpy(&new_mac, eth_frame[6..12]); // Source MAC from Ethernet header

                        const changed = if (self.gateway_mac) |old_mac|
                            !std.mem.eql(u8, &old_mac, &new_mac)
                        else
                            true;

                        if (changed) {
                            self.gateway_mac = new_mac;
                            self.last_gateway_learn = std.time.milliTimestamp();
                            std.debug.print("[🎯 GATEWAY MAC LEARNED] {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2} from IP packet (src=", .{
                                new_mac[0], new_mac[1], new_mac[2], new_mac[3], new_mac[4], new_mac[5],
                            });
                            std.debug.print("{}.{}.{}.{})\n", .{
                                (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,
                                (src_ip >> 8) & 0xFF,  src_ip & 0xFF,
                            });
                        }
                    }
                }
            }
        } else {
            // Unknown EtherType - ignore
            return null;
        }

        // Allocate copy of IP packet
        const result = try self.allocator.alloc(u8, ip_packet.len);
        @memcpy(result, ip_packet);

        self.packets_translated_l2_to_l3 += 1;

        return result;
    }

    /// Handle incoming ARP frame
    fn handleArpFrame(self: *Self, eth_frame: []const u8) !?[]const u8 {
        if (eth_frame.len < 42) return error.InvalidPacket; // Min ARP packet size

        const arp_data = eth_frame[14..]; // Skip Ethernet header
        const opcode = std.mem.readInt(u16, arp_data[6..8], .big);

        // Learn gateway MAC from ARP replies (opcode=2)
        if (opcode == 2 and self.options.learn_gateway_mac) {
            const sender_ip = std.mem.readInt(u32, arp_data[14..18], .big);

            // Check if this is from our gateway (typically x.x.x.1)
            if (self.gateway_ip) |gw_ip| {
                if (sender_ip == gw_ip) {
                    var new_mac: [6]u8 = undefined;
                    @memcpy(&new_mac, arp_data[8..14]);

                    const changed = if (self.gateway_mac) |old_mac|
                        !std.mem.eql(u8, &old_mac, &new_mac)
                    else
                        true;

                    if (changed) {
                        self.gateway_mac = new_mac;
                        self.last_gateway_learn = std.time.milliTimestamp();
                        self.arp_replies_learned += 1;
                    }
                }
            }
        }

        // Handle ARP requests targeting our IP (opcode=1)
        if (opcode == 1 and self.our_ip != null) {
            const target_ip = std.mem.readInt(u32, arp_data[24..28], .big);

            if (target_ip == self.our_ip.?) {
                const sender_mac = arp_data[8..14];
                const sender_ip_bytes = arp_data[14..18];

                const reply = try self.arp_handler.buildArpReply(
                    self.our_ip.?,
                    sender_mac[0..6].*,
                    std.mem.readInt(u32, sender_ip_bytes, .big),
                );

                self.arp_requests_handled += 1;

                // Check if we already have a pending reply for this IP
                const already_pending = self.pending_arp_ips.contains(target_ip);

                // Limit queue size to prevent memory overflow
                const max_queue_size = 10;
                if (!already_pending and self.arp_reply_queue.items.len < max_queue_size) {
                    // Queue the ARP reply and mark IP as pending
                    try self.arp_reply_queue.append(self.allocator, reply);
                    try self.pending_arp_ips.put(target_ip, {});
                } else {
                    // Already pending or queue full - free the duplicate reply
                    self.allocator.free(reply);
                }
                return null;
            }
        }

        // ARP packet not for us or already handled
        return null;
    }

    /// Manually set our IP address (alternative to learning)
    pub fn setOurIp(self: *Self, ip: u32) void {
        self.our_ip = ip;
    }

    /// Manually set gateway IP and MAC
    pub fn setGateway(self: *Self, gateway_ip: u32) void {
        if (self.gateway_ip == null or self.gateway_ip.? != gateway_ip) {
            self.gateway_ip = gateway_ip;
        }
    }

    /// Get learned IP address
    pub fn getLearnedIp(self: *const Self) ?u32 {
        return self.our_ip;
    }

    /// Get learned gateway MAC
    pub fn getGatewayMac(self: *const Self) ?[6]u8 {
        return self.gateway_mac;
    }

    /// Check if there are pending ARP replies to send
    pub fn hasPendingArpReply(self: *const Self) bool {
        return self.arp_reply_queue.items.len > 0;
    }

    /// Get the next pending ARP reply (caller takes ownership and must free)
    pub fn popArpReply(self: *Self) ?[]const u8 {
        if (self.arp_reply_queue.items.len == 0) {
            return null;
        }
        const reply = self.arp_reply_queue.orderedRemove(0);

        // Extract target IP from ARP reply to remove from pending set
        // ARP reply format: dest_mac(6) + src_mac(6) + type(2) + arp_data(28+)
        // Target IP is at offset 24 (in ARP data section)
        if (reply.len >= 38) {
            const target_ip_bytes = reply[24..28];
            const target_ip = std.mem.readInt(u32, target_ip_bytes[0..4], .big);
            _ = self.pending_arp_ips.remove(target_ip);
        }

        return reply;
    }

    /// Get translation statistics
    pub fn getStats(self: *const Self) struct {
        l2_to_l3: u64,
        l3_to_l2: u64,
        arp_handled: u64,
        arp_learned: u64,
    } {
        return .{
            .l2_to_l3 = self.packets_translated_l2_to_l3,
            .l3_to_l2 = self.packets_translated_l3_to_l2,
            .arp_handled = self.arp_requests_handled,
            .arp_learned = self.arp_replies_learned,
        };
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DHCP Client Integration (WAVE 5 PHASE 1)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Start DHCP discovery process
    /// Initializes DHCP client and generates DHCP DISCOVER packet
    /// Call this once after adapter initialization to begin IP negotiation
    pub fn startDhcp(self: *Self) !void {
        if (self.dhcp_started) {
            return; // Already started
        }

        // Create DHCP client
        self.dhcp_client = try DhcpClient.init(self.allocator, self.options.our_mac);
        self.dhcp_started = true;

        // Generate DHCP DISCOVER packet
        const discover_packet = try self.dhcp_client.?.createDiscover();

        // Wrap DHCP packet in UDP/IP/Ethernet frame
        const dhcp_frame = try self.wrapDhcpInEthernet(&discover_packet);
        try self.dhcp_packet_queue.append(self.allocator, dhcp_frame);

        std.debug.print("[DHCP] 📡 DISCOVER packet generated (xid=0x{X:0>8})\n", .{discover_packet.xid});
    }

    /// Check if there are pending DHCP packets to send
    pub fn hasPendingDhcpPacket(self: *const Self) bool {
        return self.dhcp_packet_queue.items.len > 0;
    }

    /// Get next DHCP packet to send (caller takes ownership and must free)
    pub fn popDhcpPacket(self: *Self) ?[]const u8 {
        if (self.dhcp_packet_queue.items.len == 0) {
            return null;
        }
        return self.dhcp_packet_queue.orderedRemove(0);
    }

    /// Process incoming DHCP packet (OFFER, ACK, NAK)
    pub fn processDhcpPacket(self: *Self, ethernet_frame: []const u8) !void {
        if (self.dhcp_client == null) return;

        // Parse Ethernet frame to extract DHCP packet
        // Ethernet(14) + IP(20) + UDP(8) + DHCP
        if (ethernet_frame.len < 14 + 20 + 8 + @sizeOf(DhcpPacket)) {
            return error.PacketTooSmall;
        }

        // Skip Ethernet(14) + IP(20) + UDP(8) headers
        const dhcp_offset = 14 + 20 + 8;
        const dhcp_data = ethernet_frame[dhcp_offset..];

        // Cast to DHCP packet (note: may need proper deserialization)
        if (dhcp_data.len < @sizeOf(DhcpPacket)) {
            return error.InvalidDhcpPacket;
        }

        const dhcp_packet = @as(*const DhcpPacket, @ptrCast(@alignCast(dhcp_data.ptr))).*;

        // Check if this is for us
        const client = self.dhcp_client.?;
        if (dhcp_packet.xid != client.transaction_id) {
            return; // Not our transaction
        }

        // Parse DHCP message type from options
        const msg_type = try self.parseDhcpMessageType(&dhcp_packet);

        switch (msg_type) {
            2 => { // OFFER
                try client.parseOffer(&dhcp_packet);

                // Extract offered IP and server ID
                self.offered_ip = std.mem.toBytes(dhcp_packet.yiaddr);
                self.offered_server_id = try self.extractServerId(&dhcp_packet);

                // Generate DHCP REQUEST
                const request_packet = try client.createRequest(self.offered_ip.?, self.offered_server_id.?);
                const request_frame = try self.wrapDhcpInEthernet(&request_packet);
                try self.dhcp_packet_queue.append(self.allocator, request_frame);

                std.debug.print("[DHCP] 📬 OFFER received, sending REQUEST\n", .{});
            },
            5 => { // ACK
                try client.parseAck(&dhcp_packet);

                // Learn our IP
                const ip_bytes = std.mem.toBytes(dhcp_packet.yiaddr);
                self.our_ip = std.mem.readInt(u32, &ip_bytes, .big);

                std.debug.print("[DHCP] ✅ ACK received! IP assigned: {}.{}.{}.{}\n", .{
                    ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                });
            },
            6 => { // NAK
                std.debug.print("[DHCP] ❌ NAK received, restarting...\n", .{});
                // Restart DHCP
                self.dhcp_started = false;
                if (self.dhcp_client) |c| {
                    if (c.lease) |*lease| {
                        lease.deinit(self.allocator);
                    }
                    self.allocator.destroy(c);
                    self.dhcp_client = null;
                }
                try self.startDhcp();
            },
            else => {
                // Unknown message type, ignore
            },
        }
    }

    // Helper: Wrap DHCP packet in UDP/IP/Ethernet frame
    fn wrapDhcpInEthernet(self: *Self, dhcp_packet: *const DhcpPacket) ![]const u8 {
        const dhcp_size = @sizeOf(DhcpPacket);
        const udp_size = 8 + dhcp_size;
        const ip_size = 20 + udp_size;
        const frame_size = 14 + ip_size;

        var frame = try self.allocator.alloc(u8, frame_size);
        @memset(frame, 0);

        // Ethernet header (14 bytes)
        @memset(frame[0..6], 0xFF); // Broadcast dest MAC
        @memcpy(frame[6..12], &self.options.our_mac); // Our source MAC
        frame[12] = 0x08; // EtherType = IPv4
        frame[13] = 0x00;

        // IP header (20 bytes)
        const ip_offset: usize = 14;
        frame[ip_offset + 0] = 0x45; // Version 4, IHL 5
        frame[ip_offset + 1] = 0x00; // DSCP/ECN
        std.mem.writeInt(u16, frame[ip_offset + 2 .. ip_offset + 4], @intCast(ip_size), .big); // Total length
        std.mem.writeInt(u16, frame[ip_offset + 4 .. ip_offset + 6], 0x1234, .big); // ID
        std.mem.writeInt(u16, frame[ip_offset + 6 .. ip_offset + 8], 0x0000, .big); // Flags/offset
        frame[ip_offset + 8] = 64; // TTL
        frame[ip_offset + 9] = 17; // Protocol = UDP
        // Checksum at offset 10-11 (will calculate later)
        std.mem.writeInt(u32, frame[ip_offset + 12 .. ip_offset + 16], 0x00000000, .big); // Source IP = 0.0.0.0
        std.mem.writeInt(u32, frame[ip_offset + 16 .. ip_offset + 20], 0xFFFFFFFF, .big); // Dest IP = broadcast

        // Calculate IP checksum
        const ip_checksum = self.calculateChecksum(frame[ip_offset .. ip_offset + 20]);
        std.mem.writeInt(u16, frame[ip_offset + 10 .. ip_offset + 12], ip_checksum, .big);

        // UDP header (8 bytes)
        const udp_offset: usize = ip_offset + 20;
        std.mem.writeInt(u16, frame[udp_offset + 0 .. udp_offset + 2], 68, .big); // Source port (DHCP client)
        std.mem.writeInt(u16, frame[udp_offset + 2 .. udp_offset + 4], 67, .big); // Dest port (DHCP server)
        std.mem.writeInt(u16, frame[udp_offset + 4 .. udp_offset + 6], @intCast(udp_size), .big); // Length
        std.mem.writeInt(u16, frame[udp_offset + 6 .. udp_offset + 8], 0x0000, .big); // Checksum (optional for UDP)

        // DHCP packet
        const dhcp_offset = udp_offset + 8;
        const dhcp_bytes = std.mem.asBytes(dhcp_packet);
        @memcpy(frame[dhcp_offset .. dhcp_offset + dhcp_size], dhcp_bytes);

        return frame;
    }

    // Helper: Parse DHCP message type from options
    fn parseDhcpMessageType(self: *Self, packet: *const DhcpPacket) !u8 {
        _ = self;
        var offset: usize = 0;
        while (offset < packet.options.len) {
            const option_type = packet.options[offset];
            if (option_type == 255) break; // END option
            if (option_type == 0) { // PAD option
                offset += 1;
                continue;
            }

            const option_len = packet.options[offset + 1];
            if (option_type == 53) { // MESSAGE_TYPE
                return packet.options[offset + 2];
            }
            offset += 2 + option_len;
        }
        return error.MessageTypeNotFound;
    }

    // Helper: Extract server ID from DHCP options
    fn extractServerId(self: *Self, packet: *const DhcpPacket) ![4]u8 {
        _ = self;
        var offset: usize = 0;
        while (offset < packet.options.len) {
            const option_type = packet.options[offset];
            if (option_type == 255) break;
            if (option_type == 0) {
                offset += 1;
                continue;
            }

            const option_len = packet.options[offset + 1];
            if (option_type == 54 and option_len == 4) { // SERVER_ID
                var server_id: [4]u8 = undefined;
                @memcpy(&server_id, packet.options[offset + 2 .. offset + 6]);
                return server_id;
            }
            offset += 2 + option_len;
        }
        return error.ServerIdNotFound;
    }

    // Helper: Calculate IP checksum
    fn calculateChecksum(self: *Self, data: []const u8) u16 {
        _ = self;
        var sum: u32 = 0;
        var i: usize = 0;
        while (i < data.len - 1) : (i += 2) {
            const word = (@as(u32, data[i]) << 8) | @as(u32, data[i + 1]);
            sum += word;
        }
        if (i < data.len) {
            sum += @as(u32, data[i]) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return @intCast(~sum & 0xFFFF);
    }
};

test "L2L3Translator basic init" {
    const allocator = std.testing.allocator;

    var translator = try L2L3Translator.init(allocator, .{
        .our_mac = [_]u8{ 0x02, 0x00, 0x5E, 0x00, 0x00, 0x01 },
    });
    defer translator.deinit();

    try std.testing.expect(translator.our_ip == null);
    try std.testing.expect(translator.gateway_mac == null);
}
