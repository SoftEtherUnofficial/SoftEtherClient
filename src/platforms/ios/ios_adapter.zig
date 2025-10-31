//! iOS Packet Adapter - Thread-safe queues for NEPacketTunnelProvider integration
//!
//! Architecture (iOS-specific, no TUN device):
//!   Swift PacketTunnelProvider → inject_packet() → incoming_queue
//!   incoming_queue → adapter.getNextPacket() → SoftEther
//!   SoftEther → adapter.putPacket() → outgoing_queue
//!   outgoing_queue → get_outgoing_packet() → Swift PacketTunnelProvider
//!
//! This module is ONLY compiled for iOS targets (comptime check in adapter.zig)

const std = @import("std");
const VirtualTap = @import("virtual_tap").VirtualTap;
const protocol = @import("protocol");
const log = @import("logging");

// iOS NSLog bridge (appears in Console.app) - kept for backward compatibility
extern fn ios_log_message([*:0]const u8) void;

// Legacy iOS logging macro - deprecated, use log.* instead
fn IOS_LOG(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    ios_log_message(msg.ptr);
}

/// Maximum packet size (Ethernet frame)
const MAX_PACKET_SIZE = 2048;

/// Maximum queue capacity
const MAX_QUEUE_SIZE = 512;

// Global iOS adapter pointer - set during initialization, used by C code to access incoming queue
// Must use 'export' to make it visible to C linker
export var global_ios_adapter: ?*IosAdapter = null;

/// Packet with owned buffer
pub const QueuedPacket = struct {
    data: [MAX_PACKET_SIZE]u8,
    length: u32,
    timestamp: i64,
};

/// Thread-safe circular packet queue
pub const PacketQueue = struct {
    packets: []QueuedPacket,
    read_idx: std.atomic.Value(usize),
    write_idx: std.atomic.Value(usize),
    count: std.atomic.Value(usize),
    capacity: usize,
    mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !PacketQueue {
        const packets = try allocator.alloc(QueuedPacket, capacity);

        return PacketQueue{
            .packets = packets,
            .read_idx = std.atomic.Value(usize).init(0),
            .write_idx = std.atomic.Value(usize).init(0),
            .count = std.atomic.Value(usize).init(0),
            .capacity = capacity,
            .mutex = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PacketQueue) void {
        self.allocator.free(self.packets);
    }

    /// Enqueue packet (non-blocking for Swift threads)
    /// Returns true on success, false if queue full
    pub fn enqueue(self: *PacketQueue, data: []const u8) bool {
        if (data.len == 0 or data.len > MAX_PACKET_SIZE) {
            return false;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        const current_count = self.count.load(.acquire);
        if (current_count >= self.capacity) {
            return false; // Queue full
        }

        const write_pos = self.write_idx.load(.acquire);
        var packet = &self.packets[write_pos];

        @memcpy(packet.data[0..data.len], data);
        packet.length = @intCast(data.len);
        packet.timestamp = @truncate(std.time.nanoTimestamp());

        const next_write = (write_pos + 1) % self.capacity;
        self.write_idx.store(next_write, .release);
        _ = self.count.fetchAdd(1, .release);

        return true;
    }

    /// Dequeue packet (with timeout for SoftEther polling)
    /// Returns packet or null if empty/timeout
    pub fn dequeue(self: *PacketQueue, _: i32) ?QueuedPacket {
        self.mutex.lock();
        defer self.mutex.unlock();

        const current_count = self.count.load(.acquire);
        if (current_count == 0) {
            // Queue empty - this is normal for polling
            return null;
        }

        const read_pos = self.read_idx.load(.acquire);
        const write_pos = self.write_idx.load(.acquire);

        // CRITICAL DEBUG: Check for queue corruption
        if (read_pos >= self.capacity or write_pos >= self.capacity) {
            std.log.err("⚠️  QUEUE CORRUPTION: read={d} write={d} capacity={d}", .{ read_pos, write_pos, self.capacity });
            return null;
        }

        const packet = self.packets[read_pos];

        const next_read = (read_pos + 1) % self.capacity;
        self.read_idx.store(next_read, .release);
        _ = self.count.fetchSub(1, .release);

        return packet;
    }

    pub fn available(self: *PacketQueue) usize {
        return self.count.load(.acquire);
    }
};

/// DHCP state for iOS adapter
pub const DhcpState = struct {
    client_ip: u32 = 0, // Network byte order
    subnet_mask: u32 = 0, // Network byte order
    gateway: u32 = 0, // Network byte order
    dns_server1: u32 = 0, // Network byte order
    dns_server2: u32 = 0, // Network byte order
    dhcp_server: u32 = 0, // Network byte order
    valid: bool = false,
    xid: u32 = 0, // Transaction ID
    client_mac: [6]u8 = [_]u8{0} ** 6,
};

/// iOS Adapter context
pub const IosAdapter = struct {
    allocator: std.mem.Allocator,

    // Thread-safe packet queues
    incoming_queue: PacketQueue, // iOS → SoftEther
    outgoing_queue: PacketQueue, // SoftEther → iOS

    // VirtualTap for Layer 2 virtualization (handles ARP internally)
    vtap: *VirtualTap,

    // DHCP state
    dhcp_state: DhcpState,
    dhcp_mutex: std.Thread.Mutex,
    need_gateway_arp: bool, // Flag to send ARP request after DHCP completes

    // Statistics
    packets_received: std.atomic.Value(u64),
    packets_sent: std.atomic.Value(u64),
    bytes_received: std.atomic.Value(u64),
    bytes_sent: std.atomic.Value(u64),
    queue_drops_in: std.atomic.Value(u64),
    queue_drops_out: std.atomic.Value(u64),
    l2_to_l3_translated: std.atomic.Value(u64),
    l3_to_l2_translated: std.atomic.Value(u64),
    arp_packets_handled: std.atomic.Value(u64),
    arp_replies_sent: std.atomic.Value(u64),

    // Debug: Last error code (for C bridge debugging)
    // -100: dequeue failed, -200: translation error, -300: buffer too small, -400: ARP packet, 0: success
    last_error_code: std.atomic.Value(i32),

    pub fn init(allocator: std.mem.Allocator) !*IosAdapter {
        const self = try allocator.create(IosAdapter);
        errdefer allocator.destroy(self);

        // Generate MAC address (iOS LAA format: 02:00:5E:xx:xx:xx)
        var our_mac: [6]u8 = undefined;
        our_mac[0] = 0x02; // Locally administered
        our_mac[1] = 0x00;
        our_mac[2] = 0x5E; // SoftEther prefix

        // Use truncated timestamp for randomness
        const seed: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())));
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();
        our_mac[3] = random.int(u8);
        our_mac[4] = random.int(u8);
        our_mac[5] = random.int(u8);

        // Create VirtualTap for Layer 2 virtualization (handles ARP internally)
        const vtap = try VirtualTap.init(allocator, .{
            .our_mac = our_mac,
            .our_ip = null, // Will be set after DHCP
            .gateway_ip = null, // Will be set after DHCP
            .gateway_mac = null, // Will learn from traffic
            .handle_arp = true, // Handle ARP internally
            .learn_ip = true, // Auto-learn from packets
            .learn_gateway_mac = true, // Learn from traffic
            .verbose = true,
        });

        self.* = .{
            .allocator = allocator,
            .incoming_queue = try PacketQueue.init(allocator, MAX_QUEUE_SIZE),
            .outgoing_queue = try PacketQueue.init(allocator, MAX_QUEUE_SIZE),
            .vtap = vtap,
            .dhcp_state = .{},
            .dhcp_mutex = .{},
            .need_gateway_arp = false,
            .packets_received = std.atomic.Value(u64).init(0),
            .packets_sent = std.atomic.Value(u64).init(0),
            .bytes_received = std.atomic.Value(u64).init(0),
            .bytes_sent = std.atomic.Value(u64).init(0),
            .queue_drops_in = std.atomic.Value(u64).init(0),
            .queue_drops_out = std.atomic.Value(u64).init(0),
            .l2_to_l3_translated = std.atomic.Value(u64).init(0),
            .l3_to_l2_translated = std.atomic.Value(u64).init(0),
            .arp_packets_handled = std.atomic.Value(u64).init(0),
            .arp_replies_sent = std.atomic.Value(u64).init(0),
            .last_error_code = std.atomic.Value(i32).init(0),
        };

        // Set global pointer for C code access (used by zig_packet_adapter.c)
        global_ios_adapter = self;

        return self;
    }

    pub fn deinit(self: *IosAdapter) void {
        // Clear global pointer
        if (global_ios_adapter == self) {
            global_ios_adapter = null;
        }
        self.incoming_queue.deinit();
        self.outgoing_queue.deinit();
        self.vtap.deinit();
        self.allocator.destroy(self);
    }

    /// Inject packet from iOS (L3 IP packet from NEPacketTunnelFlow)
    /// Returns true on success, false if queue full
    pub fn injectPacket(self: *IosAdapter, ip_packet: []const u8) !bool {
        if (ip_packet.len == 0) return false;

        // Log IP packet details for debugging
        if (ip_packet.len >= 20) {
            const src_ip = ip_packet[12..16];
            const dst_ip = ip_packet[16..20];
            const ip_protocol = ip_packet[9];
            IOS_LOG("[iOS→Server] IP: {d}.{d}.{d}.{d} → {d}.{d}.{d}.{d} proto={d} len={d}", .{
                src_ip[0],   src_ip[1],     src_ip[2], src_ip[3],
                dst_ip[0],   dst_ip[1],     dst_ip[2], dst_ip[3],
                ip_protocol, ip_packet.len,
            });
        }

        // Translate L3 (IP) → L2 (Ethernet) using VirtualTap
        const eth_frame = try self.vtap.ipToEthernet(ip_packet);
        defer self.allocator.free(eth_frame); // CRITICAL: Free allocated Ethernet frame!

        if (eth_frame.len == 0) {
            return false; // Translation failed
        }

        // Enqueue Ethernet frame for SoftEther (queue copies the data)
        const success = self.incoming_queue.enqueue(eth_frame);

        if (success) {
            _ = self.packets_received.fetchAdd(1, .release);
            _ = self.bytes_received.fetchAdd(ip_packet.len, .release);
            _ = self.l3_to_l2_translated.fetchAdd(1, .release);
        } else {
            _ = self.queue_drops_in.fetchAdd(1, .release);
        }

        return success;
    }

    /// Get outgoing packet for iOS (L3 IP packet for NEPacketTunnelFlow)
    /// Returns packet length or null if no packet available
    pub fn getOutgoingPacket(self: *IosAdapter, buffer: []u8) ?usize {
        // DEBUG: Log queue state - READ FROM OUTGOING_QUEUE (server→iOS packets)
        const count = self.outgoing_queue.count.load(.acquire);
        if (count > 0) {
            IOS_LOG("[GET_PACKET] Queue has {} packets", .{count});
            std.log.info("🔍 Zig getOutgoingPacket: Queue has {d} packets", .{count});
        } else {
            // Also log when queue is empty (to see if function is being called)
            IOS_LOG("[GET_PACKET] Queue EMPTY (count=0)", .{});
        }

        // Dequeue Ethernet frame from OUTGOING queue (server→iOS packets)
        const eth_packet = self.outgoing_queue.dequeue(0) orelse {
            // DEBUG: Dequeue failed
            if (count > 0) {
                IOS_LOG("[GET_PACKET] ERROR: dequeue failed but count={}", .{count});
                std.log.err("⚠️  Zig getOutgoingPacket: dequeue returned null but count={d}!", .{count});
            }
            // ERROR_CODE: -100 means dequeue failed
            self.last_error_code.store(-100, .release);
            return null;
        };

        IOS_LOG("[GET_PACKET] Dequeued packet: length={}", .{eth_packet.length});
        std.log.info("✅ Dequeued Ethernet packet: length={d}", .{eth_packet.length});

        // Log Ethernet type (bytes 12-13 are EtherType)
        if (eth_packet.length >= 14) {
            const ethertype = (@as(u16, eth_packet.data[12]) << 8) | eth_packet.data[13];
            IOS_LOG("[GET_PACKET] EtherType: 0x{x:0>4} (0x0800=IPv4, 0x0806=ARP, 0x86dd=IPv6)", .{ethertype});
        }

        // Check if this is a DHCP packet - parse and store state
        self.parseDhcpIfNeeded(eth_packet.data[0..eth_packet.length]);

        // Translate L2 (Ethernet) → L3 (IP) using VirtualTap
        IOS_LOG("[L2->L3] Calling ethernetToIp for {d}-byte Ethernet frame", .{eth_packet.length});
        std.log.info("🔄 Calling ethernetToIp for translation...", .{});
        const maybe_ip = self.vtap.ethernetToIp(
            eth_packet.data[0..eth_packet.length],
        ) catch |err| {
            IOS_LOG("[L2->L3] ERROR: Translation failed: {}", .{err});
            std.log.err("⚠️  ethernetToIp failed with error: {}", .{err});
            // ERROR_CODE: -200 means translation error
            self.last_error_code.store(-200, .release);
            return null;
        };

        // Check if VirtualTap generated any ARP replies that need to be sent back to server
        while (self.vtap.hasPendingArpReply()) {
            if (self.vtap.popArpReply()) |arp_reply| {
                defer self.allocator.free(arp_reply); // Free after use
                // ARP replies go to incoming_queue (iOS → SoftEther → Server)
                IOS_LOG("[VirtualTap] 🔄 Got ARP reply from VirtualTap: {d} bytes", .{arp_reply.len});
                const queued = self.incoming_queue.enqueue(arp_reply);
                if (queued) {
                    IOS_LOG("[VirtualTap] ✅ ARP reply queued to INCOMING queue ({d} bytes) - will be sent to server", .{arp_reply.len});
                    _ = self.arp_replies_sent.fetchAdd(1, .release);
                } else {
                    IOS_LOG("[VirtualTap] ❌ CRITICAL: Failed to queue ARP reply (incoming queue full!)", .{});
                }
            }
        }

        if (maybe_ip) |ip_packet| {
            IOS_LOG("[L2->L3] ✅ Success: {d} bytes Ethernet -> {d} bytes IP", .{ eth_packet.length, ip_packet.len });
            std.log.info("✅ Translation successful: IP packet length={d}", .{ip_packet.len});

            // Log IP packet details for debugging
            if (ip_packet.len >= 20) {
                const src_ip = ip_packet[12..16];
                const dst_ip = ip_packet[16..20];
                const ip_protocol = ip_packet[9];
                IOS_LOG("[Server→iOS] IP: {d}.{d}.{d}.{d} → {d}.{d}.{d}.{d} proto={d} len={d}", .{
                    src_ip[0],   src_ip[1],     src_ip[2], src_ip[3],
                    dst_ip[0],   dst_ip[1],     dst_ip[2], dst_ip[3],
                    ip_protocol, ip_packet.len,
                });
            }

            // Got an IP packet - copy to output buffer
            defer self.allocator.free(ip_packet); // CRITICAL: Free translated packet!

            if (ip_packet.len > buffer.len) {
                // ERROR_CODE: -300 means buffer too small
                self.last_error_code.store(-300, .release);
                return null;
            }
            @memcpy(buffer[0..ip_packet.len], ip_packet);

            _ = self.packets_sent.fetchAdd(1, .release);
            _ = self.bytes_sent.fetchAdd(ip_packet.len, .release);
            _ = self.l2_to_l3_translated.fetchAdd(1, .release);

            // Success!
            self.last_error_code.store(0, .release);
            return ip_packet.len;
        } else {
            // ARP packet handled internally by VirtualTap
            IOS_LOG("[L2->L3] NULL returned - ARP or other L2 packet handled internally by VirtualTap", .{});
            std.log.info("ℹ️  ethernetToIp returned null (ARP packet - handled internally)", .{});
            _ = self.arp_packets_handled.fetchAdd(1, .release);
            // ERROR_CODE: -400 means ARP packet (not an error, just informational)
            self.last_error_code.store(-400, .release);
            return null; // No packet for iOS
        }
    }

    /// Parse DHCP packet and update state if it's an OFFER or ACK
    fn parseDhcpIfNeeded(self: *IosAdapter, eth_frame: []const u8) void {
        // Quick check: Ethernet + IP + UDP + DHCP minimum
        if (eth_frame.len < 282) return;

        // Check EtherType = IPv4 (0x0800)
        if (eth_frame[12] != 0x08 or eth_frame[13] != 0x00) return;

        // Check IP protocol = UDP (17)
        if (eth_frame[23] != 17) return;

        // Check UDP dest port = 68 (BOOTP client)
        const dest_port = (@as(u16, eth_frame[36]) << 8) | eth_frame[37];
        if (dest_port != 68) return;

        // This is a DHCP packet - parse it
        self.dhcp_mutex.lock();
        defer self.dhcp_mutex.unlock();

        // Skip to DHCP payload (14 Ethernet + 20 IP + 8 UDP = 42)
        const dhcp = eth_frame[42..];
        if (dhcp.len < 240) return;

        // Extract yiaddr (offered IP)
        const your_ip = (@as(u32, dhcp[16]) << 24) | (@as(u32, dhcp[17]) << 16) |
            (@as(u32, dhcp[18]) << 8) | dhcp[19];

        // Extract siaddr (server IP)
        const server_ip = (@as(u32, dhcp[20]) << 24) | (@as(u32, dhcp[21]) << 16) |
            (@as(u32, dhcp[22]) << 8) | dhcp[23];

        // Parse options for message type, subnet mask, gateway, DNS
        if (dhcp.len < 240) return;

        // Check magic cookie
        if (dhcp[236] != 0x63 or dhcp[237] != 0x82 or
            dhcp[238] != 0x53 or dhcp[239] != 0x63) return;

        var offset: usize = 240;
        var msg_type: u8 = 0;
        var subnet_mask: u32 = 0;
        var gateway: u32 = 0;
        var dns1: u32 = 0;
        var dns2: u32 = 0;

        while (offset < dhcp.len) {
            const option = dhcp[offset];
            offset += 1;

            if (option == 0xFF) break; // End
            if (option == 0x00) continue; // Pad

            if (offset >= dhcp.len) break;
            const opt_len = dhcp[offset];
            offset += 1;

            if (offset + opt_len > dhcp.len) break;

            switch (option) {
                53 => if (opt_len >= 1) {
                    msg_type = dhcp[offset];
                },
                1 => if (opt_len >= 4) {
                    subnet_mask = (@as(u32, dhcp[offset]) << 24) |
                        (@as(u32, dhcp[offset + 1]) << 16) |
                        (@as(u32, dhcp[offset + 2]) << 8) |
                        dhcp[offset + 3];
                },
                3 => if (opt_len >= 4) {
                    gateway = (@as(u32, dhcp[offset]) << 24) |
                        (@as(u32, dhcp[offset + 1]) << 16) |
                        (@as(u32, dhcp[offset + 2]) << 8) |
                        dhcp[offset + 3];
                },
                6 => {
                    if (opt_len >= 4) {
                        dns1 = (@as(u32, dhcp[offset]) << 24) |
                            (@as(u32, dhcp[offset + 1]) << 16) |
                            (@as(u32, dhcp[offset + 2]) << 8) |
                            dhcp[offset + 3];
                    }
                    if (opt_len >= 8) {
                        dns2 = (@as(u32, dhcp[offset + 4]) << 24) |
                            (@as(u32, dhcp[offset + 5]) << 16) |
                            (@as(u32, dhcp[offset + 6]) << 8) |
                            dhcp[offset + 7];
                    }
                },
                else => {},
            }

            offset += opt_len;
        }

        // Only process OFFER (2) or ACK (5)
        if (msg_type == 2 or msg_type == 5) {
            self.dhcp_state.client_ip = your_ip;
            self.dhcp_state.subnet_mask = if (subnet_mask != 0) subnet_mask else 0xFFFF0000;
            self.dhcp_state.gateway = if (gateway != 0) gateway else (your_ip & 0xFF000000) | 0x00000001;
            self.dhcp_state.dns_server1 = if (dns1 != 0) dns1 else 0x08080808;
            self.dhcp_state.dns_server2 = if (dns2 != 0) dns2 else 0x08080404;
            self.dhcp_state.dhcp_server = server_ip;
            self.dhcp_state.valid = true;

            // Configure translator with our IP and gateway
            self.vtap.setOurIp(your_ip);
            self.vtap.setGatewayIp(self.dhcp_state.gateway);
        }
    }

    /// Send ARP Request to learn gateway MAC address
    /// This populates SoftEther server's MAC/IP table and enables bidirectional routing
    /// Called once after DHCP completes (similar to CLI behavior)
    fn sendGatewayArpRequest(self: *IosAdapter) !void {
        // Use IOS_LOG for visibility (stderr is captured by Console.app)
        IOS_LOG("[IOS_ADAPTER] sendGatewayArpRequest CALLED!", .{});

        if (!self.dhcp_state.valid) {
            IOS_LOG("[IOS_ADAPTER] ERROR: DHCP not valid", .{});
            log.warn(.IOS, "sendGatewayArpRequest: DHCP not valid, cannot send ARP", .{});
            return;
        }

        const our_ip = self.dhcp_state.client_ip;
        const gateway_ip = self.dhcp_state.gateway;
        const our_mac = self.vtap.config.our_mac;

        IOS_LOG("[IOS_ADAPTER] Building ARP: src_ip={}.{}.{}.{} target_ip={}.{}.{}.{}", .{ (our_ip >> 24) & 0xFF, (our_ip >> 16) & 0xFF, (our_ip >> 8) & 0xFF, our_ip & 0xFF, (gateway_ip >> 24) & 0xFF, (gateway_ip >> 16) & 0xFF, (gateway_ip >> 8) & 0xFF, gateway_ip & 0xFF });

        // Build ARP request using protocol.buildArpRequest
        var arp_buffer: [64]u8 = undefined;
        const arp_size = try protocol.buildArpRequest(our_mac, our_ip, gateway_ip, &arp_buffer);

        IOS_LOG("[IOS_ADAPTER] Built ARP request: {} bytes", .{arp_size});

        // Queue to incoming_queue for sending to server
        const queued = self.incoming_queue.enqueue(arp_buffer[0..arp_size]);
        if (!queued) {
            IOS_LOG("[IOS_ADAPTER] ERROR: Failed to queue ARP (queue full)", .{});
            return error.QueueFull;
        }

        IOS_LOG("[IOS_ADAPTER] ARP Request queued to incoming_queue SUCCESS!", .{});
    }

    /// Set DHCP configuration manually (called from C adapter after DHCP processing)
    /// This allows the C adapter to share its DHCP state with the iOS adapter
    pub fn setDhcpInfo(
        self: *IosAdapter,
        client_ip: u32,
        subnet_mask: u32,
        gateway: u32,
        dns_server1: u32,
        dns_server2: u32,
        dhcp_server: u32,
    ) void {
        log.info(.IOS, "🔧 setDhcpInfo: IP={}.{}.{}.{} GW={}.{}.{}.{} valid=true", .{
            (client_ip >> 24) & 0xFF,
            (client_ip >> 16) & 0xFF,
            (client_ip >> 8) & 0xFF,
            client_ip & 0xFF,
            (gateway >> 24) & 0xFF,
            (gateway >> 16) & 0xFF,
            (gateway >> 8) & 0xFF,
            gateway & 0xFF,
        });

        self.dhcp_mutex.lock();
        defer self.dhcp_mutex.unlock();

        self.dhcp_state.client_ip = client_ip;
        self.dhcp_state.subnet_mask = subnet_mask;
        self.dhcp_state.gateway = gateway;
        self.dhcp_state.dns_server1 = dns_server1;
        self.dhcp_state.dns_server2 = dns_server2;
        self.dhcp_state.dhcp_server = dhcp_server;
        self.dhcp_state.valid = true;

        IOS_LOG("[IOS_ADAPTER] setDhcpInfo: need_gateway_arp={}", .{self.need_gateway_arp});
        log.info(.IOS, "[setDhcpInfo] ✅ DHCP state updated successfully", .{});

        // Configure VirtualTap with DHCP-assigned addresses
        self.vtap.setOurIp(client_ip);
        self.vtap.setGatewayIp(gateway);

        // Gateway MAC will be learned automatically from incoming traffic
        IOS_LOG("[IOS_ADAPTER] ✅ VirtualTap configured: IP={}.{}.{}.{} GW={}.{}.{}.{}", .{
            (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF,
            (client_ip >> 8) & 0xFF,  client_ip & 0xFF,
            (gateway >> 24) & 0xFF,   (gateway >> 16) & 0xFF,
            (gateway >> 8) & 0xFF,    gateway & 0xFF,
        });

        // iOS LIMITATION: PacketTunnelProvider is IP-only (Layer 3)
        // Cannot send/receive raw ARP packets (Layer 2)
        //
        // SOLUTION: VirtualTap handles ARP internally!
        // - Maintains virtual ARP table (IP ↔ MAC mappings)
        // - Uses broadcast MAC (ff:ff:ff:ff:ff:ff) when gateway MAC unknown
        // - Learns gateway MAC automatically from incoming Ethernet frames
        // - Responds to ARP requests locally without platform support
        //
        // This allows the server to see our MAC from the Ethernet frames we send,
        // and we learn the gateway MAC from incoming traffic.

        IOS_LOG("[IOS_ADAPTER] setDhcpInfo: VirtualTap will handle ARP internally (no manual ARP needed)", .{});

        // ARP is handled internally by TapTun - no manual ARP needed
        if (false and self.need_gateway_arp) {
            IOS_LOG("[IOS_ADAPTER] setDhcpInfo: Calling sendGatewayArpRequest...", .{});
            self.need_gateway_arp = false; // Mark as sent (don't send again)
            log.info("[setDhcpInfo] 🔍 Sending gateway ARP request...", .{});
            self.sendGatewayArpRequest() catch |err| {
                IOS_LOG("[IOS_ADAPTER] setDhcpInfo: sendGatewayArpRequest FAILED: {}", .{@intFromError(err)});
                log.err("[setDhcpInfo] ⚠️  Failed to send gateway ARP request: {}", .{err});
            };
            IOS_LOG("[IOS_ADAPTER] setDhcpInfo: sendGatewayArpRequest returned successfully", .{});
        } else {
            IOS_LOG("[IOS_ADAPTER] setDhcpInfo: SKIPPING ARP (need_gateway_arp=false)", .{});
        }
    }

    /// Get DHCP configuration (for Swift to apply network settings)
    pub fn getDhcpInfo(self: *IosAdapter) ?DhcpState {
        self.dhcp_mutex.lock();
        defer self.dhcp_mutex.unlock();

        log.info(.IOS, "getDhcpInfo: valid={}", .{self.dhcp_state.valid});
        if (!self.dhcp_state.valid) {
            log.warn(.IOS, "getDhcpInfo: DHCP state is NOT valid, returning null", .{});
            return null;
        }

        log.info(.IOS, "getDhcpInfo: Returning DHCP info IP={}.{}.{}.{} GW={}.{}.{}.{}", .{
            (self.dhcp_state.client_ip >> 24) & 0xFF,
            (self.dhcp_state.client_ip >> 16) & 0xFF,
            (self.dhcp_state.client_ip >> 8) & 0xFF,
            self.dhcp_state.client_ip & 0xFF,
            (self.dhcp_state.gateway >> 24) & 0xFF,
            (self.dhcp_state.gateway >> 16) & 0xFF,
            (self.dhcp_state.gateway >> 8) & 0xFF,
            self.dhcp_state.gateway & 0xFF,
        });

        return self.dhcp_state;
    }

    /// Get statistics
    pub fn getStats(self: *IosAdapter) Stats {
        return .{
            .packets_received = self.packets_received.load(.acquire),
            .packets_sent = self.packets_sent.load(.acquire),
            .bytes_received = self.bytes_received.load(.acquire),
            .bytes_sent = self.bytes_sent.load(.acquire),
            .queue_drops_in = self.queue_drops_in.load(.acquire),
            .queue_drops_out = self.queue_drops_out.load(.acquire),
            .l2_to_l3_translated = self.l2_to_l3_translated.load(.acquire),
            .l3_to_l2_translated = self.l3_to_l2_translated.load(.acquire),
            .arp_packets_handled = self.arp_packets_handled.load(.acquire),
        };
    }

    /// Get packet from incoming queue (iOS → Server) - used by C adapter's GetNextPacket
    /// Returns packet length, or 0 if queue is empty
    pub fn getPacketFromIncoming(self: *IosAdapter, buffer: []u8) usize {
        // Try to dequeue from incoming queue (non-blocking)
        const packet = self.incoming_queue.dequeue(0) orelse return 0;

        const pkt_len = packet.length;
        if (pkt_len > buffer.len) {
            IOS_LOG("[getPacketFromIncoming] ⚠️ Packet too large: {d} > {d}", .{ pkt_len, buffer.len });
            return 0;
        }

        @memcpy(buffer[0..pkt_len], packet.data[0..pkt_len]);
        return pkt_len;
    }
    pub const Stats = struct {
        packets_received: u64,
        packets_sent: u64,
        bytes_received: u64,
        bytes_sent: u64,
        queue_drops_in: u64,
        queue_drops_out: u64,
        l2_to_l3_translated: u64,
        l3_to_l2_translated: u64,
        arp_packets_handled: u64,
    };
};

// ============================================================================
// C FFI Exports - Called by zig_packet_adapter.c
// ============================================================================

/// C FFI: Get packet from incoming queue (iOS → Server)
/// Used by ZigAdapterGetNextPacket to retrieve ARP replies from VirtualTap
export fn ios_adapter_get_packet_from_incoming(adapter: *IosAdapter, buffer: [*]u8, buffer_len: usize) usize {
    const buf_slice = buffer[0..buffer_len];
    return adapter.getPacketFromIncoming(buf_slice);
}
