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
const taptun = @import("taptun");
const protocol = @import("protocol");

// C printf for debugging (Zig logs may not appear in iOS Console)
extern fn printf(format: [*:0]const u8, ...) c_int;

/// Maximum packet size (Ethernet frame)
const MAX_PACKET_SIZE = 2048;

/// Maximum queue capacity
const MAX_QUEUE_SIZE = 512;

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

    // TapTun translator for L2↔L3 conversion
    translator: taptun.L2L3Translator,

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

        // Create TapTun translator (no device - just L2↔L3 conversion)
        const translator = try taptun.L2L3Translator.init(allocator, .{
            .our_mac = our_mac,
            .learn_ip = true, // Auto-learn from DHCP
            .learn_gateway_mac = true, // Learn from ARP
            .handle_arp = true, // Handle ARP internally
            .verbose = true,
        });

        self.* = .{
            .allocator = allocator,
            .incoming_queue = try PacketQueue.init(allocator, MAX_QUEUE_SIZE),
            .outgoing_queue = try PacketQueue.init(allocator, MAX_QUEUE_SIZE),
            .translator = translator,
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
            .last_error_code = std.atomic.Value(i32).init(0),
        };

        return self;
    }

    pub fn deinit(self: *IosAdapter) void {
        self.incoming_queue.deinit();
        self.outgoing_queue.deinit();
        self.translator.deinit();
        self.allocator.destroy(self);
    }

    /// Inject packet from iOS (L3 IP packet from NEPacketTunnelFlow)
    /// Returns true on success, false if queue full
    pub fn injectPacket(self: *IosAdapter, ip_packet: []const u8) !bool {
        if (ip_packet.len == 0) return false;

        // Translate L3 (IP) → L2 (Ethernet) using TapTun
        const eth_frame = try self.translator.ipToEthernet(ip_packet);
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
        // DEBUG: Log queue state
        const count = self.outgoing_queue.count.load(.acquire);
        if (count > 0) {
            std.log.info("🔍 Zig getOutgoingPacket: Queue has {d} packets", .{count});
        }

        // Dequeue Ethernet frame from SoftEther
        const eth_packet = self.outgoing_queue.dequeue(0) orelse {
            // DEBUG: Dequeue failed
            if (count > 0) {
                std.log.err("⚠️  Zig getOutgoingPacket: dequeue returned null but count={d}!", .{count});
            }
            // ERROR_CODE: -100 means dequeue failed
            self.last_error_code.store(-100, .release);
            return null;
        };

        std.log.info("✅ Dequeued Ethernet packet: length={d}", .{eth_packet.length});

        // Check if this is a DHCP packet - parse and store state
        self.parseDhcpIfNeeded(eth_packet.data[0..eth_packet.length]);

        // Translate L2 (Ethernet) → L3 (IP) using TapTun
        std.log.info("🔄 Calling ethernetToIp for translation...", .{});
        const maybe_ip = self.translator.ethernetToIp(
            eth_packet.data[0..eth_packet.length],
        ) catch |err| {
            std.log.err("⚠️  ethernetToIp failed with error: {}", .{err});
            // ERROR_CODE: -200 means translation error
            self.last_error_code.store(-200, .release);
            return null;
        };

        if (maybe_ip) |ip_packet| {
            std.log.info("✅ Translation successful: IP packet length={d}", .{ip_packet.len});
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
            // ARP packet handled internally by TapTun
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
            self.translator.setOurIp(your_ip);
            self.translator.setGateway(self.dhcp_state.gateway);
        }
    }

    /// Send ARP Request to learn gateway MAC address
    /// This populates SoftEther server's MAC/IP table and enables bidirectional routing
    /// Called once after DHCP completes (similar to CLI behavior)
    fn sendGatewayArpRequest(self: *IosAdapter) !void {
        const log = std.log.scoped(.ios_adapter);

        // Use C printf for visibility (Zig logs might be filtered)
        _ = printf("[IOS_ADAPTER] sendGatewayArpRequest CALLED!\n");

        if (!self.dhcp_state.valid) {
            _ = printf("[IOS_ADAPTER] ERROR: DHCP not valid\n");
            log.warn("[sendGatewayArpRequest] ⚠️  DHCP not valid, cannot send ARP", .{});
            return;
        }

        const our_ip = self.dhcp_state.client_ip;
        const gateway_ip = self.dhcp_state.gateway;
        const our_mac = self.translator.options.our_mac;

        _ = printf("[IOS_ADAPTER] Building ARP: src_ip=%u.%u.%u.%u target_ip=%u.%u.%u.%u\n", (our_ip >> 24) & 0xFF, (our_ip >> 16) & 0xFF, (our_ip >> 8) & 0xFF, our_ip & 0xFF, (gateway_ip >> 24) & 0xFF, (gateway_ip >> 16) & 0xFF, (gateway_ip >> 8) & 0xFF, gateway_ip & 0xFF);

        // Build ARP request using protocol.buildArpRequest
        var arp_buffer: [64]u8 = undefined;
        const arp_size = try protocol.buildArpRequest(our_mac, our_ip, gateway_ip, &arp_buffer);

        _ = printf("[IOS_ADAPTER] Built ARP request: %zu bytes\n", arp_size);

        // Queue to incoming_queue for sending to server
        const queued = self.incoming_queue.enqueue(arp_buffer[0..arp_size]);
        if (!queued) {
            _ = printf("[IOS_ADAPTER] ERROR: Failed to queue ARP (queue full)\n");
            return error.QueueFull;
        }

        _ = printf("[IOS_ADAPTER] ARP Request queued to incoming_queue SUCCESS!\n");
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
        const log = std.log.scoped(.ios_adapter);
        log.info("[setDhcpInfo] 🔧 Setting DHCP info: IP={}.{}.{}.{} GW={}.{}.{}.{} valid=true", .{
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

        _ = printf("[IOS_ADAPTER] setDhcpInfo: need_gateway_arp=%d\n", if (self.need_gateway_arp) @as(c_int, 1) else @as(c_int, 0));
        log.info("[setDhcpInfo] ✅ DHCP state updated successfully", .{});

        // Also update translator with our IP and gateway
        self.translator.setOurIp(client_ip);
        self.translator.setGateway(gateway);

        // Send ARP Request to learn gateway MAC (like CLI does)
        // This is CRITICAL for SoftEther server's MAC/IP table population
        if (self.need_gateway_arp) {
            _ = printf("[IOS_ADAPTER] setDhcpInfo: Calling sendGatewayArpRequest...\n");
            self.need_gateway_arp = false; // Mark as sent (don't send again)
            log.info("[setDhcpInfo] 🔍 Sending gateway ARP request...", .{});
            self.sendGatewayArpRequest() catch |err| {
                _ = printf("[IOS_ADAPTER] setDhcpInfo: sendGatewayArpRequest FAILED: %d\n", @intFromError(err));
                log.err("[setDhcpInfo] ⚠️  Failed to send gateway ARP request: {}", .{err});
            };
            _ = printf("[IOS_ADAPTER] setDhcpInfo: sendGatewayArpRequest returned successfully\n");
        } else {
            _ = printf("[IOS_ADAPTER] setDhcpInfo: SKIPPING ARP (need_gateway_arp=false)\n");
        }
    }

    /// Get DHCP configuration (for Swift to apply network settings)
    pub fn getDhcpInfo(self: *IosAdapter) ?DhcpState {
        const log = std.log.scoped(.ios_adapter);
        self.dhcp_mutex.lock();
        defer self.dhcp_mutex.unlock();

        log.info("[getDhcpInfo] 🔍 Called: valid={}", .{self.dhcp_state.valid});
        if (!self.dhcp_state.valid) {
            log.warn("[getDhcpInfo] ⚠️  DHCP state is NOT valid, returning null", .{});
            return null;
        }

        log.info("[getDhcpInfo] ✅ Returning DHCP info: IP={}.{}.{}.{} GW={}.{}.{}.{}", .{
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
