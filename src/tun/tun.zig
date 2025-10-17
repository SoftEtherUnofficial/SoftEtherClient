//! TUN Device with Dedicated Reader Thread
//!
//! This matches the C implementation pattern:
//! - Dedicated thread with BLOCKING reads
//! - Packet queue between reader thread and SessionMain
//! - Handles L2<->L3 translation (Ethernet frames <-> IP packets)

const std = @import("std");
const builtin = @import("builtin");

const macos = if (builtin.os.tag == .macos) @import("macos.zig") else void;

/// TUN device with dedicated reader thread
pub const TunDevice = struct {
    device: if (builtin.os.tag == .macos) macos.MacOSTunDevice else void,
    allocator: std.mem.Allocator,

    // Reader thread
    reader_thread: ?std.Thread,
    reader_should_stop: std.atomic.Value(bool),

    // Packet queues
    recv_queue: PacketQueue,
    send_queue: PacketQueue,

    // 🔥 Gateway MAC (learned from DHCP packets)
    gateway_mac: ?[6]u8,
    gateway_mac_mutex: std.Thread.Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        const device = switch (builtin.os.tag) {
            .macos => try macos.MacOSTunDevice.open(allocator),
            else => @compileError("Unsupported platform"),
        };

        return Self{
            .device = device,
            .allocator = allocator,
            .reader_thread = null,
            .reader_should_stop = std.atomic.Value(bool).init(false),
            .recv_queue = try PacketQueue.init(allocator, 256),
            .send_queue = try PacketQueue.init(allocator, 256),
            .gateway_mac = null,
            .gateway_mac_mutex = .{},
        };
    }

    /// Start reader thread (CRITICAL for ICMP!)
    pub fn startReaderThread(self: *Self) !void {
        if (self.reader_thread != null) {
            return error.ThreadAlreadyStarted;
        }

        // Keep fd in BLOCKING mode for dedicated thread
        // (Unlike Zig port which used non-blocking + poll)

        self.reader_thread = try std.Thread.spawn(.{}, tunReaderThread, .{self});
        std.log.info("[TUN] Started dedicated reader thread (BLOCKING reads)", .{});
    }

    /// Dedicated reader thread - BLOCKS on read() like C implementation
    fn tunReaderThread(self: *Self) void {
        std.log.info("[TUN Reader Thread] Started", .{});

        var ip_buf: [2048]u8 = undefined;
        var eth_buf: [2048]u8 = undefined;
        var packet_count: usize = 0;

        while (!self.reader_should_stop.load(.acquire)) {
            // BLOCKING read - waits for packet
            // This is THE FIX for missing ICMP packets!
            const ip_packet = self.device.readPacket(&ip_buf) catch |err| {
                if (err == error.WouldBlock) continue; // Should never happen in blocking mode
                std.log.err("[TUN Reader] Read error: {}", .{err});
                continue;
            };

            packet_count += 1;

            // Convert IP packet to Ethernet frame (use separate buffer!)
            const eth_frame = self.ipToEthernet(ip_packet, &eth_buf) catch |err| {
                std.log.err("[TUN Reader] L3->L2 conversion error: {}", .{err});
                continue;
            };

            // Debug log ICMP packets (only in debug builds)
            if (builtin.mode == .Debug) {
                if (eth_frame.len >= 34) { // Min Ethernet + IP header
                    const eth_type = std.mem.readInt(u16, eth_frame[12..14], .big);
                    if (eth_type == 0x0800) { // IPv4
                        const ip_proto = eth_frame[23];
                        if (ip_proto == 1) { // ICMP
                            const icmp_type = eth_frame[34];
                            const icmp_code = eth_frame[35];
                            std.log.debug("[TUN Reader] ICMP packet #{d}: type={d} code={d} ({s})", .{
                                packet_count,
                                icmp_type,
                                icmp_code,
                                if (icmp_type == 8) "ECHO REQUEST" else if (icmp_type == 0) "ECHO REPLY" else "OTHER",
                            });
                        }
                    }
                }
            }

            // Queue for SessionMain to consume
            self.recv_queue.push(eth_frame) catch |err| {
                std.log.warn("[TUN Reader] Queue full, dropping packet: {}", .{err});
            };
        }

        std.log.info("[TUN Reader Thread] Stopped (read {d} packets)", .{packet_count});
    }

    /// Read next queued Ethernet frame (called from SessionMain)
    pub fn readEthernet(self: *Self, buffer: []u8) ![]u8 {
        return self.recv_queue.pop(buffer);
    }

    /// Write Ethernet frame to TUN device
    pub fn writeEthernet(self: *Self, eth_frame: []const u8) !void {
        // Debug: Track ALL calls to writeEthernet
        const WriteDebug = struct {
            var call_count: usize = 0;
        };
        WriteDebug.call_count += 1;

        if (WriteDebug.call_count <= 20) {
            const eth_type = if (eth_frame.len >= 14) std.mem.readInt(u16, eth_frame[12..14], .big) else 0;
            std.log.info("[TUN writeEthernet #{d}] len={d} ethertype=0x{x:0>4}", .{ WriteDebug.call_count, eth_frame.len, eth_type });
        }

        // 🔥 Learn gateway MAC from incoming packets (from VPN server)
        if (eth_frame.len >= 34) { // Min Ethernet + IP header
            const eth_type = std.mem.readInt(u16, eth_frame[12..14], .big);
            if (eth_type == 0x0800) { // IPv4
                const src_ip = std.mem.readInt(u32, eth_frame[26..30], .big);

                // DEBUG: Log first 10 RX packets to diagnose MAC learning
                const State = struct {
                    var debug_count: usize = 0;
                };
                if (State.debug_count < 10) {
                    State.debug_count += 1;
                    std.log.info("[DEBUG RX] Packet from IP {}.{}.{}.{} (0x{X:0>8}), MAC {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
                        (src_ip >> 24) & 0xFF,
                        (src_ip >> 16) & 0xFF,
                        (src_ip >> 8) & 0xFF,
                        src_ip & 0xFF,
                        src_ip,
                        eth_frame[6],
                        eth_frame[7],
                        eth_frame[8],
                        eth_frame[9],
                        eth_frame[10],
                        eth_frame[11],
                    });
                }

                // Check if this is from gateway (10.21.0.1 = 0x0A150001)
                std.log.info("[MAC LEARN CHECK] src_ip=0x{X:0>8}, masked=0x{X:0>8}, checking if gateway", .{ src_ip, src_ip & 0xFFFFFF00 });
                if ((src_ip & 0xFFFFFF00) == 0x0A150000 and (src_ip & 0xFF) == 1) {
                    self.gateway_mac_mutex.lock();
                    defer self.gateway_mac_mutex.unlock();

                    var new_mac: [6]u8 = undefined;
                    @memcpy(&new_mac, eth_frame[6..12]); // Source MAC

                    // Only log when MAC changes
                    const should_log = if (self.gateway_mac) |old_mac|
                        !std.mem.eql(u8, &old_mac, &new_mac)
                    else
                        true;

                    if (should_log) {
                        std.log.info("🎯 GATEWAY MAC LEARNED: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2} from IP {}.{}.{}.{}", .{
                            new_mac[0],
                            new_mac[1],
                            new_mac[2],
                            new_mac[3],
                            new_mac[4],
                            new_mac[5],
                            (src_ip >> 24) & 0xFF,
                            (src_ip >> 16) & 0xFF,
                            (src_ip >> 8) & 0xFF,
                            src_ip & 0xFF,
                        });
                        self.gateway_mac = new_mac;
                    }
                }
            }
        }

        // Convert Ethernet frame to IP packet
        const ip_packet = ethernetToIp(eth_frame) catch |err| {
            // ARP and other non-IP packets can't be written to TUN (Layer 3 only)
            // This is expected - silently ignore them
            if (err == error.NotIpPacket) {
                const ConvertDebug = struct {
                    var skip_count: usize = 0;
                };
                ConvertDebug.skip_count += 1;
                if (ConvertDebug.skip_count <= 5) {
                    std.log.info("[TUN] Skipping non-IP packet #{d} (len={d})", .{ ConvertDebug.skip_count, eth_frame.len });
                }
                return; // Not an error, just not an IP packet
            }
            std.log.err("[TUN Write] L2->L3 conversion error: {}", .{err});
            return err;
        };

        // Debug: Log IP packets about to be written
        const IpDebug = struct {
            var ip_count: usize = 0;
        };
        IpDebug.ip_count += 1;
        if (IpDebug.ip_count <= 20) {
            const ip_proto = if (ip_packet.len >= 20) ip_packet[9] else 0;
            const proto_name = if (ip_proto == 1) "ICMP" else if (ip_proto == 6) "TCP" else if (ip_proto == 17) "UDP" else "OTHER";
            std.log.info("[TUN] Writing IP packet #{d}: len={d} proto={d} ({s})", .{ IpDebug.ip_count, ip_packet.len, ip_proto, proto_name });
        }

        // Write to TUN device
        try self.device.writePacket(ip_packet);

        // Debug: Confirm write succeeded
        if (IpDebug.ip_count <= 20) {
            std.log.info("[TUN] ✅ Write succeeded for packet #{d}", .{IpDebug.ip_count});
        }
    }

    /// Learn gateway MAC address from a packet (called from adapter.putPacket)
    pub fn learnGatewayMac(self: *Self, src_mac: []const u8, src_ip: u32) void {
        if (src_mac.len != 6) return;

        self.gateway_mac_mutex.lock();
        defer self.gateway_mac_mutex.unlock();

        var new_mac: [6]u8 = undefined;
        @memcpy(&new_mac, src_mac);

        // Only log when MAC changes or first learned
        const should_log = if (self.gateway_mac) |old_mac|
            !std.mem.eql(u8, &old_mac, &new_mac)
        else
            true;

        if (should_log) {
            std.log.info("🎯 GATEWAY MAC LEARNED: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2} from IP {}.{}.{}.{}", .{
                new_mac[0],
                new_mac[1],
                new_mac[2],
                new_mac[3],
                new_mac[4],
                new_mac[5],
                (src_ip >> 24) & 0xFF,
                (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF,
                src_ip & 0xFF,
            });
            self.gateway_mac = new_mac;
        }
    }

    pub fn stopReaderThread(self: *Self) void {
        if (self.reader_thread) |thread| {
            self.reader_should_stop.store(true, .release);
            thread.join();
            self.reader_thread = null;
        }
    }

    pub fn deinit(self: *Self) void {
        self.stopReaderThread();
        self.recv_queue.deinit();
        self.send_queue.deinit();
        self.device.close();
    }

    pub fn getName(self: *Self) []const u8 {
        return self.device.getName();
    }

    pub fn getFd(self: *Self) std.posix.fd_t {
        return self.device.getFd();
    }

    // ============================================================================
    // L2 <-> L3 Translation (simplified from deps/taptun)
    // ============================================================================

    /// Convert IP packet to Ethernet frame
    fn ipToEthernet(self: *Self, ip_packet: []const u8, buffer: []u8) ![]u8 {
        if (ip_packet.len == 0) return error.InvalidPacket;

        const eth_header_len = 14;
        const total_len = eth_header_len + ip_packet.len;

        if (total_len > buffer.len) return error.BufferTooSmall;

        // Ethernet header
        // 🔥 FIX: Use learned gateway MAC instead of broadcast!
        self.gateway_mac_mutex.lock();
        const dst_mac = if (self.gateway_mac) |gw_mac| gw_mac else [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
        self.gateway_mac_mutex.unlock();

        // Debug: Log MAC usage for first 5 ICMP packets
        if (ip_packet.len >= 20) {
            const ip_proto = ip_packet[9];
            if (ip_proto == 1) { // ICMP
                const debug_count = struct {
                    var count: usize = 0;
                };
                if (debug_count.count < 5) {
                    debug_count.count += 1;
                    if (self.gateway_mac != null) {
                        std.log.info("[TX ICMP #{}] Using learned MAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
                            debug_count.count,
                            dst_mac[0],
                            dst_mac[1],
                            dst_mac[2],
                            dst_mac[3],
                            dst_mac[4],
                            dst_mac[5],
                        });
                    } else {
                        std.log.warn("[TX ICMP #{}] ⚠️  Gateway MAC NOT learned yet! Using broadcast", .{debug_count.count});
                    }
                }
            }
        }

        @memcpy(buffer[0..6], &dst_mac);

        // Src MAC: dummy
        buffer[6] = 0x00;
        buffer[7] = 0x00;
        buffer[8] = 0x00;
        buffer[9] = 0x00;
        buffer[10] = 0x00;
        buffer[11] = 0x01;

        // EtherType
        const version = ip_packet[0] & 0xF0;
        if (version == 0x40) { // IPv4
            std.mem.writeInt(u16, buffer[12..14], 0x0800, .big);
        } else if (version == 0x60) { // IPv6
            std.mem.writeInt(u16, buffer[12..14], 0x86DD, .big);
        } else {
            return error.InvalidPacket;
        }

        // Copy IP packet
        @memcpy(buffer[eth_header_len .. eth_header_len + ip_packet.len], ip_packet);

        return buffer[0..total_len];
    }
};

// ============================================================================
// Packet Queue
// ============================================================================
const PacketQueue = struct {
    buffer: []u8,
    packets: []Packet,
    head: std.atomic.Value(usize),
    tail: std.atomic.Value(usize),
    capacity: usize,
    allocator: std.mem.Allocator,

    const Packet = struct {
        data: [2048]u8,
        len: usize,
    };

    fn init(allocator: std.mem.Allocator, capacity: usize) !PacketQueue {
        const packets = try allocator.alloc(Packet, capacity);
        return PacketQueue{
            .buffer = undefined,
            .packets = packets,
            .head = std.atomic.Value(usize).init(0),
            .tail = std.atomic.Value(usize).init(0),
            .capacity = capacity,
            .allocator = allocator,
        };
    }

    fn push(self: *PacketQueue, data: []const u8) !void {
        if (data.len > 2048) return error.PacketTooLarge;

        const head = self.head.load(.monotonic);
        const tail = self.tail.load(.monotonic);
        const next_head = (head + 1) % self.capacity;

        if (next_head == tail) {
            return error.QueueFull;
        }

        // Fast path: direct memory copy with length
        const packet = &self.packets[head];
        packet.len = data.len;
        @memcpy(packet.data[0..data.len], data);

        // Release barrier ensures data is visible before head update
        self.head.store(next_head, .release);
    }

    fn pop(self: *PacketQueue, buffer: []u8) ![]u8 {
        const tail = self.tail.load(.monotonic);
        const head = self.head.load(.acquire);

        if (head == tail) {
            return error.QueueEmpty;
        }

        // Fast path: direct pointer access
        const packet = &self.packets[tail];
        if (packet.len > buffer.len) {
            return error.BufferTooSmall;
        }

        @memcpy(buffer[0..packet.len], packet.data[0..packet.len]);

        // Release barrier ensures we're done reading before tail update
        self.tail.store((tail + 1) % self.capacity, .release);
        return buffer[0..packet.len];
    }

    fn deinit(self: *PacketQueue) void {
        self.allocator.free(self.packets);
    }
};

// ============================================================================
// Packet Queue
// ============================================================================

/// Simple packet queue (ring buffer)
/// Convert Ethernet frame to IP packet
fn ethernetToIp(eth_frame: []const u8) ![]const u8 {
    if (eth_frame.len < 14) return error.InvalidFrame;

    const eth_type = std.mem.readInt(u16, eth_frame[12..14], .big);

    // Only handle IP packets
    if (eth_type != 0x0800 and eth_type != 0x86DD) {
        return error.NotIpPacket;
    }

    return eth_frame[14..]; // Strip Ethernet header
}
