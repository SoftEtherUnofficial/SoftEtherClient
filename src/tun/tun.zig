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
            const eth_frame = ipToEthernet(ip_packet, &eth_buf) catch |err| {
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
        // Convert Ethernet frame to IP packet
        const ip_packet = ethernetToIp(eth_frame) catch |err| {
            // ARP and other non-IP packets can't be written to TUN (Layer 3 only)
            // This is expected - silently ignore them
            if (err == error.NotIpPacket) {
                return; // Not an error, just not an IP packet
            }
            std.log.err("[TUN Write] L2->L3 conversion error: {}", .{err});
            return err;
        };

        // Write to TUN device
        try self.device.writePacket(ip_packet);
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
};

/// Simple packet queue (ring buffer)
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
// L2 <-> L3 Translation (simplified from deps/taptun)
// ============================================================================

/// Convert IP packet to Ethernet frame
fn ipToEthernet(ip_packet: []const u8, buffer: []u8) ![]u8 {
    if (ip_packet.len == 0) return error.InvalidPacket;

    const eth_header_len = 14;
    const total_len = eth_header_len + ip_packet.len;

    if (total_len > buffer.len) return error.BufferTooSmall;

    // Ethernet header
    // Dst MAC: broadcast for now (could be refined)
    buffer[0] = 0xFF;
    buffer[1] = 0xFF;
    buffer[2] = 0xFF;
    buffer[3] = 0xFF;
    buffer[4] = 0xFF;
    buffer[5] = 0xFF;

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
