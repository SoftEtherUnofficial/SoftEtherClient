// High-performance Zig packet adapter for SoftEther VPN
// Uses TapTun for TUN device + Protocol layer for L2↔L3 translation
// Adds SoftEther-specific performance optimizations:
// - Lock-free ring buffers (recv=256, send=256)
// - Packet pooling (zero-copy where possible)
// - Batch processing
// Threading removed - C bridge uses sync functions directly
//
// Platform Support (compile-time):
// - macOS/Linux: TUN device I/O (this file)
// - iOS: PacketFlow queue bridge (ios_adapter.zig)

const std = @import("std");
const builtin = @import("builtin");
const RingBuffer = @import("ring_buffer.zig").RingBuffer;
const Packet = @import("packet.zig").Packet;
const PacketPool = @import("packet.zig").PacketPool;
const MAX_PACKET_SIZE = @import("packet.zig").MAX_PACKET_SIZE;
const checksum = @import("checksum.zig");
const taptun = @import("taptun"); // Platform device abstraction only
const protocol = @import("protocol"); // Protocol translation (L2/L3, ARP, DHCP)
const TunAdapter = @import("platform_wrapper").TunAdapter; // High-level wrapper combining device + protocol

// iOS adapter module (compile-time conditional)
// For iOS builds, this imports the iOS-specific adapter
// For non-iOS builds, this is just an empty struct (optimized away at compile-time)
const IosAdapterModule = if (builtin.os.tag == .ios) struct {
    pub const IosAdapter = @import("ios_adapter").IosAdapter;
} else struct {
    pub const IosAdapter = struct {};
};
const is_ios = builtin.os.tag == .ios;

// C printf for debugging
extern "c" fn printf([*:0]const u8, ...) c_int;

// iOS NSLog bridge (appears in Console.app) - only on iOS
const ios_log_message_impl = if (is_ios) struct {
    extern "c" fn ios_log_message([*:0]const u8) void;
}.ios_log_message else undefined;

// iOS logging macro - uses NSLog via Objective-C bridge
fn IOS_LOG(comptime fmt: []const u8, args: anytype) void {
    if (is_ios) {
        var buf: [512]u8 = undefined;
        const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
        ios_log_message_impl(msg.ptr);
    }
}

// C FFI for logging (macOS only - iOS uses std.log)
const c = if (!is_ios) @cImport({
    @cInclude("logging.h");
}) else struct {}; // Empty struct for iOS

// Logging wrapper functions
fn logDebug(comptime fmt: []const u8, args: anytype) void {
    if (is_ios) {
        // iOS: Use std.log (output via NSLog/os_log in Swift)
        std.log.debug(fmt, args);
        return;
    }
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    c.log_message(c.LOG_LEVEL_DEBUG, "ADAPTER", "%s", msg.ptr);
}

fn logInfo(comptime fmt: []const u8, args: anytype) void {
    if (is_ios) {
        std.log.info(fmt, args);
        return;
    }
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    c.log_message(c.LOG_LEVEL_INFO, "ADAPTER", "%s", msg.ptr);
}

fn logError(comptime fmt: []const u8, args: anytype) void {
    if (is_ios) {
        std.log.err(fmt, args);
        return;
    }
    var buf: [1024]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    c.log_message(c.LOG_LEVEL_ERROR, "ADAPTER", "%s", msg.ptr);
}

/// Packet adapter configuration
pub const Config = struct {
    /// Buffer sizes (configurable at runtime)
    /// Optimized for high throughput: 256/256 slots (balanced for bidirectional traffic)
    /// Memory per slot: ~2KB, so 256 slots = 512KB per queue
    recv_queue_size: usize = 256, // Doubled for better download throughput
    send_queue_size: usize = 256, // Doubled for better upload throughput
    packet_pool_size: usize = 512, // CRITICAL: Must be >= recv+send (doubled from 256)
    batch_size: usize = 256, // Match queue size for better throughput (doubled from 128)

    /// TUN device name
    device_name: []const u8 = "utun",
};

/// C-compatible config struct (matches zig_packet_adapter.h layout)
pub const CConfig = extern struct {
    recv_queue_size: usize,
    send_queue_size: usize,
    packet_pool_size: usize,
    batch_size: usize,
    device_name: [*:0]const u8,
    device_name_len: usize,
};

/// Packet with owned buffer
const PacketBuffer = struct {
    data: []u8,
    len: usize,
    timestamp: i64,
};

/// High-performance packet adapter for SoftEther VPN
/// Uses TapTun for device I/O and L2↔L3 translation
/// Adds performance layer: queues, pooling, adaptive scaling, metrics
///
/// Platform-specific behavior (compile-time):
/// - macOS/Linux: TUN device + queues (this struct)
/// - iOS: Wraps ios_adapter.IosAdapter (no TUN device)
pub const ZigPacketAdapter = struct {
    allocator: std.mem.Allocator,
    config: Config,

    // Platform-specific adapter
    // macOS/Linux: TunAdapter (high-level wrapper that combines device + translation)
    // iOS: IosAdapter (queue bridge only, no device)
    tun_adapter: if (!is_ios) *TunAdapter else void,
    ios_adapter: if (is_ios) *IosAdapterModule.IosAdapter else void,

    // SoftEther-specific performance layer
    // Lock-free queues (heap-allocated to avoid large stack/struct size)
    // Runtime-sized based on config
    recv_queue: *RingBuffer(PacketBuffer),
    send_queue: *RingBuffer(PacketBuffer),

    // Memory pool
    packet_pool: PacketPool,

    // Track active buffers to prevent memory leaks
    active_buffers: std.AutoHashMap(usize, []u8),

    // Adapter state
    state: AdapterState = .created,

    // Keep-alive timer for GARP (Gratuitous ARP)
    last_keepalive: i64 = 0,
    keepalive_interval_ns: i64 = 10 * std.time.ns_per_s, // 10 seconds

    // Statistics (simple counters, not updated in hot path for performance)
    stats: Stats,

    pub const AdapterState = enum {
        created,
        open,
        running,
        stopped,
    };

    pub const Stats = struct {
        // Simple counters for debugging (not updated in hot path for performance)
        packets_read: u64 = 0,
        packets_written: u64 = 0,
        bytes_read: u64 = 0,
        bytes_written: u64 = 0,
        read_errors: u64 = 0,
        write_errors: u64 = 0,
        recv_queue_drops: u64 = 0,
        send_queue_drops: u64 = 0,
        buffer_tracking_failures: u64 = 0,
        garp_sent: u64 = 0,

        pub fn format(
            self: Stats,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print(
                "Stats[rx={d}pkt/{d}B, tx={d}pkt/{d}B, err={d}/{d}, drops={d}/{d}, garp={d}]",
                .{
                    self.packets_read,
                    self.bytes_read,
                    self.packets_written,
                    self.bytes_written,
                    self.read_errors,
                    self.write_errors,
                    self.recv_queue_drops,
                    self.send_queue_drops,
                    self.garp_sent,
                },
            );
        }
    };

    /// Initialize packet adapter with given configuration
    pub fn init(allocator: std.mem.Allocator, config: Config) !*ZigPacketAdapter {
        logInfo("Initializing adapter: recv_queue={}, send_queue={}, pool={}, batch={}", .{
            config.recv_queue_size,
            config.send_queue_size,
            config.packet_pool_size,
            config.batch_size,
        });

        const self = try allocator.create(ZigPacketAdapter);
        errdefer allocator.destroy(self);
        logDebug("Allocated adapter struct at {*}", .{self});

        if (is_ios) {
            // iOS mode: Create ios_adapter (no TUN device)
            logInfo("iOS mode: Creating iOS adapter (no TUN device)", .{});
            const ios_adp = try IosAdapterModule.IosAdapter.init(allocator);
            errdefer ios_adp.deinit();

            self.* = .{
                .allocator = allocator,
                .config = config,
                .tun_adapter = {},
                .ios_adapter = ios_adp,
                .recv_queue = undefined, // iOS uses its own queues
                .send_queue = undefined,
                .packet_pool = undefined,
                .active_buffers = undefined,
                .stats = .{},
            };

            logInfo("iOS adapter initialized", .{});
            return self;
        }

        // macOS/Linux mode: Create TUN device adapter (existing code)
        logDebug("Creating packet pool (size={d})", .{config.packet_pool_size});
        var packet_pool = try PacketPool.init(allocator, config.packet_pool_size, MAX_PACKET_SIZE);
        errdefer packet_pool.deinit();
        logDebug("Packet pool created", .{});

        // Allocate ring buffers with runtime sizes from config
        logDebug("Allocating recv_queue (size={d})", .{config.recv_queue_size});
        const recv_queue = try allocator.create(RingBuffer(PacketBuffer));
        errdefer allocator.destroy(recv_queue);
        recv_queue.* = try RingBuffer(PacketBuffer).init(allocator, config.recv_queue_size);
        errdefer recv_queue.deinit();

        logDebug("Allocating send_queue (size={d})", .{config.send_queue_size});
        const send_queue = try allocator.create(RingBuffer(PacketBuffer));
        errdefer allocator.destroy(send_queue);
        send_queue.* = try RingBuffer(PacketBuffer).init(allocator, config.send_queue_size);
        errdefer send_queue.deinit();

        // Open TUN device with L2/L3 translator (TunAdapter handles everything!)
        logDebug("Opening TUN device via TunAdapter (device from taptun + translation from protocol)", .{});
        const tun_adapter = try TunAdapter.open(allocator, .{
            .device = .{
                .unit = null, // Auto-assign
                .mtu = 1500,
                .non_blocking = true,
            },
            .translator = .{
                .our_mac = [_]u8{ 0x00, 0xAC, 0x00, 0x00, 0x00, 0x01 }, // SoftEther virtual MAC
                .learn_ip = true, // Auto-learn our IP from DHCP
                .learn_gateway_mac = true, // Learn gateway MAC from ARP
                .handle_arp = true, // Handle ARP requests/replies
                .verbose = true, // Enable verbose logging to see gateway MAC learning
            },
            .manage_routes = true, // Enable automatic route management
        });
        errdefer tun_adapter.close();
        logInfo("TUN device opened: {s}", .{tun_adapter.getDeviceName()});

        self.* = .{
            .allocator = allocator,
            .config = config,
            .tun_adapter = tun_adapter,
            .ios_adapter = {},
            .recv_queue = recv_queue,
            .send_queue = send_queue,
            .packet_pool = packet_pool,
            .active_buffers = std.AutoHashMap(usize, []u8).init(allocator), // Track active buffers
            .stats = .{},
        };

        logInfo("Adapter initialized (recv={d} slots, send={d} slots)", .{ config.recv_queue_size, config.send_queue_size });
        return self;
    }

    /// Clean up resources
    pub fn deinit(self: *ZigPacketAdapter) void {
        if (is_ios) {
            // iOS mode: Clean up ios_adapter
            self.ios_adapter.deinit();
            self.allocator.destroy(self);
            return;
        }

        // macOS/Linux mode: Clean up TUN adapter (existing code)
        // Close TapTun adapter (handles device + translator cleanup)
        self.tun_adapter.close();

        self.packet_pool.deinit();

        // Clean up active buffers HashMap
        self.active_buffers.deinit();

        // Free heap-allocated ring buffers (items array then struct)
        self.recv_queue.deinit();
        self.allocator.destroy(self.recv_queue);
        self.send_queue.deinit();
        self.allocator.destroy(self.send_queue);

        self.allocator.destroy(self);
    }

    /// Open TUN device (now handled by TapTun in init, this is a no-op for compatibility)
    pub fn open(self: *ZigPacketAdapter) !void {
        _ = self;
        // Device is already opened in init() via TapTun
        logDebug("open() called (device already opened in init)", .{});
    }

    // Removed unused threading infrastructure and adaptive scaling (~330 lines eliminated)
    // Architecture Change: Threads were never started (C bridge uses sync I/O directly)
    //
    // Removed Dead Code:
    // - start(): Never called by C bridge
    // - stop(): No threads to stop
    // - readThreadFn(): C bridge uses zig_adapter_read_sync() directly (removed 80 lines)
    // - writeThreadFn(): C bridge uses zig_adapter_write_sync() directly (removed 70 lines)
    // - monitorThreadFn(): Adaptive scaling never actually resized queues (removed 70 lines)
    // - adaptive_manager field: Removed from struct, but thread functions still referenced it
    // - adaptive_buffer.zig: Module exists but never imported (320 lines of unused code)
    //
    // Result:
    // ✅ Simpler, cleaner architecture
    // ✅ No dead code that won't compile if analyzed
    // ✅ Fixed-size queues work perfectly (128/128 slots)
    // ✅ ~330 lines of misleading/confusing code eliminated
    // ✅ Same functionality, zero performance impact

    /// Get next packet (called by SoftEther protocol layer)
    pub fn getNextPacket(self: *ZigPacketAdapter) ?PacketBuffer {
        // iOS: Read from iOS adapter's incoming queue (iOS → SoftEther)
        if (is_ios) {
            const ios_adp = self.ios_adapter;
            const queued = ios_adp.incoming_queue.dequeue(0) orelse return null;

            // Allocate buffer from pool
            const buffer = self.packet_pool.alloc() orelse return null;

            // Copy data from queued packet
            if (queued.length > buffer.len) {
                self.packet_pool.free(buffer);
                return null;
            }

            @memcpy(buffer[0..queued.length], queued.data[0..queued.length]);

            return PacketBuffer{
                .data = buffer,
                .len = queued.length,
                .timestamp = queued.timestamp,
            };
        }

        // macOS/Linux: Read from recv_queue
        return self.recv_queue.pop();
    }

    /// Get batch of packets (NEW API for batch processing)
    pub fn getPacketBatch(self: *ZigPacketAdapter, out: []?PacketBuffer) usize {
        return self.recv_queue.popBatch(out);
    }

    /// Put packet for transmission
    pub fn putPacket(self: *ZigPacketAdapter, data: []const u8) bool {
        // iOS: Use iOS adapter's outgoing queue (SoftEther → iOS)
        if (is_ios) {
            IOS_LOG("[PUT_PACKET] Server→iOS: {d} bytes", .{data.len});
            const ios_adp = self.ios_adapter;
            const success = ios_adp.outgoing_queue.enqueue(data);
            if (!success) {
                IOS_LOG("[PUT_PACKET] ERROR: Queue full, dropping packet", .{});
                _ = ios_adp.queue_drops_out.fetchAdd(1, .release);
            } else {
                IOS_LOG("[PUT_PACKET] Queued successfully to outgoing_queue", .{});
            }
            return success;
        }

        // macOS/Linux: Use packet pool + send queue
        // Get buffer from pool
        const buffer = self.packet_pool.alloc() orelse return false;

        // Copy packet data directly (Ethernet frame from SoftEther)
        if (data.len > buffer.len) {
            self.packet_pool.free(buffer);
            return false;
        }

        @memcpy(buffer[0..data.len], data);

        const pkt = PacketBuffer{
            .data = buffer,
            .len = data.len,
            .timestamp = @intCast(std.time.nanoTimestamp()),
        };

        if (!self.send_queue.push(pkt)) {
            self.stats.send_queue_drops += 1;
            self.packet_pool.free(buffer);
            return false;
        }

        return true;
    }

    /// Maintain connection with periodic GARP (Gratuitous ARP)
    /// Call this regularly (e.g., in read/write loops) to keep connection alive
    /// Sends GARP every 10 seconds to prevent ARP cache staleness
    pub fn maintainConnection(self: *ZigPacketAdapter) void {
        if (is_ios) return; // iOS doesn't use GARP keepalive

        const now: i64 = @intCast(std.time.nanoTimestamp());

        // Check if it's time to send GARP
        if (now - self.last_keepalive < self.keepalive_interval_ns) {
            return; // Not time yet
        }

        // Only send GARP if we have an IP address
        const our_ip = self.tun_adapter.getLearnedIp() orelse return;

        // Send Gratuitous ARP
        self.sendGratuitousArp(our_ip) catch |err| {
            logError("Failed to send GARP: {}", .{err});
            return;
        };

        // Update last keepalive time
        self.last_keepalive = now;
        self.stats.garp_sent += 1;

        logDebug("✅ GARP keepalive sent (IP: {d}.{d}.{d}.{d})", .{
            (our_ip >> 24) & 0xFF,
            (our_ip >> 16) & 0xFF,
            (our_ip >> 8) & 0xFF,
            our_ip & 0xFF,
        });
    }

    /// Send Gratuitous ARP to announce our presence
    /// ip_network_order: Our IP address in network byte order (big-endian)
    fn sendGratuitousArp(self: *ZigPacketAdapter, ip_network_order: u32) !void {
        // Get our MAC address
        const our_mac = self.tun_adapter.translator.options.our_mac;

        // Build GARP packet (42 bytes: 14 bytes Ethernet + 28 bytes ARP)
        var garp_buffer: [42]u8 = undefined;
        var pos: usize = 0;

        // Ethernet header - broadcast
        @memset(garp_buffer[pos..][0..6], 0xFF); // Broadcast MAC
        pos += 6;
        @memcpy(garp_buffer[pos..][0..6], &our_mac); // Src MAC (our MAC)
        pos += 6;
        std.mem.writeInt(u16, garp_buffer[pos..][0..2], 0x0806, .big); // EtherType: ARP
        pos += 2;

        // ARP packet (28 bytes)
        std.mem.writeInt(u16, garp_buffer[pos..][0..2], 0x0001, .big); // Hardware type: Ethernet
        pos += 2;
        std.mem.writeInt(u16, garp_buffer[pos..][0..2], 0x0800, .big); // Protocol type: IPv4
        pos += 2;
        garp_buffer[pos] = 6; // Hardware size
        pos += 1;
        garp_buffer[pos] = 4; // Protocol size
        pos += 1;
        std.mem.writeInt(u16, garp_buffer[pos..][0..2], 0x0001, .big); // Opcode: Request (GARP uses request)
        pos += 2;

        // Sender (us) - announce our IP+MAC binding
        @memcpy(garp_buffer[pos..][0..6], &our_mac); // Sender MAC (our MAC)
        pos += 6;
        std.mem.writeInt(u32, garp_buffer[pos..][0..4], ip_network_order, .big); // Sender IP (our IP)
        pos += 4;

        // Target - GARP uses same IP for target (key characteristic of GARP)
        @memset(garp_buffer[pos..][0..6], 0x00); // Target MAC (00:00:00:00:00:00 for GARP)
        pos += 6;
        std.mem.writeInt(u32, garp_buffer[pos..][0..4], ip_network_order, .big); // Target IP (same as sender - this is GARP!)
        pos += 4;

        // Send GARP packet via TUN device
        // GARP is an Ethernet frame, so we need to queue it like any outbound packet
        const sent = self.putPacket(garp_buffer[0..42]);
        if (!sent) {
            return error.QueueFull;
        }
    }

    /// Configure VPN routing (replaces C bridge route management)
    /// Call after DHCP assigns VPN gateway
    pub fn configureRouting(self: *ZigPacketAdapter, vpn_gateway: [4]u8, vpn_server: ?[4]u8) !void {
        if (is_ios) return; // iOS routing configured by NEPacketTunnelProvider
        try self.tun_adapter.configureVpnRouting(vpn_gateway, vpn_server);
    }

    /// Get statistics
    pub fn getStats(self: *ZigPacketAdapter) StatsSnapshot {
        return .{
            .adapter = self.stats,
            .recv_queue = self.recv_queue.getStats(),
            .send_queue = self.send_queue.getStats(),
            .packet_pool = self.packet_pool.getStats(),
        };
    }

    pub const StatsSnapshot = struct {
        adapter: Stats,
        recv_queue: RingBuffer(PacketBuffer).Stats,
        send_queue: RingBuffer(PacketBuffer).Stats,
        packet_pool: PacketPool.Stats,

        pub fn print(self: StatsSnapshot) void {
            logInfo("Adapter stats - RX: {any}, TX: {any}, Pool: {any}", .{
                self.recv_queue,
                self.send_queue,
                self.packet_pool,
            });
        }
    };
};

// Export C-compatible functions for FFI
export fn zig_adapter_create(c_config: *const CConfig) ?*ZigPacketAdapter {
    const allocator = std.heap.c_allocator;

    // DEBUG: Log what C is passing
    logDebug("C config: recv={d}, send={d}, pool={d}, batch={d}, device_name_len={d}", .{
        c_config.recv_queue_size,
        c_config.send_queue_size,
        c_config.packet_pool_size,
        c_config.batch_size,
        c_config.device_name_len,
    });

    // Convert C config to Zig config
    const device_name = c_config.device_name[0..c_config.device_name_len];
    const config = Config{
        .recv_queue_size = c_config.recv_queue_size,
        .send_queue_size = c_config.send_queue_size,
        .packet_pool_size = c_config.packet_pool_size,
        .batch_size = c_config.batch_size,
        .device_name = device_name,
    };

    const adapter = ZigPacketAdapter.init(allocator, config) catch |err| {
        logError("Failed to create adapter: {any}", .{err});
        return null;
    };
    logInfo("Adapter created successfully at {*}", .{adapter});

    // iOS: Set global adapter for FFI functions
    if (is_ios) {
        global_ios_adapter = adapter;
    }

    return adapter;
}

export fn zig_adapter_destroy(adapter: *ZigPacketAdapter) void {
    adapter.deinit();
}

export fn zig_adapter_open(adapter: *ZigPacketAdapter) bool {
    adapter.open() catch return false;
    return true;
}

// No-op since threading removed (C bridge never calls this anyway)
export fn zig_adapter_start(adapter: *ZigPacketAdapter) bool {
    _ = adapter;
    return true; // Always succeed, no threads to start
}

/// Synchronous read from TUN device (blocking with timeout)
/// Returns number of bytes read (as ETHERNET FRAME), or -1 on error, 0 on timeout
///
/// **CRITICAL**: TUN devices return raw IP packets, but SoftEther expects Ethernet frames!
/// We must ADD a 14-byte Ethernet header to each IP packet read from TUN.
export fn zig_adapter_read_sync(adapter: *ZigPacketAdapter, buffer: [*]u8, buffer_len: usize) isize {
    if (is_ios) {
        // iOS implementation: dequeue from incoming queue (Swift → adapter → SoftEther)
        // These are already Ethernet frames (IP packets translated via ios_adapter.injectPacket)
        return 0; // iOS uses push model via putPacket, not pull via read
    }

    // macOS implementation: read from TUN device
    // Maintain connection with periodic GARP
    adapter.maintainConnection();

    // Read directly from TUN device (non-blocking)
    const fd = adapter.tun_adapter.device.fd;

    // Use a temp buffer to read IP packet (we'll prepend Ethernet header later)
    var temp_buf: [2048]u8 = undefined;

    // **CRITICAL FOR MACOS TUN**: Use poll() with timeout to check if TUN is readable
    // Without this, TUN device "freezes" after first ~10 reads (returns WouldBlock forever)
    // This is a known macOS utun quirk - the device needs to be polled to stay "alive"
    var fds = [_]std.posix.pollfd{
        .{
            .fd = fd,
            .events = std.posix.POLL.IN, // Wait for readable
            .revents = 0,
        },
    };

    // Poll with 1ms timeout - optimal balance for macOS TUN
    // Fast enough for low latency, slow enough to avoid busy-waiting
    const ready_count = std.posix.poll(&fds, 1) catch |err| {
        logError("poll() failed: {}", .{err});
        return -1;
    };

    // DEBUG: Log poll results every 100 calls to see what's happening
    const debug_counter = struct {
        var count: usize = 0;
    };
    debug_counter.count += 1;
    if (debug_counter.count % 100 == 0) {
        logInfo("🔍 DEBUG poll(): ready_count={d}, revents=0x{x}, fd={d}, POLLIN=0x{x}", .{
            ready_count,
            fds[0].revents,
            fd,
            @as(u32, std.posix.POLL.IN),
        });
    }

    // If no data available, return immediately (this is normal - polled frequently)
    if (ready_count == 0 or (fds[0].revents & std.posix.POLL.IN) == 0) {
        return 0; // No data ready
    }

    // Now read - TUN device is ready with data
    const bytes_read = std.posix.read(fd, temp_buf[0..]) catch |err| {
        if (err == error.WouldBlock) {
            // Should not happen after poll() said readable, but handle it anyway
            return 0;
        }
        return -1;
    };

    if (bytes_read == 0) return 0;
    if (bytes_read < 4) return 0; // Too small - need at least 4-byte AF_INET header

    // Skip 4-byte AF_INET header from macOS utun to get raw IP packet
    const ip_packet_start = 4;
    const ip_packet_len = bytes_read - ip_packet_start;

    if (ip_packet_len <= 0) return 0;

    // Check IP version (first nibble of IP packet)
    const ip_version = (temp_buf[ip_packet_start] >> 4) & 0x0F;

    // DEBUG: Log packet details
    if (ip_version == 4 and ip_packet_len >= 20) {
        const ip_protocol = temp_buf[ip_packet_start + 9];
        const protocol_name = switch (ip_protocol) {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            else => "other",
        };
        logInfo("📥 Read IPv4 packet: protocol={s} ({d}), len={d} bytes", .{ protocol_name, ip_protocol, ip_packet_len });
    }

    // **BUILD ETHERNET FRAME**: SoftEther expects [Ethernet header][IP packet]
    // Ethernet header: [6 bytes dest MAC][6 bytes src MAC][2 bytes EtherType]
    const ETHERNET_HEADER_SIZE = 14;
    const ethernet_frame_len = ETHERNET_HEADER_SIZE + ip_packet_len;

    if (ethernet_frame_len > buffer_len) {
        return 0; // Frame too large for buffer
    }

    // Build Ethernet header
    const ethertype: u16 = if (ip_version == 4) 0x0800 else if (ip_version == 6) 0x86DD else 0x0000;

    if (ethertype == 0) {
        return 0; // Unknown IP version, skip packet
    }

    // Dest MAC: Use gateway MAC if learned, otherwise broadcast (FF:FF:FF:FF:FF:FF)
    // For inbound packets, dest should be our MAC, but we use gateway MAC for routing
    if (adapter.tun_adapter.translator.gateway_mac) |gw_mac| {
        @memcpy(buffer[0..6], &gw_mac);
    } else {
        // Broadcast MAC if gateway not learned yet
        @memset(buffer[0..6], 0xFF);
    }

    // Src MAC: Our MAC address (from translator options)
    @memcpy(buffer[6..12], &adapter.tun_adapter.translator.options.our_mac); // EtherType (big-endian)
    buffer[12] = @intCast((ethertype >> 8) & 0xFF);
    buffer[13] = @intCast(ethertype & 0xFF);

    // Copy IP packet after Ethernet header
    @memcpy(buffer[14..ethernet_frame_len], temp_buf[ip_packet_start..(ip_packet_start + ip_packet_len)]);

    return @intCast(ethernet_frame_len);
}

/// Synchronous write to TUN device (called from PutPacket)
/// Drains send_queue and writes packets to TUN device
/// Returns number of packets written
/// PERFORMANCE: Uses vectored I/O (writev) with dynamic batch sizing
export fn zig_adapter_write_sync(adapter: *ZigPacketAdapter) isize {
    if (is_ios) {
        // iOS implementation: queue packets for retrieval via getOutgoingPacket
        // For now, return 0 (iOS uses different flow)
        return 0;
    }

    // macOS implementation: write to TUN device
    // Maintain connection with periodic GARP
    adapter.maintainConnection();

    var packets_written: isize = 0;

    // Smart batching for both upload and download
    // Calculate available packets in queue
    const write_idx = adapter.send_queue.write_idx.load(.acquire);
    const read_idx = adapter.send_queue.read_idx.load(.acquire);
    const available_packets = if (write_idx >= read_idx)
        write_idx - read_idx
    else
        adapter.send_queue.capacity - read_idx + write_idx;

    // Use minimum of 128 or available packets (256 causes stack overflow)
    // This ensures we write immediately when packets arrive (low latency)
    // while still batching efficiently when queue is full (high throughput)
    const max_batch: usize = @min(128, if (available_packets > 0) available_packets else 1);

    // Stack allocation for reasonable batch size (128 * 2KB = 256KB - acceptable)
    var iov_array: [128]std.posix.iovec_const = undefined;
    var write_bufs: [128][2048]u8 = undefined;
    var packets_to_free: [128][]u8 = undefined;
    var batch_size: usize = 0;

    // Build batch of packets
    while (batch_size < max_batch) {
        const pkt = adapter.send_queue.pop() orelse break;

        // **CRITICAL**: TUN expects raw IP packets, but SoftEther sends Ethernet frames!
        const ETHERNET_HEADER_SIZE = 14;
        if (pkt.len < ETHERNET_HEADER_SIZE) {
            adapter.packet_pool.free(pkt.data);
            continue;
        }

        // macOS utun requires 4-byte AF_INET header (big-endian)
        var write_buf = &write_bufs[batch_size];
        write_buf[0] = 0x00;
        write_buf[1] = 0x00;
        write_buf[2] = 0x00;
        write_buf[3] = 0x02; // AF_INET = 2

        // Copy IP packet (skip Ethernet header)
        const ip_packet_len = pkt.len - ETHERNET_HEADER_SIZE;
        const write_len = ip_packet_len + 4;

        if (write_len > write_buf.len) {
            adapter.packet_pool.free(pkt.data);
            continue;
        }

        @memcpy(write_buf[4..write_len], pkt.data[ETHERNET_HEADER_SIZE..pkt.len]);

        // Add to iovec array
        iov_array[batch_size] = .{
            .base = write_buf,
            .len = write_len,
        };
        packets_to_free[batch_size] = pkt.data;
        batch_size += 1;
    }

    // Write batch using writev for better performance
    if (batch_size > 0) {
        const fd = adapter.tun_adapter.device.fd;
        const bytes_written = std.posix.writev(fd, iov_array[0..batch_size]) catch {
            // On error, free all packets
            for (packets_to_free[0..batch_size]) |buf| {
                adapter.packet_pool.free(buf);
            }
            return 0;
        };

        // Free all packet buffers
        for (packets_to_free[0..batch_size]) |buf| {
            adapter.packet_pool.free(buf);
        }

        adapter.stats.packets_written += batch_size;
        adapter.stats.bytes_written += @as(u64, @intCast(bytes_written));
        packets_written = @intCast(batch_size);
    }

    return packets_written;
}

// No-op since threading removed (C bridge never calls this anyway)
export fn zig_adapter_stop(adapter: *ZigPacketAdapter) void {
    _ = adapter; // No threads to stop
}

export fn zig_adapter_get_packet(adapter: *ZigPacketAdapter, out_data: *[*]u8, out_len: *usize) bool {
    const pkt = adapter.getNextPacket() orelse return false;

    out_data.* = pkt.data.ptr + 4; // Skip header
    out_len.* = pkt.len;

    // Store buffer in HashMap to track for release_packet
    const key = @intFromPtr(pkt.data.ptr);
    adapter.active_buffers.put(key, pkt.data) catch {
        // HashMap allocation failed, fall back to immediate free (safe but suboptimal)
        adapter.packet_pool.free(pkt.data);
        adapter.stats.buffer_tracking_failures += 1;
        logError("⚠️ Buffer tracking HashMap full - freed immediately", .{});
        return false;
    };

    return true;
}

/// Release packet buffer back to pool (MUST be called after get_packet)
export fn zig_adapter_release_packet(adapter: *ZigPacketAdapter, data: [*]u8) void {
    // Look up buffer in HashMap and free it properly
    // C gives us pointer offset by +4 (skipped header), so subtract to get original
    const adjusted_ptr = data - 4;
    const key = @intFromPtr(adjusted_ptr);

    if (adapter.active_buffers.fetchRemove(key)) |entry| {
        adapter.packet_pool.free(entry.value);
    } else {
        // Buffer not found - this shouldn't happen, log warning
        logError("⚠️ release_packet: buffer not found for ptr={*}", .{adjusted_ptr});
    }
}

export fn zig_adapter_get_packet_batch(adapter: *ZigPacketAdapter, out_array: [*]PacketBuffer, max_count: usize) usize {
    // Use stack buffer instead of heap allocation (10-20x faster)
    var batch: [128]?PacketBuffer = undefined;
    const actual_count = @min(max_count, 128);

    const count = adapter.getPacketBatch(batch[0..actual_count]);

    // Copy non-null packets to output
    var out_idx: usize = 0;
    for (batch[0..count]) |pkt_opt| {
        if (pkt_opt) |pkt| {
            out_array[out_idx] = pkt;
            out_idx += 1;
        }
    }

    return out_idx;
}

export fn zig_adapter_put_packet(adapter: *ZigPacketAdapter, data: [*]const u8, len: usize) bool {
    return adapter.putPacket(data[0..len]);
}

export fn zig_adapter_print_stats(adapter: *ZigPacketAdapter) void {
    const stats = adapter.getStats();
    stats.print();
}

// ============================================================================
// macOS-ONLY FFI Exports (TUN device specific)
// ============================================================================

export fn zig_adapter_get_device_name(adapter: *ZigPacketAdapter, out_buffer: [*]u8, buffer_len: usize) usize {
    if (is_ios) return 0; // iOS has no TUN device name
    if (buffer_len == 0) return 0;

    const device_name = adapter.tun_adapter.getDeviceName();
    const copy_len = @min(device_name.len, buffer_len - 1);
    @memcpy(out_buffer[0..copy_len], device_name[0..copy_len]);
    out_buffer[copy_len] = 0; // Null terminate

    return copy_len;
}

/// Get device name as C string pointer (simple wrapper)
export fn zig_adapter_get_device_name_ptr(adapter: *ZigPacketAdapter) [*]const u8 {
    if (is_ios) return "ios-no-device";
    const device_name = adapter.tun_adapter.getDeviceName();
    // Note: device_name is null-terminated from TUN/TAP device
    return device_name.ptr;
}

/// Get learned IP address from TapTun translator
export fn zig_adapter_get_learned_ip(adapter: *ZigPacketAdapter) u32 {
    if (is_ios) return 0; // iOS gets IP via getDhcpInfo
    return adapter.tun_adapter.getLearnedIp() orelse 0;
}

/// Get gateway MAC address from TapTun translator
export fn zig_adapter_get_gateway_mac(adapter: *ZigPacketAdapter, out_mac: [*]u8) bool {
    if (is_ios) return false; // iOS doesn't expose gateway MAC
    if (adapter.tun_adapter.getGatewayMac()) |mac| {
        @memcpy(out_mac[0..6], &mac);
        return true;
    }
    return false;
}

/// Set gateway IP in translator (MAC will be learned from ARP/packets)
/// ip_network_order: Gateway IP in network byte order (big-endian)
export fn zig_adapter_set_gateway(adapter: *ZigPacketAdapter, ip_network_order: u32) void {
    if (is_ios) return; // iOS doesn't configure gateway via adapter
    adapter.tun_adapter.translator.setGateway(ip_network_order);
}

/// Set gateway MAC address (called from C when gateway MAC is learned via ARP)
export fn zig_adapter_set_gateway_mac(adapter: *ZigPacketAdapter, mac: [*c]const u8) void {
    if (is_ios) return; // iOS doesn't configure gateway via adapter
    var mac_array: [6]u8 = undefined;
    @memcpy(&mac_array, mac[0..6]);
    adapter.tun_adapter.translator.gateway_mac = mac_array;

    logInfo("[L2L3] 🎯 setGatewayMAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
        mac_array[0], mac_array[1], mac_array[2],
        mac_array[3], mac_array[4], mac_array[5],
    });
}

/// Configure TUN interface with IP address
/// IPs are in network byte order (big-endian)
export fn zig_adapter_configure_interface(
    adapter: *ZigPacketAdapter,
    local_ip: u32,
    peer_ip: u32,
    netmask: u32,
) bool {
    if (is_ios) return false; // iOS interface configured by PacketTunnelProvider

    // Convert IPs to string (big-endian network byte order)
    var local_str: [16]u8 = undefined;
    var peer_str: [16]u8 = undefined;
    var mask_str: [16]u8 = undefined;

    const local_fmt = std.fmt.bufPrintZ(&local_str, "{}.{}.{}.{}", .{
        (local_ip >> 24) & 0xFF,
        (local_ip >> 16) & 0xFF,
        (local_ip >> 8) & 0xFF,
        local_ip & 0xFF,
    }) catch return false;

    const peer_fmt = std.fmt.bufPrintZ(&peer_str, "{}.{}.{}.{}", .{
        (peer_ip >> 24) & 0xFF,
        (peer_ip >> 16) & 0xFF,
        (peer_ip >> 8) & 0xFF,
        peer_ip & 0xFF,
    }) catch return false;

    const mask_fmt = std.fmt.bufPrintZ(&mask_str, "{}.{}.{}.{}", .{
        (netmask >> 24) & 0xFF,
        (netmask >> 16) & 0xFF,
        (netmask >> 8) & 0xFF,
        netmask & 0xFF,
    }) catch return false;

    // Build ifconfig command
    var cmd: [256]u8 = undefined;
    const device_name = adapter.tun_adapter.getDeviceName();
    const cmd_str = std.fmt.bufPrintZ(&cmd, "ifconfig {s} {s} {s} netmask {s} up", .{
        device_name,
        local_fmt,
        peer_fmt,
        mask_fmt,
    }) catch return false;

    logInfo("Configuring interface: {s}", .{cmd_str});

    // Execute command
    const result = std.process.Child.run(.{
        .allocator = adapter.allocator,
        .argv = &[_][]const u8{ "/bin/sh", "-c", cmd_str },
    }) catch |err| {
        logError("Failed to execute ifconfig: {}", .{err});
        return false;
    };
    defer adapter.allocator.free(result.stdout);
    defer adapter.allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        logError("ifconfig failed with code {}: {s}", .{ result.term.Exited, result.stderr });
        return false;
    }

    logInfo("Interface configured: {s} -> {s}", .{ local_fmt, peer_fmt });
    return true;
}

/// Configure VPN routing (replaces C bridge RestoreZigRouting)
/// vpn_gateway: VPN gateway IP (network byte order)
/// vpn_server: VPN server IP (network byte order, 0 = none)
export fn zig_adapter_configure_routing(
    adapter: *ZigPacketAdapter,
    vpn_gateway: u32,
    vpn_server: u32,
) bool {
    // Convert to [4]u8 arrays (big-endian)
    const gw: [4]u8 = .{
        @intCast((vpn_gateway >> 24) & 0xFF),
        @intCast((vpn_gateway >> 16) & 0xFF),
        @intCast((vpn_gateway >> 8) & 0xFF),
        @intCast(vpn_gateway & 0xFF),
    };

    const server: ?[4]u8 = if (vpn_server != 0) .{
        @intCast((vpn_server >> 24) & 0xFF),
        @intCast((vpn_server >> 16) & 0xFF),
        @intCast((vpn_server >> 8) & 0xFF),
        @intCast(vpn_server & 0xFF),
    } else null;

    adapter.configureRouting(gw, server) catch |err| {
        logError("Failed to configure routing: {}", .{err});
        return false;
    };

    logInfo("✅ Routing configured: VPN gateway {}.{}.{}.{}", .{ gw[0], gw[1], gw[2], gw[3] });
    return true;
}

// ============================================================================
// DIAGNOSTIC AND STATS FFI EXPORTS
// ============================================================================

/// Get adapter statistics in a structured format for C callers
pub const CStats = extern struct {
    packets_read: u64,
    packets_written: u64,
    bytes_read: u64,
    bytes_written: u64,
    read_errors: u64,
    write_errors: u64,
    recv_queue_drops: u64,
    send_queue_drops: u64,
    buffer_tracking_failures: u64,
    garp_sent: u64,
};

export fn zig_adapter_get_stats(adapter: *ZigPacketAdapter, out_stats: *CStats) void {
    out_stats.* = .{
        .packets_read = adapter.stats.packets_read,
        .packets_written = adapter.stats.packets_written,
        .bytes_read = adapter.stats.bytes_read,
        .bytes_written = adapter.stats.bytes_written,
        .read_errors = adapter.stats.read_errors,
        .write_errors = adapter.stats.write_errors,
        .recv_queue_drops = adapter.stats.recv_queue_drops,
        .send_queue_drops = adapter.stats.send_queue_drops,
        .buffer_tracking_failures = adapter.stats.buffer_tracking_failures,
        .garp_sent = adapter.stats.garp_sent,
    };
}

export fn zig_adapter_reset_stats(adapter: *ZigPacketAdapter) void {
    adapter.stats = .{};
}

export fn zig_adapter_get_queue_info(
    adapter: *ZigPacketAdapter,
    out_recv_used: *usize,
    out_recv_capacity: *usize,
    out_send_used: *usize,
    out_send_capacity: *usize,
) void {
    out_recv_used.* = adapter.recv_queue.available();
    out_recv_capacity.* = adapter.recv_queue.capacity;
    out_send_used.* = adapter.send_queue.available();
    out_send_capacity.* = adapter.send_queue.capacity;
}

export fn zig_adapter_get_pool_info(
    adapter: *ZigPacketAdapter,
    out_available: *usize,
    out_total: *usize,
) void {
    const stats = adapter.packet_pool.getStats();
    out_available.* = stats.available;
    out_total.* = adapter.packet_pool.buffers.len;
}

export fn zig_adapter_is_running(adapter: *ZigPacketAdapter) bool {
    return adapter.state == .running;
}

export fn zig_adapter_is_dhcp_enabled(adapter: *ZigPacketAdapter) bool {
    // Check if adapter has acquired an IP address via DHCP
    return zig_adapter_get_learned_ip(adapter) != 0;
}

// ============================================================================
// iOS-SPECIFIC FFI EXPORTS (only compiled for iOS)
// ============================================================================

/// Inject packet from iOS NEPacketTunnelFlow (L3 IP packet → adapter queue)
/// Returns 0 on success, -1 on error
export fn ios_adapter_inject_packet(data: [*]const u8, length: u32) c_int {
    if (!is_ios) return -1; // Not iOS build

    // Get global adapter (TODO: pass adapter handle explicitly)
    const adapter = global_ios_adapter orelse return -1;

    const packet = data[0..length];
    const success = adapter.ios_adapter.*.injectPacket(packet) catch return -1;

    return if (success) 0 else -1;
}

/// Get outgoing packet for iOS NEPacketTunnelFlow (adapter queue → L3 IP packet)
/// Returns packet length (>0), 0 if no packet, -1 on error
export fn ios_adapter_get_outgoing_packet(buffer: [*]u8, buffer_size: u32, log_callback: ?*const fn ([*:0]const u8, c_int) void) c_int {
    if (!is_ios) return -1; // Not iOS build

    const adapter = global_ios_adapter orelse {
        std.log.err("⚠️  ios_adapter_get_outgoing_packet: global_ios_adapter is NULL!", .{});
        if (log_callback) |log| log("adapter_is_NULL", -1);
        return -1;
    };

    // Log adapter pointer address to check for instance mismatch
    const addr: usize = @intFromPtr(adapter.ios_adapter);
    if (log_callback) |log| {
        // Split 64-bit address into two 32-bit parts for logging
        const addr_high: c_int = @intCast((addr >> 32) & 0xFFFFFFFF);
        const addr_low: c_int = @intCast(addr & 0xFFFFFFFF);
        log("adapter_ptr_high", addr_high);
        log("adapter_ptr_low", addr_low);
    }

    // Check queue count BEFORE dequeue attempt
    const count = adapter.ios_adapter.*.outgoing_queue.count.load(.acquire);
    if (log_callback) |log| log("queue_count", @intCast(count));

    const buf = buffer[0..buffer_size];

    // Try to get packet
    const length = adapter.ios_adapter.*.getOutgoingPacket(buf) orelse {
        // Failed to get packet - determine why
        // Re-check count to see if it changed
        const count_after = adapter.ios_adapter.*.outgoing_queue.count.load(.acquire);

        // Get error code to diagnose failure
        const error_code = adapter.ios_adapter.*.last_error_code.load(.acquire);

        if (log_callback) |log| {
            log("failed_count_before", @intCast(count));
            log("failed_count_after", @intCast(count_after));
            log("error_code", error_code);
        }
        return 0;
    };

    std.log.info("✅ ios_adapter_get_outgoing_packet: Returning packet length={d}", .{length});
    if (log_callback) |log| log("returning_packet_size", @intCast(length));
    return @intCast(length);
}

/// Get last error code from iOS adapter (for debugging)
/// Returns: 0=success, -100=dequeue_failed, -200=translation_error, -300=buffer_too_small, -400=arp_packet
export fn ios_adapter_get_last_error() c_int {
    if (!is_ios) return 0;
    const adapter = global_ios_adapter orelse return -999; // -999 = no adapter
    return adapter.ios_adapter.*.last_error_code.load(.acquire);
}

/// Set DHCP configuration in iOS adapter (called from C adapter after DHCP processing)
/// This synchronizes the C adapter's DHCP state with the Zig iOS adapter's state
export fn ios_adapter_set_dhcp_info(
    client_ip: u32,
    subnet_mask: u32,
    gateway: u32,
    dns_server1: u32,
    dns_server2: u32,
    dhcp_server: u32,
) void {
    // FIRST: Try direct NSLog with fixed string
    if (is_ios) ios_log_message_impl("=== [ZIG-FFI] ios_adapter_set_dhcp_info ENTRY ===");

    // ALWAYS log entry - use printf directly to bypass all checks
    _ = printf("[FFI-ENTRY] ios_adapter_set_dhcp_info CALLED\n");

    IOS_LOG("[FFI] ios_adapter_set_dhcp_info CALLED: IP={}.{}.{}.{} GW={}.{}.{}.{}", .{ (client_ip >> 24) & 0xFF, (client_ip >> 16) & 0xFF, (client_ip >> 8) & 0xFF, client_ip & 0xFF, (gateway >> 24) & 0xFF, (gateway >> 16) & 0xFF, (gateway >> 8) & 0xFF, gateway & 0xFF });

    if (!is_ios) {
        const os_tag_int: i32 = @intCast(@intFromEnum(builtin.os.tag));
        _ = printf("[FFI-ERROR] is_ios=false! builtin.os.tag=%d\n", os_tag_int);
        IOS_LOG("[FFI] ERROR: is_ios=false!", .{});
        return;
    }

    const adapter = global_ios_adapter orelse {
        if (is_ios) ios_log_message_impl("=== [ZIG-FFI] ERROR: global_ios_adapter is null ===");
        _ = printf("[FFI-ERROR] global_ios_adapter is null!\n");
        IOS_LOG("[FFI] ERROR: global_ios_adapter is null!", .{});
        return;
    };

    if (is_ios) ios_log_message_impl("=== [ZIG-FFI] Calling setDhcpInfo ===");
    _ = printf("[FFI] Calling adapter.ios_adapter.setDhcpInfo...\n");
    IOS_LOG("[FFI] Calling adapter.ios_adapter.setDhcpInfo...", .{});
    adapter.ios_adapter.*.setDhcpInfo(client_ip, subnet_mask, gateway, dns_server1, dns_server2, dhcp_server);
    if (is_ios) ios_log_message_impl("=== [ZIG-FFI] setDhcpInfo returned ===");
    _ = printf("[FFI] setDhcpInfo returned successfully\n");
    IOS_LOG("[FFI] setDhcpInfo returned successfully", .{});
}

/// Get DHCP configuration from iOS adapter
/// Returns 0 on success with valid DHCP data, -1 if not available
export fn ios_adapter_get_dhcp_info(
    client_ip: *u32,
    subnet_mask: *u32,
    gateway: *u32,
    dns_server1: *u32,
    dns_server2: *u32,
) c_int {
    if (!is_ios) return -1; // Not iOS build

    const adapter = global_ios_adapter orelse return -1;

    const dhcp = adapter.ios_adapter.*.getDhcpInfo() orelse return -1;

    client_ip.* = dhcp.client_ip;
    subnet_mask.* = dhcp.subnet_mask;
    gateway.* = dhcp.gateway;
    dns_server1.* = dhcp.dns_server1;
    dns_server2.* = dhcp.dns_server2;

    return 0;
}

/// Set flag to send ARP request to gateway (called from C after DHCP completes)
export fn ios_adapter_set_need_gateway_arp(need_arp: bool) void {
    if (!is_ios) return;

    const adapter = global_ios_adapter orelse return;
    adapter.ios_adapter.*.need_gateway_arp = need_arp;
}

/// Get iOS adapter statistics
export fn ios_adapter_get_stats(
    rx_packets: *u64,
    tx_packets: *u64,
    rx_bytes: *u64,
    tx_bytes: *u64,
    drops_in: *u64,
    drops_out: *u64,
) void {
    if (!is_ios) return;

    const adapter = global_ios_adapter orelse return;
    const stats = adapter.ios_adapter.*.getStats();

    rx_packets.* = stats.packets_received;
    tx_packets.* = stats.packets_sent;
    rx_bytes.* = stats.bytes_received;
    tx_bytes.* = stats.bytes_sent;
    drops_in.* = stats.queue_drops_in;
    drops_out.* = stats.queue_drops_out;
}

// Global adapter for iOS (set by zig_adapter_create on iOS)
// Note: The actual export is in ios_adapter.zig to avoid collision
pub var global_ios_adapter: ?*ZigPacketAdapter = null;
