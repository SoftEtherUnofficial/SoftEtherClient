// Session Main Packet Processing Loop
// Ported from src/bridge/Cedar/Session.c SessionMain()
// This is the CORE data path: TUN ↔ VPN Server packet forwarding

const std = @import("std");
const Allocator = std.mem.Allocator;

// Import protocol modules
const packet_mod = @import("packet.zig");
const adapter_mod = @import("../packet/adapter.zig");

// Type aliases
const Packet = packet_mod.Packet;
const PacketAdapter = adapter_mod.ZigPacketAdapter;

/// Session statistics tracked during packet processing
pub const SessionStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,

    broadcast_sent: u64 = 0,
    unicast_sent: u64 = 0,
    broadcast_received: u64 = 0,
    unicast_received: u64 = 0,

    packets_dropped: u64 = 0,
    errors: u64 = 0,
};

/// Main packet processing loop configuration
pub const LoopConfig = struct {
    /// Maximum packets to process per iteration
    max_packets_per_iteration: u32 = 16,

    /// Maximum send queue size before dropping packets
    max_send_queue_size: usize = 5_000_000, // 5MB

    /// Enable compression for outgoing packets
    use_compression: bool = false,

    /// Enable QoS priority handling
    enable_qos: bool = true,

    /// Sleep duration when no packets (microseconds)
    idle_sleep_us: u64 = 1000, // 1ms
};

/// Session packet processing context
pub const SessionLoop = struct {
    allocator: Allocator,
    adapter: *PacketAdapter,
    config: LoopConfig,
    stats: SessionStats,
    running: std.atomic.Value(bool),

    // Queue sizes
    current_send_queue_size: usize = 0,

    pub fn init(
        allocator: Allocator,
        adapter: *PacketAdapter,
        config: LoopConfig,
    ) !*SessionLoop {
        const self = try allocator.create(SessionLoop);
        self.* = .{
            .allocator = allocator,
            .adapter = adapter,
            .config = config,
            .stats = .{},
            .running = std.atomic.Value(bool).init(true),
        };
        return self;
    }

    pub fn deinit(self: *SessionLoop) void {
        self.running.store(false, .release);
        self.allocator.destroy(self);
    }

    /// Main packet processing loop
    /// This is the core function ported from SessionMain() in Session.c
    pub fn run(self: *SessionLoop) !void {
        std.log.info("Session loop starting...", .{});

        var iteration: u64 = 0;

        while (self.running.load(.acquire)) {
            iteration += 1;

            // Process incoming packets from VPN server → TUN device
            try self.processIncomingPackets();

            // Process outgoing packets from TUN device → VPN server
            try self.processOutgoingPackets();

            // Periodic maintenance every 100 iterations (~100ms)
            if (iteration % 100 == 0) {
                self.performMaintenance();
            }

            // Brief sleep to prevent busy-waiting
            std.time.sleep(self.config.idle_sleep_us * std.time.ns_per_us);
        }

        std.log.info("Session loop stopped. Stats: sent={d}, received={d}", .{
            self.stats.packets_sent,
            self.stats.packets_received,
        });
    }

    /// Process packets coming FROM the VPN server TO the TUN device
    /// Corresponds to ReceivedBlocks processing in SessionMain()
    fn processIncomingPackets(self: *SessionLoop) !void {
        // TODO: This needs to interface with the Connection object
        // For now, this is a placeholder showing the structure

        // In C code (Session.c lines 380-450):
        // 1. Get blocks from c->ReceivedBlocks queue
        // 2. Decompress if needed
        // 3. Call pa->PutPacket(s, data, size) to write to TUN

        // Zig implementation:
        // var blocks_processed: u32 = 0;
        // while (blocks_processed < self.config.max_packets_per_iteration) : (blocks_processed += 1) {
        //     const block = connection.receiveBlock() catch break;
        //     defer block.deinit();
        //
        //     // Write to TUN device
        //     self.adapter.putPacket(block.data) catch |err| {
        //         std.log.err("Failed to write packet to TUN: {}", .{err});
        //         self.stats.errors += 1;
        //         continue;
        //     };
        //
        //     self.stats.packets_received += 1;
        //     self.stats.bytes_received += block.data.len;
        //     self.updateTrafficStats(block.data, false); // false = incoming
        // }

        // Placeholder: will be implemented when Connection is ported
        _ = self;
    }

    /// Process packets coming FROM the TUN device TO the VPN server
    /// Corresponds to pa->GetNextPacket processing in SessionMain()
    fn processOutgoingPackets(self: *SessionLoop) !void {
        var packets_read: u32 = 0;

        // Read packets from TUN device (Session.c lines 450-550)
        while (packets_read < self.config.max_packets_per_iteration) : (packets_read += 1) {
            // Check send queue size limit
            if (self.current_send_queue_size > self.config.max_send_queue_size) {
                // Queue full, stop reading more packets
                break;
            }

            // Get next packet from TUN device
            const packet_data = self.adapter.getNextPacket() catch |err| {
                if (err == error.NoPacketsAvailable) break;

                std.log.err("Failed to read packet from TUN: {}", .{err});
                self.stats.errors += 1;
                return err;
            };

            if (packet_data.len == 0) break; // No more packets

            defer self.allocator.free(packet_data);

            // Update statistics
            self.stats.packets_sent += 1;
            self.stats.bytes_sent += packet_data.len;
            self.updateTrafficStats(packet_data, true); // true = outgoing

            // TODO: Queue packet for transmission to VPN server
            // In C code: creates BLOCK, adds to c->SendBlocks queue
            // Zig implementation will:
            // 1. Create packet with compression flag if enabled
            // 2. Add to send queue with QoS priority
            // 3. Update current_send_queue_size

            self.current_send_queue_size += packet_data.len;

            // Placeholder: actual queueing will be implemented with Connection
            std.log.debug("Packet queued for send: {d} bytes", .{packet_data.len});
        }
    }

    /// Update traffic statistics based on packet type
    fn updateTrafficStats(self: *SessionLoop, packet_data: []const u8, outgoing: bool) void {
        if (packet_data.len < 14) return; // Not a valid Ethernet frame

        // Check if broadcast (first byte has bit 0 set)
        const is_broadcast = (packet_data[0] & 0x01) != 0;

        if (outgoing) {
            if (is_broadcast) {
                self.stats.broadcast_sent += 1;
            } else {
                self.stats.unicast_sent += 1;
            }
        } else {
            if (is_broadcast) {
                self.stats.broadcast_received += 1;
            } else {
                self.stats.unicast_received += 1;
            }
        }
    }

    /// Periodic maintenance tasks
    fn performMaintenance(self: *SessionLoop) void {
        // Log stats every 10 seconds (10000 iterations * 1ms = 10s)
        if (self.stats.packets_sent % 1000 == 0 and self.stats.packets_sent > 0) {
            std.log.debug("Session stats: TX={d}/{d}KB RX={d}/{d}KB queue={d}KB", .{
                self.stats.packets_sent,
                self.stats.bytes_sent / 1024,
                self.stats.packets_received,
                self.stats.bytes_received / 1024,
                self.current_send_queue_size / 1024,
            });
        }
    }

    /// Stop the session loop gracefully
    pub fn stop(self: *SessionLoop) void {
        self.running.store(false, .release);
    }

    /// Get current statistics
    pub fn getStats(self: *const SessionLoop) SessionStats {
        return self.stats;
    }
};

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if packet should get QoS priority
/// Ported from IsPriorityHighestPacketForQoS() in Session.c
pub fn isPriorityPacket(packet_data: []const u8) bool {
    if (packet_data.len < 14) return false;

    // Ethernet frame check
    const ethertype = std.mem.readInt(u16, packet_data[12..14], .big);

    // IPv4 (0x0800)
    if (ethertype == 0x0800 and packet_data.len >= 34) {
        const protocol = packet_data[23];

        // TCP (6) or UDP (17)
        if (protocol == 6 or protocol == 17) {
            const src_port = std.mem.readInt(u16, packet_data[34..36], .big);
            const dst_port = std.mem.readInt(u16, packet_data[36..38], .big);

            // DNS (53), SSH (22), RDP (3389), VoIP ports
            const priority_ports = [_]u16{ 53, 22, 3389, 5060, 5061 };
            for (priority_ports) |port| {
                if (src_port == port or dst_port == port) {
                    return true;
                }
            }
        }
    }

    return false;
}

/// Create a send block with optional compression
/// Corresponds to NewBlock() in Session.c
pub fn createSendBlock(
    allocator: Allocator,
    packet_data: []const u8,
    use_compression: bool,
) ![]u8 {
    _ = use_compression; // TODO: Implement compression
    // For now, just copy the data
    const block = try allocator.alloc(u8, packet_data.len);
    @memcpy(block, packet_data);
    return block;
}

// ============================================================================
// Integration Notes
// ============================================================================

// This module provides the core packet processing loop structure.
// To complete the integration:
//
// 1. Connection Integration:
//    - processIncomingPackets() needs connection.receiveBlock()
//    - processOutgoingPackets() needs connection.sendBlock()
//    - See src/net/connection.zig
//
// 2. Packet Adapter Integration:
//    - getNextPacket() reads from TUN device
//    - putPacket() writes to TUN device
//    - See src/packet/adapter.zig
//
// 3. Session Integration:
//    - session.zig should create SessionLoop
//    - Run loop in separate thread
//    - Handle graceful shutdown
//
// 4. Statistics Reporting:
//    - SessionStats should be exposed via session.getStats()
//    - Used by CLI status display
//
// 5. Error Handling:
//    - Device driver errors should set pa_fail flag
//    - Queue overflow should trigger packet drops
//    - Connection errors should break loop
