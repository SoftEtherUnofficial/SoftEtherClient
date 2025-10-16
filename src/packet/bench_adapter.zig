//! Packet Adapter Performance Benchmark
//! Tests single-packet vs batch processing performance
//!
//! Usage: sudo ./bench_adapter
//! (requires root for TUN device creation)

const std = @import("std");
const adapter = @import("adapter");

const ITERATIONS = 10_000;
const BATCH_SIZE = 128;
const PACKET_SIZE = 1500;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== Packet Adapter Performance Benchmark ===\n\n", .{});

    // Create adapter with performance-optimized configuration
    const config = adapter.Config{
        .recv_queue_size = 512,
        .send_queue_size = 512,
        .packet_pool_size = 1024,
        .batch_size = BATCH_SIZE,
        .device_name = "bench_tun",
    };

    std.debug.print("Initializing adapter...\n", .{});
    std.debug.print("  Config: recv={d}, send={d}, pool={d}, batch={d}\n", .{
        config.recv_queue_size,
        config.send_queue_size,
        config.packet_pool_size,
        config.batch_size,
    });

    var adapt = adapter.ZigPacketAdapter.init(allocator, config) catch |err| {
        std.debug.print("Failed to initialize adapter: {}\n", .{err});
        std.debug.print("Note: This benchmark requires root privileges\n", .{});
        return err;
    };
    defer adapt.deinit();

    try adapt.open();

    std.debug.print("Adapter ready!\n\n", .{});

    // Create test packets
    var test_packet: [PACKET_SIZE]u8 = undefined;
    for (&test_packet, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }

    // Benchmark 1: Single packet write
    std.debug.print("Benchmark 1: Single Packet Write\n", .{});
    std.debug.print("  Writing {d} packets one at a time...\n", .{ITERATIONS});

    const start_single = std.time.nanoTimestamp();
    var success_single: usize = 0;

    for (0..ITERATIONS) |_| {
        if (adapt.putPacket(&test_packet)) {
            success_single += 1;
        }
    }

    const end_single = std.time.nanoTimestamp();
    const duration_single_ns = end_single - start_single;
    const duration_single_ms = @as(f64, @floatFromInt(duration_single_ns)) / 1_000_000.0;
    const pps_single = @as(f64, @floatFromInt(success_single)) / (duration_single_ms / 1000.0);
    const ns_per_packet_single = @as(f64, @floatFromInt(duration_single_ns)) / @as(f64, @floatFromInt(success_single));

    std.debug.print("  Duration: {d:.2} ms\n", .{duration_single_ms});
    std.debug.print("  Success: {d}/{d} packets\n", .{ success_single, ITERATIONS });
    std.debug.print("  Rate: {d:.0} packets/sec\n", .{pps_single});
    std.debug.print("  Latency: {d:.2} ns/packet\n\n", .{ns_per_packet_single});

    // Benchmark 2: Batch packet write
    std.debug.print("Benchmark 2: Batch Packet Write\n", .{});
    std.debug.print("  Writing {d} packets in batches of {d}...\n", .{ ITERATIONS, BATCH_SIZE });

    // Prepare batch
    var batch_packets: [BATCH_SIZE][]const u8 = undefined;
    for (&batch_packets) |*pkt| {
        pkt.* = &test_packet;
    }

    const start_batch = std.time.nanoTimestamp();
    var success_batch: usize = 0;

    const num_batches = ITERATIONS / BATCH_SIZE;
    for (0..num_batches) |_| {
        const queued = adapt.putPacketBatch(&batch_packets);
        success_batch += queued;
    }

    const end_batch = std.time.nanoTimestamp();
    const duration_batch_ns = end_batch - start_batch;
    const duration_batch_ms = @as(f64, @floatFromInt(duration_batch_ns)) / 1_000_000.0;
    const pps_batch = @as(f64, @floatFromInt(success_batch)) / (duration_batch_ms / 1000.0);
    const ns_per_packet_batch = @as(f64, @floatFromInt(duration_batch_ns)) / @as(f64, @floatFromInt(success_batch));

    std.debug.print("  Duration: {d:.2} ms\n", .{duration_batch_ms});
    std.debug.print("  Success: {d}/{d} packets\n", .{ success_batch, ITERATIONS });
    std.debug.print("  Rate: {d:.0} packets/sec\n", .{pps_batch});
    std.debug.print("  Latency: {d:.2} ns/packet\n\n", .{ns_per_packet_batch});

    // Benchmark 3: Direct batch write (bypass queue)
    std.debug.print("Benchmark 3: Direct Batch Write (Bypass Queue)\n", .{});
    std.debug.print("  Writing {d} packets directly in batches of {d}...\n", .{ ITERATIONS, BATCH_SIZE });

    const start_direct = std.time.nanoTimestamp();
    var success_direct: usize = 0;

    for (0..num_batches) |_| {
        const written = try adapt.writeBatchDirect(&batch_packets);
        success_direct += written;
    }

    const end_direct = std.time.nanoTimestamp();
    const duration_direct_ns = end_direct - start_direct;
    const duration_direct_ms = @as(f64, @floatFromInt(duration_direct_ns)) / 1_000_000.0;
    const pps_direct = @as(f64, @floatFromInt(success_direct)) / (duration_direct_ms / 1000.0);
    const ns_per_packet_direct = @as(f64, @floatFromInt(duration_direct_ns)) / @as(f64, @floatFromInt(success_direct));

    std.debug.print("  Duration: {d:.2} ms\n", .{duration_direct_ms});
    std.debug.print("  Success: {d}/{d} packets\n", .{ success_direct, ITERATIONS });
    std.debug.print("  Rate: {d:.0} packets/sec\n", .{pps_direct});
    std.debug.print("  Latency: {d:.2} ns/packet\n\n", .{ns_per_packet_direct});

    // Calculate speedups
    const speedup_batch = ns_per_packet_single / ns_per_packet_batch;
    const speedup_direct = ns_per_packet_single / ns_per_packet_direct;

    std.debug.print("=== Performance Comparison ===\n", .{});
    std.debug.print("  Batch vs Single: {d:.2}x faster\n", .{speedup_batch});
    std.debug.print("  Direct vs Single: {d:.2}x faster\n", .{speedup_direct});
    std.debug.print("  Direct vs Batch: {d:.2}x faster\n", .{ns_per_packet_batch / ns_per_packet_direct});

    // Throughput calculation
    const mbps_single = (pps_single * PACKET_SIZE * 8.0) / 1_000_000.0;
    const mbps_batch = (pps_batch * PACKET_SIZE * 8.0) / 1_000_000.0;
    const mbps_direct = (pps_direct * PACKET_SIZE * 8.0) / 1_000_000.0;

    std.debug.print("\n=== Throughput (1500-byte packets) ===\n", .{});
    std.debug.print("  Single: {d:.2} Mbps\n", .{mbps_single});
    std.debug.print("  Batch: {d:.2} Mbps\n", .{mbps_batch});
    std.debug.print("  Direct: {d:.2} Mbps\n\n", .{mbps_direct});

    // Get final stats
    const stats = adapt.getStats();
    std.debug.print("=== Final Statistics ===\n", .{});
    std.debug.print("  Packets written: {d}\n", .{stats.adapter.packets_written.load(.monotonic)});
    std.debug.print("  Bytes written: {d}\n", .{stats.adapter.bytes_written.load(.monotonic)});
    std.debug.print("  Send queue drops: {d}\n", .{stats.adapter.send_queue_drops.load(.monotonic)});
    std.debug.print("  Pool allocated: {d}\n", .{stats.packet_pool.allocated});
    std.debug.print("  Pool freed: {d}\n", .{stats.packet_pool.freed});
    std.debug.print("  Pool reuse rate: {d:.1}%\n\n", .{stats.packet_pool.reuse_rate});

    std.debug.print("Benchmark complete!\n", .{});
}
