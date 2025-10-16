//! RC4 Crypto Performance Benchmark
//! Tests RC4, AES-256-GCM, and ChaCha20-Poly1305 encryption/decryption speed
//!
//! Usage: zig build bench-crypto
//! Or: ./zig-out/bin/bench_crypto

const std = @import("std");
const crypto = @import("protocol");

const ITERATIONS = 100_000;
const PACKET_SIZE = 1500; // Standard MTU size

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== Crypto Performance Benchmark ===\n\n", .{});
    std.debug.print("Packet size: {d} bytes\n", .{PACKET_SIZE});
    std.debug.print("Iterations: {d}\n\n", .{ITERATIONS});

    // Create test packet
    var test_packet: [PACKET_SIZE]u8 = undefined;
    for (&test_packet, 0..) |*byte, i| {
        byte.* = @truncate(i);
    }

    // Benchmark RC4
    try benchmarkAlgorithm(allocator, .rc4, "RC4", &test_packet);

    // Benchmark AES-128-GCM
    try benchmarkAlgorithm(allocator, .aes_128_gcm, "AES-128-GCM", &test_packet);

    // Benchmark AES-256-GCM
    try benchmarkAlgorithm(allocator, .aes_256_gcm, "AES-256-GCM", &test_packet);

    // Benchmark ChaCha20-Poly1305
    try benchmarkAlgorithm(allocator, .chacha20_poly1305, "ChaCha20-Poly1305", &test_packet);

    std.debug.print("\n=== Summary ===\n", .{});
    std.debug.print("All algorithms benchmarked successfully.\n", .{});
    std.debug.print("RC4 is fastest but insecure (deprecated).\n", .{});
    std.debug.print("Use AES-256-GCM or ChaCha20-Poly1305 for production.\n\n", .{});
}

fn benchmarkAlgorithm(
    allocator: std.mem.Allocator,
    algorithm: crypto.EncryptionAlgorithm,
    name: []const u8,
    test_packet: []const u8,
) !void {
    std.debug.print("--- {s} ---\n", .{name});

    // Create crypto engine
    var engine = try crypto.CryptoEngine.init(allocator, algorithm);
    defer engine.deinit();

    // Set test keys
    const key_size = algorithm.getKeySize();
    const test_key = try allocator.alloc(u8, key_size);
    defer allocator.free(test_key);
    @memset(test_key, 0x42);

    try engine.encrypt_ctx.setKey(test_key);
    try engine.decrypt_ctx.setKey(test_key);

    const iv_size = algorithm.getIvSize();
    if (iv_size > 0) {
        const test_iv = try allocator.alloc(u8, iv_size);
        defer allocator.free(test_iv);
        @memset(test_iv, 0x99);

        try engine.encrypt_ctx.setIv(test_iv);
        try engine.decrypt_ctx.setIv(test_iv);
    }

    // Benchmark encryption
    const start_encrypt = std.time.nanoTimestamp();
    var last_encrypted: ?crypto.EncryptedPacket = null;

    for (0..ITERATIONS) |_| {
        if (last_encrypted) |*e| e.deinit();
        last_encrypted = try engine.encrypt(test_packet);
    }

    const end_encrypt = std.time.nanoTimestamp();
    const duration_encrypt_ns = end_encrypt - start_encrypt;
    const duration_encrypt_ms = @as(f64, @floatFromInt(duration_encrypt_ns)) / 1_000_000.0;
    const ns_per_encrypt = @as(f64, @floatFromInt(duration_encrypt_ns)) / @as(f64, @floatFromInt(ITERATIONS));
    const encryptions_per_sec = @as(f64, @floatFromInt(ITERATIONS)) / (duration_encrypt_ms / 1000.0);

    std.debug.print("  Encryption:\n", .{});
    std.debug.print("    Duration: {d:.2} ms\n", .{duration_encrypt_ms});
    std.debug.print("    Rate: {d:.0} ops/sec\n", .{encryptions_per_sec});
    std.debug.print("    Latency: {d:.2} ns/packet\n", .{ns_per_encrypt});

    // Benchmark decryption (using last encrypted packet)
    if (last_encrypted) |*encrypted| {
        defer encrypted.deinit();

        // Reset decrypt sequence to match
        engine.decrypt_ctx.sequence = 0;

        const start_decrypt = std.time.nanoTimestamp();

        for (0..ITERATIONS) |_| {
            // Reset sequence each time for consistency
            engine.decrypt_ctx.sequence = encrypted.sequence;

            const decrypted = try engine.decrypt(encrypted);
            allocator.free(decrypted);
        }

        const end_decrypt = std.time.nanoTimestamp();
        const duration_decrypt_ns = end_decrypt - start_decrypt;
        const duration_decrypt_ms = @as(f64, @floatFromInt(duration_decrypt_ns)) / 1_000_000.0;
        const ns_per_decrypt = @as(f64, @floatFromInt(duration_decrypt_ns)) / @as(f64, @floatFromInt(ITERATIONS));
        const decryptions_per_sec = @as(f64, @floatFromInt(ITERATIONS)) / (duration_decrypt_ms / 1000.0);

        std.debug.print("  Decryption:\n", .{});
        std.debug.print("    Duration: {d:.2} ms\n", .{duration_decrypt_ms});
        std.debug.print("    Rate: {d:.0} ops/sec\n", .{decryptions_per_sec});
        std.debug.print("    Latency: {d:.2} ns/packet\n", .{ns_per_decrypt});

        // Calculate throughput
        const encrypt_throughput_mbps = (encryptions_per_sec * PACKET_SIZE * 8.0) / 1_000_000.0;
        const decrypt_throughput_mbps = (decryptions_per_sec * PACKET_SIZE * 8.0) / 1_000_000.0;

        std.debug.print("  Throughput:\n", .{});
        std.debug.print("    Encrypt: {d:.2} Mbps\n", .{encrypt_throughput_mbps});
        std.debug.print("    Decrypt: {d:.2} Mbps\n", .{decrypt_throughput_mbps});

        // Total overhead
        const total_overhead_ns = ns_per_encrypt + ns_per_decrypt;
        std.debug.print("  Total overhead: {d:.2} ns/packet\n\n", .{total_overhead_ns});
    }
}
