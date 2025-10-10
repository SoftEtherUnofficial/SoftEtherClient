//! Cedar Zig Wrapper Example
//!
//! Demonstrates using the Cedar protocol library from Zig.

const std = @import("std");
const cedar = @import("../src/cedar/wrapper.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    // Print version info
    try stdout.print("Cedar Version: {s}\n", .{cedar.getVersion()});
    try stdout.print("Protocol Version: {d}\n\n", .{cedar.getProtocolVersion()});

    // Example 1: Create and inspect a VPN packet
    try stdout.print("=== Packet Example ===\n", .{});
    try packetExample(stdout);

    // Example 2: TLS connection state
    try stdout.print("\n=== TLS Example ===\n", .{});
    try tlsExample(stdout);

    // Example 3: Compression
    try stdout.print("\n=== Compression Example ===\n", .{});
    try compressionExample(stdout);

    // Example 4: UDP Acceleration
    try stdout.print("\n=== UDP Acceleration Example ===\n", .{});
    try udpAccelExample(stdout);

    // Example 5: NAT Traversal
    try stdout.print("\n=== NAT Traversal Example ===\n", .{});
    try natTraversalExample(stdout);

    try stdout.print("\nAll examples completed successfully!\n", .{});
}

fn packetExample(writer: anytype) !void {
    // Create a new packet for authentication
    var packet = try cedar.Packet.init("hello");
    defer packet.deinit();

    // Add parameters
    try packet.addInt("protocol_version", cedar.getProtocolVersion());
    try packet.addString("client_name", "Cedar-Zig Example");
    try packet.addString("client_version", "1.0.0");
    try packet.addInt("client_id", 12345);

    // Read parameters back
    const protocol_ver = try packet.getInt("protocol_version");
    try writer.print("  Protocol Version: {d}\n", .{protocol_ver});

    var name_buf: [256]u8 = undefined;
    const client_name = try packet.getString("client_name", &name_buf);
    try writer.print("  Client Name: {s}\n", .{client_name});

    var ver_buf: [256]u8 = undefined;
    const client_version = try packet.getString("client_version", &ver_buf);
    try writer.print("  Client Version: {s}\n", .{client_version});

    const client_id = try packet.getInt("client_id");
    try writer.print("  Client ID: {d}\n", .{client_id});
}

fn tlsExample(writer: anytype) !void {
    // Create TLS connection
    var tls = try cedar.TlsConnection.init();
    defer tls.deinit();

    // Check initial state
    const state = tls.getState();
    try writer.print("  TLS State: {s}\n", .{@tagName(state)});

    // Demonstrate encryption (will fail in Disconnected state, but shows API)
    const plaintext = "Hello, VPN!";
    var ciphertext: [1024]u8 = undefined;

    if (tls.encrypt(plaintext, &ciphertext)) |bytes_written| {
        try writer.print("  Encrypted {d} bytes\n", .{bytes_written});
    } else |err| {
        try writer.print("  Encryption failed (expected in disconnected state): {s}\n", .{@errorName(err)});
    }
}

fn compressionExample(writer: anytype) !void {
    // Test different compression algorithms
    const algorithms = [_]struct { alg: cedar.CompressionAlgorithm, name: []const u8 }{
        .{ .alg = .None, .name = "None" },
        .{ .alg = .Deflate, .name = "Deflate" },
        .{ .alg = .Gzip, .name = "Gzip" },
        .{ .alg = .Lz4, .name = "LZ4" },
    };

    const input = "This is test data for compression. It should compress well if it's repetitive. " ++
        "This is test data for compression. It should compress well if it's repetitive. " ++
        "This is test data for compression. It should compress well if it's repetitive.";

    for (algorithms) |item| {
        var compressor = try cedar.Compressor.init(item.alg);
        defer compressor.deinit();

        var compressed: [4096]u8 = undefined;
        const compressed_len = try compressor.compress(input, &compressed);

        const ratio = @as(f64, @floatFromInt(input.len)) / @as(f64, @floatFromInt(compressed_len));
        try writer.print("  {s}: {d} -> {d} bytes (ratio: {d:.2}x)\n", .{
            item.name,
            input.len,
            compressed_len,
            ratio,
        });

        // Test decompression
        var decompressed: [4096]u8 = undefined;
        const decompressed_len = try compressor.decompress(compressed[0..compressed_len], &decompressed);

        if (decompressed_len == input.len) {
            try writer.print("  {s}: Decompression verified ✓\n", .{item.name});
        } else {
            try writer.print("  {s}: Decompression size mismatch!\n", .{item.name});
        }
    }
}

fn udpAccelExample(writer: anytype) !void {
    // Test different UDP acceleration modes
    const modes = [_]struct { mode: cedar.UdpAccelMode, name: []const u8 }{
        .{ .mode = .Disabled, .name = "Disabled" },
        .{ .mode = .Hybrid, .name = "Hybrid" },
        .{ .mode = .UdpOnly, .name = "UDP-Only" },
    };

    for (modes) |item| {
        var accel = try cedar.UdpAccelerator.init(item.mode);
        defer accel.deinit();

        const healthy = accel.isHealthy();
        try writer.print("  {s} Mode: {s}\n", .{
            item.name,
            if (healthy) "Healthy ✓" else "Not Initialized",
        });
    }
}

fn natTraversalExample(writer: anytype) !void {
    // Create NAT traversal engine
    var nat = try cedar.NatTraversal.init();
    defer nat.deinit();

    // Check if NAT traversal is supported
    const supported = nat.isSupported();
    try writer.print("  NAT Traversal Supported: {s}\n", .{if (supported) "Yes ✓" else "No"});

    // Detect NAT type
    const nat_type = nat.detect();
    try writer.print("  Detected NAT Type: {s}\n", .{@tagName(nat_type)});

    // Provide recommendations based on NAT type
    switch (nat_type) {
        .None => try writer.print("  → No NAT detected, direct connection possible\n", .{}),
        .FullCone => try writer.print("  → Full Cone NAT, best for P2P\n", .{}),
        .RestrictedCone => try writer.print("  → Restricted Cone NAT, P2P possible with coordination\n", .{}),
        .PortRestrictedCone => try writer.print("  → Port-Restricted Cone NAT, may need STUN\n", .{}),
        .Symmetric => try writer.print("  → Symmetric NAT, most restrictive, may need relay\n", .{}),
        .Unknown => try writer.print("  → Unknown NAT configuration\n", .{}),
    }
}

// Integration test demonstrating full session lifecycle
fn sessionLifecycleExample(writer: anytype) !void {
    try writer.print("\n=== Session Lifecycle Example ===\n", .{});

    // Create session (would connect to actual server in production)
    const session = cedar.Session.init("vpn.example.com", 443, "DEFAULT") catch |err| {
        try writer.print("  Session creation failed (expected without server): {s}\n", .{@errorName(err)});
        return;
    };
    defer session.deinit();

    // Check status
    const status = session.getStatus();
    try writer.print("  Session Status: {s}\n", .{@tagName(status)});

    // Get statistics
    if (session.getStats()) |stats| {
        try writer.print("  Statistics:\n", .{});
        try writer.print("    Bytes Sent: {d}\n", .{stats.bytes_sent});
        try writer.print("    Bytes Received: {d}\n", .{stats.bytes_received});
        try writer.print("    Packets Sent: {d}\n", .{stats.packets_sent});
        try writer.print("    Packets Received: {d}\n", .{stats.packets_received});
        try writer.print("    Duration: {d}s\n", .{stats.duration_secs});
        try writer.print("    Idle Time: {d}s\n", .{stats.idle_time_secs});
    } else |err| {
        try writer.print("  Stats retrieval failed: {s}\n", .{@errorName(err)});
    }
}
