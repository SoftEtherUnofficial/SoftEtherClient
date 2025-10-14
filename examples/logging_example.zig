const std = @import("std");
const log = @import("log");

pub fn main() !void {
    // Initialize logger
    log.init(.{
        .level = .debug,
        .use_colors = true,
        .show_timestamps = true,
        .show_category = true,
        .show_file_location = false,
    });

    // Basic logging examples
    log.info(.general, "SoftEtherZig VPN Client starting up", .{});
    log.debug(.general, "Debug mode enabled, version: {s}", .{"0.1.0"});

    // Network operations
    log.info(.network, "Connecting to server: {s}:{d}", .{ "vpn.example.com", 443 });
    log.debug(.network, "Resolving DNS for {s}", .{"vpn.example.com"});
    log.info(.network, "Connected to 203.0.113.42:443", .{});

    // Protocol layer
    log.info(.protocol, "Starting SSL/TLS handshake", .{});
    log.debug(.protocol, "Sending ClientHello (TLS 1.2)", .{});
    log.debug(.protocol, "Received ServerHello", .{});
    log.info(.protocol, "TLS handshake completed", .{});

    // Authentication
    log.info(.auth, "Authenticating user: {s}", .{"testuser"});
    log.debug(.auth, "Using password authentication", .{});
    log.info(.auth, "Authentication successful", .{});

    // Session management
    log.info(.session, "VPN session established", .{});
    log.debug(.session, "Session ID: {x:0>16}", .{0x1234567890ABCDEF});

    // Tunnel/Adapter
    log.info(.tunnel, "Created TUN device: {s}", .{"utun3"});
    log.debug(.adapter, "Device MTU: {d} bytes", .{1500});
    log.debug(.adapter, "Assigned IP: 10.0.0.42/24", .{});

    // Packet handling
    log.debug(.packet, "Received packet: {d} bytes", .{1234});
    log.debug(.packet, "Sent packet: {d} bytes", .{567});

    // Performance monitoring
    var timer = log.Timer.start("Connection Establishment", .performance);
    std.Thread.sleep(50 * std.time.ns_per_ms);
    timer.lap("DNS Resolution", .{});
    std.Thread.sleep(100 * std.time.ns_per_ms);
    timer.lap("TCP Connection", .{});
    std.Thread.sleep(150 * std.time.ns_per_ms);
    timer.lap("TLS Handshake", .{});
    std.Thread.sleep(75 * std.time.ns_per_ms);
    timer.end();

    // Memory tracking
    log.debug(.memory, "Allocated buffer: {d} bytes", .{4096});
    log.debug(.memory, "Total memory usage: {d} KB", .{1234});

    // Warning and errors
    log.warn(.network, "Connection slow, latency: {d}ms", .{250});
    log.warn(.session, "Keepalive timeout, reconnecting...", .{});
    log.err(.auth, "Failed to authenticate, retrying ({d}/3)", .{1});

    // Hex dump example
    const sample_data = [_]u8{
        0x45, 0x00, 0x00, 0x3C, 0x1C, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xB1, 0xE6, 0xC0, 0xA8, 0x01, 0x42,
        0xCB, 0x00, 0x71, 0x2A, 0x00, 0x50, 0xC3, 0xE8,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    };
    log.hexDump(.packet, &sample_data, "IPv4 Packet Header: ");

    // Scoped logger example
    const network_log = log.Scoped(.network);
    network_log.info("Using scoped logger for network module", .{});
    network_log.debug("Bandwidth: {d:.2} Mbps", .{12.34});

    // Change log level dynamically
    log.setLevel(.info);
    log.debug(.general, "This won't be shown (level too low)", .{});
    log.info(.general, "This will be shown", .{});

    // Final status
    log.info(.general, "VPN connection established successfully", .{});
    log.info(.general, "Press Ctrl+C to disconnect", .{});
}
