//! Android TUN Adapter
//!
//! This module integrates with Android VpnService (ParcelFileDescriptor)
//! and uses deps/taptun for L2↔L3 protocol translation.
//!
//! Architecture:
//!   VpnService (Kotlin/Java)
//!     ↓ file descriptor (ParcelFileDescriptor)
//!   Android TUN Adapter (this file)
//!     ↓ L2↔L3 translation
//!   deps/taptun (L2L3Translator, ArpHandler, DhcpClient)
//!     ↓ Ethernet frames
//!   SoftEther VPN Core

const std = @import("std");
const builtin = @import("builtin");
const taptun = @import("taptun");

// Ensure we're building for Android
comptime {
    if (builtin.os.tag != .linux or builtin.abi != .android) {
        @compileError("This module is only for Android");
    }
}

/// Android VPN Device using VpnService
pub const AndroidVpnDevice = struct {
    allocator: std.mem.Allocator,

    // File descriptor from VpnService.establish()
    fd: std.posix.fd_t,

    // TapTun L2↔L3 translator
    translator: *taptun.L2L3Translator,

    // Configuration
    mtu: u16 = 1500,
    mac_address: [6]u8,

    // Statistics
    bytes_read: u64 = 0,
    bytes_written: u64 = 0,
    packets_read: u64 = 0,
    packets_written: u64 = 0,

    /// Initialize Android VPN device
    pub fn init(
        allocator: std.mem.Allocator,
        fd: std.posix.fd_t,
        mac_address: [6]u8,
    ) !*AndroidVpnDevice {
        const self = try allocator.create(AndroidVpnDevice);
        errdefer allocator.destroy(self);

        // Create L2L3Translator
        const translator = try allocator.create(taptun.L2L3Translator);
        errdefer allocator.destroy(translator);

        translator.* = try taptun.L2L3Translator.init(allocator, .{
            .our_mac = mac_address,
            .learn_ip = true, // Learn our IP from outgoing packets
            .learn_gateway_mac = true, // Learn gateway MAC from ARP
            .handle_arp = true, // Handle ARP requests/replies
            .verbose = false, // Disable verbose logging on mobile
        });

        self.* = .{
            .allocator = allocator,
            .fd = fd,
            .translator = translator,
            .mac_address = mac_address,
        };

        return self;
    }

    /// Clean up resources
    pub fn deinit(self: *AndroidVpnDevice) void {
        self.translator.deinit();
        self.allocator.destroy(self.translator);
        self.allocator.destroy(self);
    }

    /// Read IP packet from TUN device
    /// Android VpnService provides IP packets directly (no Ethernet headers)
    /// Returns number of bytes read
    pub fn read(self: *AndroidVpnDevice, buffer: []u8) !usize {
        // Read IP packet from file descriptor
        const bytes_read = try std.posix.read(self.fd, buffer);

        if (bytes_read > 0) {
            self.packets_read += 1;
            self.bytes_read += bytes_read;

            // Optional: Learn our IP from outgoing packets
            // The translator can extract source IP from IP headers
            _ = self.translator.learnIpFromPacket(buffer[0..bytes_read]) catch |err| {
                std.log.debug("Failed to learn IP: {}", .{err});
            };
        }

        return bytes_read;
    }

    /// Write IP packet to TUN device
    /// Android VpnService expects IP packets directly (no Ethernet headers)
    /// Returns number of bytes written
    pub fn write(self: *AndroidVpnDevice, data: []const u8) !usize {
        // Write IP packet to file descriptor
        const bytes_written = try std.posix.write(self.fd, data);

        if (bytes_written > 0) {
            self.packets_written += 1;
            self.bytes_written += bytes_written;
        }

        return bytes_written;
    }

    /// Convert IP packet to Ethernet frame (if needed for SoftEther)
    /// Most Android usage won't need this, but included for compatibility
    pub fn ipToEthernet(self: *AndroidVpnDevice, ip_packet: []const u8) ![]u8 {
        return try self.translator.ipToEthernet(ip_packet);
    }

    /// Convert Ethernet frame to IP packet (if needed for SoftEther)
    /// Most Android usage won't need this, but included for compatibility
    pub fn ethernetToIp(self: *AndroidVpnDevice, eth_frame: []const u8) !?[]u8 {
        return try self.translator.ethernetToIp(eth_frame);
    }

    /// Get learned IP address (if any)
    pub fn getLearnedIp(self: *AndroidVpnDevice) ?u32 {
        return self.translator.our_ip;
    }

    /// Get learned gateway MAC (if any)
    pub fn getGatewayMac(self: *AndroidVpnDevice) ?[6]u8 {
        return self.translator.gateway_mac;
    }

    /// Get statistics
    pub fn getStats(self: *AndroidVpnDevice) Stats {
        return .{
            .bytes_read = self.bytes_read,
            .bytes_written = self.bytes_written,
            .packets_read = self.packets_read,
            .packets_written = self.packets_written,
            .translator_stats = .{
                .packets_l2_to_l3 = self.translator.packets_translated_l2_to_l3,
                .packets_l3_to_l2 = self.translator.packets_translated_l3_to_l2,
                .arp_requests_handled = self.translator.arp_requests_handled,
                .arp_replies_learned = self.translator.arp_replies_learned,
            },
        };
    }

    pub const Stats = struct {
        bytes_read: u64,
        bytes_written: u64,
        packets_read: u64,
        packets_written: u64,
        translator_stats: TranslatorStats,
    };

    pub const TranslatorStats = struct {
        packets_l2_to_l3: u64,
        packets_l3_to_l2: u64,
        arp_requests_handled: u64,
        arp_replies_learned: u64,
    };
};

/// C API for JNI bridge
/// Opaque handle for Android VPN device
pub const AndroidVpnDeviceHandle = ?*anyopaque;

/// Create Android VPN device from file descriptor
export fn android_vpn_device_create(
    fd: c_int,
    mac_address: [*]const u8,
) callconv(.c) AndroidVpnDeviceHandle {
    const allocator = std.heap.c_allocator;

    var mac: [6]u8 = undefined;
    @memcpy(&mac, mac_address[0..6]);

    const device = AndroidVpnDevice.init(
        allocator,
        @intCast(fd),
        mac,
    ) catch return null;

    return @ptrCast(device);
}

/// Destroy Android VPN device
export fn android_vpn_device_destroy(handle: AndroidVpnDeviceHandle) callconv(.c) void {
    if (handle) |h| {
        const device: *AndroidVpnDevice = @ptrCast(@alignCast(h));
        device.deinit();
    }
}

/// Read packet from device
export fn android_vpn_device_read(
    handle: AndroidVpnDeviceHandle,
    buffer: [*]u8,
    buffer_len: usize,
) callconv(.c) isize {
    if (handle == null) return -1;

    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle.?));
    const buf_slice = buffer[0..buffer_len];

    const bytes_read = device.read(buf_slice) catch |err| {
        std.log.err("Android device read error: {}", .{err});
        return -1;
    };

    return @intCast(bytes_read);
}

/// Write packet to device
export fn android_vpn_device_write(
    handle: AndroidVpnDeviceHandle,
    data: [*]const u8,
    data_len: usize,
) callconv(.c) isize {
    if (handle == null) return -1;

    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle.?));
    const data_slice = data[0..data_len];

    const bytes_written = device.write(data_slice) catch |err| {
        std.log.err("Android device write error: {}", .{err});
        return -1;
    };

    return @intCast(bytes_written);
}

/// Get device statistics
export fn android_vpn_device_get_stats(
    handle: AndroidVpnDeviceHandle,
    out_stats: ?*AndroidVpnDevice.Stats,
) callconv(.c) c_int {
    if (handle == null or out_stats == null) return -1;

    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle.?));
    out_stats.?.* = device.getStats();

    return 0;
}

/// Get learned IP address (network byte order)
export fn android_vpn_device_get_learned_ip(handle: AndroidVpnDeviceHandle) callconv(.c) u32 {
    if (handle == null) return 0;

    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle.?));
    return device.getLearnedIp() orelse 0;
}

/// Get learned gateway MAC
export fn android_vpn_device_get_gateway_mac(
    handle: AndroidVpnDeviceHandle,
    out_mac: [*]u8,
) callconv(.c) bool {
    if (handle == null or out_mac == null) return false;

    const device: *AndroidVpnDevice = @ptrCast(@alignCast(handle.?));

    if (device.getGatewayMac()) |mac| {
        @memcpy(out_mac[0..6], &mac);
        return true;
    }

    return false;
}
