//! macOS TUN device - simplified, direct implementation
//! No L2<->L3 translation - just raw IP packets

const std = @import("std");
const posix = std.posix;

const c = @cImport({
    @cInclude("sys/ioctl.h");
    @cInclude("sys/kern_control.h");
    @cInclude("sys/sys_domain.h");
    @cInclude("sys/socket.h");
});

const UTUN_CONTROL_NAME = "com.apple.net.utun_control";
const PF_SYSTEM = 32;
const SYSPROTO_CONTROL = 2;
const UTUN_OPT_IFNAME = 2;
const AF_INET = 2;
const AF_INET6 = 30;

pub const MacOSTunDevice = struct {
    fd: std.posix.fd_t,
    name: [16]u8,
    name_len: usize,
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Open macOS utun device
    pub fn open(allocator: std.mem.Allocator) !Self {
        const fd = try posix.socket(PF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL);
        errdefer posix.close(fd);

        // Get utun control ID
        var info: c.ctl_info = std.mem.zeroes(c.ctl_info);
        @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);

        if (c.ioctl(fd, c.CTLIOCGINFO, &info) != 0) {
            return error.DeviceNotFound;
        }

        // Connect to utun device (unit 0 = auto)
        var addr: c.sockaddr_ctl = std.mem.zeroes(c.sockaddr_ctl);
        addr.sc_len = @sizeOf(c.sockaddr_ctl);
        addr.sc_family = 32; // AF_SYSTEM
        addr.ss_sysaddr = 2; // AF_SYS_CONTROL
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0; // Auto-assign

        const addr_ptr: *const posix.sockaddr = @ptrCast(&addr);
        try posix.connect(fd, addr_ptr, @sizeOf(c.sockaddr_ctl));

        // Get device name
        var ifname: [16]u8 = undefined;
        var ifname_len: u32 = ifname.len;
        const getsockopt_result = std.posix.system.getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            &ifname,
            &ifname_len,
        );

        if (getsockopt_result != 0) {
            return error.GetNameFailed;
        }

        const name_len = std.mem.indexOfScalar(u8, &ifname, 0) orelse ifname.len;

        std.log.info("[TUN] Opened {s}", .{ifname[0..name_len]});

        return Self{
            .fd = fd,
            .name = ifname,
            .name_len = name_len,
            .allocator = allocator,
        };
    }

    /// Read IP packet from TUN device (BLOCKING)
    /// Returns IP packet with 4-byte AF header already stripped
    pub fn readPacket(self: *Self, buffer: []u8) ![]u8 {
        // Read with 4-byte AF header
        var temp_buf: [2048]u8 = undefined;
        const bytes_read = try posix.read(self.fd, &temp_buf);

        if (bytes_read < 4) {
            return error.InvalidPacket;
        }

        // Strip AF header (4 bytes)
        const ip_packet = temp_buf[4..bytes_read];

        if (ip_packet.len > buffer.len) {
            return error.BufferTooSmall;
        }

        @memcpy(buffer[0..ip_packet.len], ip_packet);
        return buffer[0..ip_packet.len];
    }

    /// Write IP packet to TUN device
    /// Automatically adds AF header
    pub fn writePacket(self: *Self, ip_packet: []const u8) !void {
        if (ip_packet.len == 0) {
            return error.InvalidPacket;
        }

        // Determine AF based on IP version
        const version = ip_packet[0] & 0xF0;
        const af: u32 = if (version == 0x40)
            AF_INET
        else if (version == 0x60)
            AF_INET6
        else
            return error.InvalidPacket;

        // Debug: Log write syscall details
        const SyscallDebug = struct {
            var write_count: usize = 0;
        };
        SyscallDebug.write_count += 1;
        if (SyscallDebug.write_count <= 20) {
            const ip_proto = if (ip_packet.len >= 20) ip_packet[9] else 0;
            std.log.info("[SYSCALL #{d}] write() to fd={d} len={d}+4 proto={d}", .{ SyscallDebug.write_count, self.fd, ip_packet.len, ip_proto });
        }

        // Add AF header
        var packet_with_header: [2052]u8 = undefined; // 4 + 2048
        std.mem.writeInt(u32, packet_with_header[0..4], af, .big);
        @memcpy(packet_with_header[4 .. 4 + ip_packet.len], ip_packet);

        const bytes_written = try posix.write(self.fd, packet_with_header[0 .. 4 + ip_packet.len]);
        if (bytes_written != 4 + ip_packet.len) {
            std.log.err("[SYSCALL] Incomplete write! Expected {d}, got {d}", .{ 4 + ip_packet.len, bytes_written });
            return error.IncompleteWrite;
        }

        if (SyscallDebug.write_count <= 20) {
            std.log.info("[SYSCALL #{d}] ✅ write() returned {d} bytes", .{ SyscallDebug.write_count, bytes_written });
        }
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: *Self, enabled: bool) !void {
        const O_NONBLOCK: u32 = 0x0004;
        const flags = try posix.fcntl(self.fd, posix.F.GETFL, 0);
        const new_flags = if (enabled)
            flags | O_NONBLOCK
        else
            flags & ~O_NONBLOCK;
        _ = try posix.fcntl(self.fd, posix.F.SETFL, new_flags);
    }

    pub fn close(self: *Self) void {
        posix.close(self.fd);
    }

    pub fn getName(self: *Self) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getFd(self: *Self) std.posix.fd_t {
        return self.fd;
    }
};
