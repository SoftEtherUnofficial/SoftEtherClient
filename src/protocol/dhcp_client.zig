/// DHCP Client Implementation
///
/// Implements DHCP state machine for automatic IP configuration:
/// DISCOVER → OFFER → REQUEST → ACK
///
/// RFC 2131: Dynamic Host Configuration Protocol
/// RFC 2132: DHCP Options and BOOTP Vendor Extensions
const std = @import("std");

/// DHCP Message Types (RFC 2132, Section 9.6)
pub const MessageType = enum(u8) {
    DISCOVER = 1,
    OFFER = 2,
    REQUEST = 3,
    DECLINE = 4,
    ACK = 5,
    NAK = 6,
    RELEASE = 7,
    INFORM = 8,
};

/// DHCP Options (RFC 2132)
pub const Option = enum(u8) {
    PAD = 0,
    SUBNET_MASK = 1,
    ROUTER = 3,
    DNS_SERVER = 6,
    HOSTNAME = 12,
    REQUESTED_IP = 50,
    LEASE_TIME = 51,
    MESSAGE_TYPE = 53,
    SERVER_ID = 54,
    PARAMETER_REQUEST_LIST = 55,
    RENEWAL_TIME = 58,
    REBINDING_TIME = 59,
    CLIENT_ID = 61,
    END = 255,
};

/// DHCP Packet Format (RFC 2131, Section 2)
pub const DhcpPacket = extern struct {
    op: u8, // 1 = BOOTREQUEST, 2 = BOOTREPLY
    htype: u8, // Hardware type (1 = Ethernet)
    hlen: u8, // Hardware address length (6 for Ethernet)
    hops: u8, // Client sets to 0
    xid: u32, // Transaction ID
    secs: u16, // Seconds elapsed
    flags: u16, // Flags (0x8000 = broadcast)
    ciaddr: u32, // Client IP address
    yiaddr: u32, // Your (client) IP address
    siaddr: u32, // Server IP address
    giaddr: u32, // Gateway IP address
    chaddr: [16]u8, // Client hardware address
    sname: [64]u8, // Server hostname
    file: [128]u8, // Boot filename
    magic: u32, // Magic cookie (0x63825363)
    options: [312]u8, // Variable options

    pub const MAGIC_COOKIE: u32 = 0x63825363;
    pub const BOOTREQUEST: u8 = 1;
    pub const BOOTREPLY: u8 = 2;
    pub const ETHERNET: u8 = 1;
    pub const BROADCAST_FLAG: u16 = 0x8000;

    pub fn init() DhcpPacket {
        return .{
            .op = BOOTREQUEST,
            .htype = ETHERNET,
            .hlen = 6,
            .hops = 0,
            .xid = 0,
            .secs = 0,
            .flags = 0,
            .ciaddr = 0,
            .yiaddr = 0,
            .siaddr = 0,
            .giaddr = 0,
            .chaddr = [_]u8{0} ** 16,
            .sname = [_]u8{0} ** 64,
            .file = [_]u8{0} ** 128,
            .magic = MAGIC_COOKIE,
            .options = [_]u8{0} ** 312,
        };
    }
};

/// DHCP Lease Information
pub const Lease = struct {
    ip_address: [4]u8,
    subnet_mask: [4]u8,
    gateway: [4]u8,
    dns_servers: std.ArrayList([4]u8),
    lease_time: u32, // seconds
    renewal_time: u32, // T1
    rebinding_time: u32, // T2
    server_id: [4]u8,
    obtained_at: i64, // Unix timestamp

    pub fn deinit(self: *Lease, allocator: std.mem.Allocator) void {
        self.dns_servers.deinit(allocator);
    }

    pub fn isExpired(self: Lease) bool {
        const now = std.time.timestamp();
        return (now - self.obtained_at) >= self.lease_time;
    }

    pub fn needsRenewal(self: Lease) bool {
        const now = std.time.timestamp();
        return (now - self.obtained_at) >= self.renewal_time;
    }

    pub fn needsRebinding(self: Lease) bool {
        const now = std.time.timestamp();
        return (now - self.obtained_at) >= self.rebinding_time;
    }
};

/// DHCP Client State Machine
pub const DhcpClient = struct {
    allocator: std.mem.Allocator,
    mac_address: [6]u8,
    transaction_id: u32,
    lease: ?Lease = null,
    state: State,

    const Self = @This();

    pub const State = enum {
        INIT,
        SELECTING,
        REQUESTING,
        BOUND,
        RENEWING,
        REBINDING,
        INIT_REBOOT,
    };

    pub fn init(allocator: std.mem.Allocator, mac_address: [6]u8) !*Self {
        const self = try allocator.create(Self);

        // Generate random transaction ID
        var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
        const random = prng.random();

        self.* = .{
            .allocator = allocator,
            .mac_address = mac_address,
            .transaction_id = random.int(u32),
            .state = .INIT,
        };
        return self;
    }

    /// Create DHCP DISCOVER packet
    pub fn createDiscover(self: *Self) !DhcpPacket {
        var packet = DhcpPacket.init();
        packet.xid = self.transaction_id;
        packet.flags = DhcpPacket.BROADCAST_FLAG;
        @memcpy(packet.chaddr[0..6], &self.mac_address);

        // Add options
        var offset: usize = 0;

        // Message Type = DISCOVER
        packet.options[offset] = @intFromEnum(Option.MESSAGE_TYPE);
        offset += 1;
        packet.options[offset] = 1; // length
        offset += 1;
        packet.options[offset] = @intFromEnum(MessageType.DISCOVER);
        offset += 1;

        // Parameter Request List
        packet.options[offset] = @intFromEnum(Option.PARAMETER_REQUEST_LIST);
        offset += 1;
        packet.options[offset] = 4; // length
        offset += 1;
        packet.options[offset] = @intFromEnum(Option.SUBNET_MASK);
        offset += 1;
        packet.options[offset] = @intFromEnum(Option.ROUTER);
        offset += 1;
        packet.options[offset] = @intFromEnum(Option.DNS_SERVER);
        offset += 1;
        packet.options[offset] = @intFromEnum(Option.LEASE_TIME);
        offset += 1;

        // End Option
        packet.options[offset] = @intFromEnum(Option.END);

        self.state = .SELECTING;
        return packet;
    }

    /// Parse DHCP OFFER packet
    pub fn parseOffer(self: *Self, packet: *const DhcpPacket) !void {
        if (packet.op != DhcpPacket.BOOTREPLY) return error.InvalidPacket;
        if (packet.xid != self.transaction_id) return error.TransactionMismatch;

        // Extract offered IP
        const offered_ip = std.mem.toBytes(packet.yiaddr);
        std.log.info("📬 Received DHCP OFFER: {d}.{d}.{d}.{d}", .{
            offered_ip[0],
            offered_ip[1],
            offered_ip[2],
            offered_ip[3],
        });

        self.state = .REQUESTING;
    }

    /// Create DHCP REQUEST packet
    pub fn createRequest(self: *Self, offered_ip: [4]u8, server_id: [4]u8) !DhcpPacket {
        var packet = DhcpPacket.init();
        packet.xid = self.transaction_id;
        packet.flags = DhcpPacket.BROADCAST_FLAG;
        @memcpy(packet.chaddr[0..6], &self.mac_address);

        // Add options
        var offset: usize = 0;

        // Message Type = REQUEST
        packet.options[offset] = @intFromEnum(Option.MESSAGE_TYPE);
        offset += 1;
        packet.options[offset] = 1;
        offset += 1;
        packet.options[offset] = @intFromEnum(MessageType.REQUEST);
        offset += 1;

        // Requested IP Address
        packet.options[offset] = @intFromEnum(Option.REQUESTED_IP);
        offset += 1;
        packet.options[offset] = 4;
        offset += 1;
        @memcpy(packet.options[offset .. offset + 4], &offered_ip);
        offset += 4;

        // Server Identifier
        packet.options[offset] = @intFromEnum(Option.SERVER_ID);
        offset += 1;
        packet.options[offset] = 4;
        offset += 1;
        @memcpy(packet.options[offset .. offset + 4], &server_id);
        offset += 4;

        // End Option
        packet.options[offset] = @intFromEnum(Option.END);

        return packet;
    }

    /// Parse DHCP ACK packet and extract lease info
    pub fn parseAck(self: *Self, packet: *const DhcpPacket) !void {
        if (packet.op != DhcpPacket.BOOTREPLY) return error.InvalidPacket;
        if (packet.xid != self.transaction_id) return error.TransactionMismatch;

        // Extract assigned IP
        const ip_bytes = std.mem.toBytes(packet.yiaddr);
        var ip_address: [4]u8 = undefined;
        @memcpy(&ip_address, ip_bytes[0..4]);

        // Parse options to extract lease info
        var lease = Lease{
            .ip_address = ip_address,
            .subnet_mask = [_]u8{ 255, 255, 255, 0 }, // default
            .gateway = [_]u8{ 0, 0, 0, 0 },
            .dns_servers = .{},
            .lease_time = 86400, // default 24 hours
            .renewal_time = 43200, // default T1 = 50%
            .rebinding_time = 75600, // default T2 = 87.5%
            .server_id = [_]u8{ 0, 0, 0, 0 },
            .obtained_at = std.time.timestamp(),
        };

        var offset: usize = 0;
        while (offset < packet.options.len) {
            const opt = packet.options[offset];
            if (opt == @intFromEnum(Option.END)) break;
            if (opt == @intFromEnum(Option.PAD)) {
                offset += 1;
                continue;
            }

            offset += 1;
            const len = packet.options[offset];
            offset += 1;

            switch (@as(Option, @enumFromInt(opt))) {
                .SUBNET_MASK => {
                    if (len == 4) @memcpy(&lease.subnet_mask, packet.options[offset .. offset + 4]);
                },
                .ROUTER => {
                    if (len >= 4) @memcpy(&lease.gateway, packet.options[offset .. offset + 4]);
                },
                .DNS_SERVER => {
                    var i: usize = 0;
                    while (i < len) : (i += 4) {
                        if (i + 4 <= len) {
                            var dns: [4]u8 = undefined;
                            @memcpy(&dns, packet.options[offset + i .. offset + i + 4]);
                            try lease.dns_servers.append(self.allocator, dns);
                        }
                    }
                },
                .LEASE_TIME => {
                    if (len == 4) {
                        lease.lease_time = std.mem.readInt(u32, packet.options[offset .. offset + 4][0..4], .big);
                    }
                },
                .SERVER_ID => {
                    if (len == 4) @memcpy(&lease.server_id, packet.options[offset .. offset + 4]);
                },
                .RENEWAL_TIME => {
                    if (len == 4) {
                        lease.renewal_time = std.mem.readInt(u32, packet.options[offset .. offset + 4][0..4], .big);
                    }
                },
                .REBINDING_TIME => {
                    if (len == 4) {
                        lease.rebinding_time = std.mem.readInt(u32, packet.options[offset .. offset + 4][0..4], .big);
                    }
                },
                else => {},
            }

            offset += len;
        }

        std.log.info("✅ DHCP ACK received:", .{});
        std.log.info("   IP: {d}.{d}.{d}.{d}", .{
            lease.ip_address[0],
            lease.ip_address[1],
            lease.ip_address[2],
            lease.ip_address[3],
        });
        std.log.info("   Gateway: {d}.{d}.{d}.{d}", .{
            lease.gateway[0],
            lease.gateway[1],
            lease.gateway[2],
            lease.gateway[3],
        });
        std.log.info("   Lease: {d}s ({d}h)", .{ lease.lease_time, lease.lease_time / 3600 });

        self.lease = lease;
        self.state = .BOUND;
    }

    /// Release current lease
    pub fn release(self: *Self) !void {
        if (self.lease) |*lease| {
            lease.deinit(self.allocator);
            self.lease = null;
        }
        self.state = .INIT;
    }

    pub fn deinit(self: *Self) void {
        if (self.lease) |*lease| {
            lease.deinit(self.allocator);
        }
        self.allocator.destroy(self);
    }
};

test "DHCP packet creation" {
    const allocator = std.testing.allocator;
    const mac = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

    var client = try DhcpClient.init(allocator, mac);
    defer client.deinit();

    const discover = try client.createDiscover();
    try std.testing.expectEqual(DhcpPacket.BOOTREQUEST, discover.op);
    try std.testing.expectEqual(DhcpPacket.MAGIC_COOKIE, discover.magic);
    try std.testing.expectEqual(DhcpClient.State.SELECTING, client.state);
}

test "Lease expiration" {
    const lease = Lease{
        .ip_address = [_]u8{ 192, 168, 1, 100 },
        .subnet_mask = [_]u8{ 255, 255, 255, 0 },
        .gateway = [_]u8{ 192, 168, 1, 1 },
        .dns_servers = std.ArrayList([4]u8){},
        .lease_time = 3600,
        .renewal_time = 1800,
        .rebinding_time = 3150,
        .server_id = [_]u8{ 192, 168, 1, 1 },
        .obtained_at = std.time.timestamp() - 7200, // 2 hours ago
    };
    defer @constCast(&lease).dns_servers.deinit(std.testing.allocator);

    try std.testing.expect(lease.isExpired());
    try std.testing.expect(lease.needsRenewal());
    try std.testing.expect(lease.needsRebinding());
}
