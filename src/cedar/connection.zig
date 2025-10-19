// Cedar Connection Module
// Handles VPN connection lifecycle and data transmission
// Based on SoftEtherRust/libs/cedar/src/connection.rs

const std = @import("std");
const net = @import("../mayaqua/network.zig");
const pack = @import("../mayaqua/pack.zig");
const time = @import("../mayaqua/time.zig");
const crypto = @import("../mayaqua/crypto.zig");

/// Connection status enum
pub const ConnectionStatus = enum(u32) {
    negotiation = 0, // Initial handshake phase
    established = 1, // Connection established
    disconnected = 2, // Connection closed

    pub fn fromU32(value: u32) !ConnectionStatus {
        return switch (value) {
            0 => .negotiation,
            1 => .established,
            2 => .disconnected,
            else => error.InvalidConnectionStatus,
        };
    }

    pub fn toU32(self: ConnectionStatus) u32 {
        return @intFromEnum(self);
    }
};

/// Connection configuration
pub const ConnectionConfig = struct {
    server_mode: bool = false,
    use_ssl: bool = true,
    timeout_secs: u32 = 15,
    keep_alive_interval_secs: u32 = 50,
    max_recv_block_size: usize = 32768,
    max_send_block_size: usize = 32768,

    pub fn default() ConnectionConfig {
        return ConnectionConfig{};
    }
};

/// Network data block for transmission
pub const Block = struct {
    data: []u8,
    compressed: bool,
    priority: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, data: []const u8) !*Block {
        const block = try allocator.create(Block);
        block.* = Block{
            .data = try allocator.dupe(u8, data),
            .compressed = false,
            .priority = false,
            .allocator = allocator,
        };
        return block;
    }

    pub fn initCompressed(allocator: std.mem.Allocator, data: []const u8) !*Block {
        const block = try allocator.create(Block);
        block.* = Block{
            .data = try allocator.dupe(u8, data),
            .compressed = true,
            .priority = false,
            .allocator = allocator,
        };
        return block;
    }

    pub fn initPriority(allocator: std.mem.Allocator, data: []const u8) !*Block {
        const block = try allocator.create(Block);
        block.* = Block{
            .data = try allocator.dupe(u8, data),
            .compressed = false,
            .priority = true,
            .allocator = allocator,
        };
        return block;
    }

    pub fn deinit(self: *Block) void {
        self.allocator.free(self.data);
        self.allocator.destroy(self);
    }
};

/// Connection state information
pub const ConnectionState = struct {
    status: ConnectionStatus,
    connected_tick: u64,
    last_comm_tick: u64,
    error_code: u32,
    total_sent: u64,
    total_received: u64,

    pub fn init() ConnectionState {
        const now = time.getTick64();
        return ConnectionState{
            .status = .negotiation,
            .connected_tick = now,
            .last_comm_tick = now,
            .error_code = 0,
            .total_sent = 0,
            .total_received = 0,
        };
    }
};

/// SoftEther VPN Connection
/// Manages a single VPN connection with the server
pub const Connection = struct {
    // Identity
    name: []const u8,
    config: ConnectionConfig,

    // Version negotiation
    server_ver: u32,
    server_build: u32,
    client_ver: u32,
    client_build: u32,
    server_str: []const u8,
    client_str: []const u8,

    // Authentication
    random: [crypto.SHA1_SIZE]u8, // Authentication random (20 bytes)
    use_ticket: bool,
    ticket: [crypto.SHA1_SIZE]u8,

    // Network info
    server_name: []const u8,
    server_port: u16,
    client_ip: []const u8,
    client_port: u16,

    // Connection state
    state: ConnectionState,

    // Control
    halt: bool,

    // Queues
    received_blocks: std.ArrayList(*Block),
    send_blocks: std.ArrayList(*Block),

    // TCP connection (optional - may not be connected yet)
    tcp_client: ?net.TcpClient,

    allocator: std.mem.Allocator,

    const Self = @This();

    /// SoftEther VPN version constants
    pub const SOFTETHER_VER: u32 = 5;
    pub const SOFTETHER_BUILD: u32 = 9680;

    /// Create new connection
    pub fn init(allocator: std.mem.Allocator, name: []const u8, config: ConnectionConfig) !*Self {
        const conn = try allocator.create(Self);

        const client_str = try std.fmt.allocPrint(
            allocator,
            "SoftEtherVPN_Zig/{d}.{d}",
            .{ SOFTETHER_VER, SOFTETHER_BUILD },
        );

        conn.* = Self{
            .name = try allocator.dupe(u8, name),
            .config = config,

            .server_ver = 0,
            .server_build = 0,
            .client_ver = SOFTETHER_VER,
            .client_build = SOFTETHER_BUILD,
            .server_str = try allocator.dupe(u8, ""),
            .client_str = client_str,

            .random = [_]u8{0} ** crypto.SHA1_SIZE,
            .use_ticket = false,
            .ticket = [_]u8{0} ** crypto.SHA1_SIZE,

            .server_name = try allocator.dupe(u8, ""),
            .server_port = 0,
            .client_ip = try allocator.dupe(u8, ""),
            .client_port = 0,

            .state = ConnectionState.init(),

            .halt = false,

            .received_blocks = std.ArrayList(*Block).initCapacity(allocator, 0) catch unreachable,
            .send_blocks = std.ArrayList(*Block).initCapacity(allocator, 0) catch unreachable,

            .tcp_client = null,

            .allocator = allocator,
        };

        // Generate random for authentication challenge
        crypto.randomBytes(&conn.random);

        return conn;
    }

    /// Connect to server
    pub fn connect(self: *Self, hostname: []const u8, port: u16) !void {
        // Store server info
        self.allocator.free(self.server_name);
        self.server_name = try self.allocator.dupe(u8, hostname);
        self.server_port = port;

        // Create TCP connection
        const client = try net.TcpClient.connect(hostname, port);
        self.tcp_client = client;

        // Update state
        self.state.status = .negotiation;
        self.state.last_comm_tick = time.getTick64();
    }

    /// Disconnect from server
    pub fn disconnect(self: *Self) void {
        if (self.tcp_client) |*client| {
            client.close();
            self.tcp_client = null;
        }

        self.state.status = .disconnected;
        self.halt = true;
    }

    /// Send a data block
    pub fn sendBlock(self: *Self, block: *Block) !void {
        try self.send_blocks.append(self.allocator, block);
    }

    /// Receive a data block (non-blocking)
    pub fn receiveBlock(self: *Self) ?*Block {
        if (self.received_blocks.items.len > 0) {
            return self.received_blocks.orderedRemove(0);
        }
        return null;
    }

    /// Flush send queue - write all pending blocks to TCP
    pub fn flushSendQueue(self: *Self) !void {
        if (self.tcp_client == null) return error.NotConnected;

        var client = &self.tcp_client.?;

        for (self.send_blocks.items) |block| {
            // TODO: Implement block serialization with SoftEther protocol
            // For now, just send raw data
            _ = try client.send(block.data);
            self.state.total_sent += block.data.len;
        }

        // Clear sent blocks
        for (self.send_blocks.items) |block| {
            block.deinit();
        }
        self.send_blocks.clearRetainingCapacity();

        self.state.last_comm_tick = time.getTick64();
    }

    /// Read data from TCP and parse into blocks
    pub fn readIncomingData(self: *Self) !void {
        if (self.tcp_client == null) return error.NotConnected;

        var client = &self.tcp_client.?;

        // Try to receive data (non-blocking)
        var buffer: [4096]u8 = undefined;
        const bytes_read = client.receive(&buffer) catch |err| {
            if (err == error.WouldBlock) {
                return; // No data available
            }
            return err;
        };

        if (bytes_read == 0) {
            // Connection closed
            self.disconnect();
            return;
        }

        // TODO: Implement proper block parsing with SoftEther protocol
        // For now, just create a simple block
        const block = try Block.init(self.allocator, buffer[0..bytes_read]);
        try self.received_blocks.append(self.allocator, block);

        self.state.total_received += bytes_read;
        self.state.last_comm_tick = time.getTick64();
    }

    /// Check if connection is alive
    pub fn isAlive(self: *const Self) bool {
        return self.state.status != .disconnected and !self.halt;
    }

    /// Check if connection is established
    pub fn isEstablished(self: *const Self) bool {
        return self.state.status == .established;
    }

    /// Get connection uptime in milliseconds
    pub fn getUptimeMillis(self: *const Self) u64 {
        const now = time.getTick64();
        return now - self.state.connected_tick;
    }

    /// Get time since last communication in milliseconds
    pub fn getIdleTimeMillis(self: *const Self) u64 {
        const now = time.getTick64();
        return now - self.state.last_comm_tick;
    }

    /// Cleanup and free resources
    pub fn deinit(self: *Self) void {
        // Disconnect if still connected
        if (self.tcp_client != null) {
            self.disconnect();
        }

        // Clean up queues
        for (self.received_blocks.items) |block| {
            block.deinit();
        }
        self.received_blocks.deinit(self.allocator);

        for (self.send_blocks.items) |block| {
            block.deinit();
        }
        self.send_blocks.deinit(self.allocator);

        // Free strings
        self.allocator.free(self.name);
        self.allocator.free(self.server_str);
        self.allocator.free(self.client_str);
        self.allocator.free(self.server_name);
        self.allocator.free(self.client_ip);

        // Zeroize sensitive data
        @memset(&self.random, 0);
        @memset(&self.ticket, 0);

        self.allocator.destroy(self);
    }
};
