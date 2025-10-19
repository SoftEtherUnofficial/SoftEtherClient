//! Pure Zig VPN Client Wrapper
//! Provides high-level interface for Pure Zig VPN implementation

const std = @import("std");
const Allocator = std.mem.Allocator;
const VpnProtocol = @import("protocol/vpn_protocol.zig").VpnProtocol;
const vpn = @import("protocol/vpn.zig");
const config_mod = @import("config.zig");

pub const PureZigVpnClient = struct {
    allocator: Allocator,
    protocol: *VpnProtocol,
    config: config_mod.ConnectionConfig,

    pub fn init(allocator: Allocator, vpn_config: config_mod.ConnectionConfig) !*PureZigVpnClient {
        const client = try allocator.create(PureZigVpnClient);
        errdefer allocator.destroy(client);

        client.allocator = allocator;
        client.config = vpn_config;

        // Extract authentication credentials based on auth method
        const username: []const u8 = switch (vpn_config.auth) {
            .password => |p| p.username,
            else => "",
        };

        const password: []const u8 = switch (vpn_config.auth) {
            .password => |p| p.password,
            else => "",
        };

        // Use AuthCredentials from vpn.zig
        const auth_creds = vpn.AuthCredentials.withPassword(username, password);

        // Initialize VPN protocol
        client.protocol = try VpnProtocol.init(
            allocator,
            vpn_config.server_name,
            vpn_config.server_port,
            vpn_config.hub_name,
            auth_creds,
        );

        return client;
    }
    pub fn connect(self: *PureZigVpnClient) !void {
        std.log.info("Pure Zig: Connecting to {s}:{d}", .{ self.config.server_name, self.config.server_port });

        // Connect to server
        try self.protocol.connect();
        std.log.info("Pure Zig: TCP connection established", .{});

        // Authenticate
        try self.protocol.authenticate();
        std.log.info("Pure Zig: Authentication successful", .{});

        std.log.info("Pure Zig: VPN session established", .{});
    }

    pub fn deinit(self: *PureZigVpnClient) void {
        self.protocol.deinit();
        self.allocator.destroy(self);
    }
};
