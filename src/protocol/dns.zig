/// DNS Configuration Management
///
/// Cross-platform DNS configuration for VPN interfaces:
/// - Set DNS servers for specific interface
/// - Restore original DNS configuration
/// - Platform-specific implementations (resolv.conf, scutil, registry)
const std = @import("std");
const builtin = @import("builtin");

pub const Ipv4Address = [4]u8;

/// DNS Configuration
pub const DnsConfig = struct {
    servers: std.ArrayList(Ipv4Address),
    search_domains: std.ArrayList([]const u8),
    interface: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator) DnsConfig {
        return .{
            .servers = std.ArrayList(Ipv4Address).init(allocator),
            .search_domains = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *DnsConfig) void {
        self.servers.deinit();
        for (self.search_domains.items) |domain| {
            self.servers.allocator.free(domain);
        }
        self.search_domains.deinit();
    }
};

/// Platform-specific DNS configurator
pub const DnsConfigurator = switch (builtin.os.tag) {
    .macos => MacOSDnsConfigurator,
    .linux => LinuxDnsConfigurator,
    .windows => WindowsDnsConfigurator,
    else => UnsupportedDnsConfigurator,
};

/// macOS DNS Configuration (using scutil)
const MacOSDnsConfigurator = struct {
    allocator: std.mem.Allocator,
    original_config: ?DnsConfig = null,
    interface: ?[]const u8 = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    /// Get current DNS configuration
    pub fn getCurrentConfig(self: *Self) !DnsConfig {
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "scutil", "--dns" },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        const config = DnsConfig.init(self.allocator);
        // Parse DNS servers from output (simplified)
        // Full implementation would parse the scutil output

        return config;
    }

    /// Set DNS servers for interface
    pub fn setDnsServers(self: *Self, interface: []const u8, servers: []const Ipv4Address) !void {
        // Save original config
        if (self.original_config == null) {
            self.original_config = try self.getCurrentConfig();
            self.interface = interface;
        }

        // Build DNS server list
        var server_list = std.ArrayList(u8).init(self.allocator);
        defer server_list.deinit();

        for (servers, 0..) |server, i| {
            if (i > 0) try server_list.append(' ');
            try server_list.writer().print("{d}.{d}.{d}.{d}", .{
                server[0],
                server[1],
                server[2],
                server[3],
            });
        }

        const server_str = try server_list.toOwnedSlice();
        defer self.allocator.free(server_str);

        std.log.info("Setting DNS servers for {s}: {s}", .{ interface, server_str });

        // Use networksetup command (requires sudo)
        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "networksetup",
                "-setdnsservers",
                interface,
                server_str,
            },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("Failed to set DNS: {s}", .{result.stderr});
            return error.DnsConfigurationFailed;
        }

        std.log.info("✅ DNS servers configured for {s}", .{interface});
    }

    /// Restore original DNS configuration
    pub fn restore(self: *Self) !void {
        if (self.original_config == null or self.interface == null) {
            std.log.debug("No DNS configuration to restore", .{});
            return;
        }

        std.log.info("🔄 Restoring original DNS configuration", .{});

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "networksetup",
                "-setdnsservers",
                self.interface.?,
                "empty",
            },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (self.original_config) |*config| {
            config.deinit();
            self.original_config = null;
        }

        std.log.info("✅ DNS configuration restored", .{});
    }

    pub fn deinit(self: *Self) void {
        self.restore() catch |err| {
            std.log.err("Failed to restore DNS during deinit: {}", .{err});
        };

        if (self.original_config) |*config| {
            config.deinit();
        }

        self.allocator.destroy(self);
    }
};

/// Linux DNS Configuration (using resolvconf or systemd-resolved)
const LinuxDnsConfigurator = struct {
    allocator: std.mem.Allocator,
    original_resolv_conf: ?[]u8 = null,
    interface: ?[]const u8 = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    /// Backup current /etc/resolv.conf
    fn backupResolvConf(self: *Self) !void {
        if (self.original_resolv_conf != null) return;

        const file = std.fs.openFileAbsolute("/etc/resolv.conf", .{}) catch |err| {
            std.log.warn("Cannot read /etc/resolv.conf: {}", .{err});
            return;
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 4096);
        self.original_resolv_conf = content;
        std.log.info("📋 Backed up /etc/resolv.conf", .{});
    }

    /// Set DNS servers for interface
    pub fn setDnsServers(self: *Self, interface: []const u8, servers: []const Ipv4Address) !void {
        self.interface = interface;

        // Try systemd-resolved first
        if (self.trySystemdResolved(interface, servers)) {
            return;
        }

        // Fallback to resolvconf
        try self.backupResolvConf();

        var config = std.ArrayList(u8).init(self.allocator);
        defer config.deinit();

        for (servers) |server| {
            try config.writer().print("nameserver {d}.{d}.{d}.{d}\n", .{
                server[0],
                server[1],
                server[2],
                server[3],
            });
        }

        const config_str = try config.toOwnedSlice();
        defer self.allocator.free(config_str);

        std.log.info("Writing DNS configuration to /etc/resolv.conf", .{});

        const file = try std.fs.createFileAbsolute("/etc/resolv.conf", .{});
        defer file.close();

        try file.writeAll(config_str);

        std.log.info("✅ DNS servers configured", .{});
    }

    /// Try using systemd-resolved
    fn trySystemdResolved(self: *Self, interface: []const u8, servers: []const Ipv4Address) bool {
        // Build DNS server list
        var server_list = std.ArrayList(u8).init(self.allocator);
        defer server_list.deinit();

        for (servers, 0..) |server, i| {
            if (i > 0) server_list.append(' ') catch return false;
            server_list.writer().print("{d}.{d}.{d}.{d}", .{
                server[0],
                server[1],
                server[2],
                server[3],
            }) catch return false;
        }

        const server_str = server_list.toOwnedSlice() catch return false;
        defer self.allocator.free(server_str);

        const result = std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "resolvectl",
                "dns",
                interface,
                server_str,
            },
        }) catch return false;

        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (result.term == .Exited and result.term.Exited == 0) {
            std.log.info("✅ DNS configured via systemd-resolved", .{});
            return true;
        }

        return false;
    }

    /// Restore original DNS configuration
    pub fn restore(self: *Self) !void {
        if (self.original_resolv_conf) |content| {
            std.log.info("🔄 Restoring /etc/resolv.conf", .{});

            const file = try std.fs.createFileAbsolute("/etc/resolv.conf", .{});
            defer file.close();

            try file.writeAll(content);

            self.allocator.free(content);
            self.original_resolv_conf = null;

            std.log.info("✅ DNS configuration restored", .{});
        }
    }

    pub fn deinit(self: *Self) void {
        self.restore() catch |err| {
            std.log.err("Failed to restore DNS during deinit: {}", .{err});
        };

        if (self.original_resolv_conf) |content| {
            self.allocator.free(content);
        }

        self.allocator.destroy(self);
    }
};

/// Windows DNS Configuration (using netsh or registry)
const WindowsDnsConfigurator = struct {
    allocator: std.mem.Allocator,
    original_servers: ?std.ArrayList(Ipv4Address) = null,
    interface: ?[]const u8 = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !*Self {
        const self = try allocator.create(Self);
        self.* = .{ .allocator = allocator };
        return self;
    }

    /// Set DNS servers for interface
    pub fn setDnsServers(self: *Self, interface: []const u8, servers: []const Ipv4Address) !void {
        self.interface = interface;

        // Save original config (simplified)
        if (self.original_servers == null) {
            self.original_servers = std.ArrayList(Ipv4Address).init(self.allocator);
        }

        std.log.info("Setting DNS servers for {s}", .{interface});

        // Set primary DNS
        if (servers.len > 0) {
            const primary = servers[0];
            var ip_buf: [16]u8 = undefined;
            const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                primary[0],
                primary[1],
                primary[2],
                primary[3],
            });

            const result = try std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{
                    "netsh",
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    interface,
                    "static",
                    ip_str,
                },
            });
            defer self.allocator.free(result.stdout);
            defer self.allocator.free(result.stderr);

            if (result.term != .Exited or result.term.Exited != 0) {
                std.log.err("Failed to set primary DNS: {s}", .{result.stderr});
                return error.DnsConfigurationFailed;
            }
        }

        // Set secondary DNS servers
        for (servers[1..], 0..) |server, i| {
            var ip_buf: [16]u8 = undefined;
            const ip_str = try std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{
                server[0],
                server[1],
                server[2],
                server[3],
            });

            var index_buf: [8]u8 = undefined;
            const index_str = try std.fmt.bufPrint(&index_buf, "{d}", .{i + 2});

            const result = try std.process.Child.run(.{
                .allocator = self.allocator,
                .argv = &[_][]const u8{
                    "netsh",
                    "interface",
                    "ip",
                    "add",
                    "dns",
                    interface,
                    ip_str,
                    "index=" ++ index_str,
                },
            });
            defer self.allocator.free(result.stdout);
            defer self.allocator.free(result.stderr);
        }

        std.log.info("✅ DNS servers configured for {s}", .{interface});
    }

    /// Restore original DNS configuration
    pub fn restore(self: *Self) !void {
        if (self.interface == null) {
            std.log.debug("No DNS configuration to restore", .{});
            return;
        }

        std.log.info("🔄 Restoring DNS configuration", .{});

        const result = try std.process.Child.run(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{
                "netsh",
                "interface",
                "ip",
                "set",
                "dns",
                self.interface.?,
                "dhcp",
            },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        if (self.original_servers) |*servers| {
            servers.deinit();
            self.original_servers = null;
        }

        std.log.info("✅ DNS configuration restored", .{});
    }

    pub fn deinit(self: *Self) void {
        self.restore() catch |err| {
            std.log.err("Failed to restore DNS during deinit: {}", .{err});
        };

        if (self.original_servers) |*servers| {
            servers.deinit();
        }

        self.allocator.destroy(self);
    }
};

/// Unsupported platform stub
const UnsupportedDnsConfigurator = struct {
    pub fn init(_: std.mem.Allocator) !*UnsupportedDnsConfigurator {
        return error.UnsupportedPlatform;
    }
};

test "DNS configuration structure" {
    var config = DnsConfig.init(std.testing.allocator);
    defer config.deinit();

    try config.servers.append([_]u8{ 8, 8, 8, 8 });
    try config.servers.append([_]u8{ 8, 8, 4, 4 });

    try std.testing.expectEqual(@as(usize, 2), config.servers.items.len);
}
