// Node Information Module
// Generates system information for SoftEther authentication protocol
const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const Pack = @import("pack.zig").Pack;

/// Operating system information
pub const OsInfo = struct {
    system_name: []const u8,
    product_name: []const u8,
    version: []const u8,
    vendor_name: []const u8,
    arch: []const u8,

    pub fn deinit(self: *OsInfo, allocator: Allocator) void {
        allocator.free(self.product_name);
        allocator.free(self.version);
    }
};

/// Node information sent during authentication
pub const NodeInfo = struct {
    client_product_name: []const u8,
    client_version: u32,
    client_build: u32,
    server_product_name: []const u8,
    server_version: u32,
    server_build: u32,
    os_system_name: []const u8,
    os_product_name: []const u8,
    os_version: []const u8,
    os_vendor_name: []const u8,
    os_arch: []const u8,
    hostname: []const u8,

    allocator: Allocator,

    /// Create node info with system detection
    pub fn create(allocator: Allocator) !NodeInfo {
        var os_info = try getOsInfo(allocator);
        errdefer os_info.deinit(allocator);

        const hostname = try getHostname(allocator);
        errdefer allocator.free(hostname);

        return NodeInfo{
            .client_product_name = "SoftEtherZig VPN Client",
            .client_version = 502, // Version 5.02
            .client_build = 9999,
            .server_product_name = "SoftEther VPN Server",
            .server_version = 0,
            .server_build = 0,
            .os_system_name = os_info.system_name,
            .os_product_name = os_info.product_name,
            .os_version = os_info.version,
            .os_vendor_name = os_info.vendor_name,
            .os_arch = os_info.arch,
            .hostname = hostname,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NodeInfo) void {
        self.allocator.free(self.os_product_name);
        self.allocator.free(self.os_version);
        self.allocator.free(self.hostname);
    }

    /// Add node info to PACK
    pub fn toPacket(self: *const NodeInfo, pack: *Pack) !void {
        // Client info
        try pack.addString("client_product_name", self.client_product_name);
        try pack.addInt("client_version", @intCast(self.client_version));
        try pack.addInt("client_build", @intCast(self.client_build));

        // Server info (usually zeros for client)
        try pack.addString("server_product_name", self.server_product_name);
        try pack.addInt("server_version", @intCast(self.server_version));
        try pack.addInt("server_build", @intCast(self.server_build));

        // OS info
        try pack.addString("os_system_name", self.os_system_name);
        try pack.addString("os_product_name", self.os_product_name);
        try pack.addString("os_version", self.os_version);
        try pack.addString("os_vendor_name", self.os_vendor_name);
        try pack.addString("os_arch", self.os_arch);

        // Machine info
        try pack.addString("hostname", self.hostname);
    }
};

// ============================================================================
// System Detection
// ============================================================================

/// Get operating system information
pub fn getOsInfo(allocator: Allocator) !OsInfo {
    const system_name = switch (builtin.os.tag) {
        .macos => "macOS",
        .linux => "Linux",
        .windows => "Windows",
        .ios => "iOS",
        else => "Unknown",
    };

    const vendor_name = switch (builtin.os.tag) {
        .macos, .ios => "Apple Inc.",
        .linux => "Linux Foundation",
        .windows => "Microsoft Corporation",
        else => "Unknown",
    };

    const arch = switch (builtin.cpu.arch) {
        .x86_64 => "x86_64",
        .aarch64 => "ARM64",
        .arm => "ARM",
        else => @tagName(builtin.cpu.arch),
    };

    // Detect OS version
    const product_name = try detectOsProductName(allocator);
    errdefer allocator.free(product_name);

    const version = try detectOsVersion(allocator);
    errdefer allocator.free(version);

    return OsInfo{
        .system_name = system_name,
        .product_name = product_name,
        .version = version,
        .vendor_name = vendor_name,
        .arch = arch,
    };
}

/// Detect OS product name
fn detectOsProductName(allocator: Allocator) ![]u8 {
    switch (builtin.os.tag) {
        .macos => {
            // Try to detect macOS version name
            const result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "sw_vers", "-productName" },
            }) catch {
                return try allocator.dupe(u8, "macOS");
            };
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);

            if (result.term.Exited == 0 and result.stdout.len > 0) {
                const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
                return try allocator.dupe(u8, trimmed);
            }
            return try allocator.dupe(u8, "macOS");
        },
        .linux => {
            // Try to read /etc/os-release
            const file = std.fs.openFileAbsolute("/etc/os-release", .{}) catch {
                return try allocator.dupe(u8, "Linux");
            };
            defer file.close();

            const content = try file.readToEndAlloc(allocator, 4096);
            defer allocator.free(content);

            var it = std.mem.splitScalar(u8, content, '\n');
            while (it.next()) |line| {
                if (std.mem.startsWith(u8, line, "PRETTY_NAME=")) {
                    const value = line[12..];
                    const unquoted = std.mem.trim(u8, value, "\"");
                    return try allocator.dupe(u8, unquoted);
                }
            }
            return try allocator.dupe(u8, "Linux");
        },
        .windows => {
            return try allocator.dupe(u8, "Windows");
        },
        .ios => {
            return try allocator.dupe(u8, "iOS");
        },
        else => {
            return try allocator.dupe(u8, "Unknown");
        },
    }
}

/// Detect OS version string
fn detectOsVersion(allocator: Allocator) ![]u8 {
    switch (builtin.os.tag) {
        .macos => {
            const result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "sw_vers", "-productVersion" },
            }) catch {
                return try allocator.dupe(u8, "Unknown");
            };
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);

            if (result.term.Exited == 0 and result.stdout.len > 0) {
                const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
                return try allocator.dupe(u8, trimmed);
            }
            return try allocator.dupe(u8, "Unknown");
        },
        .linux => {
            // Try uname -r
            const result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &[_][]const u8{ "uname", "-r" },
            }) catch {
                return try allocator.dupe(u8, "Unknown");
            };
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);

            if (result.term.Exited == 0 and result.stdout.len > 0) {
                const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
                return try allocator.dupe(u8, trimmed);
            }
            return try allocator.dupe(u8, "Unknown");
        },
        .windows => {
            // TODO: Get Windows version
            return try allocator.dupe(u8, "10.0");
        },
        .ios => {
            return try allocator.dupe(u8, "Unknown");
        },
        else => {
            return try allocator.dupe(u8, "Unknown");
        },
    }
}

/// Get system hostname
fn getHostname(allocator: Allocator) ![]u8 {
    if (builtin.os.tag == .windows) {
        // TODO: Windows hostname detection
        return try allocator.dupe(u8, "windows-host");
    }

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{"hostname"},
    }) catch {
        return try allocator.dupe(u8, "unknown-host");
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited == 0 and result.stdout.len > 0) {
        const trimmed = std.mem.trim(u8, result.stdout, &std.ascii.whitespace);
        return try allocator.dupe(u8, trimmed);
    }

    return try allocator.dupe(u8, "unknown-host");
}

/// Generate unique machine ID for authentication
pub fn generateMachineId(allocator: Allocator) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    // Hash hostname
    const hostname = try getHostname(allocator);
    defer allocator.free(hostname);
    hasher.update(hostname);

    // Hash OS info
    const os_info = try getOsInfo(allocator);
    defer {
        var mut_os = os_info;
        mut_os.deinit(allocator);
    }
    hasher.update(os_info.system_name);
    hasher.update(os_info.product_name);
    hasher.update(os_info.arch);

    // Finalize hash
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    // Return first 20 bytes (SHA1 size compatibility)
    const result = try allocator.alloc(u8, 20);
    @memcpy(result, hash[0..20]);
    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "NodeInfo: create and destroy" {
    const allocator = std.testing.allocator;
    var node_info = try NodeInfo.create(allocator);
    defer node_info.deinit();

    // Verify basic fields
    try std.testing.expectEqualStrings("SoftEtherZig VPN Client", node_info.client_product_name);
    try std.testing.expectEqual(@as(u32, 502), node_info.client_version);
}

test "NodeInfo: detect OS" {
    const allocator = std.testing.allocator;
    const os_info = try getOsInfo(allocator);
    defer {
        var mut_os = os_info;
        mut_os.deinit(allocator);
    }

    // Should detect something
    try std.testing.expect(os_info.system_name.len > 0);
    try std.testing.expect(os_info.product_name.len > 0);
    try std.testing.expect(os_info.arch.len > 0);
}

test "NodeInfo: get hostname" {
    const allocator = std.testing.allocator;
    const hostname = try getHostname(allocator);
    defer allocator.free(hostname);

    try std.testing.expect(hostname.len > 0);
}

test "NodeInfo: generate machine ID" {
    const allocator = std.testing.allocator;
    const id = try generateMachineId(allocator);
    defer allocator.free(id);

    try std.testing.expectEqual(@as(usize, 20), id.len);
}

test "NodeInfo: add to packet" {
    const allocator = std.testing.allocator;

    var node_info = try NodeInfo.create(allocator);
    defer node_info.deinit();

    const pack = try Pack.init(allocator);
    defer pack.deinit();

    try node_info.toPacket(pack);

    // Verify fields were added
    try std.testing.expectEqualStrings(
        "SoftEtherZig VPN Client",
        pack.getString("client_product_name").?,
    );
    try std.testing.expectEqual(@as(i32, 502), pack.getInt("client_version").?);
}
