const std = @import("std");
const c_mod = @import("c.zig");
const c = c_mod.c;
const errors = @import("errors.zig");
const config = @import("config.zig");
const types = @import("types.zig");

// Cedar FFI imports (always available, selected at runtime)
const cedar = @import("cedar/wrapper.zig");

// TUN device library
const taptun = @import("taptun");

const VpnError = errors.VpnError;
const ConnectionConfig = config.ConnectionConfig;

/// Reconnection state information
pub const ReconnectInfo = struct {
    enabled: bool,
    should_reconnect: bool, // True if reconnection should be attempted
    attempt: u32, // Current attempt number
    max_attempts: u32, // Maximum attempts (0=infinite)
    current_backoff: u32, // Current backoff delay in seconds
    next_retry_time: u64, // Timestamp when next retry should occur
    consecutive_failures: u32, // Count of consecutive failures
    last_disconnect_time: u64, // When connection was lost
};

/// VPN Client wrapper using the C bridge layer
pub const VpnClient = struct {
    handle: ?*c_mod.VpnBridgeClient,
    allocator: std.mem.Allocator,
    config: ConnectionConfig,

    // Cedar FFI session (runtime selection)
    cedar_session: ?cedar.Session = null,

    // TUN device adapter (optional, created after connection)
    tun_adapter: ?*taptun.TunAdapter = null,

    /// Initialize a new VPN client
    pub fn init(allocator: std.mem.Allocator, cfg: ConnectionConfig) !VpnClient {
        // Initialize the bridge library (once per program)
        // Note: BOOL in SoftEther is typedef'd as unsigned int (0 = FALSE, 1 = TRUE)
        const init_result = c.vpn_bridge_init(0); // 0 = FALSE (debug off)

        if (init_result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.InitializationFailed;
        }

        // Create client instance
        const client_handle = c.vpn_bridge_create_client() orelse {
            return VpnError.ClientCreationFailed;
        };

        // Configure the client
        const host_z = try allocator.dupeZ(u8, cfg.server_name);
        defer allocator.free(host_z);

        const hub_z = try allocator.dupeZ(u8, cfg.hub_name);
        defer allocator.free(hub_z);

        // Extract username/password from auth
        const username = switch (cfg.auth) {
            .password => |p| p.username,
            else => "anonymous",
        };
        const password = switch (cfg.auth) {
            .password => |p| p.password,
            else => "",
        };
        const is_hashed = switch (cfg.auth) {
            .password => |p| p.is_hashed,
            else => false,
        };

        const user_z = try allocator.dupeZ(u8, username);
        defer allocator.free(user_z);

        const pass_z = try allocator.dupeZ(u8, password);
        defer allocator.free(pass_z);

        const config_result = if (is_hashed)
            c.vpn_bridge_configure_with_hash(
                client_handle,
                host_z.ptr,
                cfg.server_port,
                hub_z.ptr,
                user_z.ptr,
                pass_z.ptr,
            )
        else
            c.vpn_bridge_configure(
                client_handle,
                host_z.ptr,
                cfg.server_port,
                hub_z.ptr,
                user_z.ptr,
                pass_z.ptr,
            );

        if (config_result != c_mod.VPN_BRIDGE_SUCCESS) {
            c.vpn_bridge_free_client(client_handle);
            return VpnError.ConfigurationError;
        }

        // Configure IP version
        const ip_version_code: c_int = switch (cfg.ip_version) {
            .auto => c_mod.VPN_IP_VERSION_AUTO,
            .ipv4 => c_mod.VPN_IP_VERSION_IPV4,
            .ipv6 => c_mod.VPN_IP_VERSION_IPV6,
            .dual => c_mod.VPN_IP_VERSION_DUAL,
        };
        _ = c.vpn_bridge_set_ip_version(client_handle, ip_version_code);

        // Configure max connections
        _ = c.vpn_bridge_set_max_connection(client_handle, @intCast(cfg.max_connection));

        // Configure adapter type (Zig vs C adapter)
        if (cfg.use_zig_adapter) {
            _ = c.vpn_bridge_set_use_zig_adapter(client_handle, 1);
        }

        // Configure static IP if provided
        if (cfg.static_ip) |sip| {
            if (sip.ipv4_address) |ipv4| {
                const ipv4_z = try allocator.dupeZ(u8, ipv4);
                defer allocator.free(ipv4_z);

                const mask_z = if (sip.ipv4_netmask) |m| try allocator.dupeZ(u8, m) else null;
                defer if (mask_z) |m| allocator.free(m);

                const gw_z = if (sip.ipv4_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw_z) |g| allocator.free(g);

                _ = c.vpn_bridge_set_static_ipv4(
                    client_handle,
                    ipv4_z.ptr,
                    if (mask_z) |m| m.ptr else null,
                    if (gw_z) |g| g.ptr else null,
                );
            }

            if (sip.ipv6_address) |ipv6| {
                const ipv6_z = try allocator.dupeZ(u8, ipv6);
                defer allocator.free(ipv6_z);

                const gw6_z = if (sip.ipv6_gateway) |g| try allocator.dupeZ(u8, g) else null;
                defer if (gw6_z) |g| allocator.free(g);

                _ = c.vpn_bridge_set_static_ipv6(
                    client_handle,
                    ipv6_z.ptr,
                    sip.ipv6_prefix_len orelse 64,
                    if (gw6_z) |g| g.ptr else null,
                );
            }

            if (sip.dns_servers) |dns_list| {
                // Allocate C string array
                var dns_ptrs = try allocator.alloc([*c]const u8, dns_list.len);
                defer allocator.free(dns_ptrs);

                var dns_z_list = try allocator.alloc([]const u8, dns_list.len);
                defer {
                    for (dns_z_list) |dns_z| {
                        allocator.free(dns_z);
                    }
                    allocator.free(dns_z_list);
                }

                for (dns_list, 0..) |dns, i| {
                    dns_z_list[i] = try allocator.dupeZ(u8, dns);
                    dns_ptrs[i] = @ptrCast(dns_z_list[i].ptr);
                }

                _ = c.vpn_bridge_set_dns_servers(
                    client_handle,
                    @ptrCast(dns_ptrs.ptr),
                    @intCast(dns_list.len),
                );
            }
        }

        const client = VpnClient{
            .handle = client_handle,
            .allocator = allocator,
            .config = cfg,
        };
        return client;
    }

    /// Clean up resources
    pub fn deinit(self: *VpnClient) void {
        // Clean up TUN device first (restores routes)
        if (self.tun_adapter) |adapter| {
            adapter.close();
            self.tun_adapter = null;
        }

        // Clean up Cedar session
        if (self.cedar_session) |*session| {
            session.deinit();
        }

        // Clean up SoftEther handle
        if (self.handle) |handle| {
            c.vpn_bridge_free_client(handle);
            self.handle = null;
        }
    }

    /// Connect to VPN server
    pub fn connect(self: *VpnClient) !void {
        if (self.config.use_cedar) {
            std.debug.print("🚀 Using Cedar FFI (Rust TLS, no OpenSSL)\n", .{});
            return self.connectWithCedar();
        } else {
            std.debug.print("🔧 Using C Bridge (OpenSSL legacy path)\n", .{});
            return self.connectWithOpenSSL();
        }
    }

    /// Connect using legacy OpenSSL path (SoftEther C bridge)
    fn connectWithOpenSSL(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_connect(handle);
        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return switch (result) {
                c_mod.VPN_BRIDGE_ERROR_CONNECT_FAILED => VpnError.ConnectionFailed,
                c_mod.VPN_BRIDGE_ERROR_AUTH_FAILED => VpnError.AuthenticationFailed,
                c_mod.VPN_BRIDGE_ERROR_INVALID_PARAM => VpnError.InvalidParameter,
                else => VpnError.OperationFailed,
            };
        }
    }

    /// Connect using Cedar FFI (Rust TLS implementation)
    fn connectWithCedar(self: *VpnClient) !void {
        std.debug.print("🚀 Cedar FFI Connection Path!\n", .{});
        std.debug.print("  Server: {s}:{d}\n", .{ self.config.server_name, self.config.server_port });
        std.debug.print("  Hub: {s}\n", .{self.config.hub_name});

        // Extract username for display
        const username = switch (self.config.auth) {
            .password => |p| p.username,
            else => "anonymous",
        };
        std.debug.print("  User: {s}\n", .{username});

        // Step 1: Create Cedar session with authentication
        std.debug.print("📦 Creating Cedar session...\n", .{});

        // Get username and password from config auth
        const auth_username: ?[]const u8 = switch (self.config.auth) {
            .password => |pwd| pwd.username,
            else => null,
        };
        const auth_password: ?[]const u8 = switch (self.config.auth) {
            .password => |pwd| pwd.password,
            else => null,
        };

        var session = try cedar.Session.initWithAuthEx(
            self.config.server_name,
            self.config.server_port,
            self.config.hub_name,
            auth_username,
            auth_password,
            false, // Disable encryption for testing
        );
        errdefer session.deinit();

        // Step 2: Connect (establishes TLS, performs handshake, and authenticates)
        std.debug.print("🔌 Connecting to server (TLS + handshake + auth)...\n", .{});
        try session.connect();
        std.debug.print("✅ Connection established!\n", .{});

        // NOTE: session.connect() already does:
        // - TLS connection establishment
        // - Protocol handshake (hello exchange)
        // - User authentication
        // So we don't need to do hello/auth again!

        // Step 3: Session established
        const status = session.getStatus();
        std.debug.print("🎉 Connection established! Status: {}\n", .{status});

        // Store session
        self.cedar_session = session;

        std.debug.print("✅ Cedar connection complete!\n\n", .{});

        // Step 3: Create TUN device
        std.debug.print("🌐 Creating TUN device...\n", .{});
        self.tun_adapter = taptun.TunAdapter.open(self.allocator, .{
            .device = .{ .non_blocking = true },
            .translator = .{
                .our_mac = [_]u8{ 0x00, 0xAC, 0x00, 0x00, 0x00, 0x01 },
                .learn_ip = true,
                .learn_gateway_mac = true,
                .handle_arp = true,
                .verbose = false,
            },
            .manage_routes = false,
        }) catch |err| blk: {
            std.debug.print("⚠️  Failed to create TUN device: {}\n", .{err});
            std.debug.print("💡 Note: TUN device requires root privileges\n", .{});
            std.debug.print("📦 Continuing without TUN (logging only)\n\n", .{});
            break :blk null;
        };

        if (self.tun_adapter) |adapter| {
            std.debug.print("✅ TUN device: {s}\n\n", .{adapter.device.getName()});
        }

        std.debug.print("\n📡 Starting VPN packet forwarding loop...\n", .{});

        // Create ready event to synchronize forwarding loop startup
        var ready_event = std.Thread.ResetEvent{};
        
        // Start packet forwarding with TUN device
        const forward_thread = try std.Thread.spawn(.{}, packetForwardingLoop, .{ &self.cedar_session.?, self.tun_adapter, &ready_event });
        forward_thread.detach();

        // Wait for forwarding loop to be ready and polling for packets
        // This ensures DHCP responses won't be missed
        std.debug.print("⏳ Waiting for forwarding loop to start polling...\n", .{});
        ready_event.wait();
        std.debug.print("✅ Forwarding loop ready!\n", .{});

        std.debug.print("✅ Packet forwarding active!\n", .{});
        std.debug.print("💡 Press Ctrl+C to disconnect\n\n", .{});
    }

    /// Packet forwarding loop (runs in separate thread)
    fn packetForwardingLoop(session: *cedar.Session, tun_adapter: ?*taptun.TunAdapter, ready_event: *std.Thread.ResetEvent) void {
        var tun_buffer: [65536]u8 = undefined;
        var packet_count: u64 = 0;
        var sent_count: u64 = 0;

        std.debug.print("[FORWARD] 🚀 Starting queue-based bidirectional forwarding\n", .{});

        if (tun_adapter) |adapter| {
            std.debug.print("[FORWARD] 🌐 TUN device active: {s}\n", .{adapter.device.getName()});
            std.debug.print("[FORWARD] 🔄 Bidirectional packet forwarding enabled\n", .{});
        } else {
            std.debug.print("[FORWARD] ⚠️  Running without TUN device (logging only)\n", .{});
        }

        std.debug.print("[FORWARD] 📡 Synchronous event loop (non-blocking I/O)\n\n", .{});

        // Signal that forwarding loop is ready and polling
        // This ensures we're listening BEFORE DHCP packets are sent
        std.debug.print("[FORWARD] ✅ Forwarding loop ready - signaling main thread\n", .{});
        ready_event.set();
        
        // Small delay to ensure main thread receives signal before we send DHCP
        std.Thread.sleep(10 * std.time.ns_per_ms);
        
        // Send initial DHCP packets immediately (like C Bridge adapter does)
        std.debug.print("[FORWARD] 📡 Sending initial DHCP packets...\n", .{});
        session.sendInitialDhcpPackets() catch |err| {
            std.debug.print("[FORWARD] ⚠️  Failed to send initial DHCP: {}\n", .{err});
        };

        while (true) {
            // ═══════════════════════════════════════
            // UPSTREAM: TUN → Server (synchronous send)
            // ═══════════════════════════════════════
            if (tun_adapter) |adapter| {
                if (adapter.readIp(&tun_buffer)) |ip_packet| {
                    // Send packet synchronously (non-blocking)
                    session.sendDataPacket(ip_packet) catch |err| {
                        std.debug.print("[FORWARD] ⚠️  Send error: {}\n", .{err});
                        continue;
                    };

                    sent_count += 1;
                    if (sent_count % 100 == 0) {
                        std.debug.print("[FORWARD] 📤 Sent {} packets upstream\n", .{sent_count});
                    }
                } else |err| {
                    if (err != error.WouldBlock) {
                        std.debug.print("[FORWARD] ⚠️  TUN read error: {}\n", .{err});
                    }
                }
            }

            // ═══════════════════════════════════════
            // DOWNSTREAM: Server → TUN (synchronous receive)
            // ═══════════════════════════════════════
            var recv_buffer: [65536]u8 = undefined;
            var connection_alive = true;
            while (true) {
                // Receive packet synchronously (non-blocking, returns null if none available)
                const maybe_packet = session.tryReceiveDataPacket(&recv_buffer) catch |err| {
                    // Fatal connection errors - exit main loop
                    if (err == error.InternalError or err == error.IoError or err == error.NotConnected) {
                        std.debug.print("[FORWARD] ❌ Fatal connection error: {} - exiting\n", .{err});
                        connection_alive = false;
                        break;
                    }
                    std.debug.print("[FORWARD] ⚠️  Receive error: {}\n", .{err});
                    break; // Break inner loop on error
                };

                const ip_packet = maybe_packet orelse break; // No more packets available

                packet_count += 1;

                if (tun_adapter) |adapter| {
                    // Write IP packet to TUN device
                    adapter.writeIp(ip_packet) catch |err| {
                        std.debug.print("[FORWARD] ⚠️  TUN write error: {}\n", .{err});
                        continue;
                    };

                    if (packet_count % 100 == 0) {
                        std.debug.print("[FORWARD] 📥 Received {} packets downstream\n", .{packet_count});
                    }
                } else {
                    // No TUN device - just log
                    std.debug.print("[FORWARD] 📥 Received {} bytes (packet #{})\n", .{ ip_packet.len, packet_count });

                    if (ip_packet.len >= 1) {
                        const ip_version = (ip_packet[0] >> 4) & 0x0F;
                        if (ip_version == 4) {
                            std.debug.print("[FORWARD]   IPv4 packet\n", .{});
                        } else if (ip_version == 6) {
                            std.debug.print("[FORWARD]   IPv6 packet\n", .{});
                        }
                    }
                }
            }

            // Exit main loop if connection died
            if (!connection_alive) {
                std.debug.print("[FORWARD] 🔴 Connection terminated - stopping forwarding loop\n", .{});
                break;
            }

            // ═══════════════════════════════════════
            // Keep-alive maintenance  
            // ═══════════════════════════════════════
            // Send keep-alive every 5 seconds to prevent timeout
            session.pollKeepalive(5) catch |err| {
                std.debug.print("[FORWARD] ⚠️  Keep-alive error: {}\n", .{err});
            };

            // Small delay to prevent busy-waiting (reduced for fast DHCP response)
            std.Thread.sleep(1 * std.time.ns_per_ms);  // 1ms instead of 10ms for faster packet handling
        }
    }

    /// Disconnect from VPN server
    pub fn disconnect(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_disconnect(handle);
        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }
    }

    /// Get current connection status
    pub fn getStatus(self: *const VpnClient) types.ConnectionStatus {
        // For Cedar mode, check Cedar session status directly
        if (self.cedar_session) |*session| {
            const cedar_status = session.getStatus();
            return switch (cedar_status) {
                .Init => .disconnected,
                .Connecting => .connecting,
                .Authenticating => .connecting,
                .Established => .connected,
                .Reconnecting => .connecting,
                .Closing => .disconnected,
                .Terminated => .disconnected,
            };
        }

        // For C Bridge mode, check C Bridge status
        const handle = self.handle orelse return .error_state;

        const status = c.vpn_bridge_get_status(handle);
        return switch (status) {
            c_mod.VPN_STATUS_DISCONNECTED => .disconnected,
            c_mod.VPN_STATUS_CONNECTING => .connecting,
            c_mod.VPN_STATUS_CONNECTED => .connected,
            c_mod.VPN_STATUS_ERROR => .error_state,
            else => .error_state,
        };
    }

    /// Check if client is connected
    pub fn isConnected(self: *const VpnClient) bool {
        return self.getStatus() == .connected;
    }

    /// Get connection information (bytes sent/received, connection time)
    pub fn getConnectionInfo(self: *const VpnClient) !struct {
        bytes_sent: u64,
        bytes_received: u64,
        connected_seconds: u64,
    } {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var bytes_sent: u64 = 0;
        var bytes_received: u64 = 0;
        var connected_time: u64 = 0;

        const result = c.vpn_bridge_get_connection_info(
            handle,
            &bytes_sent,
            &bytes_received,
            &connected_time,
        );

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        return .{
            .bytes_sent = bytes_sent,
            .bytes_received = bytes_received,
            .connected_seconds = connected_time,
        };
    }

    /// Get TUN device name (e.g., "utun6")
    pub fn getDeviceName(self: *const VpnClient) ![64]u8 {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var device_name: [64]u8 = undefined;
        const result = c.vpn_bridge_get_device_name(
            handle,
            &device_name,
            device_name.len,
        );

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        return device_name;
    }

    /// Get learned IP address (0 if not yet learned)
    pub fn getLearnedIp(self: *const VpnClient) !u32 {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var ip: u32 = 0;
        const result = c.vpn_bridge_get_learned_ip(handle, &ip);

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        return ip;
    }

    /// Get learned gateway MAC address
    pub fn getGatewayMac(self: *const VpnClient) !?[6]u8 {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var mac: [6]u8 = undefined;
        var has_mac: u32 = 0;
        const result = c.vpn_bridge_get_gateway_mac(handle, &mac, &has_mac);

        if (result != c_mod.VPN_BRIDGE_SUCCESS) {
            return VpnError.OperationFailed;
        }

        if (has_mac != 0) {
            return mac;
        }
        return null;
    }

    // ============================================
    // Reconnection Management
    // ============================================

    /// Enable automatic reconnection with specified parameters.
    pub fn enableReconnect(
        self: *VpnClient,
        max_attempts: u32,
        min_backoff: u32,
        max_backoff: u32,
    ) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_enable_reconnect(
            handle,
            max_attempts,
            min_backoff,
            max_backoff,
        );

        if (result != 0) {
            return VpnError.ConnectionFailed;
        }
    }

    /// Disable automatic reconnection.
    pub fn disableReconnect(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_disable_reconnect(handle);

        if (result != 0) {
            return VpnError.ConnectionFailed;
        }
    }

    /// Get current reconnection state and determine if reconnection should occur.
    pub fn getReconnectInfo(self: *const VpnClient) !ReconnectInfo {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        var enabled: u8 = 0;
        var attempt: u32 = 0;
        var max_attempts: u32 = 0;
        var current_backoff: u32 = 0;
        var next_retry_time: u64 = 0;
        var consecutive_failures: u32 = 0;
        var last_disconnect_time: u64 = 0;

        const result = c.vpn_bridge_get_reconnect_info(
            handle,
            &enabled,
            &attempt,
            &max_attempts,
            &current_backoff,
            &next_retry_time,
            &consecutive_failures,
            &last_disconnect_time,
        );

        if (result < 0) {
            return VpnError.ConnectionFailed;
        }

        return ReconnectInfo{
            .enabled = enabled != 0,
            .should_reconnect = result == 1,
            .attempt = attempt,
            .max_attempts = max_attempts,
            .current_backoff = current_backoff,
            .next_retry_time = next_retry_time,
            .consecutive_failures = consecutive_failures,
            .last_disconnect_time = last_disconnect_time,
        };
    }

    /// Mark current disconnect as user-requested (prevents reconnection).
    pub fn markUserDisconnect(self: *VpnClient) !void {
        const handle = self.handle orelse return VpnError.InitializationFailed;

        const result = c.vpn_bridge_mark_user_disconnect(handle);

        if (result != 0) {
            return VpnError.ConnectionFailed;
        }
    }
};
