const std = @import("std");

pub fn build(b: *std.Build) void {
    // Print build banner
    std.debug.print("\n", .{});
    std.debug.print("╔══════════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║           SoftEtherZig - Pure Zig VPN Client                ║\n", .{});
    std.debug.print("║              Progressive C to Zig Migration                 ║\n", .{});
    std.debug.print("║         Phase 3: Protocol Layer - COMPLETE ✅                ║\n", .{});
    std.debug.print("║    VPN ✓  Packet ✓  Crypto ✓  Integration ✓  (REAL!)      ║\n", .{});
    std.debug.print("╚══════════════════════════════════════════════════════════════╝\n", .{});
    std.debug.print("\n", .{});

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    // Build option to select packet adapter (Zig adapter is default for better performance)
    const use_zig_adapter = b.option(bool, "use-zig-adapter", "Use Zig packet adapter instead of C (default: true)") orelse true;

    // Detect target OS
    const target_os = target.result.os.tag;
    const is_ios = target_os == .ios;

    // Build option for SSL: use system OpenSSL on native macOS/Linux, OpenSSL-Zig for iOS/cross-compile
    const is_native_desktop = (target_os == .macos or target_os == .linux) and
        target.result.cpu.arch == std.Target.Cpu.Arch.aarch64;
    const use_system_ssl = b.option(bool, "system-ssl", "Use system OpenSSL instead of OpenSSL-Zig (default: true for native macOS/Linux)") orelse
        is_native_desktop;

    // iOS SDK configuration for OpenSSL-Zig
    const ios_sdk_path = if (is_ios) blk: {
        if (target.result.cpu.arch == .aarch64 and target.result.abi == .simulator) {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else if (target.result.cpu.arch == .x86_64) {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk";
        } else {
            break :blk "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk";
        }
    } else null;

    // Get OpenSSL dependency (conditional based on use_system_ssl)
    const openssl_dep = if (!use_system_ssl) b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    }) else null;
    const openssl = if (openssl_dep) |dep| blk: {
        const ssl_lib = dep.artifact("ssl");
        // Add iOS SDK sysroot for OpenSSL-Zig
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            const ios_frameworks = b.fmt("{s}/System/Library/Frameworks", .{sdk});
            ssl_lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
            ssl_lib.addFrameworkPath(.{ .cwd_relative = ios_frameworks });
            // iOS doesn't have CoreServices, use Foundation instead
            ssl_lib.linkFramework("Foundation");
            ssl_lib.linkFramework("Security");
        }
        break :blk ssl_lib;
    } else null;

    const crypto = if (openssl_dep) |dep| blk: {
        const crypto_lib = dep.artifact("crypto");
        // Add iOS SDK sysroot for OpenSSL-Zig
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            const ios_frameworks = b.fmt("{s}/System/Library/Frameworks", .{sdk});
            crypto_lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
            crypto_lib.addFrameworkPath(.{ .cwd_relative = ios_frameworks });
            // iOS doesn't have CoreServices, use Foundation instead
            crypto_lib.linkFramework("Foundation");
            crypto_lib.linkFramework("Security");
        }
        break :blk crypto_lib;
    } else null;

    // Base C flags (common to all platforms)
    const base_c_flags = &[_][]const u8{
        "-std=c99",
        "-D_REENTRANT",
        "-D_THREAD_SAFE",
        "-DCPU_64",
        "-D_FILE_OFFSET_BITS=64",
        "-DVPN_SPEED",
        "-D__bool_true_false_are_defined=1",
        "-Wno-deprecated-declarations",
        "-Wno-unused-parameter",
        "-Wno-unused-variable",
        "-Wno-sign-compare",
        "-Wno-incompatible-function-pointer-types",
        "-Wno-int-conversion",
        "-Wno-incompatible-pointer-types-discards-qualifiers",
        "-Wno-implicit-function-declaration",
        "-Wno-strict-prototypes",
        "-fno-strict-aliasing",
        "-fsigned-char",
        "-fno-sanitize=shift",
        "-fno-sanitize=null",
        "-fno-sanitize=undefined",
    };

    // Platform-specific defines
    var c_flags_list = std.ArrayList([]const u8){};
    c_flags_list = std.ArrayList([]const u8).initCapacity(b.allocator, 50) catch unreachable;
    defer c_flags_list.deinit(b.allocator);

    // Add base flags
    c_flags_list.appendSlice(b.allocator, base_c_flags) catch unreachable;

    // Add Zig adapter flag if enabled
    if (use_zig_adapter) {
        c_flags_list.append(b.allocator, "-DUSE_ZIG_ADAPTER=1") catch unreachable;
    }

    if (is_ios) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_MACOS", "-DUNIX_IOS", "-DTARGET_OS_IPHONE=1" }) catch unreachable;
    } else if (target_os == .macos) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_MACOS" }) catch unreachable;
    } else if (target_os == .linux) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DUNIX", "-DUNIX_LINUX" }) catch unreachable;
    } else if (target_os == .windows) {
        c_flags_list.appendSlice(b.allocator, &[_][]const u8{ "-DWIN32", "-D_WIN32" }) catch unreachable;
    } else {
        c_flags_list.append(b.allocator, "-DUNIX") catch unreachable;
    }

    const c_flags = c_flags_list.items;

    // Print build configuration
    std.debug.print("Build Configuration:\n", .{});
    std.debug.print("  Target: {s}\n", .{@tagName(target_os)});
    std.debug.print("  Optimize: {s}\n", .{@tagName(optimize)});
    std.debug.print("  SSL: {s}\n", .{if (use_system_ssl) "system" else "OpenSSL-Zig"});
    std.debug.print("  Packet Adapter: {s}\n", .{if (use_zig_adapter) "Zig (native)" else "C (legacy)"});
    std.debug.print("\n", .{});

    // Platform-specific packet adapter and timing files
    const packet_adapter_src = switch (target.result.os.tag) {
        .ios => "src/bridge/platform/packet_adapter_ios_stub.c",
        .macos => "src/bridge/platform/packet_adapter_macos.c",
        .linux => "src/bridge/platform/packet_adapter_linux.c",
        .windows => "src/bridge/platform/packet_adapter_windows.c",
        else => "src/bridge/platform/packet_adapter_linux.c", // fallback
    };

    // Note: tick64 now implemented in src/platform/time.zig (pure Zig)

    // ============================================
    // C Source Files
    // ============================================

    // Full source list (includes server components)
    const c_sources_full = &[_][]const u8{
        // Bridge wrapper layer
        // NOTE: softether_bridge.c REMOVED - fully replaced by src/bridge/softether.zig
        "src/bridge/unix_bridge.c", // Stub/compatibility layer for C code dependencies
        "src/bridge/tick64_macos.c", // Time functions - compatibility shim
        "src/bridge/security_utils.c", // Security functions - compatibility shim
        "src/bridge/packet_utils.c", // Packet builders - compatibility shim
        "src/bridge/session_helper.c", // Session field access helpers
        // Note: Core implementations in src/platform/*.zig (pure Zig)
        packet_adapter_src,
        "src/bridge/zig_packet_adapter.c",
        "src/bridge/Mayaqua/logging.c",
        // Note: security_utils now in src/security/utils.zig (pure Zig)
        "src/bridge/Cedar/client_bridge.c",
        "src/bridge/zig_bridge.c",

        // Mayaqua layer (utility functions) - LOCAL COPIES
        "src/bridge/Mayaqua/Mayaqua.c",
        "src/bridge/Mayaqua/Memory.c",
        "src/bridge/Mayaqua/Str.c",
        "src/bridge/Mayaqua/Object.c",
        "src/bridge/Mayaqua/OS.c",
        "src/bridge/Mayaqua/FileIO.c",
        "src/bridge/Mayaqua/Kernel.c",
        "src/bridge/Mayaqua/Network.c",
        "src/bridge/Mayaqua/TcpIp.c",
        "src/bridge/Mayaqua/Encrypt.c",
        "src/bridge/Mayaqua/Secure.c",
        "src/bridge/Mayaqua/Pack.c",
        "src/bridge/Mayaqua/Cfg.c",
        "src/bridge/Mayaqua/Table.c",
        "src/bridge/Mayaqua/Tracking.c",
        "src/bridge/Mayaqua/Microsoft.c",
        "src/bridge/Mayaqua/Internat.c",

        // Cedar layer (VPN protocol) - LOCAL COPIES
        "src/bridge/Cedar/Cedar.c",
        "src/bridge/Cedar/Client.c",
        "src/bridge/Cedar/Protocol.c",
        "src/bridge/Cedar/Connection.c",
        "src/bridge/Cedar/Session.c",
        "src/bridge/Cedar/Account.c",
        "src/bridge/Cedar/Admin.c",
        "src/bridge/Cedar/Command.c",
        "src/bridge/Cedar/Hub.c",
        "src/bridge/Cedar/Listener.c",
        "src/bridge/Cedar/Logging.c",
        "src/bridge/Cedar/Sam.c",
        "src/bridge/Cedar/Server.c",
        "src/bridge/Cedar/Virtual.c",
        "src/bridge/Cedar/Link.c",
        "src/bridge/Cedar/SecureNAT.c",
        "src/bridge/Cedar/NullLan.c",
        "src/bridge/Cedar/Bridge.c",
        "src/bridge/Cedar/BridgeUnix.c",
        "src/bridge/Cedar/Nat.c",
        "src/bridge/Cedar/UdpAccel.c",
        "src/bridge/Cedar/Database.c",
        "src/bridge/Cedar/Remote.c",
        "src/bridge/Cedar/DDNS.c",
        "src/bridge/Cedar/AzureClient.c",
        "src/bridge/Cedar/AzureServer.c",
        "src/bridge/Cedar/Radius.c",
        "src/bridge/Cedar/Console.c",
        "src/bridge/Cedar/Layer3.c",
        "src/bridge/Cedar/Interop_OpenVPN.c",
        "src/bridge/Cedar/Interop_SSTP.c",
        "src/bridge/Cedar/IPsec.c",
        "src/bridge/Cedar/IPsec_IKE.c",
        "src/bridge/Cedar/IPsec_IkePacket.c",
        "src/bridge/Cedar/IPsec_L2TP.c",
        "src/bridge/Cedar/IPsec_PPP.c",
        "src/bridge/Cedar/IPsec_EtherIP.c",
        "src/bridge/Cedar/IPsec_IPC.c",
        "src/bridge/Cedar/EtherLog.c",
        "src/bridge/Cedar/WebUI.c",
        "src/bridge/Cedar/WaterMark.c",
    };

    // Use full source list - Client/server code is tightly coupled.
    // Can't remove server files without breaking client functionality.
    // Strategy: Keep all C code, port to Zig with proper separation.
    const c_sources = c_sources_full;

    // NativeStack.c uses system() which is unavailable on iOS
    // It's only needed for server-side routing, not client VPN
    const native_stack_sources = &[_][]const u8{
        "src/bridge/Cedar/NativeStack.c",
    };

    // ============================================
    // 1. LIBRARY MODULE (for Zig programs)
    // ============================================

    // Add ZigTapTun dependency
    const taptun = b.dependency("taptun", .{
        .target = target,
        .optimize = optimize,
    });

    // Get the taptun module and configure it for iOS if needed
    const taptun_module = taptun.module("taptun");
    if (is_ios) {
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            taptun_module.addSystemIncludePath(.{ .cwd_relative = ios_include });
        }
    }

    const lib_module = b.addModule("softether", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
    });
    lib_module.addIncludePath(b.path("src"));
    lib_module.addImport("taptun", taptun_module);
    lib_module.link_libc = true;

    // ============================================
    // 2. CLI CLIENT (production tool)
    // ============================================
    const cli = b.addExecutable(.{
        .name = "vpnclient",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "softether", .module = lib_module },
            },
        }),
    });

    cli.addIncludePath(b.path("src"));
    cli.addIncludePath(b.path("src/bridge"));
    cli.addIncludePath(b.path("src/bridge/Mayaqua"));
    cli.addIncludePath(b.path("src/bridge/Cedar"));
    cli.addIncludePath(b.path("src/bridge/VGate"));
    // NOTE: All C source files are in src/bridge/, no dependency on SoftEtherVPN_Stable!

    // Link OpenSSL (system or bundled)
    if (use_system_ssl) {
        cli.linkSystemLibrary("ssl");
        cli.linkSystemLibrary("crypto");
    } else {
        if (crypto) |c| cli.linkLibrary(c);
        if (openssl) |s| cli.linkLibrary(s);
    }

    cli.addCSourceFiles(.{
        .files = c_sources,
        .flags = c_flags,
    });

    // Add NativeStack for non-iOS builds
    if (!is_ios) {
        cli.addCSourceFiles(.{
            .files = native_stack_sources,
            .flags = c_flags,
        });
    }

    // Add ZigTapTun wrapper module
    const taptun_wrapper_module = b.createModule(.{
        .root_source_file = b.path("src/bridge/taptun_wrapper.zig"),
        .target = target,
        .optimize = optimize,
    });
    taptun_wrapper_module.addImport("taptun", taptun_module);

    const taptun_wrapper = b.addObject(.{
        .name = "taptun_wrapper",
        .root_module = taptun_wrapper_module,
    });
    cli.addObject(taptun_wrapper);

    // Add Zig packet adapter (Phase 1) - compiled as static object
    const packet_adapter_module = b.createModule(.{
        .root_source_file = b.path("src/packet/adapter.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add iOS SDK paths to the module itself (for @cImport in dependencies)
    if (is_ios) {
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            packet_adapter_module.addSystemIncludePath(.{ .cwd_relative = ios_include });
        }
    }

    // Add taptun dependency for L2/L3 translation
    packet_adapter_module.addImport("taptun", taptun_module);

    const packet_adapter_obj = b.addObject(.{
        .name = "zig_packet_adapter",
        .root_module = packet_adapter_module,
    });
    packet_adapter_obj.addIncludePath(b.path("src/bridge"));
    
    // Link libc for C imports and allocator functions
    packet_adapter_obj.linkLibC();

    // Add iOS SDK paths for C imports
    if (is_ios) {
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            packet_adapter_obj.addSystemIncludePath(.{ .cwd_relative = ios_include });
        }
    }
    cli.addObject(packet_adapter_obj);

    // Link C library
    cli.linkLibC();

    // Platform-specific system libraries
    if (target_os != .windows) {
        // Unix-like systems
        cli.linkSystemLibrary("pthread");
        cli.linkSystemLibrary("z");

        if (target_os == .macos) {
            cli.linkSystemLibrary("iconv");
            cli.linkSystemLibrary("readline");
            cli.linkSystemLibrary("ncurses");
        } else if (target_os == .linux) {
            cli.linkSystemLibrary("rt");
            cli.linkSystemLibrary("dl");
        }
    } else {
        // Windows
        cli.linkSystemLibrary("ws2_32");
        cli.linkSystemLibrary("iphlpapi");
        cli.linkSystemLibrary("advapi32");
    }

    b.installArtifact(cli);

    // Run step for CLI
    const run_cli = b.addRunArtifact(cli);
    run_cli.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cli.addArgs(args);
    }

    const run_step = b.step("run", "Run the VPN client CLI");
    run_step.dependOn(&run_cli.step);

    // ============================================
    // 3. FFI LIBRARY (Cross-Platform)
    // ============================================
    const ffi_lib = b.addLibrary(.{
        .name = "softether_ffi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi/ffi.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    ffi_lib.root_module.addImport("taptun", taptun_module);
    ffi_lib.linkLibC();
    ffi_lib.addIncludePath(b.path("include"));
    ffi_lib.addIncludePath(b.path("src"));

    // Add iOS SDK configuration for FFI
    if (is_ios) {
        ffi_lib.addIncludePath(b.path("src/bridge/ios_include"));
        if (ios_sdk_path) |sdk| {
            const ios_include = b.fmt("{s}/usr/include", .{sdk});
            const ios_frameworks = b.fmt("{s}/System/Library/Frameworks", .{sdk});
            ffi_lib.addSystemIncludePath(.{ .cwd_relative = ios_include });
            ffi_lib.addFrameworkPath(.{ .cwd_relative = ios_frameworks });
            ffi_lib.linkFramework("Foundation");
            ffi_lib.linkFramework("Security");
        }
    }

    // Link OpenSSL (system or bundled)
    if (use_system_ssl) {
        ffi_lib.linkSystemLibrary("ssl");
        ffi_lib.linkSystemLibrary("crypto");
    } else {
        if (crypto) |c| ffi_lib.linkLibrary(c);
        if (openssl) |s| ffi_lib.linkLibrary(s);
    }

    b.installArtifact(ffi_lib);

    // Also install the header
    b.installFile("include/ffi.h", "include/ffi.h");

    const ffi_step = b.step("ffi", "Build FFI library (cross-platform)");
    ffi_step.dependOn(&b.addInstallArtifact(ffi_lib, .{}).step);

    // ============================================
    // 4. TESTS
    // ============================================

    // Test for Mayaqua memory module
    const memory_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mayaqua/memory.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_memory_tests = b.addRunArtifact(memory_tests);

    // Test for Mayaqua string module
    const string_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mayaqua/string.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_string_tests = b.addRunArtifact(string_tests);

    // Test for Mayaqua collections module
    const collections_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/mayaqua/collections.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_collections_tests = b.addRunArtifact(collections_tests);

    // Test for network socket module
    const socket_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/net/socket.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // Add collections module as dependency
    const collections_mod = b.createModule(.{
        .root_source_file = b.path("src/mayaqua/collections.zig"),
    });
    socket_tests.root_module.addImport("mayaqua_collections", collections_mod);

    const run_socket_tests = b.addRunArtifact(socket_tests);

    // Test for HTTP client module
    const http_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/net/http.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // HTTP module depends on socket module
    const socket_mod_for_http = b.createModule(.{
        .root_source_file = b.path("src/net/socket.zig"),
        .target = target,
        .optimize = optimize,
    });
    socket_mod_for_http.addImport("mayaqua_collections", collections_mod);
    http_tests.root_module.addImport("socket", socket_mod_for_http);
    // Also add collections directly to http tests
    http_tests.root_module.addImport("mayaqua_collections", collections_mod);

    const run_http_tests = b.addRunArtifact(http_tests);

    // Test for connection management module
    const connection_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/net/connection.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // Connection module depends on socket and http modules
    const socket_mod_for_conn = b.createModule(.{
        .root_source_file = b.path("src/net/socket.zig"),
        .target = target,
        .optimize = optimize,
    });
    socket_mod_for_conn.addImport("mayaqua_collections", collections_mod);

    const http_mod_for_conn = b.createModule(.{
        .root_source_file = b.path("src/net/http.zig"),
        .target = target,
        .optimize = optimize,
    });
    http_mod_for_conn.addImport("socket", socket_mod_for_conn);

    connection_tests.root_module.addImport("socket", socket_mod_for_conn);
    connection_tests.root_module.addImport("http", http_mod_for_conn);
    connection_tests.root_module.addImport("mayaqua_collections", collections_mod);

    const run_connection_tests = b.addRunArtifact(connection_tests);

    // Test for VPN protocol module
    const vpn_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/protocol/vpn.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    // VPN protocol depends on network layer modules
    // Reuse the same socket module for all network modules to avoid conflicts
    const socket_mod_shared = b.createModule(.{
        .root_source_file = b.path("src/net/socket.zig"),
        .target = target,
        .optimize = optimize,
    });
    socket_mod_shared.addImport("mayaqua_collections", collections_mod);

    const http_mod_shared = b.createModule(.{
        .root_source_file = b.path("src/net/http.zig"),
        .target = target,
        .optimize = optimize,
    });
    http_mod_shared.addImport("socket", socket_mod_shared);

    const connection_mod_shared = b.createModule(.{
        .root_source_file = b.path("src/net/connection.zig"),
        .target = target,
        .optimize = optimize,
    });
    connection_mod_shared.addImport("socket", socket_mod_shared);
    connection_mod_shared.addImport("http", http_mod_shared);

    vpn_tests.root_module.addImport("socket", socket_mod_shared);
    vpn_tests.root_module.addImport("http", http_mod_shared);
    vpn_tests.root_module.addImport("connection", connection_mod_shared);

    const run_vpn_tests = b.addRunArtifact(vpn_tests);

    // Test for packet protocol
    const packet_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/protocol/packet.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_packet_tests = b.addRunArtifact(packet_tests);

    // Test for crypto protocol
    const crypto_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/protocol/crypto.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_crypto_tests = b.addRunArtifact(crypto_tests);

    // Test for integration layer
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/integration/vpn_client.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Create vpn module with imports for integration tests
    const vpn_mod_for_integration = b.createModule(.{
        .root_source_file = b.path("src/protocol/vpn.zig"),
        .target = target,
        .optimize = optimize,
    });
    vpn_mod_for_integration.addImport("socket", socket_mod_shared);
    vpn_mod_for_integration.addImport("http", http_mod_shared);
    vpn_mod_for_integration.addImport("connection", connection_mod_shared);

    // Add imports for integration tests
    integration_tests.root_module.addImport("vpn", vpn_mod_for_integration);
    integration_tests.root_module.addImport("packet", b.createModule(.{
        .root_source_file = b.path("src/protocol/packet.zig"),
        .target = target,
        .optimize = optimize,
    }));
    integration_tests.root_module.addImport("crypto", b.createModule(.{
        .root_source_file = b.path("src/protocol/crypto.zig"),
        .target = target,
        .optimize = optimize,
    }));
    integration_tests.root_module.addImport("socket", socket_mod_shared);
    integration_tests.root_module.addImport("http", http_mod_shared);
    integration_tests.root_module.addImport("connection", connection_mod_shared);
    integration_tests.root_module.addImport("memory", b.createModule(.{
        .root_source_file = b.path("src/mayaqua/memory.zig"),
        .target = target,
        .optimize = optimize,
    }));

    const run_integration_tests = b.addRunArtifact(integration_tests);

    // Test for macOS platform adapter
    const macos_adapter_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/platform/test_macos_adapter.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    macos_adapter_tests.root_module.addImport("taptun", taptun_module);

    const run_macos_adapter_tests = b.addRunArtifact(macos_adapter_tests);

    // Main test step
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_memory_tests.step);
    test_step.dependOn(&run_string_tests.step);
    test_step.dependOn(&run_collections_tests.step);
    test_step.dependOn(&run_socket_tests.step);
    test_step.dependOn(&run_http_tests.step);
    test_step.dependOn(&run_connection_tests.step);
    test_step.dependOn(&run_vpn_tests.step);
    test_step.dependOn(&run_packet_tests.step);
    test_step.dependOn(&run_crypto_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_macos_adapter_tests.step);

    // ============================================
    // 5. HELP AND INFORMATION
    // ============================================

    const help_step = b.step("help", "Show build system help");
    const help_run = b.addSystemCommand(&[_][]const u8{
        "echo",
        \\
        \\SoftEtherZig Build System
        \\========================
        \\
        \\Available Build Targets:
        \\  zig build                  - Build all targets (default)
        \\  zig build run              - Build and run VPN client CLI
        \\  zig build ffi              - Build FFI library only
        \\  zig build test             - Run unit tests
        \\  zig build clean            - Clean build artifacts
        \\
        \\Build Options:
        \\  -Doptimize=<mode>          - Build mode: Debug, ReleaseSafe, ReleaseFast, ReleaseSmall
        \\                               (default: ReleaseFast)
        \\  -Dtarget=<triple>          - Target platform (e.g., aarch64-macos, x86_64-linux)
        \\  -Dsystem-ssl=<bool>        - Use system OpenSSL (default: true for macOS/Linux)
        \\  -Duse-zig-adapter=<bool>   - Use Zig packet adapter (default: true)
        \\
        \\Examples:
        \\  # Build optimized CLI
        \\  zig build -Doptimize=ReleaseFast
        \\
        \\  # Build for iOS simulator
        \\  zig build -Dtarget=aarch64-ios-simulator -Dsystem-ssl=false
        \\
        \\  # Run tests
        \\  zig build test
        \\
        \\  # Run CLI with arguments
        \\  zig build run -- -h
        \\
        \\  # Cross-compile for Linux from macOS
        \\  zig build -Dtarget=x86_64-linux-gnu
        \\
        \\Documentation:
        \\  README.md                  - Quick start guide
        \\  docs/ZIG_PORTING_ROADMAP.md - Complete porting strategy
        \\  docs/ZIG_PORTING_PROGRESS.md - Task-by-task progress
        \\  docs/MACOS_ADAPTER_MILESTONE.md - Phase 1a completion report
        \\  SECURITY.md                - Security best practices
        \\
        \\Current Status:
        \\  Phase 1: Foundation Layer (20% complete)
        \\  Overall Migration: 3% (2,100/70,000 lines)
        \\  Latest: macOS adapter Phase 1a complete ✓
        \\
        \\Need Help?
        \\  zig build --help           - Standard Zig build help
        \\  zig build help             - This message
        \\
    });
    help_step.dependOn(&help_run.step);

    // Print completion message
    std.debug.print("Build targets prepared. Use 'zig build help' for usage.\n\n", .{});
}
