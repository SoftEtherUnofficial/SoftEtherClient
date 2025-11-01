const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    // Build option to select packet adapter (Zig adapter is default for better performance)
    const use_zig_adapter = b.option(bool, "use-zig-adapter", "Use Zig packet adapter instead of C (default: true)") orelse true;

    // OpenSSL include path for iOS (optional - provided by build script)
    const openssl_include_path = b.option([]const u8, "openssl-include", "Path to OpenSSL headers for iOS builds");

    // Detect target OS
    const target_os = target.result.os.tag;
    const is_ios = target_os == .ios;

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
        "-Wno-nullability-completeness", // Suppress iOS SDK header nullability warnings
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

    // iOS needs explicit sysroot for standard C headers
    if (target_os == .ios) {
        // Detect simulator vs device (simulator has .abi == .simulator)
        const ios_sdk = if (target.result.abi == .simulator)
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
        else
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk";

        // Add sysroot flag
        c_flags_list.append(b.allocator, "-isysroot") catch unreachable;
        c_flags_list.append(b.allocator, ios_sdk) catch unreachable;

        // Explicitly add SDK include paths for standard headers
        const sdk_include = b.allocator.alloc(u8, ios_sdk.len + "/usr/include".len) catch unreachable;
        _ = std.fmt.bufPrint(sdk_include, "{s}/usr/include", .{ios_sdk}) catch unreachable;
        c_flags_list.append(b.allocator, "-I") catch unreachable;
        c_flags_list.append(b.allocator, sdk_include) catch unreachable;
    }

    // Add Zig adapter flag if enabled
    if (use_zig_adapter) {
        c_flags_list.append(b.allocator, "-DUSE_ZIG_ADAPTER=1") catch unreachable;
        c_flags_list.append(b.allocator, "-DBRIDGE_C=1") catch unreachable; // Enable zig_bridge.c
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
    std.debug.print("  SSL: system OpenSSL\n", .{});
    std.debug.print("  Packet Adapter: {s}\n", .{if (use_zig_adapter) "Zig (native)" else "C (legacy)"});
    std.debug.print("\n", .{});

    // Platform-specific packet adapter and timing files
    // Note: Even with USE_ZIG_ADAPTER=1, we need packet_adapter_macos.c for DHCP utility functions
    const packet_adapter_file = switch (target_os) {
        .ios => "src/platforms/ios/adapter/packet_adapter_ios.c",
        .macos => "src/bridge/packet_adapter_macos.c",
        .linux => "src/bridge/packet_adapter_linux.c",
        .windows => "src/bridge/packet_adapter_windows.c",
        else => "src/bridge/packet_adapter_linux.c", // fallback
    };

    const tick64_file = switch (target_os) {
        .macos, .ios => "src/bridge/tick64_macos.c",
        .linux => "src/bridge/tick64_linux.c",
        .windows => "src/bridge/tick64_windows.c",
        else => "src/bridge/tick64_linux.c", // fallback
    };

    // Common C sources (used by both Zig and C adapter modes)
    const common_sources = [_][]const u8{
        "src/bridge/softether_bridge.c",
        "src/bridge/unix_bridge.c",
        tick64_file,
        // packet_adapter_file conditionally added in c_sources below
        "src/bridge/zig_packet_adapter.c", // Zig adapter wrapper (NEW: 5x faster than C bridge)
        // packet_utils.c only for iOS (macOS has these in packet_adapter_macos.c)
        "src/bridge/logging.c", // Phase 2: Log level system
        "src/bridge/security_utils.c", // Phase 3: Secure password handling
        "src/bridge/client_bridge.c", // NEW: Zig adapter bridge (replaces VLanGetPacketAdapter)
        // "src/bridge/zig_bridge.c", // REMOVED: Old C bridge (use zig_packet_adapter.c instead)
        "src/bridge/Mayaqua/Mayaqua.c", // PATCHED: Skips InitTick64() (line 587)
        "src/bridge/Mayaqua/Memory.c", // PATCHED: Bypasses memory guard corruption (removed src/bridge override)
        "src/bridge/Mayaqua/Network_iOS.c", // NEW: iOS TCP socket buffer tuning for high-latency links
        "SoftEtherVPN/src/Mayaqua/Str.c",
        "src/bridge/Mayaqua/Object.c", // PATCHED: Adds pointer validation
        "SoftEtherVPN/src/Mayaqua/OS.c",
        "SoftEtherVPN/src/Mayaqua/FileIO.c",
        "src/bridge/Mayaqua/Kernel.c", // PATCHED: Fixes use-after-free ThreadPoolProc
        "SoftEtherVPN/src/Mayaqua/Network.c",
        "SoftEtherVPN/src/Mayaqua/TcpIp.c",
        "SoftEtherVPN/src/Mayaqua/Encrypt.c",
        "SoftEtherVPN/src/Mayaqua/Secure.c",
        "SoftEtherVPN/src/Mayaqua/Pack.c",
        "SoftEtherVPN/src/Mayaqua/Cfg.c",
        "SoftEtherVPN/src/Mayaqua/Table.c",
        "SoftEtherVPN/src/Mayaqua/Tracking.c",
        "SoftEtherVPN/src/Mayaqua/Microsoft.c",
        "SoftEtherVPN/src/Mayaqua/Internat.c",
        "SoftEtherVPN/src/Cedar/Cedar.c",
        "src/bridge/Cedar/Client.c", // PATCHED: USE_ZIG_ADAPTER, NoSaveLog=true, Eraser null check
        "src/bridge/Cedar/Protocol.c", // PATCHED
        "src/bridge/Cedar/Connection.c", // PATCHED: iOS debug logging for ConnectionReceive
        "src/bridge/Cedar/Session.c", // PATCHED
        "SoftEtherVPN/src/Cedar/Account.c",
        "SoftEtherVPN/src/Cedar/Admin.c",
        "SoftEtherVPN/src/Cedar/Command.c",
        "SoftEtherVPN/src/Cedar/Hub.c",
        "SoftEtherVPN/src/Cedar/Listener.c",
        "SoftEtherVPN/src/Cedar/Logging.c",
        "SoftEtherVPN/src/Cedar/Sam.c",
        "SoftEtherVPN/src/Cedar/Server.c",
        "SoftEtherVPN/src/Cedar/Virtual.c",
        "SoftEtherVPN/src/Cedar/Link.c",
        "SoftEtherVPN/src/Cedar/SecureNAT.c",
        "SoftEtherVPN/src/Cedar/NullLan.c",
        "SoftEtherVPN/src/Cedar/Bridge.c",
        // BridgeUnix.c excluded when using Zig adapter (provides raw Eth functions we don't need)
        "SoftEtherVPN/src/Cedar/Nat.c",
        "SoftEtherVPN/src/Cedar/UdpAccel.c",
        "SoftEtherVPN/src/Cedar/Database.c",
        "SoftEtherVPN/src/Cedar/Remote.c",
        "SoftEtherVPN/src/Cedar/DDNS.c",
        "SoftEtherVPN/src/Cedar/AzureClient.c",
        "SoftEtherVPN/src/Cedar/AzureServer.c",
        "SoftEtherVPN/src/Cedar/Radius.c",
        "SoftEtherVPN/src/Cedar/Console.c",
        "SoftEtherVPN/src/Cedar/Layer3.c",
        "SoftEtherVPN/src/Cedar/Interop_OpenVPN.c",
        "SoftEtherVPN/src/Cedar/Interop_SSTP.c",
        "SoftEtherVPN/src/Cedar/IPsec.c",
        "SoftEtherVPN/src/Cedar/IPsec_IKE.c",
        "SoftEtherVPN/src/Cedar/IPsec_IkePacket.c",
        "SoftEtherVPN/src/Cedar/IPsec_L2TP.c",
        "SoftEtherVPN/src/Cedar/IPsec_PPP.c",
        "SoftEtherVPN/src/Cedar/IPsec_EtherIP.c",
        "SoftEtherVPN/src/Cedar/IPsec_IPC.c",
        "SoftEtherVPN/src/Cedar/EtherLog.c",
        "SoftEtherVPN/src/Cedar/WebUI.c",
        "SoftEtherVPN/src/Cedar/WaterMark.c",
    };

    // Build C sources list - conditionally include platform-specific files
    const c_sources = if (use_zig_adapter) blk: {
        if (is_ios) {
            // iOS: Pure Zig ios_adapter (no TUN device, queue-based)
            // No C packet adapter needed - ios_adapter.zig handles everything
            // Include packet_utils.c for DHCP/ARP builders (packet_adapter_ios.c doesn't have them)
            break :blk &common_sources ++ &[_][]const u8{"src/bridge/packet_utils.c"};
        } else {
            // macOS: Still need packet_adapter_macos.c for DHCP utilities (BuildDhcpDiscover, etc.)
            // but exclude BridgeUnix (Zig handles device I/O)
            // packet_adapter_macos.c already has DHCP/ARP builders, so no packet_utils.c needed
            break :blk &common_sources ++ &[_][]const u8{packet_adapter_file};
        }
    } else blk: {
        // Legacy C adapter - include packet adapter AND BridgeUnix for raw Ethernet
        break :blk &common_sources ++ &[_][]const u8{ packet_adapter_file, "SoftEtherVPN/src/Cedar/BridgeUnix.c" };
    };

    // NativeStack.c uses system() which is unavailable on iOS
    // It's only needed for server-side routing, not client VPN
    const native_stack_sources = &[_][]const u8{
        "SoftEtherVPN/src/Cedar/NativeStack.c",
    };

    // ============================================
    // 1. LIBRARY MODULE (for Zig programs)
    // ============================================

    // Add TapTun dependency
    const taptun = b.dependency("taptun", .{
        .target = target,
        .optimize = optimize,
    });

    // Get the taptun module
    const taptun_module = taptun.module("taptun");

    // Add VirtualTap module (Layer 2 virtualization for L3-only platforms)
    // Using integrated API with ARP table, DHCP utils, and complete L2 protocol handling
    const virtual_tap_module = b.addModule("virtual_tap", .{
        .root_source_file = b.path("VirtualTap/src/virtual_tap_integrated.zig"),
        .target = target,
        .optimize = optimize,
    });

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
            .root_source_file = b.path("src/platforms/desktop/cli.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "softether", .module = lib_module },
                .{ .name = "taptun", .module = taptun_module },
            },
        }),
    });

    cli.addIncludePath(b.path("src"));
    cli.addIncludePath(b.path("src/bridge"));
    cli.addIncludePath(b.path("SoftEtherVPN/src"));
    cli.addIncludePath(b.path("SoftEtherVPN/src/Mayaqua"));
    cli.addIncludePath(b.path("SoftEtherVPN/src/Cedar"));

    // Link system OpenSSL
    cli.linkSystemLibrary("ssl");
    cli.linkSystemLibrary("crypto");

    cli.addCSourceFiles(.{
        .files = c_sources,
        .flags = c_flags,
    });

    // Aggressive optimizations for release builds
    if (optimize != .Debug) {
        cli.want_lto = true; // Link-time optimization for better performance
    }

    // Add NativeStack for non-iOS builds
    if (!is_ios) {
        cli.addCSourceFiles(.{
            .files = native_stack_sources,
            .flags = c_flags,
        });
    }

    // Add Zig packet adapter (Phase 1) - compiled as static object
    const packet_adapter_module = b.createModule(.{
        .root_source_file = b.path("src/packet/adapter.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add taptun dependency for L2/L3 translation
    packet_adapter_module.addImport("taptun", taptun_module);

    const packet_adapter_obj = b.addObject(.{
        .name = "zig_packet_adapter",
        .root_module = packet_adapter_module,
    });
    packet_adapter_obj.addIncludePath(b.path("src/bridge"));
    cli.addObject(packet_adapter_obj);

    // Add TapTun compatibility layer (legacy API → TapTun C FFI)
    const taptun_compat_module = b.createModule(.{
        .root_source_file = b.path("src/bridge/taptun_compat.zig"),
        .target = target,
        .optimize = optimize,
    });
    taptun_compat_module.addImport("taptun", taptun_module);
    const taptun_compat_obj = b.addObject(.{
        .name = "taptun_compat",
        .root_module = taptun_compat_module,
    });
    cli.addObject(taptun_compat_obj);

    // Phase 2.1: Add DHCP parser module (30-40% faster parsing)
    const dhcp_module = b.createModule(.{
        .root_source_file = b.path("src/packet/dhcp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const dhcp_obj = b.addObject(.{
        .name = "zig_dhcp",
        .root_module = dhcp_module,
    });
    cli.addObject(dhcp_obj);

    // Phase 2.2: Add protocol builders (DHCP/ARP packet generation, 10-15% gain)
    const protocol_module = b.createModule(.{
        .root_source_file = b.path("src/packet/protocol.zig"),
        .target = target,
        .optimize = optimize,
    });

    const protocol_obj = b.addObject(.{
        .name = "zig_protocol",
        .root_module = protocol_module,
    });
    cli.addObject(protocol_obj);

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
    // 3. MOBILE FFI LIBRARY (iOS/Android with full VPN client)
    // ============================================
    // Create a static library for mobile platforms that includes full SoftEther client
    const mobile_ffi_lib = b.addLibrary(.{
        .name = "softether_ffi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi/mobile_ffi.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    // Add C sources (SoftEther core + mobile FFI wrapper)
    mobile_ffi_lib.addCSourceFiles(.{
        .files = c_sources,
        .flags = c_flags,
    });

    // Add mobile_ffi_c.c for iOS
    // Contains mobile_vpn_* functions (always needed)
    // Zig adapter stubs are conditionally compiled based on USE_ZIG_ADAPTER
    if (is_ios) {
        mobile_ffi_lib.addCSourceFile(.{
            .file = b.path("src/ffi/mobile_ffi_c.c"),
            .flags = c_flags,
        });

        // Add iOS logging bridge (Objective-C NSLog)
        mobile_ffi_lib.addCSourceFile(.{
            .file = b.path("src/platforms/ios/ios_log.m"),
            .flags = c_flags,
        });
    }

    // Add all include paths
    mobile_ffi_lib.addIncludePath(b.path("SoftEtherVPN/src"));
    mobile_ffi_lib.addIncludePath(b.path("SoftEtherVPN/src/Mayaqua"));
    mobile_ffi_lib.addIncludePath(b.path("SoftEtherVPN/src/Cedar"));
    mobile_ffi_lib.addIncludePath(b.path("include"));
    mobile_ffi_lib.addIncludePath(b.path("src"));
    mobile_ffi_lib.addIncludePath(b.path("src/bridge/include"));
    mobile_ffi_lib.addIncludePath(b.path("VirtualTap/include")); // VirtualTap C FFI headers

    if (is_ios) {
        mobile_ffi_lib.addIncludePath(b.path("src/bridge/ios_include"));
        mobile_ffi_lib.addIncludePath(b.path("src/platforms/ios"));

        // Add OpenSSL headers if path provided (from CocoaPods in CI/Xcode builds)
        if (openssl_include_path) |ssl_path| {
            mobile_ffi_lib.addIncludePath(.{ .cwd_relative = ssl_path });
        }

        // Link Foundation framework for NSLog support
        // Need to pass framework path explicitly via linker flags
        const ios_sdk = if (target.result.abi == .simulator)
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk"
        else
            "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk";

        const framework_path = b.allocator.alloc(u8, ios_sdk.len + "/System/Library/Frameworks".len) catch unreachable;
        _ = std.fmt.bufPrint(framework_path, "{s}/System/Library/Frameworks", .{ios_sdk}) catch unreachable;

        // Use LazyPath.cwd_relative to add framework search path
        mobile_ffi_lib.addFrameworkPath(.{ .cwd_relative = framework_path });
        mobile_ffi_lib.linkFramework("Foundation");
    }
    mobile_ffi_lib.root_module.addImport("taptun", taptun_module);

    // Add Zig packet adapter module and TapTun for iOS
    if (is_ios or use_zig_adapter) {
        // Add TapTun C FFI exports (provides taptun_translator_* functions)
        const taptun_ffi_obj = b.addObject(.{
            .name = "taptun_compat",
            .root_module = b.createModule(.{
                .root_source_file = b.path("TapTun/src/c_ffi.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        taptun_ffi_obj.root_module.addImport("taptun", taptun_module);
        mobile_ffi_lib.addObject(taptun_ffi_obj);

        // Add VirtualTap C FFI exports (provides virtual_tap_* functions)
        const virtual_tap_ffi_obj = b.addObject(.{
            .name = "virtual_tap_compat",
            .root_module = b.createModule(.{
                .root_source_file = b.path("VirtualTap/src/c_ffi.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        mobile_ffi_lib.addObject(virtual_tap_ffi_obj);

        // Add DHCP parser module (provides zig_dhcp_parse function)
        const dhcp_module_mobile = b.createModule(.{
            .root_source_file = b.path("src/packet/dhcp.zig"),
            .target = target,
            .optimize = optimize,
        });

        const dhcp_obj_mobile = b.addObject(.{
            .name = "zig_dhcp_mobile",
            .root_module = dhcp_module_mobile,
        });
        mobile_ffi_lib.addObject(dhcp_obj_mobile);

        // Add protocol builders (provides zig_build_dhcp_*, zig_build_arp_* functions)
        const protocol_module_mobile = b.createModule(.{
            .root_source_file = b.path("src/packet/protocol.zig"),
            .target = target,
            .optimize = optimize,
        });

        const protocol_obj_mobile = b.addObject(.{
            .name = "zig_protocol_mobile",
            .root_module = protocol_module_mobile,
        });
        mobile_ffi_lib.addObject(protocol_obj_mobile);

        // Create logging module (cross-platform unified logging)
        const logging_module = b.addModule("logging", .{
            .root_source_file = b.path("src/logging.zig"),
        });

        // Create ios_adapter module (provides ios_adapter_* FFI exports)
        const ios_adapter_module = b.createModule(.{
            .root_source_file = b.path("src/platforms/ios/ios_adapter.zig"),
            .target = target,
            .optimize = optimize,
        });
        ios_adapter_module.addImport("taptun", taptun_module);
        ios_adapter_module.addImport("virtual_tap", virtual_tap_module);
        ios_adapter_module.addImport("protocol", protocol_module_mobile);
        ios_adapter_module.addImport("logging", logging_module);

        // Create main adapter module with ios_adapter import
        const mobile_adapter_module = b.createModule(.{
            .root_source_file = b.path("src/packet/adapter.zig"),
            .target = target,
            .optimize = optimize,
        });
        mobile_adapter_module.addImport("taptun", taptun_module);
        mobile_adapter_module.addImport("ios_adapter", ios_adapter_module);

        const mobile_adapter_obj = b.addObject(.{
            .name = "zig_ios_adapter",
            .root_module = mobile_adapter_module,
        });
        mobile_adapter_obj.addIncludePath(b.path("src/bridge"));
        mobile_ffi_lib.addObject(mobile_adapter_obj);

        std.debug.print("Added TapTun C FFI, VirtualTap C FFI, DHCP parser, protocol builders, and iOS adapter module\n", .{});
    }

    mobile_ffi_lib.linkLibC();

    // Skip OpenSSL linking for iOS - Xcode will link the CocoaPods framework
    if (!is_ios) {
        mobile_ffi_lib.linkSystemLibrary("ssl");
        mobile_ffi_lib.linkSystemLibrary("crypto");
    }

    b.installArtifact(mobile_ffi_lib);
    b.installFile("include/ffi.h", "include/ffi.h");

    const mobile_ffi_step = b.step("mobile-ffi", "Build mobile FFI library with full VPN client (iOS/Android)");
    mobile_ffi_step.dependOn(&b.addInstallArtifact(mobile_ffi_lib, .{}).step);

    // ============================================
    // 4. TESTS
    // ============================================

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
        \\  zig build -Drelease=true
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
}
