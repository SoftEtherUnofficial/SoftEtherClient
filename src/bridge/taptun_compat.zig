// Compatibility layer: Old API → TapTun C FFI
// Provides aliases for legacy function names

const taptun_ffi = @import("taptun").c_ffi;

// Alias: taptun_get_learned_ip → taptun_translator_get_gateway_mac isn't the right mapping
// These were custom functions in the old wrapper that don't exist in TapTun's C FFI

// For now, forward to TapTun's internal translator methods
// C code needs updating to use proper TapTun C FFI names

const std = @import("std");

// Note: These functions are iOS-specific and only used when NOT using Zig adapter
// Desktop Zig adapter (zig_bridge.c) doesn't call these
// They're only compiled for legacy C adapter support
// softether_bridge.c checks use_zig_adapter at runtime and skips these calls

// Stub implementations for linking (never actually called in Zig adapter mode)
export fn taptun_get_learned_ip(handle: ?*anyopaque) callconv(.c) u32 {
    _ = handle;
    return 0;
}

export fn taptun_get_gateway_mac(handle: ?*anyopaque, out_mac: [*]u8) callconv(.c) bool {
    _ = handle;
    _ = out_mac;
    return false;
}
