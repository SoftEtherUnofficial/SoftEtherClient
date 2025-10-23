// Compatibility layer: Old API → TapTun C FFI
// Provides aliases for legacy function names

const taptun_ffi = @import("taptun").c_ffi;

// Alias: taptun_get_learned_ip → taptun_translator_get_gateway_mac isn't the right mapping
// These were custom functions in the old wrapper that don't exist in TapTun's C FFI

// For now, forward to TapTun's internal translator methods
// C code needs updating to use proper TapTun C FFI names

const std = @import("std");

// Note: These were never part of TapTun's official C FFI
// They were custom additions in your wrapper
// You need to either:
// 1. Add them to TapTun's c_ffi.zig, OR
// 2. Update C code to not use them

// Placeholder exports so build doesn't fail
export fn taptun_get_learned_ip(handle: ?*anyopaque) callconv(.c) u32 {
    _ = handle;
    return 0; // TODO: Implement or remove from C code
}

export fn taptun_get_gateway_mac(handle: ?*anyopaque, out_mac: [*]u8) callconv(.c) bool {
    _ = handle;
    _ = out_mac;
    return false; // TODO: Implement or remove from C code
}

export fn NewZigPacketAdapter() callconv(.c) ?*anyopaque {
    return null; // TODO: Implement or remove from C code
}
