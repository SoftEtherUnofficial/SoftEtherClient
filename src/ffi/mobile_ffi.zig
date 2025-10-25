// Mobile FFI Root Module
// Combines two FFI layers:
//   1. Connection management: mobile_ffi_c.c (C) - mobile_vpn_* functions
//   2. Packet I/O: adapter.zig (Zig) - ios_adapter_* functions
//
// This provides a SINGLE unified FFI for Swift to call.
// Previously we had 3 layers (mobile_vpn_*, ios_adapter_*, zig_adapter_*)
// Now we have 2: mobile_vpn_* (this file + C) and ios_adapter_* (adapter.zig)

comptime {
    // Force link with C code
    _ = @import("std");
}

// Export nothing from Zig side - all exports come from:
//   - mobile_ffi_c.c (connection management)
//   - adapter.zig (packet I/O)
// Both are linked automatically through build.zig
