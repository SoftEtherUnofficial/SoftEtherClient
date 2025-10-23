// Mobile FFI Root Module
// This module exports all mobile FFI C functions
// Pure C bridge - no Zig dependencies needed

// All functions are implemented in mobile_ffi_c.c
// This file just ensures the library builds correctly
comptime {
    // Force link with C code
    _ = @import("std");
}

// Export nothing from Zig side - all exports come from C
// The C functions are linked automatically through build.zig addCSourceFiles
