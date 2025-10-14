// SoftEtherZig FFI Entry Point
// Re-exports mobile VPN FFI for C interop
//
// This file serves as the main entry point for the FFI layer.
// Using stub implementation for now - full implementation will be added incrementally

comptime {
    _ = @import("mobile_stub.zig");
}
