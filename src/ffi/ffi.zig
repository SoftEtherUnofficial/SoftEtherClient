// SoftEtherZig FFI Entry Point
// Re-exports mobile VPN FFI for C interop
//
// Phase 2: Using real implementation with SoftEther bridge integration

comptime {
    _ = @import("mobile_impl.zig");
}
