// Mobile FFI Root Module
// This module exports all FFI functions and provides all dependencies
// Use this as the root module for iOS/Android builds

// Export core dependencies at root level for ffi.zig to import
pub const vpn_core = @import("../core/vpn_core.zig");
pub const config_mod = @import("../config.zig");
pub const errors_mod = @import("../errors.zig");
pub const c_mod = @import("../c.zig");

// Import and re-export FFI
const ffi = @import("ffi.zig");

// Re-export all FFI functions
pub const mobile_vpn_init = ffi.mobile_vpn_init;
pub const mobile_vpn_create = ffi.mobile_vpn_create;
pub const mobile_vpn_destroy = ffi.mobile_vpn_destroy;
pub const mobile_vpn_connect = ffi.mobile_vpn_connect;
pub const mobile_vpn_disconnect = ffi.mobile_vpn_disconnect;
pub const mobile_vpn_get_status = ffi.mobile_vpn_get_status;
pub const mobile_vpn_get_stats = ffi.mobile_vpn_get_stats;
pub const mobile_vpn_read_packet = ffi.mobile_vpn_read_packet;
pub const mobile_vpn_write_packet = ffi.mobile_vpn_write_packet;
pub const mobile_vpn_set_network_info = ffi.mobile_vpn_set_network_info;
pub const mobile_vpn_get_network_info = ffi.mobile_vpn_get_network_info;
pub const mobile_vpn_set_status_callback = ffi.mobile_vpn_set_status_callback;
pub const mobile_vpn_set_stats_callback = ffi.mobile_vpn_set_stats_callback;
pub const mobile_vpn_set_network_callback = ffi.mobile_vpn_set_network_callback;
pub const mobile_vpn_get_error = ffi.mobile_vpn_get_error;
pub const mobile_vpn_is_connected = ffi.mobile_vpn_is_connected;
pub const mobile_vpn_get_version = ffi.mobile_vpn_get_version;
pub const mobile_vpn_get_build_info = ffi.mobile_vpn_get_build_info;

// Re-export types
pub const MobileVpnConfig = ffi.MobileVpnConfig;
pub const MobileVpnStatus = ffi.MobileVpnStatus;
pub const MobileVpnStats = ffi.MobileVpnStats;
pub const MobileNetworkInfo = ffi.MobileNetworkInfo;
pub const MobileStatusCallback = ffi.MobileStatusCallback;
pub const MobileStatsCallback = ffi.MobileStatsCallback;
pub const MobileNetworkCallback = ffi.MobileNetworkCallback;
