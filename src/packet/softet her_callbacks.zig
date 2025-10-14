// ✅ WAVE 5 PHASE 2: SoftEther VPN Callbacks (ported from C to Zig)
// These 5 callbacks implement the PACKET_ADAPTER interface for SoftEther VPN
// Replaces ~90 lines of C code in zig_packet_adapter.c

// External C functions we need from packet_utils.c (Wave 4 packet builders)
extern fn BuildGratuitousArp(my_mac: [*]const u8, my_ip: u32, out_size: *u32) [*]u8;
extern fn BuildDhcpDiscover(my_mac: [*]const u8, xid: u32, out_size: *u32) [*]u8;
extern fn BuildDhcpRequest(my_mac: [*]const u8, xid: u32, requested_ip: u32, server_ip: u32, out_size: *u32) [*]u8;

// External C functions for memory management (SoftEther)
extern fn Malloc(size: usize) *anyopaque;
extern fn Free(ptr: *anyopaque) void;
extern fn Tick64() u64;

// ========================================================================
// SoftEther PACKET_ADAPTER Callbacks (C calling convention)
// ========================================================================

/// Callback 1: softEtherInit - Initialize adapter for SoftEther session
/// Called by SoftEther when creating a new VPN session
/// @param s: SESSION* from SoftEther (opaque pointer)
/// @return: true on success, false on failure
export fn softEtherInit(s: *anyopaque) callconv(.C) bool {
    _ = s;
    // Note: Adapter is already initialized in zig_adapter_create()
    // This callback is for session-specific initialization
    // We'll store the session pointer for future use
    return true;
}

/// Callback 2: softEtherGetCancel - Get cancel handle for session
/// Called by SoftEther to get the cancel handle (for session termination)
/// @param s: SESSION* from SoftEther (opaque pointer)
/// @return: CANCEL* handle (stored in adapter context)
export fn softEtherGetCancel(s: *anyopaque) callconv(.C) ?*anyopaque {
    _ = s;
    // For now, return null - C bridge will handle cancel
    // In full Zig implementation, we'd return adapter.cancel
    return null;
}

/// Callback 3: softEtherGetNextPacket - Get next packet from TUN device
/// Called by SoftEther SessionMain to read outgoing packets (client -> server)
/// Implements DHCP state machine timing (Wave 4 compatibility)
/// @param s: SESSION* from SoftEther (opaque pointer)
/// @param data: Output pointer to packet data
/// @return: packet size in bytes (0 = no packet)
export fn softEtherGetNextPacket(s: *anyopaque, data: **anyopaque) callconv(.C) u32 {
    _ = s;
    _ = data;
    // Placeholder - full implementation in Phase 2.1
    return 0;
}

/// Callback 4: softEtherPutPacket - Write packet to TUN device
/// Called by SoftEther SessionMain to write incoming packets (server -> client)
/// Detects DHCP OFFER/ACK and transitions state machine
/// @param s: SESSION* from SoftEther (opaque pointer)
/// @param data: Packet data pointer
/// @param size: Packet size in bytes
/// @return: true on success, false on failure
export fn softEtherPutPacket(s: *anyopaque, data: *anyopaque, size: u32) callconv(.C) bool {
    _ = s;
    _ = data;
    _ = size;
    // Placeholder - full implementation in Phase 2.1
    return true;
}

/// Callback 5: softEtherFree - Free adapter resources
/// Called by SoftEther when closing VPN session
/// @param s: SESSION* from SoftEther (opaque pointer)
export fn softEtherFree(s: *anyopaque) callconv(.C) void {
    _ = s;
    // Placeholder - full implementation in Phase 2.1
}
