// SoftEther VPN Zig Client - Linux Packet Adapter Stub
// Linux builds now use pure Zig adapter (adapter.zig)
// This stub provides minimal C symbols for compatibility during transition

#include "zig_packet_adapter.h"
#include "logging.h"
#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"
#include <string.h>

// Linux-specific stubs for symbols that might be referenced
// Real implementation is in adapter.zig for Linux

// Stub implementations - redirect to Zig adapter
void* NewLinuxTunAdapter(void) {
    // Linux uses Zig adapter - this stub should not be called
    Debug("WARNING: NewLinuxTunAdapter stub called - should use Zig adapter\n");
    return NULL;
}

void FreeLinuxTunAdapter(void* adapter) {
    // Linux uses Zig adapter - this stub should not be called
    Debug("WARNING: FreeLinuxTunAdapter stub called - should use Zig adapter\n");
}

// Stub for undefined Cedar symbols on Linux
BOOL NsIsMacAddressOnLocalhost(UCHAR *mac) {
    (void)mac;
    return FALSE;
}

BOOL NsStartIpTablesTracking(void *stack) {
    (void)stack;
    return FALSE;
}

NATIVE_STACK *NewNativeStack(CEDAR *cedar, char *device_name, char *mac_address_seed) {
    (void)cedar;
    (void)device_name;
    (void)mac_address_seed;
    return NULL;
}

void FreeNativeStack(NATIVE_STACK *stack) {
    (void)stack;
}

// Linux-specific routing stubs
int LinuxConfigureRouting(const char *device, UINT32 vpn_gateway, UINT32 vpn_server) {
    (void)device;
    (void)vpn_gateway;
    (void)vpn_server;
    Debug("Linux routing stub called - implement with ip route commands\n");
    return 0;
}

int LinuxRestoreRouting(void) {
    Debug("Linux routing restore stub called\n");
    return 0;
}

// End of Linux packet adapter stub
