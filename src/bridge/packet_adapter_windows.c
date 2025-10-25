// SoftEther VPN Zig Client - Windows Packet Adapter Stub
// Windows builds now use pure Zig adapter (adapter.zig)
// This stub provides minimal C symbols for compatibility during transition

#include "zig_packet_adapter.h"
#include "logging.h"
#include "../../SoftEtherVPN/src/Mayaqua/Mayaqua.h"
#include "../../SoftEtherVPN/src/Cedar/Cedar.h"
#include <string.h>

// Windows-specific stubs for symbols that might be referenced
// Real implementation is in adapter.zig for Windows

// Stub implementations - redirect to Zig adapter
void* NewWindowsTapAdapter(void) {
    // Windows uses Zig adapter - this stub should not be called
    Debug("WARNING: NewWindowsTapAdapter stub called - should use Zig adapter\n");
    return NULL;
}

void FreeWindowsTapAdapter(void* adapter) {
    // Windows uses Zig adapter - this stub should not be called
    Debug("WARNING: FreeWindowsTapAdapter stub called - should use Zig adapter\n");
}

// Stub for undefined Cedar symbols on Windows
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

// Windows console stub
int getch(void) {
    return 0;
}

// End of Windows packet adapter stub
