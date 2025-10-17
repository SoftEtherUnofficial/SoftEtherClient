/*
 * iOS Stub Implementations
 * 
 * Provides stub implementations for functions that are not available on iOS
 * (e.g., system() calls, TUN device operations, etc.)
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// Stub for NewNativeStack (not used on iOS - uses system() calls)
void* NewNativeStack(void* cedar, char* device_name, char* mac_address_seed) {
    return NULL;
}

// Stub for FreeNativeStack (not used on iOS)
void FreeNativeStack(void* a) {
    // Nothing to free
}

// Stub for NsIsMacAddressOnLocalhost (not used on iOS)
bool NsIsMacAddressOnLocalhost(uint8_t* mac) {
    return false;
}

// Stub for NsStartIpTablesTracking (not used on iOS - uses system() calls)
void NsStartIpTablesTracking(void* a) {
    // No-op on iOS
}

// Stub for NewZigPacketAdapter (not used on iOS - uses system() calls)
void* NewZigPacketAdapter(void) {
    return NULL;
}

// Stub for NewMacOsTunAdapter (TUN device not available in iOS NetworkExtension)
void* NewMacOsTunAdapter(const char* device_name) {
    return NULL;
}
