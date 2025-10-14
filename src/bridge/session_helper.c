// Session helper functions for safe field access
// This avoids hardcoded offsets and uses proper C struct access

#include "Mayaqua/Mayaqua.h"
#include "Cedar/Cedar.h"
#include <stdio.h>

// CLIENT_AUTH helper functions - ensures proper struct field access
void SetClientAuthType(CLIENT_AUTH *auth, UINT auth_type) {
    if (auth) {
        auth->AuthType = auth_type;
        printf("[SetClientAuthType] Set auth->AuthType=%u\n", auth->AuthType);
        fflush(stdout);
    }
}

void SetClientAuthHashedPassword(CLIENT_AUTH *auth, const UCHAR *hashed_password, UINT len) {
    if (auth && hashed_password && len == 20) {
        memcpy(auth->HashedPassword, hashed_password, 20);
        printf("[SetClientAuthHashedPassword] Copied 20 bytes to auth->HashedPassword\n");
        fflush(stdout);
    }
}

// CLIENT_OPTION setter helpers - ensures proper struct field access
void SetClientOptionNumRetry(CLIENT_OPTION *opt, UINT num_retry) {
    if (opt) {
        opt->NumRetry = num_retry;
    }
}

void SetClientOptionRetryInterval(CLIENT_OPTION *opt, UINT interval) {
    if (opt) {
        opt->RetryInterval = interval;
    }
}

void SetClientOptionPort(CLIENT_OPTION *opt, UINT port) {
    if (opt) {
        opt->Port = port;
    }
}

void SetClientOptionPortUDP(CLIENT_OPTION *opt, UINT port_udp) {
    if (opt) {
        opt->PortUDP = port_udp;
    }
}

void SetClientOptionMaxConnection(CLIENT_OPTION *opt, UINT max_conn) {
    if (opt) {
        opt->MaxConnection = max_conn;
    }
}

void SetClientOptionFlags(CLIENT_OPTION *opt, bool use_encrypt, bool use_compress, 
                          bool half_connection, bool no_routing_tracking,
                          bool no_udp_accel, bool disable_qos, bool require_bridge_routing) {
    if (opt) {
        opt->UseEncrypt = use_encrypt;
        opt->UseCompress = use_compress;
        opt->HalfConnection = half_connection;
        opt->NoRoutingTracking = no_routing_tracking;
        opt->NoUdpAcceleration = no_udp_accel;
        opt->DisableQoS = disable_qos;
        opt->RequireBridgeRoutingMode = require_bridge_routing;
    }
}

// Get session ClientStatus with memory barrier
// Use volatile to force CPU to read from memory, not cache
UINT GetSessionClientStatus(SESSION *s) {
    if (!s) {
        return 0; // CLIENT_STATUS_IDLE
    }
    
    // Force memory barrier by using volatile pointer
    volatile UINT *status_ptr = &s->ClientStatus;
    UINT status = *status_ptr;
    
    // Debug: print session pointer and status
    static int call_count = 0;
    if (call_count++ % 20 == 0) {  // Print every 20th call
        printf("[GetSessionClientStatus] session=%p, &ClientStatus=%p, status=%u\n", s, status_ptr, status);
        fflush(stdout);
    }
    
    return status;
}

// Get session Halt flag with memory barrier
bool GetSessionHalt(SESSION *s) {
    if (!s) {
        return true;
    }
    
    // Force memory barrier
    volatile bool *halt_ptr = &s->Halt;
    return *halt_ptr;
}

// Check if session lock pointer exists
// We're not actually using it anymore, but keep for compatibility
bool IsSessionLockInitialized(SESSION *s) {
    return (s != NULL && s->lock != NULL);
}
