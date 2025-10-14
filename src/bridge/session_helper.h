// Session helper functions for safe field access
#ifndef SESSION_HELPER_H
#define SESSION_HELPER_H

#include "Cedar/Cedar.h"

// CLIENT_AUTH setter helpers
void SetClientAuthType(CLIENT_AUTH *auth, UINT auth_type);
void SetClientAuthHashedPassword(CLIENT_AUTH *auth, const UCHAR *hashed_password, UINT len);

// CLIENT_OPTION setter helpers
void SetClientOptionNumRetry(CLIENT_OPTION *opt, UINT num_retry);
void SetClientOptionRetryInterval(CLIENT_OPTION *opt, UINT interval);
void SetClientOptionPort(CLIENT_OPTION *opt, UINT port);
void SetClientOptionPortUDP(CLIENT_OPTION *opt, UINT port_udp);
void SetClientOptionMaxConnection(CLIENT_OPTION *opt, UINT max_conn);
void SetClientOptionFlags(CLIENT_OPTION *opt, bool use_encrypt, bool use_compress,
                          bool half_connection, bool no_routing_tracking,
                          bool no_udp_accel, bool disable_qos, bool require_bridge_routing);

// Get session ClientStatus (thread-safe with lock)
UINT GetSessionClientStatus(SESSION *s);

// Get session Halt flag (thread-safe with lock)
bool GetSessionHalt(SESSION *s);

// Check if session lock is initialized
bool IsSessionLockInitialized(SESSION *s);

#endif // SESSION_HELPER_H
