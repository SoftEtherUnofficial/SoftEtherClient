// Network_iOS.h - iOS-specific network overrides header
#ifndef NETWORK_IOS_H
#define NETWORK_IOS_H

#include <sys/socket.h>
#include <stdbool.h>

// Minimal type definition
typedef int SOCKET;

// Initialize TCP socket buffer sizes for iOS high-latency links
// Call this immediately after socket() or accept() for TCP sockets
void InitTcpSocketBufferSize_iOS(SOCKET s);

#endif // NETWORK_IOS_H
