// Network_iOS.c - iOS-specific TCP socket buffer tuning overrides
// This bridges/patches the original SoftEtherVPN Network.c for iOS performance
//
// ROOT CAUSE OF THROTTLING:
// Default TCP SO_SNDBUF/SO_RCVBUF = 64KB on iOS
// At 200ms RTT: max_throughput = buffer_size / RTT = 64KB / 0.2s = 2.56 mbps
// This is classic TCP window/buffer-delay product limitation
//
// FIX EVOLUTION:
// v1: 4MB buffers → 5.28mbps @ 368ms latency (bufferbloat!)
//     Analysis: Large buffers cause queue buildup, latency spikes
// v2: 512KB/1MB buffers (current) → balances throughput vs latency
//     Target: ~20-40mbps @ 200-250ms latency

#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>

// Minimal type definitions from SoftEther
typedef int SOCKET;
typedef unsigned int UINT;

// Forward declaration from Network.c
extern UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size);

// Initialize TCP socket buffer sizes for iOS
void InitTcpSocketBufferSize_iOS(SOCKET s)
{
#ifdef UNIX_IOS
	// CRITICAL: Buffer size vs latency tradeoff
	// 
	// Test results:
	//   Baseline: 64KB default → 2.44mbps @ 200ms
	//   4MB buffers → 5.28mbps @ 368ms (bufferbloat! +168ms latency)
	//
	// Issue: Large buffers increase bufferbloat
	// - Sends fill 4MB buffer before TCP backpressure
	// - Recvs queue 4MB before app processes
	// - This adds ~150ms of queue delay @ 5mbps
	//
	// Better approach: Moderate buffering
	// - 512KB send buffer → supports ~20mbps @ 200ms
	// - 1MB recv buffer → downloads benefit from larger window
	// - Prioritize latency over max throughput
	//
	// Formula: BDP = bandwidth * RTT
	//   512KB / 0.2s = 20mbps (target)
	//   1MB / 0.2s = 40mbps (receive can be larger)
	
	UINT send_target = 512 * 1024;  // 512KB send buffer
	UINT recv_target = 1024 * 1024; // 1MB recv buffer
	
	// Try to set, fall back to smaller if OS rejects
	SetSocketBufferSizeWithBestEffort(s, true, send_target);   // SO_SNDBUF
	SetSocketBufferSizeWithBestEffort(s, false, recv_target);  // SO_RCVBUF
#else
	// Non-iOS: Use standard tuning (256KB conservative)
	UINT target_size = 256 * 1024;
	SetSocketBufferSizeWithBestEffort(s, true, target_size);
	SetSocketBufferSizeWithBestEffort(s, false, target_size);
#endif
}

