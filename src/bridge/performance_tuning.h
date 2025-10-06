// Performance Tuning Module Header
// TCP/socket optimizations for better throughput

#ifndef PERFORMANCE_TUNING_H
#define PERFORMANCE_TUNING_H

#include <stdint.h>

// Note: Don't include stdbool.h - SoftEther defines its own bool type
// We use int for bool-like values to avoid conflicts

// Enable or disable performance tuning
void SetPerformanceTuningEnabled(int enabled);
int IsPerformanceTuningEnabled();

// Apply performance tuning to a socket
void ApplySocketPerformanceTuning(int sock);

// Hook called when a socket is created
void OnSocketCreated(int sock, const char *purpose);

// Statistics
typedef struct PERF_STATS {
    uint64_t total_sockets_tuned;
    uint64_t rcvbuf_size_total;
    uint64_t sndbuf_size_total;
    uint64_t nodelay_enabled;
    uint64_t quickack_enabled;
} PERF_STATS;

void GetPerformanceTuningStats(PERF_STATS *stats);
void PrintPerformanceTuningStats();

// Module lifecycle
void InitPerformanceTuning();
void CleanupPerformanceTuning();

#endif // PERFORMANCE_TUNING_H
