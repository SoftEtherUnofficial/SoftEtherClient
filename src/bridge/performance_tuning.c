// Performance Tuning Module
// Applies TCP optimizations without modifying original SoftEther code
// 
// This module patches socket settings at runtime for better throughput

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>

// Performance tuning constants
#define PERF_TCP_RCVBUF_SIZE (1024 * 1024)  // 1 MB receive buffer
#define PERF_TCP_SNDBUF_SIZE (1024 * 1024)  // 1 MB send buffer
#define PERF_ENABLE_TCP_NODELAY 1            // Disable Nagle's algorithm
#define PERF_ENABLE_TCP_QUICKACK 1           // Enable quick ACK (Linux)

// Global flag to enable/disable performance tuning
static int g_performance_tuning_enabled = 1;

// Enable or disable performance tuning at runtime
void SetPerformanceTuningEnabled(int enabled) {
    g_performance_tuning_enabled = enabled;
    if (enabled) {
        printf("[PerfTune] 🚀 Performance tuning ENABLED\n");
        printf("[PerfTune]    TCP buffers: %d KB\n", PERF_TCP_RCVBUF_SIZE / 1024);
        printf("[PerfTune]    TCP_NODELAY: %s\n", PERF_ENABLE_TCP_NODELAY ? "ON" : "OFF");
    } else {
        printf("[PerfTune] Performance tuning DISABLED (using defaults)\n");
    }
}

// Check if performance tuning is enabled
int IsPerformanceTuningEnabled() {
    return g_performance_tuning_enabled;
}

// Apply performance tuning to a socket
// Call this after creating any TCP socket
void ApplySocketPerformanceTuning(int sock) {
    if (!g_performance_tuning_enabled) {
        return; // Performance tuning disabled
    }

    if (sock < 0) {
        return; // Invalid socket
    }

    int result;
    int enabled = 1;

    // Set receive buffer size
    int rcvbuf = PERF_TCP_RCVBUF_SIZE;
    result = setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    if (result == 0) {
        // Verify actual size set
        socklen_t len = sizeof(rcvbuf);
        getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len);
        printf("[PerfTune] SO_RCVBUF set to %d KB (requested %d KB)\n", 
               rcvbuf / 1024, PERF_TCP_RCVBUF_SIZE / 1024);
    }

    // Set send buffer size
    int sndbuf = PERF_TCP_SNDBUF_SIZE;
    result = setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    if (result == 0) {
        // Verify actual size set
        socklen_t len = sizeof(sndbuf);
        getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len);
        printf("[PerfTune] SO_SNDBUF set to %d KB (requested %d KB)\n", 
               sndbuf / 1024, PERF_TCP_SNDBUF_SIZE / 1024);
    }

    // Enable TCP_NODELAY (disable Nagle's algorithm)
    if (PERF_ENABLE_TCP_NODELAY) {
        result = setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        if (result == 0) {
            printf("[PerfTune] TCP_NODELAY enabled (low latency mode)\n");
        }
    }

#ifdef TCP_QUICKACK
    // Enable TCP_QUICKACK (Linux only)
    if (PERF_ENABLE_TCP_QUICKACK) {
        result = setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &enabled, sizeof(enabled));
        if (result == 0) {
            printf("[PerfTune] TCP_QUICKACK enabled (fast ACKs)\n");
        }
    }
#endif

#ifdef SO_NOSIGPIPE
    // Prevent SIGPIPE on macOS/BSD
    result = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
    if (result == 0) {
        printf("[PerfTune] SO_NOSIGPIPE enabled (no SIGPIPE)\n");
    }
#endif
}

// Hook function that wraps socket creation
// This gets called after the original socket is created
void OnSocketCreated(int sock, const char *purpose) {
    if (sock < 0) {
        return;
    }

    printf("[PerfTune] Socket created: fd=%d, purpose=%s\n", sock, purpose ? purpose : "unknown");
    ApplySocketPerformanceTuning(sock);
}

// Statistics structure (defined in header)
typedef struct PERF_STATS {
    uint64_t total_sockets_tuned;
    uint64_t rcvbuf_size_total;
    uint64_t sndbuf_size_total;
    uint64_t nodelay_enabled;
    uint64_t quickack_enabled;
} PERF_STATS;

static PERF_STATS g_perf_stats = {0};

// Get performance tuning statistics
void GetPerformanceTuningStats(PERF_STATS *stats) {
    if (stats) {
        memcpy(stats, &g_perf_stats, sizeof(PERF_STATS));
    }
}

// Print performance tuning statistics
void PrintPerformanceTuningStats() {
    printf("\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("        Performance Tuning Statistics\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("  Sockets Tuned:       %llu\n", g_perf_stats.total_sockets_tuned);
    if (g_perf_stats.total_sockets_tuned > 0) {
        printf("  Avg RCVBUF:          %llu KB\n", 
               (g_perf_stats.rcvbuf_size_total / g_perf_stats.total_sockets_tuned) / 1024);
        printf("  Avg SNDBUF:          %llu KB\n", 
               (g_perf_stats.sndbuf_size_total / g_perf_stats.total_sockets_tuned) / 1024);
    }
    printf("  TCP_NODELAY Count:   %llu\n", g_perf_stats.nodelay_enabled);
    printf("  TCP_QUICKACK Count:  %llu\n", g_perf_stats.quickack_enabled);
    printf("═══════════════════════════════════════════════════════\n");
    printf("\n");
}

// Initialize performance tuning module
void InitPerformanceTuning() {
    printf("[PerfTune] Performance Tuning Module initialized\n");
    printf("[PerfTune] Target settings:\n");
    printf("[PerfTune]   - SO_RCVBUF: %d KB\n", PERF_TCP_RCVBUF_SIZE / 1024);
    printf("[PerfTune]   - SO_SNDBUF: %d KB\n", PERF_TCP_SNDBUF_SIZE / 1024);
    printf("[PerfTune]   - TCP_NODELAY: %s\n", PERF_ENABLE_TCP_NODELAY ? "enabled" : "disabled");
    printf("[PerfTune]   - TCP_QUICKACK: %s\n", PERF_ENABLE_TCP_QUICKACK ? "enabled" : "disabled");
    
    SetPerformanceTuningEnabled(1);
}

// Cleanup performance tuning module
void CleanupPerformanceTuning() {
    PrintPerformanceTuningStats();
    printf("[PerfTune] Performance Tuning Module cleanup complete\n");
}
