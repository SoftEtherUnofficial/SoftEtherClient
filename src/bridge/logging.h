// SoftEther VPN Zig Client - Unified Logging System
// Provides log level control and consistent output formatting

#ifndef SOFTETHER_LOGGING_H
#define SOFTETHER_LOGGING_H

#include <stdio.h>
#include <stdarg.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Log levels (lower = less verbose)
typedef enum {
    LOG_LEVEL_SILENT = 0,  // No output (except errors)
    LOG_LEVEL_ERROR = 1,   // Critical errors only
    LOG_LEVEL_WARN = 2,    // Warnings + errors
    LOG_LEVEL_INFO = 3,    // Important info (default)
    LOG_LEVEL_DEBUG = 4,   // Detailed debugging
    LOG_LEVEL_TRACE = 5    // Extremely verbose (packet-level)
} LogLevel;

// Global log level (can be set from CLI or config)
extern LogLevel g_log_level;

// Set log level at runtime
void set_log_level(LogLevel level);
const char* get_log_level_name(LogLevel level);
LogLevel parse_log_level(const char* str);

// Generic log function (used by Zig code)
void log_message(LogLevel level, const char* tag, const char* fmt, ...);

// Platform-specific logging functions (implemented in logging.c)
void log_error_impl(const char* tag, const char* fmt, ...);
void log_warn_impl(const char* tag, const char* fmt, ...);
void log_info_impl(const char* tag, const char* fmt, ...);
void log_debug_impl(const char* tag, const char* fmt, ...);
void log_trace_impl(const char* tag, const char* fmt, ...);

// Logging macros that call platform-specific implementations
#define LOG_ERROR(tag, fmt, ...) log_error_impl(tag, fmt, ##__VA_ARGS__)
#define LOG_WARN(tag, fmt, ...) log_warn_impl(tag, fmt, ##__VA_ARGS__)
#define LOG_INFO(tag, fmt, ...) log_info_impl(tag, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(tag, fmt, ...) log_debug_impl(tag, fmt, ##__VA_ARGS__)
#define LOG_TRACE(tag, fmt, ...) log_trace_impl(tag, fmt, ##__VA_ARGS__)

// Convenience macros for common tags
#define LOG_TUN_ERROR(fmt, ...)   LOG_ERROR("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_WARN(fmt, ...)    LOG_WARN("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_INFO(fmt, ...)    LOG_INFO("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_DEBUG(fmt, ...)   LOG_DEBUG("TUN", fmt, ##__VA_ARGS__)
#define LOG_TUN_TRACE(fmt, ...)   LOG_TRACE("TUN", fmt, ##__VA_ARGS__)

#define LOG_DHCP_ERROR(fmt, ...)  LOG_ERROR("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_WARN(fmt, ...)   LOG_WARN("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_INFO(fmt, ...)   LOG_INFO("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_DEBUG(fmt, ...)  LOG_DEBUG("DHCP", fmt, ##__VA_ARGS__)
#define LOG_DHCP_TRACE(fmt, ...)  LOG_TRACE("DHCP", fmt, ##__VA_ARGS__)

#define LOG_VPN_ERROR(fmt, ...)   LOG_ERROR("VPN", fmt, ##__VA_ARGS__)
#define LOG_VPN_WARN(fmt, ...)    LOG_WARN("VPN", fmt, ##__VA_ARGS__)
#define LOG_VPN_INFO(fmt, ...)    LOG_INFO("VPN", fmt, ##__VA_ARGS__)
#define LOG_VPN_DEBUG(fmt, ...)   LOG_DEBUG("VPN", fmt, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // SOFTETHER_LOGGING_H
