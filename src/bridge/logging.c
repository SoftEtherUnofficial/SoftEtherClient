// SoftEther VPN Zig Client - Unified Logging Implementation

#include "logging.h"
#include <string.h>

#ifdef __APPLE__
#include <os/log.h>
#endif

// Global log level (default: INFO)
LogLevel g_log_level = LOG_LEVEL_INFO;

// ANSI color codes for terminal output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"  // ERROR
#define COLOR_YELLOW  "\033[1;33m"  // WARN
#define COLOR_GREEN   "\033[1;32m"  // INFO
#define COLOR_CYAN    "\033[1;36m"  // DEBUG
#define COLOR_GRAY    "\033[0;37m"  // TRACE

// Set log level at runtime
void set_log_level(LogLevel level) {
    if (level >= LOG_LEVEL_SILENT && level <= LOG_LEVEL_TRACE) {
        g_log_level = level;
    }
}

// Get log level name string
const char* get_log_level_name(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_SILENT: return "SILENT";
        case LOG_LEVEL_ERROR:  return "ERROR";
        case LOG_LEVEL_WARN:   return "WARN";
        case LOG_LEVEL_INFO:   return "INFO";
        case LOG_LEVEL_DEBUG:  return "DEBUG";
        case LOG_LEVEL_TRACE:  return "TRACE";
        default: return "UNKNOWN";
    }
}

// Parse log level from string (case-insensitive)
LogLevel parse_log_level(const char* str) {
    if (!str) return LOG_LEVEL_INFO;
    
    if (strcasecmp(str, "silent") == 0 || strcasecmp(str, "quiet") == 0) {
        return LOG_LEVEL_SILENT;
    } else if (strcasecmp(str, "error") == 0 || strcasecmp(str, "err") == 0) {
        return LOG_LEVEL_ERROR;
    } else if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) {
        return LOG_LEVEL_WARN;
    } else if (strcasecmp(str, "info") == 0) {
        return LOG_LEVEL_INFO;
    } else if (strcasecmp(str, "debug") == 0) {
        return LOG_LEVEL_DEBUG;
    } else if (strcasecmp(str, "trace") == 0 || strcasecmp(str, "verbose") == 0) {
        return LOG_LEVEL_TRACE;
    }
    
    return LOG_LEVEL_INFO; // Default
}

// Get color for log level
static const char* get_level_color(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return COLOR_RED;
        case LOG_LEVEL_WARN:  return COLOR_YELLOW;
        case LOG_LEVEL_INFO:  return COLOR_GREEN;
        case LOG_LEVEL_DEBUG: return COLOR_CYAN;
        case LOG_LEVEL_TRACE: return COLOR_GRAY;
        default: return COLOR_RESET;
    }
}

// Get short log level symbol
static const char* get_level_symbol(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "✗";
        case LOG_LEVEL_WARN:  return "⚠";
        case LOG_LEVEL_INFO:  return "●";
        case LOG_LEVEL_DEBUG: return "◆";
        case LOG_LEVEL_TRACE: return "·";
        default: return " ";
    }
}

// Core logging function
void log_message(LogLevel level, const char* tag, const char* fmt, ...) {
    if (level > g_log_level) return;
    
#ifdef __APPLE__
    // iOS: Use os_log for unified logging system (appears in Console.app)
    static os_log_t log_handle = NULL;
    if (log_handle == NULL) {
        log_handle = os_log_create("com.worxvpn.ios", "SoftEther");
    }
    
    // Format message with tag
    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    // Map our log levels to os_log types
    os_log_type_t os_type;
    switch (level) {
        case LOG_LEVEL_ERROR: os_type = OS_LOG_TYPE_ERROR; break;
        case LOG_LEVEL_WARN:  os_type = OS_LOG_TYPE_DEFAULT; break;
        case LOG_LEVEL_INFO:  os_type = OS_LOG_TYPE_DEFAULT; break; // Use DEFAULT so it always appears
        case LOG_LEVEL_DEBUG: os_type = OS_LOG_TYPE_DEFAULT; break; // Use DEFAULT so it always appears
        case LOG_LEVEL_TRACE: os_type = OS_LOG_TYPE_DEBUG; break;
        default: os_type = OS_LOG_TYPE_DEFAULT;
    }
    
    // Log with tag prefix
    os_log_with_type(log_handle, os_type, "[%{public}s] %{public}s", tag, message);
    
#else
    // Unix/Linux: Use fprintf to stderr
    const char* color = get_level_color(level);
    const char* symbol = get_level_symbol(level);
    
    // Print tag and symbol with color
    fprintf(stderr, "%s[%s] %s:%s ", color, symbol, tag, COLOR_RESET);
    
    // Print message
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    
    fprintf(stderr, "\n");
    fflush(stderr);
#endif
}

// Platform-specific logging function implementations
void log_error_impl(const char* tag, const char* fmt, ...) {
#ifdef __APPLE__
    static os_log_t log_handle = NULL;
    if (log_handle == NULL) {
        log_handle = os_log_create("com.worxvpn.ios", "SoftEther");
    }
    
    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    os_log_error(log_handle, "[%{public}s] %{public}s", tag, message);
#else
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_ERROR, tag, fmt, args);
    va_end(args);
#endif
}

void log_warn_impl(const char* tag, const char* fmt, ...) {
#ifdef __APPLE__
    static os_log_t log_handle = NULL;
    if (log_handle == NULL) {
        log_handle = os_log_create("com.worxvpn.ios", "SoftEther");
    }
    
    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    os_log(log_handle, "[%{public}s] %{public}s", tag, message);
#else
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_WARN, tag, fmt, args);
    va_end(args);
#endif
}

void log_info_impl(const char* tag, const char* fmt, ...) {
#ifdef __APPLE__
    static os_log_t log_handle = NULL;
    if (log_handle == NULL) {
        log_handle = os_log_create("com.worxvpn.ios", "SoftEther");
    }
    
    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    os_log(log_handle, "[%{public}s] %{public}s", tag, message);
#else
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_INFO, tag, fmt, args);
    va_end(args);
#endif
}

void log_debug_impl(const char* tag, const char* fmt, ...) {
#ifdef __APPLE__
    static os_log_t log_handle = NULL;
    if (log_handle == NULL) {
        log_handle = os_log_create("com.worxvpn.ios", "SoftEther");
    }
    
    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    os_log_debug(log_handle, "[%{public}s] %{public}s", tag, message);
#else
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_DEBUG, tag, fmt, args);
    va_end(args);
#endif
}

void log_trace_impl(const char* tag, const char* fmt, ...) {
#ifdef __APPLE__
    static os_log_t log_handle = NULL;
    if (log_handle == NULL) {
        log_handle = os_log_create("com.worxvpn.ios", "SoftEther");
    }
    
    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    
    os_log_debug(log_handle, "[%{public}s] %{public}s", tag, message);
#else
    va_list args;
    va_start(args, fmt);
    log_message(LOG_LEVEL_TRACE, tag, fmt, args);
    va_end(args);
#endif
}
