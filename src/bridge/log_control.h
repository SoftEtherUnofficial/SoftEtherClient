// Log Control - Environment-based logging configuration for C code
#ifndef LOG_CONTROL_H
#define LOG_CONTROL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// Log levels
typedef enum {
    LOG_LEVEL_TRACE = 0,
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_WARN = 3,
    LOG_LEVEL_ERROR = 4,
    LOG_LEVEL_FATAL = 5,
    LOG_LEVEL_SILENT = 99
} LogLevel;

// Global log level (set from environment on init)
static LogLevel g_log_level = LOG_LEVEL_INFO;
static bool g_log_initialized = false;

// Initialize logging from environment
static inline void log_init(void) {
    if (g_log_initialized) return;
    
    const char *level_str = getenv("LOG_LEVEL");
    if (level_str != NULL) {
        if (strcmp(level_str, "TRACE") == 0 || strcmp(level_str, "trace") == 0) {
            g_log_level = LOG_LEVEL_TRACE;
        } else if (strcmp(level_str, "DEBUG") == 0 || strcmp(level_str, "debug") == 0) {
            g_log_level = LOG_LEVEL_DEBUG;
        } else if (strcmp(level_str, "INFO") == 0 || strcmp(level_str, "info") == 0) {
            g_log_level = LOG_LEVEL_INFO;
        } else if (strcmp(level_str, "WARN") == 0 || strcmp(level_str, "warn") == 0) {
            g_log_level = LOG_LEVEL_WARN;
        } else if (strcmp(level_str, "ERROR") == 0 || strcmp(level_str, "error") == 0) {
            g_log_level = LOG_LEVEL_ERROR;
        } else if (strcmp(level_str, "FATAL") == 0 || strcmp(level_str, "fatal") == 0) {
            g_log_level = LOG_LEVEL_FATAL;
        } else if (strcmp(level_str, "SILENT") == 0 || strcmp(level_str, "silent") == 0) {
            g_log_level = LOG_LEVEL_SILENT;
        }
    }
    
    g_log_initialized = true;
}

// Logging macros
#define LOG_TRACE(fmt, ...) do { \
    if (!g_log_initialized) log_init(); \
    if (g_log_level <= LOG_LEVEL_TRACE) printf("[TRACE] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LOG_DEBUG(fmt, ...) do { \
    if (!g_log_initialized) log_init(); \
    if (g_log_level <= LOG_LEVEL_DEBUG) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LOG_INFO(fmt, ...) do { \
    if (!g_log_initialized) log_init(); \
    if (g_log_level <= LOG_LEVEL_INFO) printf("[INFO] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LOG_WARN(fmt, ...) do { \
    if (!g_log_initialized) log_init(); \
    if (g_log_level <= LOG_LEVEL_WARN) printf("[WARN] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LOG_ERROR(fmt, ...) do { \
    if (!g_log_initialized) log_init(); \
    if (g_log_level <= LOG_LEVEL_ERROR) printf("[ERROR] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LOG_FATAL(fmt, ...) do { \
    if (!g_log_initialized) log_init(); \
    if (g_log_level <= LOG_LEVEL_FATAL) printf("[FATAL] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#endif // LOG_CONTROL_H
