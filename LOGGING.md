# Unified Logging System

## Overview

A comprehensive, platform-agnostic logging system designed for cross-platform VPN development (iOS, Android, Linux, macOS, Windows).

## Features

- **Single API** across all platforms
- **Runtime log level filtering** (DEBUG, INFO, WARN, ERROR, FATAL)
- **Component-based filtering** (CORE, ADAPTER, VIRTUALTAP, IOS, ANDROID, etc.)
- **Platform-specific backends** (NSLog, logcat, stderr, etc.)
- **Zero-allocation hot paths**
- **Thread-safe**
- **Performance tracking** with built-in timers
- **Structured logging** helpers for common patterns
- **Compile-time filtering** (DEBUG logs removed in release builds)

## Quick Start

```zig
const log = @import("logging.zig");

// Initialize at startup
pub fn main() !void {
    log.init(.{
        .min_level = .INFO,
        .show_timestamp = true,
        .show_emoji = true,
        .performance_tracking = true,
    });
    
    // Use logging
    log.info(.CORE, "Application started", .{});
    log.warn(.NETWORK, "Slow connection detected", .{});
    log.err(.IOS, "Failed to configure tunnel: {s}", .{error_msg});
}
```

## Basic Logging

### Log Levels

```zig
// DEBUG: Verbose debugging (disabled in release builds)
log.debug(.ADAPTER, "Processing packet: {d} bytes", .{packet_len});

// INFO: General information
log.info(.CORE, "VPN connected successfully", .{});

// WARN: Warnings (potential issues)
log.warn(.QUEUE, "Queue utilization at 80%: {d}/{d}", .{count, capacity});

// ERROR: Errors (recoverable)
log.err(.IOS, "Failed to inject packet: {s}", .{@errorName(err)});

// FATAL: Fatal errors (unrecoverable)
log.fatal(.CORE, "Out of memory, terminating", .{});
```

### Log Components

Organize logs by module/component for easy filtering:

```zig
pub const LogComponent = enum {
    CORE,        // Core VPN logic
    ADAPTER,     // Packet adapter
    VIRTUALTAP,  // VirtualTap L2 virtualization
    IOS,         // iOS-specific
    ANDROID,     // Android-specific
    MACOS,       // macOS-specific
    LINUX,       // Linux-specific
    WINDOWS,     // Windows-specific
    DHCP,        // DHCP client
    ARP,         // ARP handling
    PACKET,      // Packet processing
    QUEUE,       // Queue operations
    NETWORK,     // Network operations
    TLS,         // TLS/encryption
    PERF,        // Performance metrics
    TEST,        // Testing
};
```

## Structured Logging Helpers

### Packet Logging

```zig
// Outgoing packet: iOS→Server
log.logPacket(
    .IOS,
    .outgoing,
    src_ip,   // [4]u8
    dst_ip,   // [4]u8
    protocol, // u8 (6=TCP, 17=UDP)
    length,   // usize
);

// Output: 📦 10.21.251.97 → 8.8.8.8 proto=17 len=235

// Incoming packet: Server→iOS
log.logPacket(.IOS, .incoming, src_ip, dst_ip, protocol, length);
// Output: 📦 8.8.8.8 ← 10.21.251.97 proto=17 len=1218
```

### Queue Operations

```zig
// Queue enqueue
log.logQueue(.ADAPTER, .enqueue, "incoming_queue", count, capacity);
// Output: ➕ incoming_queue: 57/512

// Queue dequeue
log.logQueue(.ADAPTER, .dequeue, "outgoing_queue", count, capacity);
// Output: ➖ outgoing_queue: 56/512

// Queue full
log.logQueue(.ADAPTER, .full, "packet_queue", count, capacity);
// Output: 🚫 packet_queue: 512/512

// Queue empty
log.logQueue(.ADAPTER, .empty, "packet_queue", count, capacity);
// Output: 📭 packet_queue: 0/512
```

### Network Configuration

```zig
log.logNetworkConfig(
    .IOS,
    [_]u8{ 10, 21, 251, 97 },    // IP
    [_]u8{ 10, 21, 0, 1 },       // Gateway
    [_]u8{ 255, 255, 0, 0 },     // Netmask
    &[_][4]u8{
        [_]u8{ 8, 8, 8, 8 },     // DNS 1
        [_]u8{ 8, 8, 4, 4 },     // DNS 2
    },
);

// Output:
// 🌐 IP: 10.21.251.97 GW: 10.21.0.1 Mask: 255.255.0.0
// 🌐 DNS1: 8.8.8.8
// 🌐 DNS2: 8.8.4.4
```

### MAC Address Learning

```zig
// Regular MAC learning
log.logMacLearning(
    .VIRTUALTAP,
    [_]u8{ 10, 21, 0, 1 },                         // IP
    [_]u8{ 0x82, 0x5c, 0x48, 0x46, 0xb6, 0xa2 },  // MAC
    false,                                          // is_gateway
);
// Output: 📝 Learned MAC: 82:5C:48:46:B6:A2 for IP 10.21.0.1

// Gateway MAC learning (special)
log.logMacLearning(.VIRTUALTAP, gateway_ip, gateway_mac, true);
// Output: 🎯 Learned MAC: 82:5C:48:46:B6:A2 for IP 10.21.0.1
```

### DHCP State Transitions

```zig
log.logDhcpState(.DHCP, .init, null);
// Output: 🔄 DHCP: INIT

log.logDhcpState(.DHCP, .discover_sent, null);
// Output: 🔄 DHCP: DISCOVER_SENT

log.logDhcpState(.DHCP, .offer_received, "Offered IP: 10.21.251.97");
// Output: 🔄 DHCP: OFFER_RECEIVED - Offered IP: 10.21.251.97

log.logDhcpState(.DHCP, .configured, "Ready for traffic");
// Output: 🔄 DHCP: CONFIGURED ✅ - Ready for traffic
```

## Performance Tracking

```zig
// Start timer
var timer = log.PerfTimer.start(.PACKET, "encrypt_packet");

// ... do work ...

// End timer (automatically logs duration)
timer.end();
// Output: [PACKET] ⏱️ encrypt_packet: 127µs
```

## Runtime Configuration

### Set Minimum Log Level

```zig
// Only show INFO and above (skip DEBUG)
log.LogConfig.setMinLevel(.INFO);

// Show all logs including DEBUG
log.LogConfig.setMinLevel(.DEBUG);

// Only show errors
log.LogConfig.setMinLevel(.ERROR);
```

### Component Filtering

```zig
// Disable noisy component
log.LogConfig.disableComponent(.PACKET);

// Re-enable component
log.LogConfig.enableComponent(.PACKET);

// Check if enabled
if (log.LogConfig.isComponentEnabled(.IOS)) {
    // Do expensive logging prep
}
```

### Configuration Options

```zig
log.init(.{
    .min_level = .INFO,              // Minimum log level
    .show_timestamp = true,          // Show HH:MM:SS.mmm timestamps
    .show_thread_id = false,         // Show thread ID (expensive)
    .show_emoji = true,              // Use emoji indicators
    .colored_output = false,         // ANSI colors (terminal only)
    .performance_tracking = true,    // Enable perf timers
    .max_message_length = 512,       // Max message buffer size
});
```

## Platform-Specific Backends

### iOS
- **Backend**: NSLog via Objective-C bridge
- **Visibility**: Xcode Console, Console.app
- **Format**: Automatic timestamp, process info

### Android
- **Backend**: `__android_log_print` (logcat)
- **Visibility**: `adb logcat`
- **Tag**: `SoftEtherVPN`
- **Format**: Standard Android log format

### macOS
- **Backend**: stderr
- **Visibility**: Terminal, Console.app
- **Format**: Manual timestamp formatting

### Linux
- **Backend**: stderr
- **Visibility**: Terminal, journald
- **Format**: Manual timestamp formatting

### Windows
- **Backend**: stderr (or OutputDebugString)
- **Visibility**: Terminal, DebugView
- **Format**: Manual timestamp formatting

## Debug Utilities

### Hex Dump (Debug builds only)

```zig
log.hexDump(.PACKET, "DHCP packet", packet_data, 64);

// Output:
// DHCP packet (235 bytes):
//   01 01 06 00 AB CD EF 12 00 00 00 00 00 00 00 00
//   00 00 00 00 00 00 00 00 00 00 00 00 82 5C 48 46
//   B6 A2 00 00 00 00 00 00 00 00 00 00 00 00 00 00
//   ...
```

## Migration Guide

### From Old IOS_LOG()

```zig
// Old
IOS_LOG("[Component] Message: {d}", .{value});

// New
log.info(.IOS, "Message: {d}", .{value});
```

### From std.log

```zig
// Old
std.log.info("Processing packet: {d} bytes", .{len});

// New
log.info(.CORE, "Processing packet: {d} bytes", .{len});
```

### From printf()

```zig
// Old
_ = printf("[DEBUG] Value: %d\n", value);

// New
log.debug(.CORE, "Value: {d}", .{value});
```

## Best Practices

### 1. Choose Appropriate Log Levels

```zig
// ✅ Good: Use INFO for important events
log.info(.CORE, "VPN connection established", .{});

// ❌ Bad: Using DEBUG for important events
log.debug(.CORE, "VPN connection established", .{});

// ✅ Good: Use DEBUG for verbose details
log.debug(.PACKET, "Packet checksum: 0x{X:0>4}", .{checksum});

// ❌ Bad: Using INFO for every packet (too noisy)
log.info(.PACKET, "Packet checksum: 0x{X:0>4}", .{checksum});
```

### 2. Use Appropriate Components

```zig
// ✅ Good: Use specific component
log.err(.DHCP, "Failed to parse DHCP offer", .{});

// ❌ Bad: Using generic component
log.err(.CORE, "Failed to parse DHCP offer", .{});
```

### 3. Structured Logging Over Free-form

```zig
// ✅ Good: Use helper function
log.logPacket(.IOS, .outgoing, src_ip, dst_ip, proto, len);

// ❌ Bad: Manual formatting
log.info(.IOS, "Packet: {}.{}.{}.{} -> {}.{}.{}.{} proto={d}", .{
    src_ip[0], src_ip[1], src_ip[2], src_ip[3],
    dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
    proto,
});
```

### 4. Performance Tracking

```zig
// ✅ Good: Track expensive operations
var timer = log.PerfTimer.start(.TLS, "handshake");
try performTlsHandshake();
timer.end();

// ❌ Bad: No performance visibility
try performTlsHandshake();
```

### 5. Conditional Expensive Logging

```zig
// ✅ Good: Check if component enabled before expensive work
if (log.LogConfig.isComponentEnabled(.PACKET)) {
    const parsed = parsePacket(data); // Expensive
    log.debug(.PACKET, "Parsed: {}", .{parsed});
}

// ❌ Bad: Always do expensive work
const parsed = parsePacket(data);
log.debug(.PACKET, "Parsed: {}", .{parsed});
```

## Example Output

### iOS Console
```
11:23:45.123 ℹ️ [CORE] 🚀 SoftEther VPN Logging System initialized
11:23:45.124 ℹ️ [CORE]    Platform: ios
11:23:45.125 ℹ️ [CORE]    Build: ReleaseFast
11:23:45.126 ℹ️ [IOS] 📦 10.21.251.97 → 8.8.8.8 proto=17 len=235
11:23:45.127 ℹ️ [IOS] 📦 8.8.8.8 ← 10.21.251.97 proto=17 len=1218
11:23:45.128 ℹ️ [VIRTUALTAP] 🎯 Learned MAC: 82:5C:48:46:B6:A2 for IP 10.21.0.1
11:23:45.129 ℹ️ [DHCP] 🔄 DHCP: CONFIGURED ✅ - Ready for traffic
11:23:45.130 ℹ️ [PACKET] ⏱️ encrypt_packet: 127µs
```

### Android logcat
```
11:23:45.123 I/SoftEtherVPN: 11:23:45.123 ℹ️ [CORE] 🚀 SoftEther VPN Logging System initialized
11:23:45.124 I/SoftEtherVPN: 11:23:45.124 ℹ️ [ANDROID] 📦 10.21.251.97 → 8.8.8.8 proto=17 len=235
```

## Testing

```bash
# Run logging tests
zig build test --summary all

# Test specific logging module
zig test src/logging.zig
```

## Architecture

```
┌─────────────────────────────────────────┐
│       Application Code (Zig)            │
│   log.info(.CORE, "message", .{})       │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│      Unified Logging API                 │
│  - Level filtering                       │
│  - Component filtering                   │
│  - Message formatting                    │
│  - Structured helpers                    │
└─────────────────┬───────────────────────┘
                  │
          ┌───────┴────────┐
          │                │
┌─────────▼─────┐  ┌──────▼──────┐
│ iOS Backend   │  │Android BE   │  ...
│  (NSLog)      │  │ (logcat)    │
└───────────────┘  └─────────────┘
```

## License

Same as SoftEtherVPN project.

## Contributing

When adding new log messages:
1. Choose appropriate level (DEBUG, INFO, WARN, ERROR, FATAL)
2. Choose appropriate component
3. Use structured helpers when available
4. Include context (IDs, counts, timestamps)
5. Keep messages concise but informative
6. Test in debug and release builds
