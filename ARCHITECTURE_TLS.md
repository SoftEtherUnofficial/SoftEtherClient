# TLS/SSL Architecture: Two Implementation Approaches

## Overview

SoftEtherZig provides **two TLS/SSL implementation approaches** that users can choose at runtime:

1. **Legacy C Bridge (Default)** - Uses OpenSSL via SoftEtherVPN_Stable
2. **Rust Cedar FFI (Optional)** - Uses native-tls/rustls, avoiding OpenSSL dependency

---

## Approach 1: Legacy C Bridge (Default) 🔒

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│  Zig Client Code (src/client.zig, src/main.zig)            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Patched C Bridge (src/bridge/Cedar/*.c, Mayaqua/*.c)       │
│  • Initialization fixes                                      │
│  • Thread safety patches                                     │
│  • Memory leak fixes                                         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  SoftEtherVPN_Stable (submodule)                            │
│  • Original SoftEther VPN C codebase                        │
│  • Uses OpenSSL for TLS/SSL                                 │
└─────────────────────────────────────────────────────────────┘
```

### Key Features
- ✅ **Default behavior** - No runtime flags needed
- ✅ **Mature codebase** - Battle-tested SoftEther implementation
- ✅ **Full protocol support** - All SoftEther features available
- ⚠️ **OpenSSL dependency** - Requires OpenSSL at compile time
- ⚠️ **Platform-specific** - Different OpenSSL versions per OS

### Usage
```bash
# Default - uses OpenSSL via C bridge
sudo ./zig-out/bin/vpnclient --config config.json
```

### Build Configuration
```bash
# Standard build (includes C bridge)
zig build

# The C bridge is always compiled, no special flags needed
```

---

## Approach 2: Rust Cedar FFI (Optional) 🦀

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│  Zig Client Code (src/client.zig, src/main.zig)            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Zig FFI Wrappers (src/cedar/wrapper.zig)                   │
│  • Ergonomic Zig API                                         │
│  • Safe memory management                                    │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Cedar FFI Layer (cedar/src/ffi.rs)                         │
│  • C-compatible exports                                      │
│  • Session lifecycle management                              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Cedar Rust Implementation (cedar/src/)                     │
│  • Protocol handling (protocol.rs, session.rs)              │
│  • Encryption (encryption.rs)                                │
│  • Connection management (connection.rs)                     │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│  Mayaqua Rust TLS (mayaqua/src/tls.rs)                     │
│  • Uses native-tls (platform TLS: Secure Transport, SChannel)│
│  • Falls back to rustls if needed                           │
│  • NO OpenSSL dependency                                     │
└─────────────────────────────────────────────────────────────┘
```

### Key Features
- ✅ **No OpenSSL** - Uses native platform TLS (Secure Transport on macOS)
- ✅ **Cross-platform** - Consistent behavior across OSes
- ✅ **Memory safe** - Rust's ownership system prevents leaks
- ✅ **Modern TLS** - Supports TLS 1.3, modern cipher suites
- ⚠️ **Opt-in** - Requires `--no-openssl` runtime flag
- ⚠️ **Newer code** - Less battle-tested than C implementation

### Usage
```bash
# Use Rust native-tls (avoids OpenSSL)
sudo ./zig-out/bin/vpnclient --config config.json --no-openssl
```

### Build Configuration
```bash
# Standard build (includes both implementations)
zig build

# Both C bridge AND Rust Cedar are always compiled
# User chooses at runtime with --no-openssl flag
```

---

## Comparison Table

| Feature | C Bridge (Default) | Rust Cedar (--no-openssl) |
|---------|-------------------|---------------------------|
| **TLS Library** | OpenSSL | native-tls / rustls |
| **Runtime Flag** | None (default) | `--no-openssl` |
| **Compile Dependency** | Requires OpenSSL headers | No OpenSSL needed |
| **Platform TLS** | No (always OpenSSL) | Yes (Secure Transport, etc.) |
| **Memory Safety** | Manual C management | Rust ownership |
| **Maturity** | Very mature (10+ years) | Newer (2+ years) |
| **Code Location** | `src/bridge/`, `SoftEtherVPN_Stable/` | `cedar/`, `mayaqua/` |
| **Threading Model** | Multi-threaded C | Synchronous non-blocking |
| **Protocol Support** | Full SoftEther | Core features |

---

## When to Use Which Approach?

### Use **Default C Bridge** (No flag) if:
- ✅ You need maximum compatibility with SoftEther servers
- ✅ Your system already has OpenSSL installed
- ✅ You want the most mature, tested implementation
- ✅ You need all SoftEther protocol features

### Use **Rust Cedar** (`--no-openssl`) if:
- ✅ You want to avoid OpenSSL dependencies
- ✅ You prefer native platform TLS (Secure Transport on macOS)
- ✅ You want modern TLS 1.3 support
- ✅ You prefer memory-safe Rust code
- ✅ You're building for environments where OpenSSL is problematic

---

## Implementation Details

### TLS Handshake Flow

#### C Bridge (OpenSSL):
```
Client → OpenSSL_connect() → Server
      ← SSL_read/write() ←
```

#### Rust Cedar (native-tls):
```
Client → TlsConnector::connect() → Server (via Secure Transport on macOS)
      ← stream.read/write() ←
```

### File Structure

```
SoftEtherZig/
├── src/
│   ├── client.zig              # Main VPN client (uses either approach)
│   ├── main.zig                # CLI entry point
│   └── bridge/                 # Approach 1: Patched C code
│       ├── Cedar/              # Protocol, session management
│       ├── Mayaqua/            # Core utilities (with OpenSSL)
│       └── *.c                 # Bridge patches
├── cedar/                      # Approach 2: Rust Cedar
│   ├── src/
│   │   ├── ffi.rs              # FFI exports
│   │   ├── session.rs          # Session management
│   │   ├── protocol.rs         # Protocol handling
│   │   └── encryption.rs       # TLS via mayaqua
│   └── Cargo.toml
├── mayaqua/                    # Rust TLS abstraction
│   ├── src/
│   │   ├── tls.rs              # native-tls wrapper (NO OpenSSL)
│   │   └── error.rs
│   └── Cargo.toml
└── SoftEtherVPN_Stable/        # Original C codebase (submodule)
    └── src/                    # Uses OpenSSL
```

---

## Build System Integration

Both implementations are **always compiled** and included in the binary:

```bash
# This builds BOTH:
# 1. C bridge with OpenSSL
# 2. Rust Cedar with native-tls
zig build

# Result: Single binary that supports both approaches
```

The choice between them is made **at runtime** via the `--no-openssl` flag.

---

## FAQ

### Q: Do I need OpenSSL to build?
**A:** Yes, currently the C bridge requires OpenSSL headers at compile time. However, if you use `--no-openssl` at runtime, you'll use Rust's native-tls instead.

### Q: Can I disable the C bridge entirely?
**A:** Not yet, but we plan to add a build option `-Dno-c-bridge` in the future to create a pure Rust binary.

### Q: Which is faster?
**A:** Both are roughly equivalent in performance. The bottleneck is typically network I/O, not TLS processing.

### Q: Which is more secure?
**A:** Both use strong TLS implementations. Rust Cedar may have fewer memory safety bugs due to Rust's ownership system.

### Q: Can I switch between them without reconnecting?
**A:** No, you must choose at startup with the `--no-openssl` flag.

---

## Migration Path

If you're currently using the default (C bridge), you can easily try Rust Cedar:

```bash
# Before (default, uses OpenSSL):
sudo ./zig-out/bin/vpnclient --config config.json

# After (Rust native-tls, no OpenSSL dependency at runtime):
sudo ./zig-out/bin/vpnclient --config config.json --no-openssl
```

No configuration changes needed! The same `config.json` works for both.

---

## Future Plans

- [ ] Make C bridge optional at compile time (`-Dno-c-bridge`)
- [ ] Add pure Rust builds with no C dependencies
- [ ] Support more Rust TLS backends (rustls, boring)
- [ ] Feature parity: Bring all C bridge features to Rust Cedar
- [ ] Performance profiling and optimization

---

## Related Documentation

- [Build Instructions](README.md) - How to build the project
- [Configuration](docs/CONFIGURATION.md) - Config file format
- [Testing](TESTING.md) - Running tests for both implementations
- [Cross-Platform](CROSS_PLATFORM.md) - Platform-specific notes

---

**Last Updated**: October 12, 2025
