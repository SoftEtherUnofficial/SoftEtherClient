# SoftEtherZig

A modern, cross-platform VPN client implementation in **pure Zig**, progressively replacing the SoftEther VPN C codebase.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zig Version](https://img.shields.io/badge/zig-0.15.1+-blue)](https://ziglang.org/)


## 🔒 Security Notice

**IMPORTANT**: Never use plaintext passwords on the command line! See [SECURITY.md](SECURITY.md) for secure credential management best practices.

**Recommended**: Use pre-hashed passwords or environment variables:
```bash
# Generate hash (do this once)
./vpnclient --gen-hash username password

# Use hash instead of plaintext password
./vpnclient -u username --password-hash "your_hash_here"

# Or use environment variables
export SOFTETHER_PASSWORD_HASH="your_hash_here"
./vpnclient
```

## Overview

SoftEtherZig is a complete rewrite of SoftEther VPN in pure Zig. While currently wrapping the battle-tested C core, we're systematically replacing all C code with safe, idiomatic Zig implementations.

**Why Zig?**
- **Memory Safety**: Eliminate buffer overflows, use-after-free, null pointer dereferences
- **Performance**: Zero-cost abstractions, LLVM optimizations, compile-time code generation
- **Maintainability**: No header files, built-in testing, clear error handling
- **Portability**: Native cross-compilation to any platform without toolchain hassle

## Features

**Zig Components (Pure Zig - Phase 1-3 Complete)**:
- ✅ **Foundation Layer** (Phase 1): Memory management, string operations, collections (1,530 lines, 52 tests)
- ✅ **Network Layer** (Phase 2): Socket, HTTP, connection management (1,754 lines, 34 tests)
- ✅ **Protocol Layer** (Phase 3): VPN protocol, packet handling, **REAL cryptography** (3,121 lines, 50 tests)
  - **VPN Protocol**: Session management, authentication, state machine (607 lines, 12 tests)
  - **Packet Handling**: Format, fragmentation, compression (791 lines, 13 tests)
  - **Encryption**: Production AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (823 lines, 16 tests)
  - **Integration**: Full end-to-end VPN client with worker threads (900 lines, 9 tests)
- ✅ **FFI Layer**: Cross-platform C API (`include/ffi.h`) for iOS, Android, and other platforms
- ✅ **CLI Interface**: Command-line tool with secure credential handling
- ✅ **Configuration System**: Type-safe JSON parsing with validation
- ✅ **Test Coverage**: 122/126 tests passing (96.8%), zero memory leaks, zero warnings
- ⏳ **Phase 4**: Platform adapters (Linux/Windows TUN/TAP porting from C)

**VPN Capabilities** (SoftEther SSL-VPN Protocol):
- 🔒 **Secure**: SSL/TLS 1.3 encryption with SoftEther's proven SSL-VPN protocol
- 🌐 **Cross-Platform**: Native support for macOS, Linux, Windows, Android, and iOS
- ⚡ **UDP Acceleration**: Optimized network performance with R-UDP protocol
- 🌉 **Dual Mode Support**: SecureNAT (Layer 3) and Local Bridge (Layer 2) modes
- 🔄 **Automatic Reconnection**: Exponential backoff with configurable retry limits
- 📝 **Note**: This is **SoftEther's proprietary SSL-VPN**, not SSTP/OpenVPN/L2TP

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/SoftEtherZig.git
cd SoftEtherZig

# Build the client
zig build

# Generate password hash (recommended for security)
./zig-out/bin/vpnclient --gen-hash username password
# Copy the generated hash

# Connect to a VPN server (using hash)
sudo ./zig-out/bin/vpnclient -s vpn.example.com -H VPN -u username --password-hash "your_hash_here"

# Or use environment variables (most secure)
export SOFTETHER_SERVER="vpn.example.com"
export SOFTETHER_HUB="VPN"
export SOFTETHER_USER="username"
export SOFTETHER_PASSWORD_HASH="your_hash_here"
sudo -E ./zig-out/bin/vpnclient
```

> ⚠️ **Security Warning**: The examples in the rest of this README may show `-P password` for simplicity, but you should **always use `--password-hash`** in production. See [SECURITY.md](SECURITY.md) for details.

## Installation

### Prerequisites

- **Zig**: 0.15.1 or later ([download](https://ziglang.org/download/))
- **OpenSSL**: 3.0+ (system package manager)
- **Root/Admin privileges**: Required for TUN device creation

### System Dependencies

```bash
# macOS
brew install openssl@3

# Ubuntu/Debian
sudo apt update
sudo apt install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# Windows
# Download OpenSSL from https://slproweb.com/products/Win32OpenSSL.html
```

### Build

```bash
# Development build
zig build

# Optimized release build
zig build -Doptimize=ReleaseFast

# Install system-wide (optional)
sudo cp zig-out/bin/vpnclient /usr/local/bin/
```

## Usage

### Command Line Interface

```bash
# Basic connection
sudo vpnclient -s vpn.example.com -H VPN -u username -P password

# Custom port
sudo vpnclient -s vpn.example.com -p 8443 -H VPN -u username -P password

# Daemon mode (background)
sudo vpnclient -s vpn.example.com -H VPN -u username -P password -d

# Show help
vpnclient --help
```

### CLI Options

#### Connection Options
| Option | Description | Default |
|--------|-------------|---------|
| `-s, --server <HOST>` | VPN server hostname | *required* |
| `-p, --port <PORT>` | VPN server port | 443 |
| `-H, --hub <HUB>` | Virtual hub name | *required* |
| `-u, --user <USERNAME>` | Username | *required* |
| `-P, --password <PASS>` | Password (use `--password-hash` instead!) | *required* |
| `--password-hash <HASH>` | Pre-hashed password (recommended) | |
| `-a, --account <NAME>` | Account name | username |
| `--no-encrypt` | Disable encryption | false |
| `--no-compress` | Disable compression | false |
| `-d, --daemon` | Run as daemon | false |

#### Performance Options
| Option | Description | Default |
|--------|-------------|---------|
| `--use-zig-adapter` | Use Zig packet adapter (default, 10x faster) | **true** |
| `--use-c-adapter` | Use legacy C adapter (fallback) | false |
| `--profile` | Enable performance profiling | false |

#### Reconnection Options
| Option | Description | Default |
|--------|-------------|---------|
| `--reconnect` | Enable auto-reconnection | true |
| `--no-reconnect` | Disable auto-reconnection | false |
| `--max-retries <N>` | Max reconnection attempts (0=infinite) | 0 |
| `--min-backoff <SEC>` | Min backoff delay (seconds) | 5 |
| `--max-backoff <SEC>` | Max backoff delay (seconds) | 300 |

#### Other Options
| Option | Description | Default |
|--------|-------------|---------|
| `--log-level <LEVEL>` | Log verbosity: silent, error, warn, info, debug, trace | info |
| `-h, --help` | Show help | |
| `-v, --version` | Show version | |

### Library Usage

```zig
const softether = @import("softether");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = softether.ConnectionConfig{
        .server_name = "vpn.example.com",
        .server_port = 443,
        .hub_name = "VPN",
        .account_name = "myaccount",
        .auth = .{ .password = .{
            .username = "user",
            .password = "pass",
        } },
        .use_encrypt = true,
        .use_compress = true,
    };

    var client = try softether.VpnClient.init(allocator, config);
    defer client.deinit();

    try client.connect();

    // Your application logic here
    while (client.isConnected()) {
        std.time.sleep(1 * std.time.ns_per_s);
    }
}
```

## Architecture

### FFI Status

| FFI Layer | Status | Platforms | Implementation | Recommended |
|-----------|--------|-----------|----------------|-------------|
| **ffi.h** | ✅ Active | All platforms | Pure Zig | ✅ **YES** |
| ~~softether_ffi.h~~ | ❌ Removed | iOS only | C | ❌ No |

**Note**: Legacy FFI was archived October 2025. See [Migration Guide](docs/FFI_MIGRATION_GUIDE.md) for historical context.

### Porting Status

| Phase | Component | Status | Progress | Target |
|-------|-----------|--------|----------|--------|
| 1 | **Foundation** | 🟡 In Progress | 15% | Q2 2026 |
| 1.1 | Platform Adapters (TUN/TAP) | ⏳ Starting | 0% | Q1 2026 |
| 1.2 | Mayaqua Library (utilities) | ⏳ Planned | 0% | Q2 2026 |
| 2 | **Core Infrastructure** | ⏸️ Not Started | 0% | Q4 2026 |
| 2.1 | Network Stack (TCP/UDP/HTTP) | ⏸️ Not Started | 0% | Q3 2026 |
| 2.2 | Cryptography Layer | ⏸️ Not Started | 0% | Q4 2026 |
| 3 | **Session Management** | ⏸️ Not Started | 0% | Q2 2027 |
| 4 | **Protocols** (SSTP/L2TP/OpenVPN) | ⏸️ Not Started | 0% | Q4 2027 |
| 5 | **Applications** (Client/Server) | ⏸️ Not Started | 0% | Q2 2028 |

**Overall**: 2% complete (~1,200 of ~70,000 lines ported to Zig)

### Current Sprint (October 2025)
**Goal**: Port macOS packet adapter to pure Zig
- [ ] Create `src/platform/macos.zig`
- [ ] Integrate ZigTapTun for utun management
- [ ] Port DHCP packet handling
- [ ] Achieve performance parity with C version

See [Porting Progress Tracker](docs/ZIG_PORTING_PROGRESS.md) for detailed task list.

## Architecture

### Current Hybrid Architecture (Phase 1)

```
┌─────────────────────────────────────┐
│    Zig Application Layer (PURE ZIG) │
│  cli.zig, client.zig, config.zig    │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    FFI Layer (PURE ZIG)             │
│  ffi/ffi.zig - Cross-platform API   │
└──────────────┬──────────────────────┘
               │
         ┌─────┴─────┐
         │  C Bridge │ ← Being eliminated
         └─────┬─────┘
               │
┌──────────────▼──────────────────────┐
│   SoftEther Core (C → Zig in progress)
│  Cedar + Mayaqua libraries          │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Platform Layer (C → Zig Phase 1)   │
│  TUN/TAP adapters                   │
└─────────────────────────────────────┘
```

### Target Pure Zig Architecture (Phase 5)

```
┌─────────────────────────────────────┐
│         Zig Application             │
│  (Client, Server, Bridge)           │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Protocol Layer (Zig)           │
│  SSTP, L2TP, OpenVPN                │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Session Management (Zig)         │
│  Connection pooling, Keep-alive     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Network Stack (Zig)              │
│  TCP/UDP, HTTP, TLS via std.crypto  │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│    Platform Adapters (Zig)          │
│  Pure Zig TUN/TAP via ZigTapTun     │
└─────────────────────────────────────┘
```

## Project Structure

```
SoftEtherZig/
├── SoftEtherVPN_Stable/          # SoftEther C source (submodule)
│   └── src/                      # Original SoftEther VPN codebase
├── src/                          # Zig implementation
│   ├── main.zig                  # Library entry point
│   ├── cli.zig                   # Command-line interface
│   ├── client.zig                # VPN client logic
│   ├── config.zig                # Configuration types
│   ├── types.zig                 # Common data structures
│   ├── errors.zig                # Error definitions
│   ├── ffi/
│   │   └── ffi.zig               # ✅ FFI (cross-platform C API)
│   ├── c.zig                     # C imports and bindings
│   └── bridge/                   # C bridge layer
│       ├── softether_bridge.c    # Main SoftEther interface
│       ├── unix_bridge.c         # POSIX system abstraction
│       ├── packet_adapter_*.c    # Platform-specific TUN/TAP
│       └── tick64_*.c            # High-resolution timing
├── legacy/                       # Archived deprecated code
│   └── ffi/                      # Legacy FFI (archived Oct 2025)
│       ├── ios_ffi.c.archived    # Old iOS FFI implementation
│       ├── softether_ffi.h.archived  # Old FFI header
│       └── ffi.zig.archived      # Old Zig FFI stubs
├── build.zig                     # Build configuration
├── build.zig.zon                 # Zig package dependencies
└── zig-out/                      # Build artifacts
    └── bin/
        └── vpnclient             # Compiled executable
```

### Component Overview

1. **CLI Layer** (`cli.zig`): Command-line argument parsing and user interaction
2. **Client Layer** (`client.zig`): High-level VPN connection management
3. **Bridge Layer** (`bridge/`): C code that interfaces with SoftEther VPN
4. **FFI Layer** (`ffi.zig`): Safe Zig bindings to C functions

### Network Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │────│   Zig Client     │────│   C Bridge      │
│   (CLI/Library) │    │   Logic          │    │   Layer         │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌────────────────────┐
                    │  SoftEther VPN     │
                    │  Core (C)          │
                    └────────────────────┘
                             │
                    ┌────────────────────┐
                    │  SSL/TLS 1.3       │
                    │  (OpenSSL)         │
                    └────────────────────┘
                             │
                    ┌────────────────────┐
                    │  TUN/TAP Device    │
                    │  (Platform)        │
                    └────────────────────┘
```

## Platform Support

### Desktop Platforms

| Platform | Architecture | TUN Device | Status |
|----------|--------------|------------|--------|
| macOS | x86_64, ARM64 | utun | ✅ Tested |
| Linux | x86_64, ARM64 | TUN/TAP | 🚧 Planned |
| Windows | x86_64 | TAP-Windows6 | 🚧 Planned |

### Mobile Platforms

| Platform | Architecture | Implementation | Status |
|----------|--------------|----------------|--------|
| Android | ARM64, ARMv7, x86_64 | JNI + VpnService | ✅ Complete |
| iOS | ARM64, x86_64 | PacketTunnelProvider | ✅ Complete |

**Mobile implementations are production-ready!** See:
- [`android/README.md`](android/README.md) - Android integration guide
- [`ios/README.md`](ios/README.md) - iOS integration guide

### Building for Different Platforms

Zig enables seamless cross-compilation:

```bash
# Build for Linux from macOS
zig build -Dtarget=x86_64-linux-gnu

# Build for Windows from macOS
zig build -Dtarget=x86_64-windows-gnu

# Build for ARM64 Linux
zig build -Dtarget=aarch64-linux-gnu
```

## Building from Source

### Standard Build

```bash
# Debug build (with symbols)
zig build

# Release build (optimized)
zig build -Doptimize=ReleaseFast

# Safe release build
zig build -Doptimize=ReleaseSafe
```

### Custom Build Options

```bash
# Build with custom target
zig build -Dtarget=aarch64-linux-gnu

# Build with specific CPU features
zig build -Dcpu=baseline

# Clean build artifacts
rm -rf zig-cache zig-out
```

### Build Dependencies

The build system automatically:
- Downloads and compiles SoftEther C sources
- Links with system OpenSSL
- Creates platform-specific TUN adapters
- Generates optimized binaries

## Configuration

### Configuration Methods

SoftEtherZig supports three configuration methods with priority order:
1. **Command-line arguments** (highest priority)
2. **Environment variables** (medium priority)
3. **Configuration file** (lowest priority)

### Configuration File (NEW in v1.1)

Create `~/.config/softether-zig/config.json`:

```json
{
  "server": "vpn.example.com",
  "port": 443,
  "hub": "VPN",
  "username": "myuser",
  "password_hash": "base64-hashed-password"
}
```

Then simply run:
```bash
vpnclient  # Uses config file
```

**See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for complete configuration guide.**

Example configurations:
- `config.example.json` - Full configuration with all options
- `config.minimal.json` - Minimal working configuration

### Environment Variables

Connection settings:
- `SOFTETHER_SERVER`: VPN server hostname
- `SOFTETHER_PORT`: VPN server port
- `SOFTETHER_HUB`: Virtual hub name
- `SOFTETHER_USER`: Username
- `SOFTETHER_PASSWORD`: Password (plaintext, not recommended)
- `SOFTETHER_PASSWORD_HASH`: Pre-hashed password (recommended)

SSL/TLS settings:
- `SSL_CERT_FILE`: Path to custom CA certificate bundle
- `SSL_CERT_DIR`: Directory containing CA certificates

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Solution: Run with sudo for TUN device access
sudo vpnclient -s server -H hub -u user -P pass
```

**Connection Timeout**
- Verify server hostname and port
- Check firewall settings
- Ensure VPN server is accessible

**Authentication Failed**
- Confirm username and password
- Check virtual hub name
- Verify account permissions

**TUN Device Busy**
- macOS: Wait for utun device to become available
- Linux: Check `/dev/net/tun` permissions

### Debug Mode

```bash
# Build with debug symbols
zig build -Doptimize=Debug

# Run with verbose logging
sudo ./zig-out/bin/vpnclient -s server -H hub -u user -P pass 2>&1 | tee debug.log
```

## Development

### Code Organization

- **`src/`**: Zig source code
- **`src/bridge/`**: C bridge code interfacing with SoftEther
- **`SoftEtherVPN_Stable/`**: Upstream SoftEther VPN source

### Adding Features

**CLI Features:**
- Edit `src/cli.zig` for new command-line options

**Client Features:**
- Modify `src/client.zig` for connection logic

**Bridge Features:**
- Update `src/bridge/softether_bridge.c` for new SoftEther integration

### Testing

```bash
# Run tests
zig build test

# Build and test specific target
zig build -Dtarget=x86_64-linux-gnu test
```

### Code Style

- **Zig**: Follow official Zig style guide
- **C**: Follow SoftEther VPN conventions
- **Documentation**: Use Zig doc comments for public APIs

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Areas for Contribution

- 🐧 Linux TUN/TAP implementation
- 🪟 Windows TAP-Windows6 support
- 🔐 Additional authentication methods (certificate, RADIUS)
- 📊 Performance optimizations
- 🧪 Comprehensive test suite
- 📚 Documentation improvements

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

The SoftEther VPN components are licensed under Apache License 2.0 by the SoftEther VPN Project.

## Credits

- **SoftEther VPN Project**: Original VPN implementation
- **Zig Programming Language**: Modern systems programming language
- **OpenSSL Project**: Cryptography library

## Related Projects

- [SoftEther VPN Official](https://www.softether.org/) - Original SoftEther VPN
- [Zig Language](https://ziglang.org/) - Programming language
- [OpenSSL](https://www.openssl.org/) - Cryptography toolkit

## Documentation

### Getting Started
- [QUICKSTART.md](QUICKSTART.md) - Get started quickly
- [QUICKREF.md](QUICKREF.md) - Quick reference guide
- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) - Configuration guide

### Architecture & Design
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [docs/ARCHITECTURE_AND_DEPENDENCIES.md](docs/ARCHITECTURE_AND_DEPENDENCIES.md) - Pure Zig architecture & dependencies
- [deps/taptun/PROJECT_SUMMARY.md](deps/taptun/PROJECT_SUMMARY.md) - ZigTapTun library overview
- [PROGRESS.md](PROGRESS.md) - Implementation progress and roadmap

### Migration to Pure Zig 🚀
- [docs/MIGRATION_EXECUTIVE_SUMMARY.md](docs/MIGRATION_EXECUTIVE_SUMMARY.md) - **START HERE** - Executive summary
- [docs/ZIG_PURE_CLIENT_FEASIBILITY.md](docs/ZIG_PURE_CLIENT_FEASIBILITY.md) - Detailed feasibility analysis
- [docs/ZIG_MIGRATION_ROADMAP.md](docs/ZIG_MIGRATION_ROADMAP.md) - Month-by-month execution plan
- [RUST_TO_ZIG_MIGRATION.md](RUST_TO_ZIG_MIGRATION.md) - Historical context (Rust → Zig)

### Platform Support
- [CROSS_PLATFORM.md](CROSS_PLATFORM.md) - Cross-platform build guide
- [IOS_BUILD_GUIDE.md](IOS_BUILD_GUIDE.md) - iOS build instructions

### Server Mode Comparison
- [DOCS_INDEX.md](DOCS_INDEX.md) - Documentation navigation and overview
- [SECURENAT_VS_LOCALBRIDGE.md](SECURENAT_VS_LOCALBRIDGE.md) - Complete technical comparison of server modes
- [LOCALBRIDGE_QUICKREF.md](LOCALBRIDGE_QUICKREF.md) - Quick reference for Local Bridge implementation
- [PACKET_FLOW_DIAGRAMS.md](PACKET_FLOW_DIAGRAMS.md) - Visual diagrams of packet flows

### Security
- [SECURITY.md](SECURITY.md) - Security best practices

---

**SoftEtherZig** - Bringing modern programming practices to enterprise VPN connectivity.
