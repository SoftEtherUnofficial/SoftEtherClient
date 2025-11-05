#!/bin/bash
# Build and run the direct API test program

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/zig-out/test"

echo "═══════════════════════════════════════════════════════════════"
echo "  Building Direct API Test Program"
echo "═══════════════════════════════════════════════════════════════"

# Create build directory
mkdir -p "$BUILD_DIR"

# Build the test program directly with clang
cd "$PROJECT_ROOT"

echo ""
echo "→ Compiling test program with clang..."
echo ""

# Compile all C sources and link
clang -arch arm64 \
    -O0 -g \
    -o "$BUILD_DIR/test_direct_api" \
    test/test_direct_api.c \
    src/bridge/direct_api.c \
    src/bridge/softether_bridge.c \
    src/bridge/unix_bridge.c \
    src/bridge/tick64_macos.c \
    src/bridge/logging.c \
    src/bridge/security_utils.c \
    src/bridge/Mayaqua/Mayaqua.c \
    src/bridge/Mayaqua/Memory.c \
    src/bridge/Mayaqua/Network_iOS.c \
    SoftEtherVPN/src/Mayaqua/Str.c \
    src/bridge/Mayaqua/Object.c \
    SoftEtherVPN/src/Mayaqua/OS.c \
    SoftEtherVPN/src/Mayaqua/FileIO.c \
    src/bridge/Mayaqua/Kernel.c \
    SoftEtherVPN/src/Mayaqua/Network.c \
    SoftEtherVPN/src/Mayaqua/TcpIp.c \
    SoftEtherVPN/src/Mayaqua/Encrypt.c \
    SoftEtherVPN/src/Mayaqua/Secure.c \
    SoftEtherVPN/src/Mayaqua/Pack.c \
    SoftEtherVPN/src/Mayaqua/Cfg.c \
    SoftEtherVPN/src/Mayaqua/Table.c \
    SoftEtherVPN/src/Mayaqua/Tracking.c \
    SoftEtherVPN/src/Mayaqua/Microsoft.c \
    SoftEtherVPN/src/Mayaqua/Internat.c \
    SoftEtherVPN/src/Cedar/Cedar.c \
    src/bridge/Cedar/Client.c \
    src/bridge/Cedar/Protocol.c \
    src/bridge/Cedar/Connection.c \
    src/bridge/Cedar/Session.c \
    SoftEtherVPN/src/Cedar/Account.c \
    SoftEtherVPN/src/Cedar/Admin.c \
    SoftEtherVPN/src/Cedar/Command.c \
    SoftEtherVPN/src/Cedar/Hub.c \
    SoftEtherVPN/src/Cedar/Listener.c \
    SoftEtherVPN/src/Cedar/Logging.c \
    SoftEtherVPN/src/Cedar/Sam.c \
    SoftEtherVPN/src/Cedar/Server.c \
    SoftEtherVPN/src/Cedar/Virtual.c \
    SoftEtherVPN/src/Cedar/Link.c \
    SoftEtherVPN/src/Cedar/SecureNAT.c \
    SoftEtherVPN/src/Cedar/NullLan.c \
    SoftEtherVPN/src/Cedar/Bridge.c \
    SoftEtherVPN/src/Cedar/Nat.c \
    SoftEtherVPN/src/Cedar/UdpAccel.c \
    SoftEtherVPN/src/Cedar/Database.c \
    SoftEtherVPN/src/Cedar/Remote.c \
    SoftEtherVPN/src/Cedar/DDNS.c \
    SoftEtherVPN/src/Cedar/AzureClient.c \
    SoftEtherVPN/src/Cedar/AzureServer.c \
    SoftEtherVPN/src/Cedar/Radius.c \
    SoftEtherVPN/src/Cedar/Console.c \
    SoftEtherVPN/src/Cedar/Layer3.c \
    SoftEtherVPN/src/Cedar/Interop_OpenVPN.c \
    SoftEtherVPN/src/Cedar/Interop_SSTP.c \
    SoftEtherVPN/src/Cedar/IPsec.c \
    SoftEtherVPN/src/Cedar/IPsec_IKE.c \
    SoftEtherVPN/src/Cedar/IPsec_IkePacket.c \
    SoftEtherVPN/src/Cedar/IPsec_L2TP.c \
    SoftEtherVPN/src/Cedar/IPsec_PPP.c \
    SoftEtherVPN/src/Cedar/IPsec_EtherIP.c \
    SoftEtherVPN/src/Cedar/IPsec_IPC.c \
    SoftEtherVPN/src/Cedar/EtherLog.c \
    SoftEtherVPN/src/Cedar/WebUI.c \
    SoftEtherVPN/src/Cedar/WaterMark.c \
    -I SoftEtherVPN/src \
    -I SoftEtherVPN/src/Mayaqua \
    -I SoftEtherVPN/src/Cedar \
    -I include \
    -I src \
    -I src/bridge/include \
    -I /opt/homebrew/opt/openssl@3/include \
    -L /opt/homebrew/opt/openssl@3/lib \
    -lssl -lcrypto -lz -lpthread -lresolv \
    -D_REENTRANT -D_THREAD_SAFE -DCPU_64 -D_FILE_OFFSET_BITS=64 \
    -DVPN_SPEED -DUNIX -DUNIX_MACOS -DBRIDGE_C=1 \
    -Wno-deprecated-declarations \
    -Wno-unused-parameter \
    -Wno-unused-variable \
    -Wno-sign-compare \
    -Wno-incompatible-function-pointer-types \
    -Wno-int-conversion \
    -Wno-implicit-function-declaration \
    -Wno-strict-prototypes \
    2>&1 || {
        echo ""
        echo "✗ Build failed"
        echo ""
        exit 1
    }

echo ""
echo "✓ Build successful"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Test binary: $BUILD_DIR/test_direct_api"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "To run tests:"
echo "  ./zig-out/test/test_direct_api              # Run basic tests"
echo "  ./zig-out/test/test_direct_api --connect    # Include connection test"
echo ""

# Optionally run tests
if [ "$1" == "--run" ]; then
    echo "Running tests..."
    echo ""
    "$BUILD_DIR/test_direct_api"
fi
