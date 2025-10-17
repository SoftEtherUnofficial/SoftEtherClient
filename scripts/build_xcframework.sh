#!/bin/bash
set -e

# Build SoftEtherClient XCFramework for iOS
# This script builds the Zig-based SoftEther client for both iOS device and simulator

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/.."
BUILD_DIR="${PROJECT_DIR}/build_ios"
OUTPUT_DIR="${PROJECT_DIR}/../ZigFramework"

echo "🔨 Building SoftEtherClient.xcframework..."
echo "📁 Project: ${PROJECT_DIR}"
echo "📁 Output: ${OUTPUT_DIR}"

# Clean previous build
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/device"
mkdir -p "${BUILD_DIR}/simulator"

# Build for iOS Device (arm64)
echo ""
echo "📱 Building for iOS Device (aarch64-ios)..."
cd "${PROJECT_DIR}"

# Clean Zig cache to ensure fresh OpenSSL build for this target
echo "   Cleaning Zig cache for fresh build..."
rm -rf .zig-cache

zig build ffi -Dtarget=aarch64-ios -Drelease=true

if [ ! -f "zig-out/lib/libsoftether_ffi.a" ]; then
    echo "❌ Error: Device build failed - libsoftether_ffi.a not found"
    exit 1
fi

# Find and merge OpenSSL libraries
echo "📋 Merging OpenSSL into SoftEther library..."
# Find the most recently modified OpenSSL libraries (should be from this build)
SSL_LIB=$(find .zig-cache -name "libssl.a" -type f -print0 | xargs -0 ls -t | head -1)
CRYPTO_LIB=$(find .zig-cache -name "libcrypto.a" -type f -print0 | xargs -0 ls -t | head -1)

if [ -n "$SSL_LIB" ] && [ -n "$CRYPTO_LIB" ]; then
    echo "   Found libssl: $(basename $(dirname $SSL_LIB))"
    echo "   Found libcrypto: $(basename $(dirname $CRYPTO_LIB))"
    
    # Use libtool with absolute paths
    libtool -static -o "${BUILD_DIR}/device/libsoftether_ffi.a" \
        "${PROJECT_DIR}/zig-out/lib/libsoftether_ffi.a" \
        "${PROJECT_DIR}/${SSL_LIB}" \
        "${PROJECT_DIR}/${CRYPTO_LIB}"
else
    echo "⚠️  Warning: Could not find OpenSSL libraries"
    cp -v "zig-out/lib/libsoftether_ffi.a" "${BUILD_DIR}/device/"
fi

echo "✅ Device library: $(ls -lh ${BUILD_DIR}/device/libsoftether_ffi.a | awk '{print $5}')"

# Build for iOS Simulator (arm64)
echo ""
echo "🖥️  Building for iOS Simulator (aarch64-ios-simulator)..."

# Clean Zig cache to ensure fresh OpenSSL build for this target
echo "   Cleaning Zig cache for fresh build..."
rm -rf .zig-cache

zig build ffi -Dtarget=aarch64-ios-simulator -Drelease=true

if [ ! -f "zig-out/lib/libsoftether_ffi.a" ]; then
    echo "❌ Error: Simulator build failed - libsoftether_ffi.a not found"
    exit 1
fi

# Find and merge OpenSSL libraries
echo "📋 Merging OpenSSL into SoftEther library..."
# Find the most recently modified OpenSSL libraries (should be from this build)
SSL_LIB=$(find .zig-cache -name "libssl.a" -type f -print0 | xargs -0 ls -t | head -1)
CRYPTO_LIB=$(find .zig-cache -name "libcrypto.a" -type f -print0 | xargs -0 ls -t | head -1)

if [ -n "$SSL_LIB" ] && [ -n "$CRYPTO_LIB" ]; then
    echo "   Found libssl: $(basename $(dirname $SSL_LIB))"
    echo "   Found libcrypto: $(basename $(dirname $CRYPTO_LIB))"
    
    # Use libtool with absolute paths
    libtool -static -o "${BUILD_DIR}/simulator/libsoftether_ffi.a" \
        "${PROJECT_DIR}/zig-out/lib/libsoftether_ffi.a" \
        "${PROJECT_DIR}/${SSL_LIB}" \
        "${PROJECT_DIR}/${CRYPTO_LIB}"
else
    echo "⚠️  Warning: Could not find OpenSSL libraries"
    cp -v "zig-out/lib/libsoftether_ffi.a" "${BUILD_DIR}/simulator/"
fi

echo "✅ Simulator library: $(ls -lh ${BUILD_DIR}/simulator/libsoftether_ffi.a | awk '{print $5}')"

# Create XCFramework
echo ""
echo "📦 Creating SoftEtherClient.xcframework..."
rm -rf "${OUTPUT_DIR}/SoftEtherClient.xcframework"

xcodebuild -create-xcframework \
  -library "${BUILD_DIR}/device/libsoftether_ffi.a" \
  -headers "${PROJECT_DIR}/include" \
  -library "${BUILD_DIR}/simulator/libsoftether_ffi.a" \
  -headers "${PROJECT_DIR}/include" \
  -output "${OUTPUT_DIR}/SoftEtherClient.xcframework"

if [ ! -d "${OUTPUT_DIR}/SoftEtherClient.xcframework" ]; then
    echo "❌ Error: XCFramework creation failed"
    exit 1
fi

echo ""
echo "✅ SoftEtherClient.xcframework created successfully!"
echo ""
echo "📊 Framework structure:"
ls -lah "${OUTPUT_DIR}/SoftEtherClient.xcframework/"

echo ""
echo "📊 Device slice:"
ls -lh "${OUTPUT_DIR}/SoftEtherClient.xcframework/ios-arm64/" | grep -v "^total"

echo ""
echo "📊 Simulator slice:"
ls -lh "${OUTPUT_DIR}/SoftEtherClient.xcframework/ios-arm64-simulator/" | grep -v "^total"

echo ""
echo "✅ Done! Framework is ready at:"
echo "   ${OUTPUT_DIR}/SoftEtherClient.xcframework"
