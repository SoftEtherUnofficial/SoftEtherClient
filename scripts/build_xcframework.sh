#!/bin/bash
set -e

# Build SoftEtherClient XCFramework for iOS
# This script builds the Zig-based SoftEther client for both iOS device and simulator

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}/.."
BUILD_DIR="${PROJECT_DIR}/build_ios"
OUTPUT_DIR="${PROJECT_DIR}/../RustFramework"

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
zig build ffi -Dtarget=aarch64-ios -Drelease=true

if [ ! -f "zig-out/lib/libsoftether_ffi.a" ]; then
    echo "❌ Error: Device build failed - libsoftether_ffi.a not found"
    exit 1
fi

cp -v "zig-out/lib/libsoftether_ffi.a" "${BUILD_DIR}/device/"
echo "✅ Device library: $(ls -lh ${BUILD_DIR}/device/libsoftether_ffi.a | awk '{print $5}')"

# Build for iOS Simulator (arm64)
echo ""
echo "🖥️  Building for iOS Simulator (aarch64-ios-simulator)..."
zig build ffi -Dtarget=aarch64-ios-simulator -Drelease=true

if [ ! -f "zig-out/lib/libsoftether_ffi.a" ]; then
    echo "❌ Error: Simulator build failed - libsoftether_ffi.a not found"
    exit 1
fi

cp -v "zig-out/lib/libsoftether_ffi.a" "${BUILD_DIR}/simulator/"
echo "✅ Simulator library: $(ls -lh ${BUILD_DIR}/simulator/libsoftether_ffi.a | awk '{print $5}')"

# Create XCFramework
echo ""
echo "📦 Creating XCFramework..."
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
