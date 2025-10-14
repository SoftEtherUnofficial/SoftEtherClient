#!/bin/bash
set -e

# Build iOS Framework Script
# Automatically builds SoftEtherClient.xcframework for iOS device and simulator
# Called from Xcode build phases

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_ios"
OUTPUT_DIR="${SCRIPT_DIR}"

echo "🔨 Building SoftEther iOS Framework..."
echo "📁 Script dir: ${SCRIPT_DIR}"
echo "📁 Build dir: ${BUILD_DIR}"

# Clean previous builds
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/ios-arm64"
mkdir -p "${BUILD_DIR}/ios-arm64-simulator"

# Build for iOS Device (arm64)
echo "📱 Building for iOS Device (arm64)..."
cd "${SCRIPT_DIR}"
zig build -Dtarget=aarch64-ios -Drelease=true ffi

# Copy the build artifact (OpenSSL is statically linked into libsoftether_ffi.a)
cp -v "${SCRIPT_DIR}/zig-out/lib/libsoftether_ffi.a" "${BUILD_DIR}/ios-arm64/libSoftEtherClient.a"

# Build for iOS Simulator (arm64)
echo "📱 Building for iOS Simulator (arm64)..."
zig build -Dtarget=aarch64-ios-simulator -Drelease=true ffi

# Copy the build artifact
cp -v "${SCRIPT_DIR}/zig-out/lib/libsoftether_ffi.a" "${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient.a"

# Create XCFramework
echo "📦 Creating XCFramework..."
rm -rf "${OUTPUT_DIR}/SoftEtherClient.xcframework"
xcodebuild -create-xcframework \
  -library "${BUILD_DIR}/ios-arm64/libSoftEtherClient.a" \
  -headers "${SCRIPT_DIR}/include" \
  -library "${BUILD_DIR}/ios-arm64-simulator/libSoftEtherClient.a" \
  -headers "${SCRIPT_DIR}/include" \
  -output "${OUTPUT_DIR}/SoftEtherClient.xcframework"

echo "✅ SoftEtherClient.xcframework built successfully!"
ls -lah "${OUTPUT_DIR}/SoftEtherClient.xcframework/"
