#!/bin/bash

# SoftEtherZig iOS XCFramework Build Script
# Builds a universal XCFramework for iOS devices and simulator

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
OUTPUT_DIR="$PROJECT_ROOT/build_xcframework"
WORXVPN_FRAMEWORK_DIR="$PROJECT_ROOT/../WorxVPN-iOS/ZigFramework"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}SoftEtherZig iOS XCFramework Builder${NC}"
echo -e "${GREEN}========================================${NC}"

# Parse arguments
SKIP_CLEAN=0
COPY_TO_WORXVPN=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-clean)
            SKIP_CLEAN=1
            shift
            ;;
        --no-copy)
            COPY_TO_WORXVPN=0
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Clean previous builds
if [ $SKIP_CLEAN -eq 0 ]; then
    echo -e "${YELLOW}Cleaning previous builds...${NC}"
    rm -rf "$OUTPUT_DIR"
fi

mkdir -p "$OUTPUT_DIR"

# Build for iOS ARM64 (device)
echo -e "${GREEN}Building for iOS ARM64 (device)...${NC}"
zig build ffi -Dtarget=aarch64-ios -Drelease=true
mkdir -p "$OUTPUT_DIR/ios-arm64/lib"
mkdir -p "$OUTPUT_DIR/ios-arm64/Headers"
cp "$PROJECT_ROOT/zig-out/lib/libsoftether_ffi.a" "$OUTPUT_DIR/ios-arm64/lib/"
cp "$PROJECT_ROOT/include/ffi.h" "$OUTPUT_DIR/ios-arm64/Headers/"

# Build for iOS Simulator ARM64
echo -e "${GREEN}Building for iOS Simulator ARM64...${NC}"
zig build ffi -Dtarget=aarch64-ios-simulator -Drelease=true
mkdir -p "$OUTPUT_DIR/ios-arm64-simulator/lib"
mkdir -p "$OUTPUT_DIR/ios-arm64-simulator/Headers"
cp "$PROJECT_ROOT/zig-out/lib/libsoftether_ffi.a" "$OUTPUT_DIR/ios-arm64-simulator/lib/"
cp "$PROJECT_ROOT/include/ffi.h" "$OUTPUT_DIR/ios-arm64-simulator/Headers/"

# Build for iOS Simulator x86_64 (for Intel Macs)
echo -e "${GREEN}Building for iOS Simulator x86_64...${NC}"
zig build ffi -Dtarget=x86_64-ios-simulator -Drelease=true
mkdir -p "$OUTPUT_DIR/ios-x86_64-simulator/lib"
mkdir -p "$OUTPUT_DIR/ios-x86_64-simulator/Headers"
cp "$PROJECT_ROOT/zig-out/lib/libsoftether_ffi.a" "$OUTPUT_DIR/ios-x86_64-simulator/lib/"
cp "$PROJECT_ROOT/include/ffi.h" "$OUTPUT_DIR/ios-x86_64-simulator/Headers/"

# Create universal simulator binary
echo -e "${GREEN}Creating universal simulator binary...${NC}"
mkdir -p "$OUTPUT_DIR/ios-simulator-universal/lib"
mkdir -p "$OUTPUT_DIR/ios-simulator-universal/Headers"
lipo -create \
    "$OUTPUT_DIR/ios-arm64-simulator/lib/libsoftether_ffi.a" \
    "$OUTPUT_DIR/ios-x86_64-simulator/lib/libsoftether_ffi.a" \
    -output "$OUTPUT_DIR/ios-simulator-universal/lib/libsoftether_ffi.a"
cp "$PROJECT_ROOT/include/ffi.h" "$OUTPUT_DIR/ios-simulator-universal/Headers/"

# Create framework structure for device
echo -e "${GREEN}Creating framework for iOS device...${NC}"
DEVICE_FRAMEWORK="$OUTPUT_DIR/device/SoftEtherVPN.framework"
mkdir -p "$DEVICE_FRAMEWORK/Headers"
mkdir -p "$DEVICE_FRAMEWORK/Modules"
cp "$OUTPUT_DIR/ios-arm64/lib/libsoftether_ffi.a" "$DEVICE_FRAMEWORK/SoftEtherVPN"
cp "$OUTPUT_DIR/ios-arm64/Headers/ffi.h" "$DEVICE_FRAMEWORK/Headers/"

# Create module map for device framework
cat > "$DEVICE_FRAMEWORK/Modules/module.modulemap" << EOF
framework module SoftEtherVPN {
    umbrella header "ffi.h"
    export *
    module * { export * }
}
EOF

# Create Info.plist for device framework
cat > "$DEVICE_FRAMEWORK/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>SoftEtherVPN</string>
    <key>CFBundleIdentifier</key>
    <string>com.softether.zig.vpn</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>SoftEtherVPN</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>MinimumOSVersion</key>
    <string>15.0</string>
</dict>
</plist>
EOF

# Create framework structure for simulator
echo -e "${GREEN}Creating framework for iOS simulator...${NC}"
SIMULATOR_FRAMEWORK="$OUTPUT_DIR/simulator/SoftEtherVPN.framework"
mkdir -p "$SIMULATOR_FRAMEWORK/Headers"
mkdir -p "$SIMULATOR_FRAMEWORK/Modules"
cp "$OUTPUT_DIR/ios-simulator-universal/lib/libsoftether_ffi.a" "$SIMULATOR_FRAMEWORK/SoftEtherVPN"
cp "$OUTPUT_DIR/ios-simulator-universal/Headers/ffi.h" "$SIMULATOR_FRAMEWORK/Headers/"

# Create module map for simulator framework
cat > "$SIMULATOR_FRAMEWORK/Modules/module.modulemap" << EOF
framework module SoftEtherVPN {
    umbrella header "ffi.h"
    export *
    module * { export * }
}
EOF

# Create Info.plist for simulator framework
cp "$DEVICE_FRAMEWORK/Info.plist" "$SIMULATOR_FRAMEWORK/Info.plist"

# Create XCFramework
echo -e "${GREEN}Creating XCFramework...${NC}"
rm -rf "$OUTPUT_DIR/SoftEtherVPN.xcframework"
xcodebuild -create-xcframework \
    -framework "$DEVICE_FRAMEWORK" \
    -framework "$SIMULATOR_FRAMEWORK" \
    -output "$OUTPUT_DIR/SoftEtherVPN.xcframework"

echo -e "${GREEN}✓ XCFramework created successfully at:${NC}"
echo -e "  $OUTPUT_DIR/SoftEtherVPN.xcframework"

# Copy to WorxVPN if requested
if [ $COPY_TO_WORXVPN -eq 1 ]; then
    if [ -d "$WORXVPN_FRAMEWORK_DIR" ]; then
        echo -e "${GREEN}Copying XCFramework to WorxVPN-iOS...${NC}"
        rm -rf "$WORXVPN_FRAMEWORK_DIR/SoftEtherVPN.xcframework"
        cp -R "$OUTPUT_DIR/SoftEtherVPN.xcframework" "$WORXVPN_FRAMEWORK_DIR/"
        echo -e "${GREEN}✓ Copied to: $WORXVPN_FRAMEWORK_DIR${NC}"
    else
        echo -e "${YELLOW}⚠ WorxVPN framework directory not found: $WORXVPN_FRAMEWORK_DIR${NC}"
    fi
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Build complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "To use in WorxVPN-iOS:"
echo -e "  1. The XCFramework has been copied to ZigFramework/"
echo -e "  2. Regenerate Xcode project: ${YELLOW}cd ../WorxVPN-iOS && xcodegen${NC}"
echo -e "  3. Open and build: ${YELLOW}open WorxVPN.xcodeproj${NC}"
