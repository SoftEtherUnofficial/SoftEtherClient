#!/bin/bash
# Build SoftEther VPN Android native library with TapTun integration

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../../../.."  # Go to SoftEtherZig root

echo "════════════════════════════════════════════════════════════════"
echo "📱 Building SoftEther VPN for Android with TapTun"
echo "════════════════════════════════════════════════════════════════"

# Check for Zig
if ! command -v zig &> /dev/null; then
    echo "❌ Zig compiler not found. Please install Zig 0.15.1 or later."
    exit 1
fi

ZIG_VERSION=$(zig version)
echo "✅ Found Zig: $ZIG_VERSION"

# Android ABI targets
ABIS=("arm64-v8a" "armeabi-v7a" "x86_64" "x86")
ZIG_TARGETS=("aarch64-linux-android" "armv7a-linux-androideabi" "x86_64-linux-android" "i686-linux-android")

# Output directory
OUTPUT_DIR="android_build"
mkdir -p "$OUTPUT_DIR"

echo ""
echo "🏗️  Building Android native libraries for ${#ABIS[@]} ABIs..."
echo ""

# Build for each ABI
for i in "${!ABIS[@]}"; do
    ABI="${ABIS[$i]}"
    ZIG_TARGET="${ZIG_TARGETS[$i]}"
    
    echo "────────────────────────────────────────────────────────────────"
    echo "📦 Building for $ABI ($ZIG_TARGET)"
    echo "────────────────────────────────────────────────────────────────"
    
    # Create output directory for this ABI
    ABI_DIR="$OUTPUT_DIR/jniLibs/$ABI"
    mkdir -p "$ABI_DIR"
    
    # Build Zig FFI library with TapTun
    echo "🔨 Compiling Zig FFI with TapTun..."
    zig build-lib \
        -target "$ZIG_TARGET" \
        -static \
        -O ReleaseFast \
        --name softether_ffi \
        -I include \
        -I src \
        --dep taptun \
        -Mroot=src/ffi/ffi.zig \
        -Mtaptun=deps/taptun/src/taptun.zig \
        -femit-bin="$ABI_DIR/libsoftether_ffi.a"
    
    if [ $? -eq 0 ]; then
        echo "✅ Built libsoftether_ffi.a for $ABI"
        
        # Show file size
        SIZE=$(du -h "$ABI_DIR/libsoftether_ffi.a" | cut -f1)
        echo "   Size: $SIZE"
    else
        echo "❌ Failed to build for $ABI"
        exit 1
    fi
    
    echo ""
done

echo "════════════════════════════════════════════════════════════════"
echo "✅ Android Native Build Complete!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📁 Output directory: $OUTPUT_DIR/jniLibs/"
echo ""
echo "Libraries built for:"
for ABI in "${ABIS[@]}"; do
    echo "  ✅ $ABI"
done
echo ""
echo "🔍 Directory structure:"
tree -L 3 "$OUTPUT_DIR" 2>/dev/null || ls -R "$OUTPUT_DIR"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "📱 Next Steps:"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "1. Copy libraries to Android Studio project:"
echo "   cp -r $OUTPUT_DIR/jniLibs/* <YourAndroidProject>/app/src/main/jniLibs/"
echo ""
echo "2. Or use CMake integration (recommended):"
echo "   - Add to app/build.gradle:"
echo "     android {"
echo "         externalNativeBuild {"
echo "             cmake {"
echo "                 path \"path/to/CMakeLists.txt\""
echo "             }"
echo "         }"
echo "     }"
echo ""
echo "3. Build Android app:"
echo "   cd <YourAndroidProject>"
echo "   ./gradlew assembleDebug"
echo ""
echo "4. Install and test on device/emulator"
echo ""
echo "════════════════════════════════════════════════════════════════"

# Optional: Create a verification script
cat > "$OUTPUT_DIR/verify_libs.sh" << 'EOF'
#!/bin/bash
echo "Verifying Android native libraries..."
echo ""

for ABI_DIR in jniLibs/*/; do
    ABI=$(basename "$ABI_DIR")
    LIB="$ABI_DIR/libsoftether_ffi.a"
    
    if [ -f "$LIB" ]; then
        echo "✅ $ABI:"
        echo "   File: $LIB"
        echo "   Size: $(du -h "$LIB" | cut -f1)"
        
        # Check if it's a valid archive
        if ar t "$LIB" > /dev/null 2>&1; then
            OBJ_COUNT=$(ar t "$LIB" | wc -l)
            echo "   Objects: $OBJ_COUNT"
        else
            echo "   ⚠️  Warning: Not a valid archive"
        fi
        echo ""
    else
        echo "❌ Missing: $ABI"
        echo ""
    fi
done
EOF

chmod +x "$OUTPUT_DIR/verify_libs.sh"
echo "💡 Run '$OUTPUT_DIR/verify_libs.sh' to verify libraries"
