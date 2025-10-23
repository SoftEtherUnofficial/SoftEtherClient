# Android Native Build Configuration
# Builds SoftEther VPN Android native library with TapTun integration

cmake_minimum_required(VERSION 3.18)
project(SoftEtherAndroid)

# Find Android NDK
if(NOT ANDROID_NDK)
    message(FATAL_ERROR "ANDROID_NDK environment variable must be set")
endif()

# Zig compiler path
if(NOT ZIG_COMPILER)
    set(ZIG_COMPILER "zig")
endif()

# Android ABI targets
if(NOT ANDROID_ABI)
    set(ANDROID_ABI "arm64-v8a")  # Default to ARM64
endif()

# Map Android ABI to Zig targets
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(ZIG_TARGET "aarch64-linux-android")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(ZIG_TARGET "armv7a-linux-androideabi")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(ZIG_TARGET "x86_64-linux-android")
elseif(ANDROID_ABI STREQUAL "x86")
    set(ZIG_TARGET "i686-linux-android")
else()
    message(FATAL_ERROR "Unsupported Android ABI: ${ANDROID_ABI}")
endif()

message(STATUS "Building for Android ABI: ${ANDROID_ABI}")
message(STATUS "Zig target: ${ZIG_TARGET}")

# Source directories
set(SOFTETHER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../..")
set(FFI_SRC "${SOFTETHER_ROOT}/src/ffi")
set(TAPTUN_SRC "${SOFTETHER_ROOT}/deps/taptun/src")
set(ANDROID_JNI "${SOFTETHER_ROOT}/src/platforms/android/jni")

# Output directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/libs/${ANDROID_ABI}")

# ============================================================================
# Build Zig FFI Library with TapTun
# ============================================================================

# Custom command to build Zig FFI with TapTun dependency
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/libsoftether_ffi.a
    COMMAND ${ZIG_COMPILER} build-lib
        -target ${ZIG_TARGET}
        -static
        -O ReleaseFast
        --name softether_ffi
        -I ${SOFTETHER_ROOT}/include
        -I ${SOFTETHER_ROOT}/src
        --dep taptun
        -Mroot=${FFI_SRC}/ffi.zig
        -Mtaptun=${TAPTUN_SRC}/taptun.zig
        -femit-bin=${CMAKE_CURRENT_BINARY_DIR}/libsoftether_ffi.a
    DEPENDS
        ${FFI_SRC}/ffi.zig
        ${TAPTUN_SRC}/taptun.zig
        ${SOFTETHER_ROOT}/src/platforms/android/adapter/android_tun_adapter.zig
    COMMENT "Building Zig FFI with TapTun for ${ANDROID_ABI}"
    VERBATIM
)

# Create imported library target
add_custom_target(zigffi ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/libsoftether_ffi.a)

# ============================================================================
# JNI Wrapper Library
# ============================================================================

add_library(softethervpn SHARED
    ${ANDROID_JNI}/softether_jni.c
)

# Link with Zig FFI library
target_link_libraries(softethervpn
    ${CMAKE_CURRENT_BINARY_DIR}/libsoftether_ffi.a
    log  # Android logging
)

# Include directories
target_include_directories(softethervpn PRIVATE
    ${SOFTETHER_ROOT}/include
    ${ANDROID_NDK}/sources/android/native_app_glue
)

# Ensure Zig FFI is built first
add_dependencies(softethervpn zigffi)

# ============================================================================
# Build Options
# ============================================================================

# C compiler flags for Android
target_compile_options(softethervpn PRIVATE
    -Wall
    -Wextra
    -O2
    -fvisibility=hidden
)

# Strip debug symbols in release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(softethervpn PRIVATE
        -Wl,--strip-all
        -Wl,--gc-sections
    )
endif()

# ============================================================================
# Installation
# ============================================================================

install(TARGETS softethervpn
    LIBRARY DESTINATION libs/${ANDROID_ABI}
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsoftether_ffi.a
    DESTINATION libs/${ANDROID_ABI}
)

# ============================================================================
# Multi-ABI Build Support
# ============================================================================

# Helper script to build all ABIs
if(BUILD_ALL_ABIS)
    set(ALL_ABIS arm64-v8a armeabi-v7a x86_64 x86)
    
    foreach(ABI ${ALL_ABIS})
        add_custom_target(build_${ABI}
            COMMAND ${CMAKE_COMMAND}
                -DANDROID_ABI=${ABI}
                -DCMAKE_BUILD_TYPE=Release
                -B ${CMAKE_CURRENT_BINARY_DIR}/build_${ABI}
                ${CMAKE_CURRENT_SOURCE_DIR}
            COMMAND ${CMAKE_COMMAND}
                --build ${CMAKE_CURRENT_BINARY_DIR}/build_${ABI}
            COMMENT "Building for ${ABI}"
        )
    endforeach()
    
    add_custom_target(build_all_abis
        DEPENDS build_arm64-v8a build_armeabi-v7a build_x86_64 build_x86
    )
endif()

# ============================================================================
# Build Information
# ============================================================================

message(STATUS "===========================================")
message(STATUS "SoftEther VPN Android Native Build")
message(STATUS "===========================================")
message(STATUS "Android ABI: ${ANDROID_ABI}")
message(STATUS "Zig Target: ${ZIG_TARGET}")
message(STATUS "Zig Compiler: ${ZIG_COMPILER}")
message(STATUS "Android NDK: ${ANDROID_NDK}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output Dir: ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
message(STATUS "TapTun Integration: ENABLED")
message(STATUS "===========================================")
