//! Mayaqua Zig Wrapper Library
//!
//! Ergonomic Zig bindings over the Mayaqua C FFI layer.
//! Provides safe abstractions with RAII, error unions, and idiomatic Zig APIs.
//!
//! ## Module Organization
//! - `crypto`: Cryptographic operations (SHA0/1, RC4, password hashing)
//! - `fs`: Filesystem operations (read/write, directory management)
//! - `strings`: String utilities (UTF-8/16, binary/hex conversion, MAC addresses)
//! - `network`: TCP/UDP socket operations
//! - `tables`: Data structures (List, Queue, Table)
//! - `platform`: Platform-specific utilities (directories, interfaces)
//! - `config`: VPN configuration management
//!
//! ## Usage Example
//! ```zig
//! const mayaqua = @import("mayaqua.zig");
//!
//! // Crypto operations
//! var hash: [20]u8 = undefined;
//! try mayaqua.crypto.sha0("hello", &hash);
//!
//! // Filesystem operations
//! const data = try mayaqua.fs.readFile(allocator, "/path/to/file");
//! defer allocator.free(data);
//!
//! // Network operations
//! var socket = try mayaqua.network.TcpSocket.connect("example.com", 443);
//! defer socket.close();
//! ```

const std = @import("std");

/// C FFI bindings from mayaqua_ffi.h
pub const c = @cImport({
    @cInclude("mayaqua_ffi.h");
});

/// Common error set for all Mayaqua operations
pub const MayaquaError = error{
    NullPointer,
    EncodingError,
    OperationFailed,
    FieldIsNone,
    OutOfMemory,
    InvalidParameter,
};

/// Convert C return code to Zig error
pub fn checkResult(code: i32) MayaquaError!void {
    return switch (code) {
        0 => {},
        -1 => MayaquaError.NullPointer,
        -2 => MayaquaError.EncodingError,
        -3 => MayaquaError.OperationFailed,
        -4 => MayaquaError.FieldIsNone,
        else => MayaquaError.InvalidParameter,
    };
}

// Re-export submodules
pub const crypto = @import("mayaqua/crypto.zig");
pub const fs = @import("mayaqua/fs.zig");
pub const strings = @import("mayaqua/strings.zig");
pub const network = @import("mayaqua/network.zig");
pub const tables = @import("mayaqua/tables.zig");
pub const platform = @import("mayaqua/platform.zig");
pub const config = @import("mayaqua/config.zig");

test "mayaqua module imports" {
    const testing = std.testing;
    _ = testing;

    // Verify all submodules can be imported
    _ = crypto;
    _ = fs;
    _ = strings;
    _ = network;
    _ = tables;
    _ = platform;
    _ = config;
}
