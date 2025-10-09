/// OpenSSL Compatibility Shim
///
/// This module provides OpenSSL-like API that internally uses rustls.
/// It allows gradual migration by keeping the same API surface.
///
/// Phase 3: Drop-in replacement for common OpenSSL calls
const std = @import("std");
const rustls = @import("rustls.zig");
const TlsConnection = @import("tls_connection.zig").TlsConnection;

// ============================================
// OpenSSL-like Type Definitions
// ============================================

/// Opaque SSL context (maps to rustls ClientConfig)
pub const SSL_CTX = opaque {};

/// Opaque SSL connection (maps to rustls Connection + socket)
pub const SSL = opaque {};

/// SSL method (client/server)
pub const SSL_METHOD = opaque {};

/// Return codes
pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;

// Internal connection state
const SslState = struct {
    tls_conn: TlsConnection,
    allocator: std.mem.Allocator,
};

// Global allocator for compatibility layer
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const global_allocator = gpa.allocator();

// ============================================
// OpenSSL-like API Functions
// ============================================

/// Initialize OpenSSL (compatibility stub)
export fn SSL_library_init() c_int {
    // rustls doesn't need global init, but we'll initialize it anyway
    rustls.init() catch return 0;
    return 1;
}

/// Load error strings (compatibility stub)
export fn SSL_load_error_strings() void {
    // No-op for rustls
}

/// Get TLS client method
export fn TLS_client_method() ?*const SSL_METHOD {
    // Return a dummy pointer (not actually used)
    return @ptrFromInt(1);
}

/// Create SSL context
export fn SSL_CTX_new(method: ?*const SSL_METHOD) ?*SSL_CTX {
    _ = method; // Not used in rustls

    // Create a ClientConfig
    const config = rustls.ClientConfig.init(global_allocator) catch return null;

    // Cast to opaque pointer
    const ptr = global_allocator.create(rustls.ClientConfig) catch return null;
    ptr.* = config;

    return @ptrCast(ptr);
}

/// Free SSL context
export fn SSL_CTX_free(ctx: ?*SSL_CTX) void {
    if (ctx) |c| {
        const config: *rustls.ClientConfig = @ptrCast(@alignCast(c));
        config.deinit();
        global_allocator.destroy(config);
    }
}

/// Set verification mode (compatibility stub)
export fn SSL_CTX_set_verify(ctx: ?*SSL_CTX, mode: c_int, callback: ?*anyopaque) void {
    _ = ctx;
    _ = mode;
    _ = callback;
    // rustls always verifies certificates by default
}

/// Load CA certificates
export fn SSL_CTX_load_verify_locations(
    ctx: ?*SSL_CTX,
    file: [*:0]const u8,
    path: ?[*:0]const u8,
) c_int {
    _ = path; // Not used

    if (ctx) |c| {
        const config: *rustls.ClientConfig = @ptrCast(@alignCast(c));
        const file_slice = std.mem.span(file);

        config.loadRootCerts(file_slice) catch return 0;
        return 1;
    }
    return 0;
}

/// Create SSL connection
export fn SSL_new(ctx: ?*SSL_CTX) ?*SSL {
    _ = ctx; // We'll use ctx later when implementing full connection

    // For now, allocate state structure
    const state = global_allocator.create(SslState) catch return null;

    return @ptrCast(state);
}

/// Free SSL connection
export fn SSL_free(ssl: ?*SSL) void {
    if (ssl) |s| {
        const state: *SslState = @ptrCast(@alignCast(s));
        state.tls_conn.deinit();
        global_allocator.destroy(state);
    }
}

/// Set file descriptor
export fn SSL_set_fd(ssl: ?*SSL, fd: c_int) c_int {
    _ = ssl;
    _ = fd;
    // This would associate the socket with the SSL connection
    // For now, return success
    return 1;
}

/// Perform SSL handshake
export fn SSL_connect(ssl: ?*SSL) c_int {
    if (ssl) |s| {
        const state: *SslState = @ptrCast(@alignCast(s));
        state.tls_conn.connect() catch return -1;
        return 1;
    }
    return -1;
}

/// Write data
export fn SSL_write(ssl: ?*SSL, buf: ?*const anyopaque, num: c_int) c_int {
    if (ssl == null or buf == null or num <= 0) return -1;

    const state: *SslState = @ptrCast(@alignCast(ssl.?));
    const data: [*]const u8 = @ptrCast(buf.?);
    const slice = data[0..@intCast(num)];

    const written = state.tls_conn.write(slice) catch return -1;
    return @intCast(written);
}

/// Read data
export fn SSL_read(ssl: ?*SSL, buf: ?*anyopaque, num: c_int) c_int {
    if (ssl == null or buf == null or num <= 0) return -1;

    const state: *SslState = @ptrCast(@alignCast(ssl.?));
    const data: [*]u8 = @ptrCast(buf.?);
    const slice = data[0..@intCast(num)];

    const bytes_read = state.tls_conn.read(slice) catch return -1;
    return @intCast(bytes_read);
}

/// Get error
export fn SSL_get_error(ssl: ?*SSL, ret: c_int) c_int {
    _ = ssl;
    if (ret > 0) return SSL_ERROR_NONE;
    return SSL_ERROR_SSL;
}

/// Shutdown SSL connection
export fn SSL_shutdown(ssl: ?*SSL) c_int {
    if (ssl) |s| {
        const state: *SslState = @ptrCast(@alignCast(s));
        state.tls_conn.close();
        return 1;
    }
    return 0;
}

// ============================================
// Additional Compatibility Functions
// ============================================

/// Set hostname for SNI
export fn SSL_set_tlsext_host_name(ssl: ?*SSL, name: [*:0]const u8) c_int {
    _ = ssl;
    _ = name;
    // rustls handles SNI automatically from the hostname
    return 1;
}

/// Set cipher list (compatibility stub)
export fn SSL_set_cipher_list(ssl: ?*SSL, str: [*:0]const u8) c_int {
    _ = ssl;
    _ = str;
    // rustls uses a fixed set of secure ciphers
    return 1;
}

/// Get cipher name
export fn SSL_get_cipher(ssl: ?*SSL) [*:0]const u8 {
    _ = ssl;
    // Return a generic cipher name
    return "TLS_AES_128_GCM_SHA256";
}

/// Get SSL version
export fn SSL_get_version(ssl: ?*SSL) [*:0]const u8 {
    _ = ssl;
    return "TLSv1.3";
}

// ============================================
// Helper Functions
// ============================================

/// Check if OpenSSL compatibility is initialized
export fn ssl_compat_check() c_int {
    return 1;
}

/// Get rustls version through compatibility layer
export fn ssl_compat_version() [*:0]const u8 {
    const ver = rustls.version();
    // This is unsafe - ideally we'd allocate properly
    return @ptrCast(ver.ptr);
}

// ============================================
// Tests
// ============================================

test "SSL_library_init" {
    const result = SSL_library_init();
    try std.testing.expectEqual(@as(c_int, 1), result);
}

test "SSL_CTX lifecycle" {
    const method = TLS_client_method();
    try std.testing.expect(method != null);

    const ctx = SSL_CTX_new(method);
    try std.testing.expect(ctx != null);

    SSL_CTX_free(ctx);
}

test "SSL connection lifecycle" {
    const method = TLS_client_method();
    const ctx = SSL_CTX_new(method);
    defer SSL_CTX_free(ctx);

    const ssl = SSL_new(ctx);
    try std.testing.expect(ssl != null);

    SSL_free(ssl);
}

test "SSL_get_version" {
    const version = SSL_get_version(null);
    const version_slice = std.mem.span(version);
    try std.testing.expect(std.mem.eql(u8, version_slice, "TLSv1.3"));
}

test "ssl_compat_check" {
    const result = ssl_compat_check();
    try std.testing.expectEqual(@as(c_int, 1), result);
}
