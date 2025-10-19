//! Error handling for SoftEther VPN - Zig implementation
//!
//! Unified error types that map to SoftEther error codes from the C implementation.
//! Uses Zig's error set system for compile-time error checking.
//!
//! Ported from: SoftEtherRust/libs/mayaqua/src/error.rs

const std = @import("std");

/// Main error set for SoftEther operations
///
/// These errors map to C implementation error codes and provide
/// type-safe error handling throughout the codebase.
pub const SoftEtherError = error{
    // ============================================
    // Core errors (matching C implementation)
    // ============================================

    /// No error occurred (success case - not actually used as error)
    NoError, // ERR_NO_ERROR = 0

    /// Internal error occurred
    InternalError, // ERR_INTERNAL_ERROR = 1

    /// Object or resource not found
    ObjectNotFound, // ERR_OBJECT_NOT_FOUND = 2

    /// Invalid parameter passed to function
    InvalidParameter, // ERR_INVALID_PARAMETER = 3

    /// Operation timed out
    TimeOut, // ERR_TIME_OUT = 4

    /// Out of memory
    NoMemory, // ERR_NO_MEMORY = 5

    /// Connection was disconnected
    DisconnectedError, // ERR_DISCONNECTED = 6

    /// Authentication type not supported
    AuthTypeNotSupported, // ERR_AUTHTYPE_NOT_SUPPORTED = 7

    // ============================================
    // Pack system errors (100-199)
    // ============================================

    /// Pack or value size exceeds limits
    SizeOver,

    /// Corrupted or invalid pack data
    InvalidPack,

    /// Element not found in pack
    ElementNotFound,

    /// Wrong value type accessed
    ValueTypeError,

    /// Invalid UTF-8 string
    InvalidUtf8,

    // ============================================
    // Network errors (200-299)
    // ============================================

    /// Network connection failed
    ConnectFailed,

    /// Generic socket error
    SocketError,

    /// TLS/SSL error
    TlsError,

    /// DNS resolution failed
    HostNotFound,

    /// Network unreachable
    NetworkUnreachable,

    /// Connection refused by remote host
    ConnectionRefused,

    /// Connection reset by peer
    ConnectionReset,

    // ============================================
    // Protocol errors (300-399)
    // ============================================

    /// Protocol violation
    ProtocolError,

    /// Invalid protocol signature
    InvalidSignature,

    /// Authentication failed
    AuthenticationFailed,

    /// Invalid session key
    InvalidSessionKey,

    /// Protocol version mismatch
    VersionMismatch,

    /// Handshake failed
    HandshakeFailed,

    // ============================================
    // Crypto errors (400-499)
    // ============================================

    /// Cryptographic operation failed
    CryptoError,

    /// Certificate validation failed
    InvalidCertificate,

    /// Key generation failed
    KeyGenerationFailed,

    /// Signature verification failed
    SignatureVerificationFailed,

    /// Encryption failed
    EncryptionFailed,

    /// Decryption failed
    DecryptionFailed,

    // ============================================
    // I/O errors (500-599)
    // ============================================

    /// I/O operation failed
    IoError,

    /// End of stream reached unexpectedly
    EndOfStream,

    /// Buffer overflow
    BufferOverflow,

    /// File not found
    FileNotFound,

    /// Permission denied
    PermissionDenied,

    /// Resource busy
    ResourceBusy,

    // ============================================
    // Platform errors (600-699)
    // ============================================

    /// Platform-specific error
    PlatformError,

    /// Not implemented on this platform
    NotImplemented,

    /// Feature not supported
    NotSupported,
};

/// Error code mapping for C interop
pub const ErrorCode = enum(u32) {
    // Core errors (0-99)
    no_error = 0,
    internal_error = 1,
    object_not_found = 2,
    invalid_parameter = 3,
    time_out = 4,
    no_memory = 5,
    disconnected = 6,
    auth_type_not_supported = 7,

    // Pack errors (100-199)
    size_over = 100,
    invalid_pack = 101,
    element_not_found = 102,
    value_type_error = 103,
    invalid_utf8 = 104,

    // Network errors (200-299)
    connect_failed = 200,
    socket_error = 201,
    tls_error = 202,
    host_not_found = 203,
    network_unreachable = 204,
    connection_refused = 205,
    connection_reset = 206,

    // Protocol errors (300-399)
    protocol_error = 300,
    invalid_signature = 301,
    authentication_failed = 302,
    invalid_session_key = 303,
    version_mismatch = 304,
    handshake_failed = 305,

    // Crypto errors (400-499)
    crypto_error = 400,
    invalid_certificate = 401,
    key_generation_failed = 402,
    signature_verification_failed = 403,
    encryption_failed = 404,
    decryption_failed = 405,

    // I/O errors (500-599)
    io_error = 500,
    end_of_stream = 501,
    buffer_overflow = 502,
    file_not_found = 503,
    permission_denied = 504,
    resource_busy = 505,

    // Platform errors (600-699)
    platform_error = 600,
    not_implemented = 601,
    not_supported = 602,

    // Unknown error
    unknown = 999,
};

/// Convert error to numeric error code (for C interop)
pub fn errorToCode(err: anyerror) ErrorCode {
    // Use error name comparison instead of errorToInt
    const err_name = @errorName(err);

    // Core errors
    if (std.mem.eql(u8, err_name, "NoError")) return .no_error;
    if (std.mem.eql(u8, err_name, "InternalError")) return .internal_error;
    if (std.mem.eql(u8, err_name, "ObjectNotFound")) return .object_not_found;
    if (std.mem.eql(u8, err_name, "InvalidParameter")) return .invalid_parameter;
    if (std.mem.eql(u8, err_name, "TimeOut")) return .time_out;
    if (std.mem.eql(u8, err_name, "NoMemory")) return .no_memory;
    if (std.mem.eql(u8, err_name, "DisconnectedError")) return .disconnected;
    if (std.mem.eql(u8, err_name, "AuthTypeNotSupported")) return .auth_type_not_supported;

    // Pack errors
    if (std.mem.eql(u8, err_name, "SizeOver")) return .size_over;
    if (std.mem.eql(u8, err_name, "InvalidPack")) return .invalid_pack;
    if (std.mem.eql(u8, err_name, "ElementNotFound")) return .element_not_found;
    if (std.mem.eql(u8, err_name, "ValueTypeError")) return .value_type_error;
    if (std.mem.eql(u8, err_name, "InvalidUtf8")) return .invalid_utf8;

    // Network errors
    if (std.mem.eql(u8, err_name, "ConnectFailed")) return .connect_failed;
    if (std.mem.eql(u8, err_name, "SocketError")) return .socket_error;
    if (std.mem.eql(u8, err_name, "TlsError")) return .tls_error;
    if (std.mem.eql(u8, err_name, "HostNotFound")) return .host_not_found;
    if (std.mem.eql(u8, err_name, "NetworkUnreachable")) return .network_unreachable;
    if (std.mem.eql(u8, err_name, "ConnectionRefused")) return .connection_refused;
    if (std.mem.eql(u8, err_name, "ConnectionReset")) return .connection_reset;

    // Protocol errors
    if (std.mem.eql(u8, err_name, "ProtocolError")) return .protocol_error;
    if (std.mem.eql(u8, err_name, "InvalidSignature")) return .invalid_signature;
    if (std.mem.eql(u8, err_name, "AuthenticationFailed")) return .authentication_failed;
    if (std.mem.eql(u8, err_name, "InvalidSessionKey")) return .invalid_session_key;
    if (std.mem.eql(u8, err_name, "VersionMismatch")) return .version_mismatch;
    if (std.mem.eql(u8, err_name, "HandshakeFailed")) return .handshake_failed;

    // Crypto errors
    if (std.mem.eql(u8, err_name, "CryptoError")) return .crypto_error;
    if (std.mem.eql(u8, err_name, "InvalidCertificate")) return .invalid_certificate;
    if (std.mem.eql(u8, err_name, "KeyGenerationFailed")) return .key_generation_failed;
    if (std.mem.eql(u8, err_name, "SignatureVerificationFailed")) return .signature_verification_failed;
    if (std.mem.eql(u8, err_name, "EncryptionFailed")) return .encryption_failed;
    if (std.mem.eql(u8, err_name, "DecryptionFailed")) return .decryption_failed;

    // I/O errors
    if (std.mem.eql(u8, err_name, "IoError")) return .io_error;
    if (std.mem.eql(u8, err_name, "EndOfStream")) return .end_of_stream;
    if (std.mem.eql(u8, err_name, "BufferOverflow")) return .buffer_overflow;
    if (std.mem.eql(u8, err_name, "FileNotFound")) return .file_not_found;
    if (std.mem.eql(u8, err_name, "PermissionDenied")) return .permission_denied;
    if (std.mem.eql(u8, err_name, "ResourceBusy")) return .resource_busy;

    // Platform errors
    if (std.mem.eql(u8, err_name, "PlatformError")) return .platform_error;
    if (std.mem.eql(u8, err_name, "NotImplemented")) return .not_implemented;
    if (std.mem.eql(u8, err_name, "NotSupported")) return .not_supported;

    // Check for stdlib errors
    if (std.mem.eql(u8, err_name, "OutOfMemory")) return .no_memory;
    if (std.mem.eql(u8, err_name, "Timeout")) return .time_out;
    if (std.mem.eql(u8, err_name, "BrokenPipe")) return .connection_reset;
    if (std.mem.eql(u8, err_name, "ConnectionResetByPeer")) return .connection_reset;
    if (std.mem.eql(u8, err_name, "AccessDenied")) return .permission_denied;

    return .unknown;
}

/// Get human-readable error message
pub fn errorToString(err: anyerror) []const u8 {
    return switch (errorToCode(err)) {
        .no_error => "No error",
        .internal_error => "Internal error",
        .object_not_found => "Object not found",
        .invalid_parameter => "Invalid parameter",
        .time_out => "Operation timed out",
        .no_memory => "Out of memory",
        .disconnected => "Connection disconnected",
        .auth_type_not_supported => "Authentication type not supported",
        .size_over => "Size exceeds maximum limit",
        .invalid_pack => "Invalid pack data",
        .element_not_found => "Element not found",
        .value_type_error => "Value type mismatch",
        .invalid_utf8 => "Invalid UTF-8 encoding",
        .connect_failed => "Connection failed",
        .socket_error => "Socket error",
        .tls_error => "TLS/SSL error",
        .host_not_found => "Host not found",
        .network_unreachable => "Network unreachable",
        .connection_refused => "Connection refused",
        .connection_reset => "Connection reset by peer",
        .protocol_error => "Protocol error",
        .invalid_signature => "Invalid signature",
        .authentication_failed => "Authentication failed",
        .invalid_session_key => "Invalid session key",
        .version_mismatch => "Protocol version mismatch",
        .handshake_failed => "Handshake failed",
        .crypto_error => "Cryptographic error",
        .invalid_certificate => "Invalid certificate",
        .key_generation_failed => "Key generation failed",
        .signature_verification_failed => "Signature verification failed",
        .encryption_failed => "Encryption failed",
        .decryption_failed => "Decryption failed",
        .io_error => "I/O error",
        .end_of_stream => "End of stream",
        .buffer_overflow => "Buffer overflow",
        .file_not_found => "File not found",
        .permission_denied => "Permission denied",
        .resource_busy => "Resource busy",
        .platform_error => "Platform error",
        .not_implemented => "Not implemented",
        .not_supported => "Not supported",
        .unknown => "Unknown error",
    };
}

/// Format error with additional context
pub fn formatError(allocator: std.mem.Allocator, err: anyerror, context: []const u8) ![]u8 {
    const error_msg = errorToString(err);
    return std.fmt.allocPrint(allocator, "{s}: {s}", .{ context, error_msg });
}

// ============================================
// Tests
// ============================================

test "errorToCode basic mapping" {
    try std.testing.expectEqual(ErrorCode.invalid_parameter, errorToCode(error.InvalidParameter));
    try std.testing.expectEqual(ErrorCode.time_out, errorToCode(error.TimeOut));
    try std.testing.expectEqual(ErrorCode.no_memory, errorToCode(error.NoMemory));
}

test "errorToCode pack errors" {
    try std.testing.expectEqual(ErrorCode.size_over, errorToCode(error.SizeOver));
    try std.testing.expectEqual(ErrorCode.invalid_pack, errorToCode(error.InvalidPack));
}

test "errorToCode network errors" {
    try std.testing.expectEqual(ErrorCode.connect_failed, errorToCode(error.ConnectFailed));
    try std.testing.expectEqual(ErrorCode.tls_error, errorToCode(error.TlsError));
}

test "errorToCode protocol errors" {
    try std.testing.expectEqual(ErrorCode.protocol_error, errorToCode(error.ProtocolError));
    try std.testing.expectEqual(ErrorCode.authentication_failed, errorToCode(error.AuthenticationFailed));
}

test "errorToString messages" {
    try std.testing.expectEqualStrings("Invalid parameter", errorToString(error.InvalidParameter));
    try std.testing.expectEqualStrings("Operation timed out", errorToString(error.TimeOut));
    try std.testing.expectEqualStrings("Connection failed", errorToString(error.ConnectFailed));
}

test "formatError with context" {
    const allocator = std.testing.allocator;

    const formatted = try formatError(allocator, error.ConnectFailed, "VPN server connection");
    defer allocator.free(formatted);

    try std.testing.expect(std.mem.indexOf(u8, formatted, "VPN server connection") != null);
    try std.testing.expect(std.mem.indexOf(u8, formatted, "Connection failed") != null);
}

test "stdlib error mapping" {
    // Zig stdlib errors should map to SoftEther equivalents
    try std.testing.expectEqual(ErrorCode.no_memory, errorToCode(error.OutOfMemory));
    try std.testing.expectEqual(ErrorCode.time_out, errorToCode(error.Timeout));
    try std.testing.expectEqual(ErrorCode.connection_reset, errorToCode(error.ConnectionResetByPeer));
}
