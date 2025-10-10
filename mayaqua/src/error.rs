//! Error handling for SoftEther VPN Rust implementation
//!
//! Unified error types that map to SoftEther error codes from the C implementation.

use std::fmt;
use std::io;

/// Main error type for SoftEther operations
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    // Core errors (matching C implementation error codes)
    NoError,              // ERR_NO_ERROR = 0
    InternalError,        // ERR_INTERNAL_ERROR = 1
    ObjectNotFound,       // ERR_OBJECT_NOT_FOUND = 2
    InvalidParameter,     // ERR_INVALID_PARAMETER = 3
    TimeOut,              // ERR_TIME_OUT = 4
    NoMemory,             // ERR_NO_MEMORY = 5
    DisconnectedError,    // ERR_DISCONNECTED = 6
    AuthTypeNotSupported, // ERR_AUTHTYPE_NOT_SUPPORTED = 7

    // Pack system errors
    SizeOver,        // Pack/value size exceeds limits
    InvalidPack,     // Corrupted pack data
    ElementNotFound, // Element not found in pack
    ValueTypeError,  // Wrong value type accessed

    // Network errors
    ConnectFailed, // Network connection failed
    SocketError,   // Generic socket error
    TlsError,      // TLS/SSL error

    // Protocol errors
    ProtocolError,        // Protocol violation
    InvalidSignature,     // Invalid protocol signature
    AuthenticationFailed, // Authentication failed
    InvalidResponse,      // Invalid response received
    UnexpectedPacketType, // Unexpected packet type
    InvalidPacketFormat,  // Invalid packet format
    PacketTooLarge,       // Packet size exceeds maximum
    InvalidPacketSize,    // Invalid packet size (too small or too large)
    BufferTooSmall,       // Buffer too small for operation
    EncodingError,        // String encoding error

    // Crypto errors
    CryptoError,        // Cryptographic operation failed
    InvalidCertificate, // Certificate validation failed

    // I/O errors
    IoError(String), // I/O operation failed
    InvalidString,   // String encoding error

    // Configuration errors
    ConfigError(String), // Configuration validation/parsing error

    // State errors
    InvalidState,     // Invalid state for operation
    NotConnected,     // Not connected
    NotImplemented,   // Feature not implemented
    NotSupported,     // Operation not supported
    TooManyConnections, // Too many connections

    // Platform-specific errors
    /// Pack-related errors
    Pack(String),

    /// Network communication errors
    Network(String),

    /// HTTP protocol errors  
    Http(String),

    // Platform-specific errors
    PlatformError(String), // Platform-specific error
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoError => write!(f, "No error"),
            Error::InternalError => write!(f, "Internal error"),
            Error::ObjectNotFound => write!(f, "Object not found"),
            Error::InvalidParameter => write!(f, "Invalid parameter"),
            Error::TimeOut => write!(f, "Operation timed out"),
            Error::NoMemory => write!(f, "Out of memory"),
            Error::DisconnectedError => write!(f, "Connection disconnected"),
            Error::AuthTypeNotSupported => write!(f, "Authentication type not supported"),
            Error::SizeOver => write!(f, "Size exceeds maximum limit"),
            Error::InvalidPack => write!(f, "Invalid pack data"),
            Error::ElementNotFound => write!(f, "Element not found"),
            Error::ValueTypeError => write!(f, "Value type mismatch"),
            Error::ConnectFailed => write!(f, "Connection failed"),
            Error::SocketError => write!(f, "Socket error"),
            Error::TlsError => write!(f, "TLS error"),
            Error::ProtocolError => write!(f, "Protocol error"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::AuthenticationFailed => write!(f, "Authentication failed"),
            Error::InvalidResponse => write!(f, "Invalid response"),
            Error::UnexpectedPacketType => write!(f, "Unexpected packet type"),
            Error::InvalidPacketFormat => write!(f, "Invalid packet format"),
            Error::PacketTooLarge => write!(f, "Packet too large"),
            Error::InvalidPacketSize => write!(f, "Invalid packet size"),
            Error::BufferTooSmall => write!(f, "Buffer too small"),
            Error::EncodingError => write!(f, "Encoding error"),
            Error::CryptoError => write!(f, "Cryptographic error"),
            Error::InvalidCertificate => write!(f, "Invalid certificate"),
            Error::IoError(msg) => write!(f, "I/O error: {msg}"),
            Error::InvalidString => write!(f, "Invalid string encoding"),
            Error::ConfigError(msg) => write!(f, "Configuration error: {msg}"),
            Error::InvalidState => write!(f, "Invalid state"),
            Error::NotConnected => write!(f, "Not connected"),
            Error::NotImplemented => write!(f, "Not implemented"),
            Error::NotSupported => write!(f, "Not supported"),
            Error::TooManyConnections => write!(f, "Too many connections"),
            Error::Pack(msg) => write!(f, "Pack error: {msg}"),
            Error::Network(msg) => write!(f, "Network error: {msg}"),
            Error::Http(msg) => write!(f, "HTTP error: {msg}"),
            Error::PlatformError(msg) => write!(f, "Platform error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IoError(err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(_: std::string::FromUtf8Error) -> Self {
        Error::InvalidString
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_: std::str::Utf8Error) -> Self {
        Error::InvalidString
    }
}

/// Result type alias for SoftEther operations
pub type Result<T> = std::result::Result<T, Error>;

// Error code constants matching C implementation
impl Error {
    /// Convert to numeric error code (compatible with C implementation)
    pub fn to_code(&self) -> u32 {
        match self {
            Error::NoError => 0,
            Error::InternalError => 1,
            Error::ObjectNotFound => 2,
            Error::InvalidParameter => 3,
            Error::TimeOut => 4,
            Error::NoMemory => 5,
            Error::DisconnectedError => 6,
            Error::AuthTypeNotSupported => 7,
            // Custom error codes for Rust-specific errors
            Error::SizeOver => 100,
            Error::InvalidPack => 101,
            Error::ElementNotFound => 102,
            Error::ValueTypeError => 103,
            Error::ConnectFailed => 200,
            Error::SocketError => 201,
            Error::TlsError => 202,
            Error::ProtocolError => 300,
            Error::InvalidSignature => 301,
            Error::AuthenticationFailed => 302,
            Error::InvalidResponse => 303,
            Error::UnexpectedPacketType => 304,
            Error::InvalidPacketFormat => 305,
            Error::PacketTooLarge => 306,
            Error::InvalidPacketSize => 307,
            Error::BufferTooSmall => 308,
            Error::EncodingError => 309,
            Error::CryptoError => 400,
            Error::InvalidCertificate => 401,
            Error::IoError(_) => 500,
            Error::InvalidString => 501,
            Error::ConfigError(_) => 502,
            Error::InvalidState => 503,
            Error::NotConnected => 504,
            Error::NotImplemented => 505,
            Error::NotSupported => 506,
            Error::TooManyConnections => 507,
            Error::Pack(_) => 508,
            Error::Network(_) => 509,
            Error::Http(_) => 510,
            Error::PlatformError(_) => 600,
        }
    }

    /// Create error from numeric code
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => Error::NoError,
            1 => Error::InternalError,
            2 => Error::ObjectNotFound,
            3 => Error::InvalidParameter,
            4 => Error::TimeOut,
            5 => Error::NoMemory,
            6 => Error::DisconnectedError,
            7 => Error::AuthTypeNotSupported,
            _ => Error::InternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(Error::NoError.to_code(), 0);
        assert_eq!(Error::InternalError.to_code(), 1);
        assert_eq!(Error::InvalidParameter.to_code(), 3);
    }

    #[test]
    fn test_error_from_code() {
        assert_eq!(Error::from_code(0), Error::NoError);
        assert_eq!(Error::from_code(1), Error::InternalError);
        assert_eq!(Error::from_code(999), Error::InternalError); // Unknown codes -> InternalError
    }

    #[test]
    fn test_error_display() {
        let err = Error::InvalidParameter;
        assert!(err.to_string().contains("Invalid parameter"));
    }
}
