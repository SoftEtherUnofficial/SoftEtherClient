//! Mayaqua - Memory, Buffer, and Utility Library
//!
//! This is a Rust port of SoftEther's Mayaqua kernel core utilities.
//! Provides memory-safe equivalents to Memory.c functions.

// Phase 1 modules (our implementation)
pub mod buffer;
pub mod memory;
pub mod types;

// Extracted modules from softether-rust (Tier 1)
pub mod error; // Error types
pub mod pack; // Pack/Element serialization system
pub mod sha0; // SHA-0 for password hashing
pub mod time; // Tick64 utilities

// Extracted modules from softether-rust (Tier 2A)
#[cfg(feature = "compress")]
pub mod compress; // Compression utilities (zlib/deflate)
pub mod http; // HTTP request/response handling
pub mod logging; // Logging abstraction

// Extracted modules from softether-rust (Phase 3.1)
pub mod config; // Configuration management (JSON-based, schema-validated)
pub mod crypto; // Cryptographic functions (SHA-0, RC4, password hashing)
pub mod fs; // Filesystem operations (atomic write, safe read, permissions)
pub mod platform; // Platform-specific utilities (directories, network interfaces)
pub mod strings; // String utilities (UTF-8/UTF-16, conversion, manipulation)
pub mod tables;  // Data structures (LIST, QUEUE, TABLE from SoftEther C)
pub mod network; // Network I/O (blocking TCP/UDP sockets, DNS resolution)

// Phase 4: Crypto and TLS
pub mod tls; // TLS support using native-tls (OpenSSL)

// FFI exports for C compatibility
pub mod ffi;

// Re-export Phase 1
pub use buffer::*;
pub use memory::*;
pub use types::*;

// Re-export Tier 1
pub use error::{Error, Result};
pub use pack::{Element, Pack, Value, ValueType};
pub use sha0::{Sha0Context, Sha1Sum, SHA1_SIZE};
pub use time::{get_tick64, Tick64};

// Re-export Tier 2A
#[cfg(feature = "compress")]
pub use compress::{compress_deflate, decompress_deflate};
pub use http::{HttpRequest, HttpResponse};
// logging module doesn't need re-exports (internal use)

// Re-export Phase 3.1 (Crypto)
// Re-export commonly used crypto functions
pub use crypto::{rc4_apply, rc4_apply_inplace, sha1, softether_password_hash};
// Note: SHA1_SIZE and Sha1Sum already re-exported from sha0 module

// Re-export Phase 3.1 (Filesystem)
pub use fs::{ensure_dir, read_all, set_user_rw_only, write_all_atomic};

// Re-export Phase 3.1 (Platform)
pub use platform::{get_config_directory, get_system_directory};

// Re-export Phase 3.1 (Config)
pub use config::{IpVersion, PerformanceConfig, VpnConfig};

// Re-export Phase 3.1 (Strings)
// Strings module re-exports
pub use strings::{
    utf8_to_utf16, utf16_to_utf8, bin_to_str, str_to_bin, mac_to_str, str_to_mac,
    is_printable_ascii, is_safe_str, make_safe_str, search_str, search_stri,
    replace_str, replace_stri, str_cmpi, starts_with_i, ends_with_i, tokenize,
    str_to_lines, trim_str, truncate_str,
};

// Tables module re-exports
pub use tables::{
    List, Queue, Table, IntList, Int64List, StrList,
    new_int_list, new_int64_list, new_str_list, new_str_map,
};

// Network module re-exports
pub use network::{
    TcpSocket, TcpSocketListener, UdpSocketWrapper,
    SOCK_TCP, SOCK_UDP, DEFAULT_TIMEOUT, DEFAULT_BUFFER_SIZE,
};


// Constants from Pack.h - Architecture-dependent sizes
#[cfg(target_pointer_width = "64")]
pub const MAX_VALUE_SIZE: usize = 384 * 1024 * 1024; // 384MB per VALUE on 64-bit

#[cfg(target_pointer_width = "32")]
pub const MAX_VALUE_SIZE: usize = 96 * 1024 * 1024; // 96MB per VALUE on 32-bit

#[cfg(target_pointer_width = "64")]
pub const MAX_PACK_SIZE: usize = 512 * 1024 * 1024; // 512MB PACK on 64-bit

#[cfg(target_pointer_width = "32")]
pub const MAX_PACK_SIZE: usize = 128 * 1024 * 1024; // 128MB PACK on 32-bit

pub const MAX_VALUE_NUM: u32 = 262144; // Max VALUEs per ELEMENT
pub const MAX_ELEMENT_NAME_LEN: u32 = 63; // Element name length
pub const MAX_ELEMENT_NUM: u32 = 262144; // Max ELEMENTs per PACK
