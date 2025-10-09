//! Mayaqua - Memory, Buffer, and Utility Library
//! 
//! This is a Rust port of SoftEther's Mayaqua kernel core utilities.
//! Provides memory-safe equivalents to Memory.c functions.

// Phase 1 modules (our implementation)
pub mod memory;
pub mod buffer;
pub mod types;

// Extracted modules from softether-rust (Tier 1)
pub mod error;     // Error types
pub mod sha0;      // SHA-0 for password hashing
pub mod pack;      // Pack/Element serialization system
pub mod time;      // Tick64 utilities

// FFI exports for C compatibility
pub mod ffi;

// Re-export Phase 1
pub use memory::*;
pub use buffer::*;
pub use types::*;

// Re-export Tier 1 
pub use error::{Error, Result};
pub use sha0::{Sha0Context, Sha1Sum, SHA1_SIZE};
pub use pack::{Pack, Element, Value, ValueType};
pub use time::{get_tick64, Tick64};

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
