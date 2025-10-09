//! Mayaqua Core - Memory and Buffer Management
//! 
//! This is a Rust port of SoftEther's Mayaqua kernel core utilities.
//! Provides memory-safe equivalents to Memory.c functions.

pub mod memory;
pub mod buffer;
pub mod types;

pub use memory::*;
pub use buffer::*;
pub use types::*;
