//! Type definitions matching Mayaqua C types

use std::os::raw::c_uint;

/// Mayaqua UINT type (32-bit unsigned)
pub type UINT = c_uint;

/// Mayaqua UCHAR type
pub type UCHAR = u8;

/// Mayaqua USHORT type
pub type USHORT = u16;

/// Mayaqua UINT64 type
pub type UINT64 = u64;

/// Boolean type compatible with C
pub type BOOL = i32;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;
