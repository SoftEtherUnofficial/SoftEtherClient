//! Mayaqua FFI - C-compatible bindings
//! 
//! Drop-in replacement for Mayaqua C API with Rust implementation.

use mayaqua_core::{Buffer, UINT};
use std::os::raw::{c_void, c_uint};
use std::ptr;
use std::slice;

// ============================================================================
// Opaque Types (for FFI safety)
// ============================================================================

/// Opaque BUF handle (backed by Rust Buffer)
#[repr(C)]
pub struct MayaquaBuf {
    _private: [u8; 0],
}

// ============================================================================
// Memory Management Functions
// ============================================================================

/// Allocate memory (equivalent to Malloc)
/// 
/// # Safety
/// Returns null on allocation failure. Caller must free with mayaqua_free.
#[no_mangle]
pub unsafe extern "C" fn mayaqua_malloc(size: c_uint) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }
    mayaqua_core::malloc(size as usize) as *mut c_void
}

/// Allocate zero-initialized memory (equivalent to ZeroMalloc)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_zero_malloc(size: c_uint) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }
    mayaqua_core::zero_malloc(size as usize) as *mut c_void
}

/// Free memory (equivalent to Free)
/// 
/// # Safety
/// Pointer must have been allocated by mayaqua_malloc or mayaqua_zero_malloc.
/// Size must match original allocation size.
#[no_mangle]
pub unsafe extern "C" fn mayaqua_free(ptr: *mut c_void, size: c_uint) {
    if !ptr.is_null() && size > 0 {
        mayaqua_core::free(ptr as *mut u8, size as usize);
    }
}

/// Zero memory (equivalent to Zero/ZeroMem)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_zero(addr: *mut c_void, size: c_uint) {
    mayaqua_core::zero_mem(addr as *mut u8, size as usize);
}

/// Copy memory (equivalent to Copy)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_copy(
    dst: *mut c_void,
    src: *const c_void,
    size: c_uint,
) {
    mayaqua_core::copy_mem(dst as *mut u8, src as *const u8, size as usize);
}

// ============================================================================
// Buffer Management Functions
// ============================================================================

/// Create new buffer (equivalent to NewBuf)
#[no_mangle]
pub extern "C" fn mayaqua_buf_new() -> *mut MayaquaBuf {
    let buf = Box::new(Buffer::new());
    Box::into_raw(buf) as *mut MayaquaBuf
}

/// Create buffer with capacity
#[no_mangle]
pub extern "C" fn mayaqua_buf_new_with_capacity(capacity: c_uint) -> *mut MayaquaBuf {
    let buf = Box::new(Buffer::with_capacity(capacity as usize));
    Box::into_raw(buf) as *mut MayaquaBuf
}

/// Create buffer from memory (equivalent to NewBufFromMemory)
/// 
/// # Safety
/// `data` must be valid for `size` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_from_memory(
    data: *const c_void,
    size: c_uint,
) -> *mut MayaquaBuf {
    if data.is_null() || size == 0 {
        return mayaqua_buf_new();
    }
    
    let slice = slice::from_raw_parts(data as *const u8, size as usize);
    let buf = Box::new(Buffer::from_bytes(slice));
    Box::into_raw(buf) as *mut MayaquaBuf
}

/// Free buffer (equivalent to FreeBuf)
/// 
/// # Safety
/// Buffer must have been created by mayaqua_buf_* functions
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_free(buf: *mut MayaquaBuf) {
    if !buf.is_null() {
        let _ = Box::from_raw(buf as *mut Buffer);
    }
}

/// Write data to buffer (equivalent to WriteBuf)
/// 
/// # Safety
/// `data` must be valid for `size` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_write(
    buf: *mut MayaquaBuf,
    data: *const c_void,
    size: c_uint,
) -> c_uint {
    if buf.is_null() || data.is_null() || size == 0 {
        return 0;
    }
    
    let buffer = &mut *(buf as *mut Buffer);
    let slice = slice::from_raw_parts(data as *const u8, size as usize);
    buffer.write(slice) as c_uint
}

/// Read data from buffer (equivalent to ReadBuf)
/// 
/// # Safety
/// `dst` must be valid for `size` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_read(
    buf: *mut MayaquaBuf,
    dst: *mut c_void,
    size: c_uint,
) -> c_uint {
    if buf.is_null() || dst.is_null() || size == 0 {
        return 0;
    }
    
    let buffer = &mut *(buf as *mut Buffer);
    match buffer.read(size as usize) {
        Some(data) => {
            ptr::copy_nonoverlapping(data.as_ptr(), dst as *mut u8, data.len());
            data.len() as c_uint
        }
        None => 0,
    }
}

/// Get buffer size
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_size(buf: *const MayaquaBuf) -> c_uint {
    if buf.is_null() {
        return 0;
    }
    let buffer = &*(buf as *const Buffer);
    buffer.size()
}

/// Get buffer data pointer
/// 
/// # Safety
/// Pointer is valid only while buffer exists and is not modified
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_data(buf: *const MayaquaBuf) -> *const c_void {
    if buf.is_null() {
        return ptr::null();
    }
    let buffer = &*(buf as *const Buffer);
    buffer.as_ptr() as *const c_void
}

/// Get buffer current position
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_position(buf: *const MayaquaBuf) -> c_uint {
    if buf.is_null() {
        return 0;
    }
    let buffer = &*(buf as *const Buffer);
    buffer.position()
}

/// Seek buffer position
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_seek(buf: *mut MayaquaBuf, pos: c_uint) {
    if !buf.is_null() {
        let buffer = &mut *(buf as *mut Buffer);
        buffer.seek(pos as usize);
    }
}

/// Clear buffer
#[no_mangle]
pub unsafe extern "C" fn mayaqua_buf_clear(buf: *mut MayaquaBuf) {
    if !buf.is_null() {
        let buffer = &mut *(buf as *mut Buffer);
        buffer.clear();
    }
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize Mayaqua library
#[no_mangle]
pub extern "C" fn mayaqua_init() -> i32 {
    // Currently no global initialization needed
    0
}

/// Free Mayaqua library resources
#[no_mangle]
pub extern "C" fn mayaqua_free_library() {
    // Currently no global cleanup needed
}

/// Get version string
#[no_mangle]
pub extern "C" fn mayaqua_version() -> *const i8 {
    b"Mayaqua-Rust 0.1.0\0".as_ptr() as *const i8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malloc_free() {
        unsafe {
            let ptr = mayaqua_malloc(1024);
            assert!(!ptr.is_null());
            mayaqua_free(ptr, 1024);
        }
    }

    #[test]
    fn test_buffer_operations() {
        unsafe {
            let buf = mayaqua_buf_new();
            assert!(!buf.is_null());
            
            let data = b"Hello, World!";
            let written = mayaqua_buf_write(buf, data.as_ptr() as *const c_void, data.len() as c_uint);
            assert_eq!(written, data.len() as c_uint);
            
            let size = mayaqua_buf_size(buf);
            assert_eq!(size, data.len() as c_uint);
            
            mayaqua_buf_free(buf);
        }
    }
}
