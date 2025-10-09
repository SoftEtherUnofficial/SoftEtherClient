//! Mayaqua FFI - C-compatible bindings
//!
//! Drop-in replacement for Mayaqua C API with Rust implementation.

use crate::Buffer;
use std::os::raw::{c_uint, c_void};
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
    crate::malloc(size as usize) as *mut c_void
}

/// Allocate zero-initialized memory (equivalent to ZeroMalloc)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_zero_malloc(size: c_uint) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }
    crate::zero_malloc(size as usize) as *mut c_void
}

/// Free memory (equivalent to Free)
///
/// # Safety
/// Pointer must have been allocated by mayaqua_malloc or mayaqua_zero_malloc.
/// Size must match original allocation size.
#[no_mangle]
pub unsafe extern "C" fn mayaqua_free(ptr: *mut c_void, size: c_uint) {
    if !ptr.is_null() && size > 0 {
        crate::free(ptr as *mut u8, size as usize);
    }
}

/// Zero memory (equivalent to Zero/ZeroMem)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_zero(addr: *mut c_void, size: c_uint) {
    crate::zero_mem(addr as *mut u8, size as usize);
}

/// Copy memory (equivalent to Copy)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_copy(dst: *mut c_void, src: *const c_void, size: c_uint) {
    crate::copy_mem(dst as *mut u8, src as *const u8, size as usize);
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

// ============================================================================
// Compression Functions (Tier 2A)
// ============================================================================

#[cfg(feature = "compress")]
/// Compress data using zlib/deflate
///
/// # Safety
/// - `data` must be valid for `data_len` bytes
/// - `out_len` will be set to the compressed size
/// - Returns null on error
/// - Caller must free result with mayaqua_free()
#[no_mangle]
pub unsafe extern "C" fn mayaqua_compress_deflate(
    data: *const u8,
    data_len: c_uint,
    out_len: *mut c_uint,
) -> *mut u8 {
    if data.is_null() || data_len == 0 || out_len.is_null() {
        return ptr::null_mut();
    }

    let input = slice::from_raw_parts(data, data_len as usize);

    match crate::compress::compress_deflate(input) {
        Ok(compressed) => {
            let len = compressed.len();
            let output = crate::malloc(len);
            if output.is_null() {
                return ptr::null_mut();
            }
            ptr::copy_nonoverlapping(compressed.as_ptr(), output, len);
            *out_len = len as c_uint;
            output
        }
        Err(_) => ptr::null_mut(),
    }
}

#[cfg(feature = "compress")]
/// Decompress zlib/deflate data
///
/// # Safety
/// - `data` must be valid for `data_len` bytes
/// - `out_len` will be set to the decompressed size
/// - Returns null on error
/// - Caller must free result with mayaqua_free()
#[no_mangle]
pub unsafe extern "C" fn mayaqua_decompress_deflate(
    data: *const u8,
    data_len: c_uint,
    out_len: *mut c_uint,
) -> *mut u8 {
    if data.is_null() || data_len == 0 || out_len.is_null() {
        return ptr::null_mut();
    }

    let input = slice::from_raw_parts(data, data_len as usize);

    match crate::compress::decompress_deflate(input) {
        Ok(decompressed) => {
            let len = decompressed.len();
            let output = crate::malloc(len);
            if output.is_null() {
                return ptr::null_mut();
            }
            ptr::copy_nonoverlapping(decompressed.as_ptr(), output, len);
            *out_len = len as c_uint;
            output
        }
        Err(_) => ptr::null_mut(),
    }
}

// ============================================================================
// HTTP Functions (Tier 2A)
// ============================================================================

/// Opaque HTTP request handle
#[repr(C)]
pub struct MayaquaHttpRequest {
    _private: [u8; 0],
}

/// Opaque HTTP response handle
#[repr(C)]
pub struct MayaquaHttpResponse {
    _private: [u8; 0],
}

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Create a new HTTP request
///
/// # Safety
/// - `method` and `path` must be valid null-terminated C strings
/// - Returns null on error
/// - Caller must free with mayaqua_http_request_free()
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_request_new(
    method: *const c_char,
    path: *const c_char,
) -> *mut MayaquaHttpRequest {
    if method.is_null() || path.is_null() {
        return ptr::null_mut();
    }

    let method_str = match CStr::from_ptr(method).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ptr::null_mut(),
    };

    let path_str = match CStr::from_ptr(path).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ptr::null_mut(),
    };

    let request = Box::new(crate::http::HttpRequest::new(method_str, path_str));
    Box::into_raw(request) as *mut MayaquaHttpRequest
}

/// Add a header to HTTP request
///
/// # Safety
/// - `request` must be a valid MayaquaHttpRequest pointer
/// - `name` and `value` must be valid null-terminated C strings
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_request_add_header(
    request: *mut MayaquaHttpRequest,
    name: *const c_char,
    value: *const c_char,
) -> bool {
    if request.is_null() || name.is_null() || value.is_null() {
        return false;
    }

    let req = &mut *(request as *mut crate::http::HttpRequest);

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return false,
    };

    let value_str = match CStr::from_ptr(value).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return false,
    };

    req.add_header(name_str, value_str);
    true
}

/// Set HTTP request body
///
/// # Safety
/// - `request` must be a valid MayaquaHttpRequest pointer
/// - `body` must be valid for `body_len` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_request_set_body(
    request: *mut MayaquaHttpRequest,
    body: *const u8,
    body_len: c_uint,
) -> bool {
    if request.is_null() || body.is_null() {
        return false;
    }

    let req = &mut *(request as *mut crate::http::HttpRequest);
    let body_data = slice::from_raw_parts(body, body_len as usize).to_vec();

    req.set_body(body_data);
    true
}

/// Convert HTTP request to bytes for transmission
///
/// # Safety
/// - `request` must be a valid MayaquaHttpRequest pointer
/// - `out_len` will be set to the output size
/// - Returns null on error
/// - Caller must free result with mayaqua_free()
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_request_to_bytes(
    request: *const MayaquaHttpRequest,
    out_len: *mut c_uint,
) -> *mut u8 {
    if request.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }

    let req = &*(request as *const crate::http::HttpRequest);
    let bytes = req.to_bytes();
    let len = bytes.len();

    let output = crate::malloc(len);
    if output.is_null() {
        return ptr::null_mut();
    }

    ptr::copy_nonoverlapping(bytes.as_ptr(), output, len);
    *out_len = len as c_uint;
    output
}

/// Free HTTP request
///
/// # Safety
/// - `request` must be a valid MayaquaHttpRequest pointer
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_request_free(request: *mut MayaquaHttpRequest) {
    if !request.is_null() {
        let _ = Box::from_raw(request as *mut crate::http::HttpRequest);
    }
}

/// Get HTTP response status code
///
/// # Safety
/// - `response` must be a valid MayaquaHttpResponse pointer
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_response_status(
    response: *const MayaquaHttpResponse,
) -> c_uint {
    if response.is_null() {
        return 0;
    }

    let resp = &*(response as *const crate::http::HttpResponse);
    resp.status_code as c_uint
}

/// Get HTTP response body
///
/// # Safety
/// - `response` must be a valid MayaquaHttpResponse pointer
/// - `out_len` will be set to the body size
/// - Returns pointer to body data (valid until response is freed)
/// - DO NOT free the returned pointer separately
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_response_body(
    response: *const MayaquaHttpResponse,
    out_len: *mut c_uint,
) -> *const u8 {
    if response.is_null() || out_len.is_null() {
        return ptr::null();
    }

    let resp = &*(response as *const crate::http::HttpResponse);
    *out_len = resp.body.len() as c_uint;
    resp.body.as_ptr()
}

/// Get HTTP response header value
///
/// # Safety
/// - `response` must be a valid MayaquaHttpResponse pointer
/// - `name` must be a valid null-terminated C string
/// - Returns null if header not found
/// - Caller must free result with mayaqua_free_cstring()
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_response_get_header(
    response: *const MayaquaHttpResponse,
    name: *const c_char,
) -> *mut c_char {
    if response.is_null() || name.is_null() {
        return ptr::null_mut();
    }

    let resp = &*(response as *const crate::http::HttpResponse);

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    match resp.headers.get(name_str) {
        Some(value) => match CString::new(value.as_str()) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

/// Free C string returned by mayaqua functions
///
/// # Safety
/// - `s` must be a pointer returned by a mayaqua function that returns C strings
#[no_mangle]
pub unsafe extern "C" fn mayaqua_free_cstring(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

/// Free HTTP response
///
/// # Safety
/// - `response` must be a valid MayaquaHttpResponse pointer
#[no_mangle]
pub unsafe extern "C" fn mayaqua_http_response_free(response: *mut MayaquaHttpResponse) {
    if !response.is_null() {
        let _ = Box::from_raw(response as *mut crate::http::HttpResponse);
    }
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
            let written =
                mayaqua_buf_write(buf, data.as_ptr() as *const c_void, data.len() as c_uint);
            assert_eq!(written, data.len() as c_uint);

            let size = mayaqua_buf_size(buf);
            assert_eq!(size, data.len() as c_uint);

            mayaqua_buf_free(buf);
        }
    }
}
