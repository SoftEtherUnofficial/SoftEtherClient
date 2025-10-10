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

// ============================================================================
// Phase 3.1 FFI Exports - Crypto Module
// ============================================================================

/// Compute SHA-0 hash (20 bytes)
/// 
/// # Safety
/// - `data` must be valid for reads of `len` bytes
/// - `output` must be valid for writes of 20 bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_sha0(
    data: *const c_void,
    len: c_uint,
    output: *mut c_void,
) -> i32 {
    if data.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let input = slice::from_raw_parts(data as *const u8, len as usize);
    let hash = crate::crypto::sha0(input);
    
    ptr::copy_nonoverlapping(hash.as_ptr(), output as *mut u8, 20);
    0 // Success
}

/// Compute SHA-1 hash (20 bytes) - requires sha1-compat feature
/// 
/// # Safety
/// - `data` must be valid for reads of `len` bytes
/// - `output` must be valid for writes of 20 bytes
#[cfg(feature = "sha1-compat")]
#[no_mangle]
pub unsafe extern "C" fn mayaqua_sha1(
    data: *const c_void,
    len: c_uint,
    output: *mut c_void,
) -> i32 {
    if data.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let input = slice::from_raw_parts(data as *const u8, len as usize);
    let hash = crate::crypto::sha1(input);
    
    ptr::copy_nonoverlapping(hash.as_ptr(), output as *mut u8, 20);
    0 // Success
}

/// Compute SoftEther password hash
/// 
/// # Safety
/// - `password` must be a valid null-terminated UTF-8 string
/// - `username` must be a valid null-terminated UTF-8 string
/// - `output` must be valid for writes of 20 bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_password_hash(
    password: *const c_char,
    username: *const c_char,
    output: *mut c_void,
) -> i32 {
    if password.is_null() || username.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let pass_str = match std::ffi::CStr::from_ptr(password).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    let user_str = match std::ffi::CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    let hash = crate::crypto::softether_password_hash(pass_str, user_str);
    ptr::copy_nonoverlapping(hash.as_ptr(), output as *mut u8, 20);
    0 // Success
}

/// Apply RC4 cipher (creates new output buffer)
/// 
/// # Safety
/// - `key` must be valid for reads of `key_len` bytes
/// - `data` must be valid for reads of `data_len` bytes
/// - `output` must be valid for writes of `data_len` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_rc4_apply(
    key: *const c_void,
    key_len: c_uint,
    data: *const c_void,
    data_len: c_uint,
    output: *mut c_void,
) -> i32 {
    if key.is_null() || data.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let key_slice = slice::from_raw_parts(key as *const u8, key_len as usize);
    let data_slice = slice::from_raw_parts(data as *const u8, data_len as usize);
    
    let result = crate::crypto::rc4_apply(key_slice, data_slice);
    ptr::copy_nonoverlapping(result.as_ptr(), output as *mut u8, data_len as usize);
    0 // Success
}

/// Apply RC4 cipher in-place
/// 
/// # Safety
/// - `key` must be valid for reads of `key_len` bytes
/// - `data` must be valid for reads and writes of `data_len` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_rc4_apply_inplace(
    key: *const c_void,
    key_len: c_uint,
    data: *mut c_void,
    data_len: c_uint,
) -> i32 {
    if key.is_null() || data.is_null() {
        return -1; // Invalid pointer
    }

    let key_slice = slice::from_raw_parts(key as *const u8, key_len as usize);
    let data_slice = slice::from_raw_parts_mut(data as *mut u8, data_len as usize);
    
    crate::crypto::rc4_apply_inplace(key_slice, data_slice);
    0 // Success
}

// ============================================================================
// Phase 3.1 FFI Exports - Filesystem Module
// ============================================================================

/// Ensure directory exists (recursive creation)
/// 
/// # Safety
/// - `path` must be a valid null-terminated UTF-8 string
#[no_mangle]
pub unsafe extern "C" fn mayaqua_ensure_dir(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1; // Invalid pointer
    }

    let c_str = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    let path_buf = std::path::PathBuf::from(c_str);
    match crate::fs::ensure_dir(&path_buf) {
        Ok(_) => 0,
        Err(_) => -3, // Failed to create directory
    }
}

/// Read entire file into buffer
/// 
/// # Safety
/// - `path` must be a valid null-terminated UTF-8 string
/// - `output` will be allocated by this function and must be freed by caller using `mayaqua_free_buffer`
/// - `output_len` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_read_file(
    path: *const c_char,
    output: *mut *mut c_void,
    output_len: *mut c_uint,
) -> i32 {
    if path.is_null() || output.is_null() || output_len.is_null() {
        return -1; // Invalid pointer
    }

    let c_str = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    let path_buf = std::path::PathBuf::from(c_str);
    match crate::fs::read_all(&path_buf) {
        Ok(data) => {
            let len = data.len();
            let boxed = data.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut c_void;
            
            *output = ptr;
            *output_len = len as c_uint;
            0 // Success
        }
        Err(_) => -3, // Failed to read file
    }
}

/// Write data to file atomically
/// 
/// # Safety
/// - `path` must be a valid null-terminated UTF-8 string
/// - `data` must be valid for reads of `len` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_write_file(
    path: *const c_char,
    data: *const c_void,
    len: c_uint,
) -> i32 {
    if path.is_null() || data.is_null() {
        return -1; // Invalid pointer
    }

    let c_str = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    let path_buf = std::path::PathBuf::from(c_str);
    let data_slice = slice::from_raw_parts(data as *const u8, len as usize);

    match crate::fs::write_all_atomic(&path_buf, data_slice) {
        Ok(_) => 0,
        Err(_) => -3, // Failed to write file
    }
}

/// Set file permissions to user read/write only
/// 
/// # Safety
/// - `path` must be a valid null-terminated UTF-8 string
#[no_mangle]
pub unsafe extern "C" fn mayaqua_set_user_rw_only(path: *const c_char) -> i32 {
    if path.is_null() {
        return -1; // Invalid pointer
    }

    let c_str = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    let path_buf = std::path::PathBuf::from(c_str);
    crate::fs::set_user_rw_only(&path_buf);
    0 // Success
}

/// Free buffer allocated by FFI functions
/// 
/// # Safety
/// - `buffer` must have been allocated by an FFI function
/// - `len` must match the length returned by that function
/// - Must only be called once per buffer
#[no_mangle]
pub unsafe extern "C" fn mayaqua_free_buffer(buffer: *mut c_void, len: c_uint) {
    if !buffer.is_null() && len > 0 {
        let _ = Vec::from_raw_parts(buffer as *mut u8, len as usize, len as usize);
        // Vec will be dropped here, freeing the memory
    }
}

// ============================================================================
// Phase 3.1 FFI Exports - Strings Module
// ============================================================================

/// Convert UTF-8 string to UTF-16 (null-terminated)
/// 
/// # Safety
/// - `input` must be a valid null-terminated UTF-8 string
/// - `output` will be allocated by this function and must be freed by caller using `mayaqua_free_utf16`
/// - `output_len` must be valid for writes (length includes null terminator)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_utf8_to_utf16(
    input: *const c_char,
    output: *mut *mut u16,
    output_len: *mut c_uint,
) -> i32 {
    if input.is_null() || output.is_null() || output_len.is_null() {
        return -1; // Invalid pointer
    }

    let c_str = match std::ffi::CStr::from_ptr(input).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    let utf16_data = crate::strings::utf8_to_utf16(c_str);
    let len = utf16_data.len();
    let boxed = utf16_data.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u16;

    *output = ptr;
    *output_len = len as c_uint;
    0 // Success
}

/// Convert UTF-16 string to UTF-8 (null-terminated)
/// 
/// # Safety
/// - `input` must be valid for reads of `len` u16 values
/// - `output` will be allocated by this function and must be freed by caller using `mayaqua_free_string`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_utf16_to_utf8(
    input: *const u16,
    len: c_uint,
    output: *mut *mut c_char,
) -> i32 {
    if input.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let utf16_slice = slice::from_raw_parts(input, len as usize);
    match crate::strings::utf16_to_utf8(utf16_slice) {
        Ok(s) => {
            match std::ffi::CString::new(s) {
                Ok(c_string) => {
                    *output = c_string.into_raw();
                    0 // Success
                }
                Err(_) => -3, // Contains null byte
            }
        }
        Err(_) => -2, // Invalid UTF-16
    }
}

/// Convert binary data to hex string
/// 
/// # Safety
/// - `data` must be valid for reads of `len` bytes
/// - `output` will be allocated by this function and must be freed by caller using `mayaqua_free_string`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_bin_to_str(
    data: *const c_void,
    len: c_uint,
    output: *mut *mut c_char,
) -> i32 {
    if data.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let data_slice = slice::from_raw_parts(data as *const u8, len as usize);
    let hex_str = crate::strings::bin_to_str(data_slice);
    
    match std::ffi::CString::new(hex_str) {
        Ok(c_string) => {
            *output = c_string.into_raw();
            0 // Success
        }
        Err(_) => -2, // Contains null byte (shouldn't happen with hex)
    }
}

/// Convert hex string to binary data
/// 
/// # Safety
/// - `hex_str` must be a valid null-terminated string containing hex digits
/// - `output` will be allocated by this function and must be freed by caller using `mayaqua_free_buffer`
/// - `output_len` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_str_to_bin(
    hex_str: *const c_char,
    output: *mut *mut c_void,
    output_len: *mut c_uint,
) -> i32 {
    if hex_str.is_null() || output.is_null() || output_len.is_null() {
        return -1; // Invalid pointer
    }

    let c_str = match std::ffi::CStr::from_ptr(hex_str).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    match crate::strings::str_to_bin(c_str) {
        Ok(data) => {
            let len = data.len();
            let boxed = data.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut c_void;
            
            *output = ptr;
            *output_len = len as c_uint;
            0 // Success
        }
        Err(_) => -3, // Invalid hex string
    }
}

/// Convert MAC address to string (XX:XX:XX:XX:XX:XX)
/// 
/// # Safety
/// - `mac` must be valid for reads of 6 bytes
/// - `output` must be valid for writes of at least 18 bytes (17 + null)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_mac_to_str(
    mac: *const c_void,
    output: *mut c_char,
) -> i32 {
    if mac.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let mac_ptr = mac as *const u8;
    let mac_array: [u8; 6] = [
        *mac_ptr.offset(0),
        *mac_ptr.offset(1),
        *mac_ptr.offset(2),
        *mac_ptr.offset(3),
        *mac_ptr.offset(4),
        *mac_ptr.offset(5),
    ];

    let mac_str = crate::strings::mac_to_str(&mac_array);
    let c_string = std::ffi::CString::new(mac_str).unwrap();
    
    // Copy to output buffer
    ptr::copy_nonoverlapping(
        c_string.as_ptr(),
        output,
        c_string.as_bytes_with_nul().len(),
    );
    
    0 // Success
}

/// Parse MAC address from string
/// 
/// # Safety
/// - `str` must be a valid null-terminated string
/// - `output` must be valid for writes of 6 bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_str_to_mac(
    str: *const c_char,
    output: *mut c_void,
) -> i32 {
    if str.is_null() || output.is_null() {
        return -1; // Invalid pointer
    }

    let c_str = match std::ffi::CStr::from_ptr(str).to_str() {
        Ok(s) => s,
        Err(_) => return -2, // Invalid UTF-8
    };

    match crate::strings::str_to_mac(c_str) {
        Ok(mac) => {
            ptr::copy_nonoverlapping(mac.as_ptr(), output as *mut u8, 6);
            0 // Success
        }
        Err(_) => -3, // Invalid MAC address format
    }
}

/// Free string allocated by FFI functions
/// 
/// # Safety
/// - `str` must have been allocated by an FFI function that returns `*mut c_char`
/// - Must only be called once per string
#[no_mangle]
pub unsafe extern "C" fn mayaqua_free_string(str: *mut c_char) {
    if !str.is_null() {
        let _ = std::ffi::CString::from_raw(str);
        // CString will be dropped here, freeing the memory
    }
}

/// Free UTF-16 buffer allocated by mayaqua_utf8_to_utf16
/// 
/// # Safety
/// - `buffer` must have been allocated by `mayaqua_utf8_to_utf16`
/// - `len` must match the length returned by `mayaqua_utf8_to_utf16`
/// - Must only be called once per buffer
#[no_mangle]
pub unsafe extern "C" fn mayaqua_free_utf16(buffer: *mut u16, len: c_uint) {
    if !buffer.is_null() && len > 0 {
        let _ = Vec::from_raw_parts(buffer, len as usize, len as usize);
        // Vec will be dropped here, freeing the memory
    }
}

// ============================================================================
// Phase 3.1 FFI Exports - Network Module
// ============================================================================

/// Opaque handle for TcpSocket
#[repr(C)]
pub struct MayaquaTcpSocket {
    _private: [u8; 0],
}

/// Opaque handle for TcpSocketListener
#[repr(C)]
pub struct MayaquaTcpListener {
    _private: [u8; 0],
}

/// Opaque handle for UdpSocket
#[repr(C)]
pub struct MayaquaUdpSocket {
    _private: [u8; 0],
}

/// Connect to TCP server
/// 
/// # Safety
/// - `hostname` must be a valid null-terminated UTF-8 string
/// - `socket_out` must be valid for writes
/// - Caller must free returned socket with `mayaqua_tcp_close`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_connect(
    hostname: *const c_char,
    port: u16,
    socket_out: *mut *mut MayaquaTcpSocket,
) -> i32 {
    if hostname.is_null() || socket_out.is_null() {
        return -1;
    }

    let host_str = match std::ffi::CStr::from_ptr(hostname).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match crate::network::TcpSocket::connect(host_str, port) {
        Ok(socket) => {
            let boxed = Box::new(socket);
            *socket_out = Box::into_raw(boxed) as *mut MayaquaTcpSocket;
            0
        }
        Err(_) => -3,
    }
}

/// Connect to TCP server with timeout
/// 
/// # Safety
/// - `hostname` must be a valid null-terminated UTF-8 string
/// - `socket_out` must be valid for writes
/// - Caller must free returned socket with `mayaqua_tcp_close`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_connect_timeout(
    hostname: *const c_char,
    port: u16,
    timeout_ms: c_uint,
    socket_out: *mut *mut MayaquaTcpSocket,
) -> i32 {
    if hostname.is_null() || socket_out.is_null() {
        return -1;
    }

    let host_str = match std::ffi::CStr::from_ptr(hostname).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let timeout = std::time::Duration::from_millis(timeout_ms as u64);
    match crate::network::TcpSocket::connect_timeout(host_str, port, timeout) {
        Ok(socket) => {
            let boxed = Box::new(socket);
            *socket_out = Box::into_raw(boxed) as *mut MayaquaTcpSocket;
            0
        }
        Err(_) => -3,
    }
}

/// Send data over TCP socket
/// 
/// # Safety
/// - `socket` must be a valid TcpSocket handle
/// - `data` must be valid for reads of `len` bytes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_send(
    socket: *mut MayaquaTcpSocket,
    data: *const c_void,
    len: c_uint,
) -> i32 {
    if socket.is_null() || data.is_null() {
        return -1;
    }

    let sock = &mut *(socket as *mut crate::network::TcpSocket);
    let data_slice = slice::from_raw_parts(data as *const u8, len as usize);

    match sock.send(data_slice) {
        Ok(n) => n as i32,
        Err(_) => -3,
    }
}

/// Receive data from TCP socket
/// 
/// # Safety
/// - `socket` must be a valid TcpSocket handle
/// - `buffer` must be valid for writes of `len` bytes
/// - Returns number of bytes read, or negative on error
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_recv(
    socket: *mut MayaquaTcpSocket,
    buffer: *mut c_void,
    len: c_uint,
) -> i32 {
    if socket.is_null() || buffer.is_null() {
        return -1;
    }

    let sock = &mut *(socket as *mut crate::network::TcpSocket);
    let buf_slice = slice::from_raw_parts_mut(buffer as *mut u8, len as usize);

    match sock.recv(buf_slice) {
        Ok(n) => n as i32,
        Err(_) => -3,
    }
}

/// Close TCP socket
/// 
/// # Safety
/// - `socket` must be a valid TcpSocket handle
/// - Must only be called once per socket
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_close(socket: *mut MayaquaTcpSocket) {
    if !socket.is_null() {
        let _ = Box::from_raw(socket as *mut crate::network::TcpSocket);
        // Box will be dropped here, closing the socket
    }
}

/// Create TCP listener
/// 
/// # Safety
/// - `listener_out` must be valid for writes
/// - Caller must free returned listener with `mayaqua_tcp_listener_close`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_listen(
    port: u16,
    listener_out: *mut *mut MayaquaTcpListener,
) -> i32 {
    if listener_out.is_null() {
        return -1;
    }

    match crate::network::TcpSocketListener::listen(port) {
        Ok(listener) => {
            let boxed = Box::new(listener);
            *listener_out = Box::into_raw(boxed) as *mut MayaquaTcpListener;
            0
        }
        Err(_) => -3,
    }
}

/// Create TCP listener with options
/// 
/// # Safety
/// - `listener_out` must be valid for writes
/// - Caller must free returned listener with `mayaqua_tcp_listener_close`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_listen_ex(
    port: u16,
    local_only: bool,
    listener_out: *mut *mut MayaquaTcpListener,
) -> i32 {
    if listener_out.is_null() {
        return -1;
    }

    match crate::network::TcpSocketListener::listen_ex(port, local_only) {
        Ok(listener) => {
            let boxed = Box::new(listener);
            *listener_out = Box::into_raw(boxed) as *mut MayaquaTcpListener;
            0
        }
        Err(_) => -3,
    }
}

/// Accept incoming TCP connection
/// 
/// # Safety
/// - `listener` must be a valid TcpSocketListener handle
/// - `socket_out` must be valid for writes
/// - Caller must free returned socket with `mayaqua_tcp_close`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_accept(
    listener: *mut MayaquaTcpListener,
    socket_out: *mut *mut MayaquaTcpSocket,
) -> i32 {
    if listener.is_null() || socket_out.is_null() {
        return -1;
    }

    let lst = &*(listener as *const crate::network::TcpSocketListener);
    match lst.accept() {
        Ok(socket) => {
            let boxed = Box::new(socket);
            *socket_out = Box::into_raw(boxed) as *mut MayaquaTcpSocket;
            0
        }
        Err(_) => -3,
    }
}

/// Close TCP listener
/// 
/// # Safety
/// - `listener` must be a valid TcpSocketListener handle
/// - Must only be called once per listener
#[no_mangle]
pub unsafe extern "C" fn mayaqua_tcp_listener_close(listener: *mut MayaquaTcpListener) {
    if !listener.is_null() {
        let _ = Box::from_raw(listener as *mut crate::network::TcpSocketListener);
        // Box will be dropped here, closing the listener
    }
}

/// Create UDP socket
/// 
/// # Safety
/// - `socket_out` must be valid for writes
/// - Caller must free returned socket with `mayaqua_udp_close`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_udp_new(
    port: u16,
    socket_out: *mut *mut MayaquaUdpSocket,
) -> i32 {
    if socket_out.is_null() {
        return -1;
    }

    match crate::network::UdpSocketWrapper::new(port) {
        Ok(socket) => {
            let boxed = Box::new(socket);
            *socket_out = Box::into_raw(boxed) as *mut MayaquaUdpSocket;
            0
        }
        Err(_) => -3,
    }
}

/// Send UDP data to address
/// 
/// # Safety
/// - `socket` must be a valid UdpSocket handle
/// - `data` must be valid for reads of `len` bytes
/// - `hostname` must be a valid null-terminated UTF-8 string
#[no_mangle]
pub unsafe extern "C" fn mayaqua_udp_send_to(
    socket: *mut MayaquaUdpSocket,
    data: *const c_void,
    len: c_uint,
    hostname: *const c_char,
    port: u16,
) -> i32 {
    if socket.is_null() || data.is_null() || hostname.is_null() {
        return -1;
    }

    let sock = &*(socket as *const crate::network::UdpSocketWrapper);
    let data_slice = slice::from_raw_parts(data as *const u8, len as usize);
    
    let host_str = match std::ffi::CStr::from_ptr(hostname).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    // Resolve hostname to SocketAddr
    let addr = match format!("{}:{}", host_str, port).parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            // Try DNS resolution
            let addrs: Vec<_> = match format!("{}:{}", host_str, port).to_socket_addrs() {
                Ok(a) => a.collect(),
                Err(_) => return -2,
            };
            match addrs.first() {
                Some(a) => *a,
                None => return -2,
            }
        }
    };

    match sock.send_to(data_slice, addr) {
        Ok(n) => n as i32,
        Err(_) => -3,
    }
}

/// Receive UDP data from socket
/// 
/// # Safety
/// - `socket` must be a valid UdpSocket handle
/// - `buffer` must be valid for writes of `len` bytes
/// - `hostname_out` will be allocated and must be freed with `mayaqua_free_string`
/// - `port_out` must be valid for writes
/// - Returns number of bytes read, or negative on error
#[no_mangle]
pub unsafe extern "C" fn mayaqua_udp_recv_from(
    socket: *mut MayaquaUdpSocket,
    buffer: *mut c_void,
    len: c_uint,
    hostname_out: *mut *mut c_char,
    port_out: *mut u16,
) -> i32 {
    if socket.is_null() || buffer.is_null() || hostname_out.is_null() || port_out.is_null() {
        return -1;
    }

    let sock = &*(socket as *const crate::network::UdpSocketWrapper);
    let buf_slice = slice::from_raw_parts_mut(buffer as *mut u8, len as usize);

    match sock.recv_from(buf_slice) {
        Ok((n, addr)) => {
            let hostname = addr.ip().to_string();
            match std::ffi::CString::new(hostname) {
                Ok(c_string) => {
                    *hostname_out = c_string.into_raw();
                    *port_out = addr.port();
                    n as i32
                }
                Err(_) => -2,
            }
        }
        Err(_) => -3,
    }
}

/// Close UDP socket
/// 
/// # Safety
/// - `socket` must be a valid UdpSocket handle
/// - Must only be called once per socket
#[no_mangle]
pub unsafe extern "C" fn mayaqua_udp_close(socket: *mut MayaquaUdpSocket) {
    if !socket.is_null() {
        let _ = Box::from_raw(socket as *mut crate::network::UdpSocketWrapper);
        // Box will be dropped here, closing the socket
    }
}

// ============================================================================
// Phase 3.1 FFI Exports - Tables Module
// ============================================================================

use std::net::ToSocketAddrs;

/// Opaque handle for List<T> - stores void pointers
#[repr(C)]
pub struct MayaquaList {
    _private: [u8; 0],
}

/// Opaque handle for Queue<T> - stores void pointers
#[repr(C)]
pub struct MayaquaQueue {
    _private: [u8; 0],
}

/// Opaque handle for Table<T> - maps strings to void pointers
#[repr(C)]
pub struct MayaquaTable {
    _private: [u8; 0],
}

/// Create new list
/// 
/// # Safety
/// - Caller must free returned list with `mayaqua_list_free`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_list_new() -> *mut MayaquaList {
    let list = crate::tables::List::<*mut c_void>::new();
    let boxed = Box::new(list);
    Box::into_raw(boxed) as *mut MayaquaList
}

/// Add item to list
/// 
/// # Safety
/// - `list` must be a valid List handle
/// - `item` can be any pointer (will be stored as-is)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_list_add(list: *mut MayaquaList, item: *mut c_void) {
    if list.is_null() {
        return;
    }
    let lst = &mut *(list as *mut crate::tables::List<*mut c_void>);
    lst.add(item);
}

/// Get item from list by index
/// 
/// # Safety
/// - `list` must be a valid List handle
/// - Returns NULL if index out of bounds
#[no_mangle]
pub unsafe extern "C" fn mayaqua_list_get(
    list: *mut MayaquaList,
    index: c_uint,
) -> *mut c_void {
    if list.is_null() {
        return ptr::null_mut();
    }
    let lst = &*(list as *const crate::tables::List<*mut c_void>);
    lst.get(index as usize).copied().unwrap_or(ptr::null_mut())
}

/// Remove item from list by index
/// 
/// # Safety
/// - `list` must be a valid List handle
/// - Returns the removed item, or NULL if index out of bounds
#[no_mangle]
pub unsafe extern "C" fn mayaqua_list_remove(
    list: *mut MayaquaList,
    index: c_uint,
) -> *mut c_void {
    if list.is_null() {
        return ptr::null_mut();
    }
    let lst = &mut *(list as *mut crate::tables::List<*mut c_void>);
    lst.remove(index as usize).unwrap_or(ptr::null_mut())
}

/// Get list length
/// 
/// # Safety
/// - `list` must be a valid List handle
#[no_mangle]
pub unsafe extern "C" fn mayaqua_list_len(list: *mut MayaquaList) -> c_uint {
    if list.is_null() {
        return 0;
    }
    let lst = &*(list as *const crate::tables::List<*mut c_void>);
    lst.len() as c_uint
}

/// Clear all items from list
/// 
/// # Safety
/// - `list` must be a valid List handle
/// - Does NOT free the items themselves, only removes them from list
#[no_mangle]
pub unsafe extern "C" fn mayaqua_list_clear(list: *mut MayaquaList) {
    if list.is_null() {
        return;
    }
    let lst = &mut *(list as *mut crate::tables::List<*mut c_void>);
    lst.clear();
}

/// Free list
/// 
/// # Safety
/// - `list` must be a valid List handle
/// - Does NOT free the items themselves, only the list structure
/// - Must only be called once per list
#[no_mangle]
pub unsafe extern "C" fn mayaqua_list_free(list: *mut MayaquaList) {
    if !list.is_null() {
        let _ = Box::from_raw(list as *mut crate::tables::List<*mut c_void>);
    }
}

/// Create new queue
/// 
/// # Safety
/// - Caller must free returned queue with `mayaqua_queue_free`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_queue_new() -> *mut MayaquaQueue {
    let queue = crate::tables::Queue::<*mut c_void>::new();
    let boxed = Box::new(queue);
    Box::into_raw(boxed) as *mut MayaquaQueue
}

/// Push item to queue (enqueue)
/// 
/// # Safety
/// - `queue` must be a valid Queue handle
/// - `item` can be any pointer (will be stored as-is)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_queue_push(queue: *mut MayaquaQueue, item: *mut c_void) {
    if queue.is_null() {
        return;
    }
    let q = &*(queue as *const crate::tables::Queue<*mut c_void>);
    q.push(item);
}

/// Pop item from queue (dequeue)
/// 
/// # Safety
/// - `queue` must be a valid Queue handle
/// - Returns NULL if queue is empty
#[no_mangle]
pub unsafe extern "C" fn mayaqua_queue_pop(queue: *mut MayaquaQueue) -> *mut c_void {
    if queue.is_null() {
        return ptr::null_mut();
    }
    let q = &*(queue as *const crate::tables::Queue<*mut c_void>);
    q.pop().unwrap_or(ptr::null_mut())
}

/// Get queue length
/// 
/// # Safety
/// - `queue` must be a valid Queue handle
#[no_mangle]
pub unsafe extern "C" fn mayaqua_queue_len(queue: *mut MayaquaQueue) -> c_uint {
    if queue.is_null() {
        return 0;
    }
    let q = &*(queue as *const crate::tables::Queue<*mut c_void>);
    q.len() as c_uint
}

/// Free queue
/// 
/// # Safety
/// - `queue` must be a valid Queue handle
/// - Does NOT free the items themselves, only the queue structure
/// - Must only be called once per queue
#[no_mangle]
pub unsafe extern "C" fn mayaqua_queue_free(queue: *mut MayaquaQueue) {
    if !queue.is_null() {
        let _ = Box::from_raw(queue as *mut crate::tables::Queue<*mut c_void>);
    }
}

/// Create new table
/// 
/// # Safety
/// - Caller must free returned table with `mayaqua_table_free`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_table_new() -> *mut MayaquaTable {
    let table = crate::tables::Table::<*mut c_void>::new();
    let boxed = Box::new(table);
    Box::into_raw(boxed) as *mut MayaquaTable
}

/// Insert key-value pair into table
/// 
/// # Safety
/// - `table` must be a valid Table handle
/// - `key` must be a valid null-terminated UTF-8 string
/// - `value` can be any pointer (will be stored as-is)
#[no_mangle]
pub unsafe extern "C" fn mayaqua_table_insert(
    table: *mut MayaquaTable,
    key: *const c_char,
    value: *mut c_void,
) -> i32 {
    if table.is_null() || key.is_null() {
        return -1;
    }

    let tbl = &mut *(table as *mut crate::tables::Table<*mut c_void>);
    let key_str = match std::ffi::CStr::from_ptr(key).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -2,
    };

    tbl.insert(key_str, value);
    0
}

/// Get value from table by key
/// 
/// # Safety
/// - `table` must be a valid Table handle
/// - `key` must be a valid null-terminated UTF-8 string
/// - Returns NULL if key not found
#[no_mangle]
pub unsafe extern "C" fn mayaqua_table_get(
    table: *mut MayaquaTable,
    key: *const c_char,
) -> *mut c_void {
    if table.is_null() || key.is_null() {
        return ptr::null_mut();
    }

    let tbl = &*(table as *const crate::tables::Table<*mut c_void>);
    let key_str = match std::ffi::CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    tbl.get(key_str).copied().unwrap_or(ptr::null_mut())
}

/// Remove key-value pair from table
/// 
/// # Safety
/// - `table` must be a valid Table handle
/// - `key` must be a valid null-terminated UTF-8 string
/// - Returns the removed value, or NULL if key not found
#[no_mangle]
pub unsafe extern "C" fn mayaqua_table_remove(
    table: *mut MayaquaTable,
    key: *const c_char,
) -> *mut c_void {
    if table.is_null() || key.is_null() {
        return ptr::null_mut();
    }

    let tbl = &mut *(table as *mut crate::tables::Table<*mut c_void>);
    let key_str = match std::ffi::CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    tbl.remove(key_str).unwrap_or(ptr::null_mut())
}

/// Check if table contains key
/// 
/// # Safety
/// - `table` must be a valid Table handle
/// - `key` must be a valid null-terminated UTF-8 string
#[no_mangle]
pub unsafe extern "C" fn mayaqua_table_contains(
    table: *mut MayaquaTable,
    key: *const c_char,
) -> bool {
    if table.is_null() || key.is_null() {
        return false;
    }

    let tbl = &*(table as *const crate::tables::Table<*mut c_void>);
    let key_str = match std::ffi::CStr::from_ptr(key).to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    tbl.contains_key(key_str)
}

/// Get table size
/// 
/// # Safety
/// - `table` must be a valid Table handle
#[no_mangle]
pub unsafe extern "C" fn mayaqua_table_len(table: *mut MayaquaTable) -> c_uint {
    if table.is_null() {
        return 0;
    }
    let tbl = &*(table as *const crate::tables::Table<*mut c_void>);
    tbl.len() as c_uint
}

/// Free table
/// 
/// # Safety
/// - `table` must be a valid Table handle
/// - Does NOT free the values themselves, only the table structure
/// - Must only be called once per table
#[no_mangle]
pub unsafe extern "C" fn mayaqua_table_free(table: *mut MayaquaTable) {
    if !table.is_null() {
        let _ = Box::from_raw(table as *mut crate::tables::Table<*mut c_void>);
    }
}

// ============================================================================
// Phase 3.1 FFI Exports - Platform Module
// ============================================================================

/// Get system directory path
/// 
/// # Safety
/// - `path_out` must be valid for writes
/// - Caller must free returned string with `mayaqua_free_string`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_get_system_dir(path_out: *mut *mut c_char) -> i32 {
    if path_out.is_null() {
        return -1;
    }

    match crate::platform::get_system_directory() {
        Ok(path) => {
            let path_str = path.to_string_lossy().to_string();
            match std::ffi::CString::new(path_str) {
                Ok(c_string) => {
                    *path_out = c_string.into_raw();
                    0
                }
                Err(_) => -2,
            }
        }
        Err(_) => -3,
    }
}

/// Get config directory path
/// 
/// # Safety
/// - `path_out` must be valid for writes
/// - Caller must free returned string with `mayaqua_free_string`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_get_config_dir(path_out: *mut *mut c_char) -> i32 {
    if path_out.is_null() {
        return -1;
    }

    match crate::platform::get_config_directory() {
        Ok(path) => {
            let path_str = path.to_string_lossy().to_string();
            match std::ffi::CString::new(path_str) {
                Ok(c_string) => {
                    *path_out = c_string.into_raw();
                    0
                }
                Err(_) => -2,
            }
        }
        Err(_) => -3,
    }
}

/// Get network interfaces
/// 
/// # Safety
/// - `interfaces_out` must be valid for writes
/// - `count_out` must be valid for writes
/// - Caller must free returned array with `mayaqua_free_string_array`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_get_interfaces(
    interfaces_out: *mut *mut *mut c_char,
    count_out: *mut c_uint,
) -> i32 {
    if interfaces_out.is_null() || count_out.is_null() {
        return -1;
    }

    match crate::platform::network_interface::get_interfaces() {
        Ok(interfaces) => {
            let count = interfaces.len();
            let mut c_strings: Vec<*mut c_char> = Vec::with_capacity(count);

            for iface in interfaces {
                match std::ffi::CString::new(iface) {
                    Ok(c_string) => c_strings.push(c_string.into_raw()),
                    Err(_) => {
                        // Clean up already allocated strings
                        for cs in c_strings {
                            let _ = std::ffi::CString::from_raw(cs);
                        }
                        return -2;
                    }
                }
            }

            let boxed = c_strings.into_boxed_slice();
            *interfaces_out = Box::into_raw(boxed) as *mut *mut c_char;
            *count_out = count as c_uint;
            0
        }
        Err(_) => -3,
    }
}

/// Free string array allocated by mayaqua_get_interfaces
/// 
/// # Safety
/// - `array` must have been allocated by `mayaqua_get_interfaces`
/// - `count` must match the count returned by `mayaqua_get_interfaces`
/// - Must only be called once per array
#[no_mangle]
pub unsafe extern "C" fn mayaqua_free_string_array(array: *mut *mut c_char, count: c_uint) {
    if !array.is_null() && count > 0 {
        let slice = slice::from_raw_parts_mut(array, count as usize);
        for i in 0..count as usize {
            if !slice[i].is_null() {
                let _ = std::ffi::CString::from_raw(slice[i]);
            }
        }
        let _ = Vec::from_raw_parts(array, count as usize, count as usize);
    }
}

// ============================================================================
// Phase 3.1 FFI Exports - Config Module
// ============================================================================

/// Opaque handle for VpnConfig
#[repr(C)]
pub struct MayaquaConfig {
    _private: [u8; 0],
}

/// Load config from file
/// 
/// # Safety
/// - `path` must be a valid null-terminated UTF-8 string
/// - `config_out` must be valid for writes
/// - Caller must free returned config with `mayaqua_config_free`
#[no_mangle]
pub unsafe extern "C" fn mayaqua_config_load(
    path: *const c_char,
    config_out: *mut *mut MayaquaConfig,
) -> i32 {
    if path.is_null() || config_out.is_null() {
        return -1;
    }

    let path_str = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let path_buf = std::path::PathBuf::from(path_str);
    match crate::config::VpnConfig::load(&path_buf) {
        Ok(config) => {
            let boxed = Box::new(config);
            *config_out = Box::into_raw(boxed) as *mut MayaquaConfig;
            0
        }
        Err(_) => -3,
    }
}

/// Save config to file
/// 
/// # Safety
/// - `config` must be a valid Config handle
/// - `path` must be a valid null-terminated UTF-8 string
#[no_mangle]
pub unsafe extern "C" fn mayaqua_config_save(
    config: *mut MayaquaConfig,
    path: *const c_char,
) -> i32 {
    if config.is_null() || path.is_null() {
        return -1;
    }

    let cfg = &*(config as *const crate::config::VpnConfig);
    let path_str = match std::ffi::CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let path_buf = std::path::PathBuf::from(path_str);
    match cfg.save(&path_buf) {
        Ok(_) => 0,
        Err(_) => -3,
    }
}

/// Validate config
/// 
/// # Safety
/// - `config` must be a valid Config handle
#[no_mangle]
pub unsafe extern "C" fn mayaqua_config_validate(config: *mut MayaquaConfig) -> i32 {
    if config.is_null() {
        return -1;
    }

    let cfg = &*(config as *const crate::config::VpnConfig);
    match cfg.validate() {
        Ok(_) => 0,
        Err(_) => -3,
    }
}

/// Get string field from config
/// 
/// # Safety
/// - `config` must be a valid Config handle
/// - `field` must be a valid null-terminated UTF-8 string
/// - `value_out` must be valid for writes
/// - Caller must free returned string with `mayaqua_free_string`
/// - Returns -4 if field is None
#[no_mangle]
pub unsafe extern "C" fn mayaqua_config_get_string(
    config: *mut MayaquaConfig,
    field: *const c_char,
    value_out: *mut *mut c_char,
) -> i32 {
    if config.is_null() || field.is_null() || value_out.is_null() {
        return -1;
    }

    let cfg = &*(config as *const crate::config::VpnConfig);
    let field_str = match std::ffi::CStr::from_ptr(field).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let value_opt = match field_str {
        "server" => cfg.server.as_ref(),
        "hub" => cfg.hub.as_ref(),
        "account" => cfg.account.as_ref(),
        "username" => cfg.username.as_ref(),
        "password" => cfg.password.as_ref(),
        "password_hash" => cfg.password_hash.as_ref(),
        "static_ipv4" => cfg.static_ipv4.as_ref(),
        "static_ipv4_netmask" => cfg.static_ipv4_netmask.as_ref(),
        "static_ipv4_gateway" => cfg.static_ipv4_gateway.as_ref(),
        "static_ipv6" => cfg.static_ipv6.as_ref(),
        "static_ipv6_gateway" => cfg.static_ipv6_gateway.as_ref(),
        _ => return -3,
    };

    match value_opt {
        Some(val) => {
            match std::ffi::CString::new(val.clone()) {
                Ok(c_string) => {
                    *value_out = c_string.into_raw();
                    0
                }
                Err(_) => -2,
            }
        }
        None => -4, // Field is None
    }
}

/// Get integer field from config
/// 
/// # Safety
/// - `config` must be a valid Config handle
/// - `field` must be a valid null-terminated UTF-8 string
/// - `value_out` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_config_get_int(
    config: *mut MayaquaConfig,
    field: *const c_char,
    value_out: *mut i32,
) -> i32 {
    if config.is_null() || field.is_null() || value_out.is_null() {
        return -1;
    }

    let cfg = &*(config as *const crate::config::VpnConfig);
    let field_str = match std::ffi::CStr::from_ptr(field).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let value = match field_str {
        "port" => cfg.port as i32,
        "max_connection" => cfg.max_connection as i32,
        "max_reconnect_attempts" => cfg.max_reconnect_attempts as i32,
        "min_backoff" => cfg.min_backoff as i32,
        "max_backoff" => cfg.max_backoff as i32,
        "static_ipv6_prefix" => cfg.static_ipv6_prefix.unwrap_or(0) as i32,
        "recv_buffer_slots" => cfg.performance.recv_buffer_slots as i32,
        "send_buffer_slots" => cfg.performance.send_buffer_slots as i32,
        _ => return -3,
    };

    *value_out = value;
    0
}

/// Get boolean field from config
/// 
/// # Safety
/// - `config` must be a valid Config handle
/// - `field` must be a valid null-terminated UTF-8 string
/// - `value_out` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn mayaqua_config_get_bool(
    config: *mut MayaquaConfig,
    field: *const c_char,
    value_out: *mut bool,
) -> i32 {
    if config.is_null() || field.is_null() || value_out.is_null() {
        return -1;
    }

    let cfg = &*(config as *const crate::config::VpnConfig);
    let field_str = match std::ffi::CStr::from_ptr(field).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let value = match field_str {
        "use_encrypt" => cfg.use_encrypt,
        "use_compress" => cfg.use_compress,
        "reconnect" => cfg.reconnect,
        _ => return -3,
    };

    *value_out = value;
    0
}

/// Free config handle
/// 
/// # Safety
/// - `config` must be a valid Config handle
/// - Must only be called once per config
#[no_mangle]
pub unsafe extern "C" fn mayaqua_config_free(config: *mut MayaquaConfig) {
    if !config.is_null() {
        let _ = Box::from_raw(config as *mut crate::config::VpnConfig);
    }
}
