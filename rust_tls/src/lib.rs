//! SoftEther TLS Bridge - FFI wrapper around rustls-ffi
//! 
//! This provides a minimal FFI interface to rustls for use in SoftEtherZig.
//! It re-exports the rustls-ffi C API for use in Zig.

// Re-export rustls-ffi's public API
// This makes all rustls-ffi functions available to our library consumers
pub use rustls_ffi::*;

use std::os::raw::{c_char, c_int};

/// Initialize rustls with default settings for SoftEther
/// Returns 0 on success, negative on error
#[no_mangle]
pub extern "C" fn softether_tls_init() -> c_int {
    // Any global initialization if needed
    0
}

/// Version information
#[no_mangle]
pub extern "C" fn softether_tls_version() -> *const c_char {
    static VERSION: &[u8] = b"SoftEther-TLS 0.1.0 (rustls 0.23)\0";
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert_eq!(softether_tls_init(), 0);
    }

    #[test]
    fn test_version() {
        use std::ffi::CStr;
        let version = unsafe { CStr::from_ptr(softether_tls_version()) };
        assert!(version.to_str().unwrap().contains("SoftEther-TLS"));
    }
}
