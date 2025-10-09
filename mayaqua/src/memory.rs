//! Memory management functions
//! 
//! Rust ports of Mayaqua Memory.c functions with automatic memory safety.

use std::alloc::{self, Layout};
use std::ptr;

/// Allocate memory (equivalent to Malloc)
/// 
/// Returns a pointer to allocated memory, or null on failure.
/// Memory is NOT zero-initialized unless you use zero_malloc.
#[inline]
pub fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    
    let layout = match Layout::array::<u8>(size) {
        Ok(layout) => layout,
        Err(_) => return ptr::null_mut(),
    };
    
    unsafe { alloc::alloc(layout) }
}

/// Allocate zero-initialized memory (equivalent to ZeroMalloc)
#[inline]
pub fn zero_malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    
    let layout = match Layout::array::<u8>(size) {
        Ok(layout) => layout,
        Err(_) => return ptr::null_mut(),
    };
    
    unsafe { alloc::alloc_zeroed(layout) }
}

/// Free memory (equivalent to Free)
/// 
/// # Safety
/// - `ptr` must have been allocated by malloc or zero_malloc
/// - `size` must be the original allocation size
#[inline]
pub unsafe fn free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    
    let layout = match Layout::array::<u8>(size) {
        Ok(layout) => layout,
        Err(_) => return,
    };
    
    alloc::dealloc(ptr, layout);
}

/// Zero memory (equivalent to Zero/ZeroMem)
#[inline]
pub fn zero_mem(ptr: *mut u8, size: usize) {
    if !ptr.is_null() && size > 0 {
        unsafe {
            ptr::write_bytes(ptr, 0, size);
        }
    }
}

/// Copy memory (equivalent to Copy)
/// 
/// # Safety
/// - Both pointers must be valid for `size` bytes
/// - Regions may overlap (uses memmove semantics)
#[inline]
pub unsafe fn copy_mem(dst: *mut u8, src: *const u8, size: usize) {
    if !dst.is_null() && !src.is_null() && size > 0 {
        ptr::copy(src, dst, size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malloc_free() {
        let ptr = malloc(1024);
        assert!(!ptr.is_null());
        unsafe {
            free(ptr, 1024);
        }
    }

    #[test]
    fn test_zero_malloc() {
        let ptr = zero_malloc(1024);
        assert!(!ptr.is_null());
        
        // Verify it's zeroed
        unsafe {
            for i in 0..1024 {
                assert_eq!(*ptr.add(i), 0);
            }
            free(ptr, 1024);
        }
    }

    #[test]
    fn test_zero_mem() {
        let ptr = malloc(1024);
        assert!(!ptr.is_null());
        
        // Fill with non-zero
        unsafe {
            ptr::write_bytes(ptr, 0xFF, 1024);
        }
        
        // Zero it
        zero_mem(ptr, 1024);
        
        // Verify
        unsafe {
            for i in 0..1024 {
                assert_eq!(*ptr.add(i), 0);
            }
            free(ptr, 1024);
        }
    }

    #[test]
    fn test_copy_mem() {
        let src = zero_malloc(1024);
        let dst = malloc(1024);
        
        unsafe {
            // Fill source with pattern
            for i in 0..1024 {
                *src.add(i) = (i % 256) as u8;
            }
            
            // Copy
            copy_mem(dst, src, 1024);
            
            // Verify
            for i in 0..1024 {
                assert_eq!(*dst.add(i), (i % 256) as u8);
            }
            
            free(src, 1024);
            free(dst, 1024);
        }
    }
}
