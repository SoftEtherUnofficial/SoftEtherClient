//! Buffer management (BUF structure)
//!
//! Rust port of Mayaqua's BUF structure with automatic memory management.

use crate::types::UINT;

/// Dynamically sized buffer (equivalent to C BUF structure)
///
/// ```c
/// struct BUF {
///     void *Buf;
///     UINT Size;
///     UINT SizeReserved;
///     UINT Current;
/// };
/// ```
#[derive(Debug)]
pub struct Buffer {
    data: Vec<u8>,
    current: usize, // Read/write position
}

impl Buffer {
    /// Create a new empty buffer (equivalent to NewBuf)
    #[inline]
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            current: 0,
        }
    }

    /// Create a buffer with initial capacity
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            current: 0,
        }
    }

    /// Create buffer from existing data (equivalent to NewBufFromMemory)
    #[inline]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            current: 0,
        }
    }

    /// Write data to buffer
    #[inline]
    pub fn write(&mut self, data: &[u8]) -> usize {
        self.data.extend_from_slice(data);
        data.len()
    }

    /// Read data from buffer at current position
    #[inline]
    pub fn read(&mut self, size: usize) -> Option<&[u8]> {
        if self.current + size > self.data.len() {
            return None;
        }

        let start = self.current;
        self.current += size;
        Some(&self.data[start..self.current])
    }

    /// Get buffer size
    #[inline]
    pub fn size(&self) -> UINT {
        self.data.len() as UINT
    }

    /// Get reserved size (capacity)
    #[inline]
    pub fn capacity(&self) -> UINT {
        self.data.capacity() as UINT
    }

    /// Get current position
    #[inline]
    pub fn position(&self) -> UINT {
        self.current as UINT
    }

    /// Set current position (seek)
    #[inline]
    pub fn seek(&mut self, pos: usize) {
        self.current = pos.min(self.data.len());
    }

    /// Get buffer data as slice
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable buffer data
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get raw pointer (for FFI)
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    /// Get raw mutable pointer (for FFI)
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Clear buffer contents
    #[inline]
    pub fn clear(&mut self) {
        self.data.clear();
        self.current = 0;
    }

    /// Clone the buffer data into a new buffer
    #[inline]
    pub fn clone_buffer(&self) -> Self {
        Self {
            data: self.data.clone(),
            current: self.current,
        }
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Buffer {
    fn clone(&self) -> Self {
        self.clone_buffer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_buffer() {
        let buf = Buffer::new();
        assert_eq!(buf.size(), 0);
        assert_eq!(buf.position(), 0);
    }

    #[test]
    fn test_write() {
        let mut buf = Buffer::new();
        let data = b"Hello, World!";
        let written = buf.write(data);
        assert_eq!(written, data.len());
        assert_eq!(buf.size(), data.len() as UINT);
        assert_eq!(buf.as_slice(), data);
    }

    #[test]
    fn test_read() {
        let mut buf = Buffer::from_bytes(b"Hello, World!");

        let data = buf.read(5).unwrap();
        assert_eq!(data, b"Hello");
        assert_eq!(buf.position(), 5);

        let data = buf.read(7).unwrap();
        assert_eq!(data, b", World");
        assert_eq!(buf.position(), 12);
    }

    #[test]
    fn test_seek() {
        let mut buf = Buffer::from_bytes(b"Hello, World!");
        buf.seek(7);
        assert_eq!(buf.position(), 7);

        let data = buf.read(5).unwrap();
        assert_eq!(data, b"World");
    }

    #[test]
    fn test_capacity() {
        let buf = Buffer::with_capacity(1024);
        assert!(buf.capacity() >= 1024);
    }

    #[test]
    fn test_clear() {
        let mut buf = Buffer::from_bytes(b"Hello");
        buf.clear();
        assert_eq!(buf.size(), 0);
        assert_eq!(buf.position(), 0);
    }
}
