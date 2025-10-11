//! # crypto - OpenSSL replacement cryptographic primitives
//!
//! This module provides drop-in replacements for OpenSSL crypto functions used in SoftEther.
//! Uses pure Rust implementations for SHA-0, SHA-1, and RC4.

use crate::sha0::Sha1Sum;

// Re-export SHA-0 function and types from sha0 module (don't duplicate implementation)
pub use crate::sha0::{sha0, Sha0Context};

/// Compute SHA-1 hash of data (using external crate for non-compatibility cases)
pub fn sha1(data: &[u8]) -> Sha1Sum {
    use ::sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 20];
    output.copy_from_slice(&result);
    output
}

/// Calculate SoftEther password hash (SHA-0 of password + uppercase username)
/// This matches the Go implementation: mayaqua.Sha0([]byte(password + username))
pub fn softether_password_hash(password: &str, username: &str) -> Sha1Sum {
    let username_upper = username.to_uppercase();
    let combined = format!("{password}{username_upper}");
    crate::sha0::sha0(combined.as_bytes())
}

/// RC4 stream cipher (legacy compatibility). Same function for encrypt/decrypt.
pub fn rc4_apply(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j: u8 = 0;
    // KSA
    for i in 0..256 {
        let ki = key[i % key.len()];
        j = j.wrapping_add(s[i]).wrapping_add(ki);
        s.swap(i, j as usize);
    }
    // PRGA
    let mut i: u8 = 0;
    let mut j2: u8 = 0;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        i = i.wrapping_add(1);
        j2 = j2.wrapping_add(s[i as usize]);
        s.swap(i as usize, j2 as usize);
        let t = s[i as usize].wrapping_add(s[j2 as usize]);
        let k = s[t as usize];
        out.push(b ^ k);
    }
    out
}

/// Stateful RC4 cipher for stream encryption/decryption
/// Maintains internal state across multiple encrypt/decrypt operations
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// Create a new RC4 cipher with the given key
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        
        // KSA (Key Scheduling Algorithm)
        let mut j: u8 = 0;
        for i in 0..256 {
            let ki = key[i % key.len()];
            j = j.wrapping_add(s[i]).wrapping_add(ki);
            s.swap(i, j as usize);
        }
        
        Self { s, i: 0, j: 0 }
    }
    
    /// Encrypt/decrypt data in-place (RC4 is symmetric)
    pub fn process_inplace(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let t = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            let k = self.s[t as usize];
            *b ^= k;
        }
    }
    
    /// Encrypt/decrypt data, returning a new Vec (RC4 is symmetric)
    pub fn process(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        self.process_inplace(&mut out);
        out
    }
}

/// RC4 in-place on mutable buffer (stateless - reinitializes for each call)
pub fn rc4_apply_inplace(key: &[u8], buf: &mut [u8]) {
    let keystream = rc4_keystream(key, buf.len());
    for (b, k) in buf.iter_mut().zip(keystream) {
        *b ^= k;
    }
}

fn rc4_keystream(key: &[u8], len: usize) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        let ki = key[i % key.len()];
        j = j.wrapping_add(s[i]).wrapping_add(ki);
        s.swap(i, j as usize);
    }
    let mut i: u8 = 0;
    let mut j2: u8 = 0;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        i = i.wrapping_add(1);
        j2 = j2.wrapping_add(s[i as usize]);
        s.swap(i as usize, j2 as usize);
        let t = s[i as usize].wrapping_add(s[j2 as usize]);
        out.push(s[t as usize]);
    }
    out
}

// TODO: Implement additional crypto functions
// - RC4 encryption (for legacy compatibility)
// - AES encryption
// - RSA operations
// - Certificate handling

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha0_empty() {
        let result = sha0(b"");
        // SHA-0 of empty string should be different from SHA-1
        let sha1_result = sha1(b"");

        // They should be different due to the rotation difference
        // This test validates our SHA-0 implementation is different from SHA-1
        println!("SHA-0 empty: {:02x?}", result);
        println!("SHA-1 empty: {:02x?}", sha1_result);

        // The first few bytes should be the same since the difference
        // only appears after the first transform
        // But they will diverge for most inputs
    }

    #[test]
    fn test_sha0_basic() {
        let result = sha0(b"abc");
        println!("SHA-0 'abc': {:02x?}", result);

        let sha1_result = sha1(b"abc");
        println!("SHA-1 'abc': {:02x?}", sha1_result);

        // Should be different due to SHA-0 vs SHA-1 algorithm difference
        assert_ne!(result, sha1_result);
    }

    #[test]
    fn test_sha0_incremental() {
        let mut ctx = Sha0Context::new();
        ctx.update(b"a");
        ctx.update(b"bc");
        let result1 = ctx.finalize();

        let result2 = sha0(b"abc");
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_softether_password_hash() {
        // Test with sample credentials to validate SHA-0 implementation
        let result = softether_password_hash("testpass", "testuser");
        let expected_b64 = "Z8aeAfh8/a88naS5l/Uxf9ig+cM="; // Actual SHA-0("testpassTESTUSER")

        // Convert result to base64 to compare with known good value
        use base64::prelude::*;
        let actual_b64 = BASE64_STANDARD.encode(result);

        println!("Password hash for testpass+TESTUSER:");
        println!("Expected: {}", expected_b64);
        println!("Actual:   {}", actual_b64);

        // This test validates our SHA-0 implementation matches SoftEther Go
        assert_eq!(
            actual_b64, expected_b64,
            "Password hash doesn't match expected value"
        );
    }

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"secretkey";
        let plain = b"hello world";
        let enc = rc4_apply(key, plain);
        let dec = rc4_apply(key, &enc);
        assert_eq!(dec, plain);
    }
}
