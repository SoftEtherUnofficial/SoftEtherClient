//! String utilities for SoftEther VPN
//!
//! Provides UTF-8/UTF-16 conversion, string manipulation, and C string compatibility
//! to match the behavior of SoftEther C implementation (Str.c/Str.h)

use crate::error::{Error, Result};
use std::ffi::{CStr, CString};

/// Convert UTF-8 string to UTF-16 (wide string for Windows/C compatibility)
/// Returns Vec<u16> with null terminator
pub fn utf8_to_utf16(s: &str) -> Vec<u16> {
    let mut utf16: Vec<u16> = s.encode_utf16().collect();
    utf16.push(0); // Add null terminator
    utf16
}

/// Convert UTF-16 to UTF-8 string
/// Strips null terminator if present
pub fn utf16_to_utf8(utf16: &[u16]) -> Result<String> {
    // Find null terminator and truncate
    let end = utf16.iter().position(|&c| c == 0).unwrap_or(utf16.len());
    let utf16_slice = &utf16[..end];
    
    String::from_utf16(utf16_slice)
        .map_err(|_e| Error::InvalidString)
}

/// Convert Rust string to C string (null-terminated)
pub fn to_cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| Error::InvalidString)
}

/// Convert C string to Rust string (UTF-8)
/// # Safety
/// Caller must ensure ptr is valid null-terminated C string
pub unsafe fn from_cstring(ptr: *const i8) -> Result<String> {
    if ptr.is_null() {
        return Err(Error::InvalidParameter);
    }
    
    let c_str = CStr::from_ptr(ptr);
    c_str.to_str()
        .map(|s| s.to_string())
        .map_err(|_| Error::InvalidString)
}

/// Check if string contains only printable ASCII characters
pub fn is_printable_ascii(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii() && (c.is_ascii_graphic() || c.is_ascii_whitespace()))
}

/// Check if string is "safe" (alphanumeric + common symbols)
/// Matches SoftEther C IsSafeStr() behavior
pub fn is_safe_str(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() 
            || c == '_' 
            || c == '-' 
            || c == '.' 
            || c == '@' 
            || c == ':'
    })
}

/// Replace non-safe characters with specified replacement
pub fn make_safe_str(s: &str, replace: char) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '@' || c == ':' {
                c
            } else {
                replace
            }
        })
        .collect()
}

/// Case-insensitive string comparison
pub fn str_cmpi(s1: &str, s2: &str) -> i32 {
    let s1_lower = s1.to_lowercase();
    let s2_lower = s2.to_lowercase();
    
    if s1_lower < s2_lower {
        -1
    } else if s1_lower > s2_lower {
        1
    } else {
        0
    }
}

/// Case-sensitive string search
/// Returns position of keyword in string, or None if not found
pub fn search_str(string: &str, keyword: &str, start: usize) -> Option<usize> {
    if start >= string.len() {
        return None;
    }
    
    string[start..].find(keyword).map(|pos| start + pos)
}

/// Case-insensitive string search
pub fn search_stri(string: &str, keyword: &str, start: usize) -> Option<usize> {
    if start >= string.len() {
        return None;
    }
    
    let string_lower = string[start..].to_lowercase();
    let keyword_lower = keyword.to_lowercase();
    
    string_lower.find(&keyword_lower).map(|pos| start + pos)
}

/// Replace all occurrences of old_keyword with new_keyword (case-sensitive)
pub fn replace_str(string: &str, old_keyword: &str, new_keyword: &str) -> String {
    string.replace(old_keyword, new_keyword)
}

/// Replace all occurrences of old_keyword with new_keyword (case-insensitive)
pub fn replace_stri(string: &str, old_keyword: &str, new_keyword: &str) -> String {
    let old_lower = old_keyword.to_lowercase();
    let mut result = String::with_capacity(string.len());
    let mut remaining = string;
    
    while !remaining.is_empty() {
        let remaining_lower = remaining.to_lowercase();
        
        if let Some(pos) = remaining_lower.find(&old_lower) {
            result.push_str(&remaining[..pos]);
            result.push_str(new_keyword);
            remaining = &remaining[pos + old_keyword.len()..];
        } else {
            result.push_str(remaining);
            break;
        }
    }
    
    result
}

/// Split string into lines (by \n or \r\n)
pub fn str_to_lines(s: &str) -> Vec<String> {
    s.lines().map(|line| line.to_string()).collect()
}

/// Split string by delimiter into tokens
pub fn tokenize(s: &str, delimiter: &str) -> Vec<String> {
    s.split(delimiter)
        .map(|token| token.to_string())
        .collect()
}

/// Trim whitespace from both ends
pub fn trim_str(s: &str) -> String {
    s.trim().to_string()
}

/// Convert binary data to hex string
pub fn bin_to_str(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join("")
}

/// Convert hex string to binary data
pub fn str_to_bin(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::InvalidParameter);
    }
    
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Error::InvalidParameter)
        })
        .collect()
}

/// Format MAC address from bytes (e.g., "00:11:22:33:44:55")
pub fn mac_to_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse MAC address string to bytes
pub fn str_to_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(&[':', '-'][..]).collect();
    
    if parts.len() != 6 {
        return Err(Error::InvalidParameter);
    }
    
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| Error::InvalidParameter)?;
    }
    
    Ok(mac)
}

/// Check if string starts with prefix (case-insensitive)
pub fn starts_with_i(s: &str, prefix: &str) -> bool {
    s.to_lowercase().starts_with(&prefix.to_lowercase())
}

/// Check if string ends with suffix (case-insensitive)
pub fn ends_with_i(s: &str, suffix: &str) -> bool {
    s.to_lowercase().ends_with(&suffix.to_lowercase())
}

/// Truncate string to maximum length, add ellipsis if truncated
pub fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s[..max_len].to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_to_utf16() {
        let s = "Hello, 世界";
        let utf16 = utf8_to_utf16(s);
        
        // Should have null terminator
        assert_eq!(utf16.last(), Some(&0));
        
        // Convert back (without null terminator)
        let back = utf16_to_utf8(&utf16[..utf16.len() - 1]).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn test_utf16_to_utf8() {
        let utf16 = vec![0x0048, 0x0065, 0x006C, 0x006C, 0x006F, 0x0000]; // "Hello\0"
        let result = utf16_to_utf8(&utf16).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_is_printable_ascii() {
        assert!(is_printable_ascii("Hello World 123"));
        assert!(is_printable_ascii("test@example.com"));
        assert!(!is_printable_ascii("Hello\x00World"));
        assert!(!is_printable_ascii("Hello\x01"));
    }

    #[test]
    fn test_is_safe_str() {
        assert!(is_safe_str("test123"));
        assert!(is_safe_str("user@example.com"));
        assert!(is_safe_str("192.168.1.1:443"));
        assert!(!is_safe_str("test space"));
        assert!(!is_safe_str("test/path"));
        assert!(!is_safe_str("test\\path"));
    }

    #[test]
    fn test_make_safe_str() {
        assert_eq!(make_safe_str("test space", '_'), "test_space");
        assert_eq!(make_safe_str("path/to/file", '_'), "path_to_file");
        assert_eq!(make_safe_str("test@ok.com", '_'), "test@ok.com");
    }

    #[test]
    fn test_str_cmpi() {
        assert_eq!(str_cmpi("Hello", "hello"), 0);
        assert_eq!(str_cmpi("abc", "ABC"), 0);
        assert!(str_cmpi("abc", "xyz") < 0);
        assert!(str_cmpi("xyz", "abc") > 0);
    }

    #[test]
    fn test_search_str() {
        assert_eq!(search_str("Hello World", "World", 0), Some(6));
        assert_eq!(search_str("Hello World", "world", 0), None); // case-sensitive
        assert_eq!(search_str("Hello World", "Hello", 5), None); // past start
        assert_eq!(search_str("test test", "test", 1), Some(5));
    }

    #[test]
    fn test_search_stri() {
        assert_eq!(search_stri("Hello World", "world", 0), Some(6));
        assert_eq!(search_stri("Hello World", "WORLD", 0), Some(6));
        assert_eq!(search_stri("Hello World", "hello", 0), Some(0));
    }

    #[test]
    fn test_replace_str() {
        assert_eq!(replace_str("hello world", "world", "rust"), "hello rust");
        assert_eq!(replace_str("test test", "test", "demo"), "demo demo");
        assert_eq!(replace_str("Hello World", "world", "rust"), "Hello World"); // case-sensitive
    }

    #[test]
    fn test_replace_stri() {
        assert_eq!(replace_stri("Hello World", "world", "rust"), "Hello rust");
        assert_eq!(replace_stri("Hello World", "WORLD", "rust"), "Hello rust");
        assert_eq!(replace_stri("test TEST", "test", "demo"), "demo demo");
    }

    #[test]
    fn test_str_to_lines() {
        let lines = str_to_lines("line1\nline2\nline3");
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
        
        let lines = str_to_lines("line1\r\nline2\r\nline3");
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn test_tokenize() {
        let tokens = tokenize("a,b,c,d", ",");
        assert_eq!(tokens, vec!["a", "b", "c", "d"]);
        
        let tokens = tokenize("one:two:three", ":");
        assert_eq!(tokens, vec!["one", "two", "three"]);
    }

    #[test]
    fn test_bin_to_str() {
        let data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        assert_eq!(bin_to_str(&data), "0123456789abcdef");
    }

    #[test]
    fn test_str_to_bin() {
        let result = str_to_bin("0123456789abcdef").unwrap();
        assert_eq!(result, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
        
        let result = str_to_bin("AABBCCDD").unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        
        // Invalid hex
        assert!(str_to_bin("xyz").is_err());
        assert!(str_to_bin("123").is_err()); // odd length
    }

    #[test]
    fn test_mac_to_str() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(mac_to_str(&mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_str_to_mac() {
        let mac = str_to_mac("00:11:22:33:44:55").unwrap();
        assert_eq!(mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        
        let mac = str_to_mac("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        
        // Invalid formats
        assert!(str_to_mac("invalid").is_err());
        assert!(str_to_mac("00:11:22:33:44").is_err()); // too short
    }

    #[test]
    fn test_starts_with_i() {
        assert!(starts_with_i("Hello World", "hello"));
        assert!(starts_with_i("Hello World", "HELLO"));
        assert!(!starts_with_i("Hello World", "world"));
    }

    #[test]
    fn test_ends_with_i() {
        assert!(ends_with_i("Hello World", "world"));
        assert!(ends_with_i("Hello World", "WORLD"));
        assert!(!ends_with_i("Hello World", "hello"));
    }

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("Hello World", 20), "Hello World");
        assert_eq!(truncate_str("Hello World", 8), "Hello...");
        assert_eq!(truncate_str("Hello World", 5), "He...");
        assert_eq!(truncate_str("Hi", 10), "Hi");
    }

    #[test]
    fn test_to_cstring() {
        let s = "Hello, World!";
        let cstring = to_cstring(s).unwrap();
        assert_eq!(cstring.to_str().unwrap(), s);
        
        // Null byte in string should fail
        let result = to_cstring("Hello\0World");
        assert!(result.is_err());
    }
}
