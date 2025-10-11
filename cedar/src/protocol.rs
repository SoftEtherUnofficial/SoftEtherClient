//! Protocol Module
//!
//! Wire protocol implementation for SoftEther VPN packet format.

use mayaqua::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Protocol version - SoftEther 4.44 (same as working implementations)
pub const PROTOCOL_VERSION: u32 = 444;

/// Cedar protocol signature (not used in HTTP mode)
pub const CEDAR_SIGNATURE: &str = "SE-VPN4-PROTOCOL";

/// Digital watermark - must be prepended to HTTP POST body
/// This is a GIF89a image used as a watermark for authentication
pub const WATERMARK: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0xC8, 0x00, 0x33, 0x00, 0xF2, 0x00, 0x00, 0x36, 0x37, 0x34,
    0x79, 0x68, 0x54, 0x80, 0x80, 0x80, 0xAF, 0x7F, 0x5B, 0xB3, 0xA8, 0x9D, 0xD5, 0xD5, 0xD4, 0xFF,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x33, 0x00, 0x00, 0x03,
    0xFE, 0x08, 0x1A, 0xDC, 0x34, 0x0A, 0x04, 0x41, 0x6B, 0x65, 0x31, 0x4F, 0x11, 0x80, 0xF9, 0x60,
    0x28, 0x8E, 0x64, 0x69, 0x9E, 0x68, 0xAA, 0xAE, 0x6C, 0xEB, 0x9A, 0x4B, 0xE3, 0x0C, 0x0C, 0x25,
    0x6F, 0x56, 0xA7, 0xE9, 0xD2, 0xEB, 0xFF, 0xC0, 0xA0, 0x70, 0xC8, 0x8A, 0xDC, 0x2C, 0x9C, 0xC6,
    0x05, 0xC7, 0x31, 0x66, 0x24, 0x04, 0xA2, 0x74, 0x4A, 0xAD, 0x4E, 0x05, 0xB1, 0x0D, 0x61, 0xCB,
    0x25, 0xD4, 0xB8, 0x49, 0x1B, 0xE6, 0x19, 0xB1, 0x9A, 0xCF, 0xE8, 0xF4, 0x07, 0x2B, 0x11, 0x74,
    0x09, 0x85, 0x78, 0xFC, 0x0D, 0x6E, 0x90, 0x9F, 0xEA, 0x02, 0x81, 0x12, 0x35, 0xEF, 0x29, 0x6A,
    0x81, 0x2C, 0x04, 0x0A, 0x6E, 0x5C, 0x72, 0x88, 0x7A, 0x7A, 0x6F, 0x4D, 0x77, 0x19, 0x25, 0x71,
    0x16, 0x71, 0x2F, 0x05, 0x92, 0x06, 0x95, 0x80, 0x22, 0x48, 0x16, 0x7D, 0x98, 0x02, 0x9A, 0x7C,
    0x82, 0x06, 0x16, 0x23, 0x7F, 0x02, 0x05, 0x6B, 0x48, 0x70, 0x23, 0x15, 0x7D, 0x1F, 0x98, 0xA8,
    0x21, 0x7F, 0x87, 0x89, 0xB5, 0x8B, 0x7C, 0x7B, 0x3C, 0x8E, 0x23, 0x9E, 0x9B, 0xAE, 0x2B, 0xAD,
    0x20, 0xA6, 0xAC, 0x9B, 0x14, 0xB1, 0xC3, 0x21, 0x15, 0xB1, 0x81, 0x9E, 0x22, 0x9E, 0xAE, 0xC5,
    0x99, 0x20, 0x96, 0xAF, 0xC6, 0xA0, 0x70, 0xB6, 0xB6, 0x5B, 0x03, 0x1C, 0x16, 0x8E, 0x65, 0x21,
    0xBD, 0x9B, 0xCB, 0x2A, 0x9E, 0xCB, 0xC1, 0xE1, 0xD1, 0xA7, 0xA9, 0x6E, 0xE9, 0xD6, 0x82, 0xCD,
    0xC9, 0xCA, 0xD5, 0xD1, 0xAE, 0xBD, 0xCB, 0x7F, 0xAC, 0xB4, 0xD9, 0x73, 0x34, 0x37, 0x76, 0xDF,
    0x3C, 0xC8, 0x9A, 0x07, 0x42, 0x4E, 0x38, 0x4C, 0xAB, 0x0A, 0xFA, 0x12, 0x17, 0xEA, 0x52, 0x05,
    0x12, 0x0C, 0xDB, 0x35, 0xD3, 0xF3, 0xCE, 0xD9, 0x2C, 0x72, 0x13, 0xB7, 0x40, 0x22, 0xE8, 0xFE,
    0xB0, 0x61, 0xC7, 0x4F, 0xEC, 0x40, 0x7E, 0x94, 0xF6, 0x50, 0x13, 0x36, 0x83, 0xA8, 0x6A, 0x79,
    0xF9, 0x77, 0xE3, 0x1B, 0x28, 0x69, 0x1B, 0x55, 0x09, 0x1B, 0x67, 0x8A, 0x1A, 0xA9, 0x52, 0xC5,
    0x50, 0x71, 0x42, 0x82, 0x31, 0xDA, 0xB4, 0x56, 0x15, 0x9D, 0x71, 0xBC, 0x19, 0xF2, 0x27, 0x49,
    0x3E, 0xEF, 0x3C, 0x4E, 0xDB, 0x92, 0xED, 0x52, 0xBF, 0x01, 0xFE, 0x02, 0x44, 0x95, 0xB1, 0x6B,
    0xA0, 0x32, 0x72, 0x0A, 0x25, 0x72, 0x1C, 0xE5, 0x11, 0x99, 0x3C, 0x5F, 0x33, 0x61, 0x72, 0x75,
    0x93, 0x92, 0x28, 0x42, 0xA3, 0x7D, 0x72, 0x9A, 0x20, 0x68, 0x8A, 0x1C, 0x3A, 0x73, 0x3F, 0xE1,
    0x84, 0x82, 0x55, 0xEA, 0xE4, 0xA5, 0xBB, 0x89, 0xDE, 0x4C, 0x60, 0x30, 0x75, 0x0C, 0x9E, 0x97,
    0xD4, 0x8C, 0xC6, 0x32, 0x3B, 0xB4, 0x64, 0xD6, 0x71, 0x46, 0x45, 0x7E, 0x3C, 0x67, 0xB8, 0x30,
    0x20, 0xB8, 0x29, 0x82, 0x3D, 0x73, 0xE7, 0x93, 0x1E, 0xAA, 0x3F, 0x91, 0xD6, 0x89, 0x60, 0x9A,
    0xC8, 0x69, 0x36, 0xA8, 0x1B, 0xA4, 0xFE, 0x23, 0x03, 0x51, 0xED, 0xC7, 0xC4, 0x87, 0x19, 0xB7,
    0xA3, 0xCC, 0x13, 0x2D, 0x65, 0xD5, 0xB1, 0x22, 0x4A, 0xDE, 0xBA, 0xF6, 0xA1, 0x57, 0x7A, 0x0B,
    0xB3, 0x96, 0x3D, 0x95, 0xAF, 0x2E, 0x4A, 0xBC, 0x2A, 0xB9, 0x25, 0x61, 0x09, 0x10, 0x1C, 0x24,
    0x53, 0x7D, 0xBC, 0xA2, 0x33, 0xE0, 0x15, 0x72, 0x58, 0xC5, 0xAF, 0xAD, 0x8A, 0x84, 0x5C, 0x13,
    0xF1, 0xED, 0x13, 0xE6, 0x68, 0x57, 0x3F, 0x85, 0xB5, 0xF7, 0x58, 0xC3, 0xB2, 0x3A, 0xA7, 0x54,
    0xB9, 0x87, 0x86, 0x98, 0xBD, 0xA3, 0x8D, 0xD7, 0xCE, 0x44, 0xD4, 0xF1, 0x74, 0xDA, 0x44, 0x85,
    0x06, 0x25, 0x7C, 0x54, 0xEC, 0x57, 0xE8, 0x26, 0x18, 0xFE, 0x2A, 0xBA, 0xFE, 0xB9, 0xFE, 0xE6,
    0xCD, 0x88, 0x00, 0x57, 0x0B, 0x54, 0xFE, 0x20, 0x31, 0x1A, 0x0F, 0x01, 0x14, 0x94, 0xD0, 0x61,
    0x69, 0x95, 0x14, 0x0F, 0x3B, 0xAE, 0x5C, 0x37, 0x16, 0x56, 0xCF, 0xBD, 0x14, 0xA1, 0x61, 0x12,
    0x0E, 0xA6, 0x14, 0x76, 0x88, 0xBD, 0x44, 0xA1, 0x3C, 0xF6, 0x04, 0x76, 0x90, 0x78, 0xE4, 0x81,
    0x26, 0x80, 0x70, 0x0F, 0x10, 0xA7, 0xC4, 0x61, 0x95, 0x2D, 0xC6, 0x5C, 0x45, 0xCE, 0x89, 0x28,
    0x1B, 0x34, 0x1C, 0xC5, 0xE8, 0xD1, 0x64, 0xAF, 0xAC, 0xE2, 0x1C, 0x0A, 0xE2, 0xEC, 0xE7, 0x62,
    0x4C, 0xE4, 0xB4, 0x05, 0x51, 0x80, 0x93, 0x04, 0xE7, 0x8F, 0x70, 0x01, 0x6C, 0xA1, 0x62, 0x0D,
    0xFE, 0x75, 0xF8, 0xC1, 0x76, 0x3D, 0x55, 0x54, 0x5D, 0x27, 0xD1, 0xE0, 0x23, 0x13, 0x64, 0x3B,
    0x6E, 0x67, 0xCD, 0x8E, 0x28, 0x20, 0x51, 0x5A, 0x50, 0xF2, 0x45, 0x89, 0xDF, 0x2B, 0xB5, 0x78,
    0x26, 0x07, 0x17, 0x04, 0x8A, 0xE6, 0x46, 0x5F, 0x2C, 0x1D, 0x84, 0xDC, 0x24, 0xBC, 0x60, 0xD6,
    0x1D, 0x78, 0x1F, 0x25, 0xA4, 0xE5, 0x7F, 0x75, 0x5E, 0x66, 0x18, 0x97, 0x73, 0xF0, 0x01, 0xA7,
    0x84, 0x27, 0x88, 0x58, 0xA1, 0x09, 0xDE, 0xC5, 0x05, 0x09, 0x3F, 0x88, 0xA0, 0x79, 0x24, 0x54,
    0x0F, 0x80, 0xC6, 0x66, 0x07, 0xA2, 0x44, 0x2A, 0xE9, 0xA4, 0x23, 0x22, 0x3A, 0xC7, 0x36, 0x0D,
    0x0C, 0xD0, 0x28, 0x81, 0xA0, 0xB5, 0x44, 0xE9, 0xA7, 0xA0, 0xA2, 0x71, 0x52, 0x36, 0x70, 0xE8,
    0x25, 0x55, 0x9A, 0x9C, 0x46, 0xE5, 0x8F, 0x40, 0xA1, 0xB6, 0xEA, 0x6A, 0x10, 0xA3, 0x9E, 0x49,
    0x9E, 0x92, 0xA7, 0xA6, 0xCA, 0xA9, 0xA7, 0xAF, 0xE6, 0xAA, 0xEB, 0x0A, 0xA5, 0x4E, 0x99, 0x57,
    0x1D, 0xB5, 0x6E, 0x8A, 0xEA, 0x18, 0xBB, 0x16, 0x6B, 0xAC, 0x3E, 0x71, 0x20, 0xFE, 0x48, 0x16,
    0x36, 0x5D, 0x24, 0xC1, 0xA9, 0xB0, 0x69, 0xEA, 0x70, 0xEC, 0xB4, 0xC6, 0x26, 0xD9, 0x45, 0x0D,
    0x1C, 0x8C, 0x0A, 0x2C, 0x81, 0xD0, 0x76, 0x2A, 0x2D, 0xB5, 0xE0, 0xBE, 0x9A, 0xA4, 0x21, 0xB9,
    0x0C, 0x47, 0x6E, 0x9F, 0xB5, 0xDA, 0xEA, 0x28, 0xB1, 0x25, 0x88, 0x54, 0xD2, 0x98, 0x8D, 0xD5,
    0xA7, 0x09, 0x31, 0xF6, 0x25, 0x33, 0x4A, 0x48, 0x9F, 0x80, 0x34, 0xA6, 0x0A, 0x74, 0x56, 0xA1,
    0xAF, 0x0F, 0x6D, 0x10, 0x27, 0x41, 0x1B, 0x4C, 0x79, 0xA1, 0x2E, 0x5F, 0x9D, 0xAA, 0x67, 0xEF,
    0x1A, 0xD3, 0x30, 0xBC, 0xF0, 0xBD, 0xEE, 0xDE, 0xEB, 0x30, 0x57, 0xF3, 0x36, 0x4C, 0xC2, 0xBF,
    0x12, 0x5B, 0xBC, 0x6F, 0x97, 0x16, 0x9B, 0xB1, 0xB1, 0x0A, 0x59, 0xC8, 0x30, 0x9C, 0xC8, 0xDB,
    0x68, 0x9A, 0xEA, 0x02, 0x09, 0x2B, 0x70, 0x71, 0xC7, 0x15, 0xB3, 0x92, 0x71, 0xBE, 0x1A, 0x67,
    0x3C, 0xF1, 0x57, 0xF8, 0xC2, 0x6C, 0x14, 0xC4, 0xEE, 0xB2, 0x27, 0x33, 0xBC, 0x3A, 0xC3, 0x2C,
    0x2F, 0xC4, 0xEC, 0x8C, 0x25, 0xF1, 0xBB, 0xFD, 0x7E, 0x10, 0xB2, 0x12, 0xC4, 0x91, 0x5B, 0x32,
    0x54, 0x46, 0x14, 0xB7, 0xF2, 0xCC, 0x0F, 0xCF, 0x1B, 0x71, 0xC4, 0x40, 0x83, 0xF2, 0x30, 0xC6,
    0xFA, 0x92, 0x92, 0x35, 0xC3, 0x53, 0x43, 0x87, 0x5F, 0xD7, 0xA9, 0x70, 0xDD, 0xB0, 0xCE, 0x62,
    0x57, 0x6D, 0xF6, 0x98, 0x4D, 0x8B, 0x3C, 0x32, 0xD2, 0xE4, 0xA6, 0x8A, 0xB0, 0x5F, 0x4F, 0xCB,
    0x1C, 0x75, 0xCC, 0x65, 0x57, 0xBD, 0x2F, 0xD9, 0x43, 0x3B, 0xEC, 0xF5, 0xC4, 0xF9, 0x6A, 0xED,
    0x72, 0xCB, 0x36, 0xBF, 0x2C, 0xB8, 0x62, 0x7E, 0x9F, 0x2D, 0xF8, 0x08, 0x69, 0x87, 0xB1, 0xF6,
    0x3F, 0x6B, 0xAA, 0x0B, 0x9A, 0xC2, 0x7C, 0xB7, 0xFB, 0xF7, 0xE0, 0x63, 0xFE, 0xC7, 0x27, 0x35,
    0xDD, 0x18, 0xD3, 0x6D, 0x36, 0xD4, 0x72, 0x53, 0x1E, 0xF9, 0xD4, 0x1D, 0xDB, 0x1C, 0xF8, 0xE8,
    0x24, 0x2C, 0xB0, 0x44, 0x0E, 0x2C, 0x99, 0xDE, 0x6D, 0x9A, 0x90, 0xEF, 0x1C, 0x7A, 0xCB, 0x9E,
    0xBB, 0x1E, 0x35, 0xE9, 0x79, 0xCB, 0x9D, 0x39, 0xE9, 0xF0, 0x8E, 0xAD, 0x7B, 0xD8, 0x86, 0x53,
    0x0D, 0xC8, 0xBF, 0xA0, 0x73, 0x6E, 0x80, 0x12, 0x39, 0x9C, 0x27, 0x72, 0x07, 0x3A, 0xB4, 0xED,
    0x76, 0xEB, 0x5E, 0xC3, 0x44, 0xF8, 0x4D, 0xF1, 0xEE, 0x0D, 0xD8, 0xCD, 0x7A, 0xF7, 0xFD, 0xD0,
    0xEF, 0x1A, 0xE3, 0xFD, 0x12, 0xF5, 0x60, 0x07, 0xBD, 0xB3, 0xCF, 0xA2, 0xE3, 0x9D, 0xB9, 0x01,
    0xA6, 0x9F, 0x6E, 0x7C, 0x0D, 0x18, 0xE8, 0x60, 0x2D, 0xB4, 0xEC, 0x4E, 0x1E, 0x77, 0xB8, 0x81,
    0x7C, 0x9C, 0x06, 0xF1, 0x17, 0xD8, 0x60, 0x6E, 0x68, 0x03, 0x2F, 0xA0, 0x68, 0x54, 0x2A, 0x4B,
    0xFE, 0x3E, 0xFC, 0x6A, 0x90, 0x1F, 0x1A, 0xCA, 0x57, 0xBF, 0xD0, 0x98, 0x2B, 0x09, 0xF9, 0x03,
    0x80, 0x21, 0x6E, 0xD5, 0x3A, 0x00, 0x3A, 0x30, 0x0D, 0x04, 0xB4, 0x1F, 0x0E, 0x8E, 0xE0, 0x17,
    0x23, 0x48, 0xF0, 0x11, 0x67, 0x20, 0xDC, 0xF7, 0xDE, 0xF5, 0x3F, 0xF9, 0x79, 0x29, 0x52, 0x02,
    0x7C, 0x60, 0x1A, 0x70, 0x37, 0xBB, 0xB5, 0xC0, 0xEE, 0x7D, 0x21, 0x94, 0x42, 0x0A, 0x45, 0xE8,
    0xB1, 0xD8, 0xB9, 0x6E, 0x6B, 0xE0, 0x13, 0x9A, 0x0C, 0x59, 0x96, 0xB5, 0x9C, 0xD9, 0x50, 0x6C,
    0xBE, 0x3B, 0x4A, 0xE7, 0x58, 0x28, 0x0A, 0x12, 0x26, 0x06, 0x78, 0x61, 0xEB, 0x59, 0xE4, 0x7E,
    0xF8, 0xB9, 0xDD, 0xE1, 0xAC, 0x88, 0x65, 0xAB, 0x17, 0x0F, 0x03, 0x18, 0x33, 0x0D, 0xC6, 0xCE,
    0x87, 0x14, 0xAB, 0x98, 0x0D, 0xD9, 0x33, 0xC5, 0xC0, 0xD9, 0xAD, 0x55, 0x70, 0x3B, 0x5C, 0xE2,
    0x08, 0xA1, 0x27, 0xBB, 0xBC, 0x05, 0x6F, 0x73, 0xB6, 0xD3, 0x9C, 0x14, 0x61, 0x27, 0x3A, 0xC0,
    0x69, 0x11, 0x84, 0x97, 0x73, 0xA2, 0x17, 0x83, 0xB8, 0x3B, 0xAA, 0x0D, 0xF1, 0x8B, 0x50, 0x1C,
    0xE2, 0x15, 0xCF, 0xD8, 0xC3, 0x34, 0x96, 0x10, 0x86, 0x83, 0xAB, 0x21, 0x19, 0xBD, 0x37, 0x43,
    0x0E, 0xCE, 0x4E, 0x87, 0xE3, 0xA3, 0x63, 0xB8, 0x56, 0x28, 0xC8, 0x42, 0x82, 0xB0, 0x68, 0x86,
    0x4C, 0xA4, 0x22, 0x17, 0xC9, 0xC8, 0x46, 0x3A, 0xF2, 0x91, 0x90, 0x8C, 0xA4, 0x24, 0x75, 0x95,
    0x00, 0x00, 0x3B,
];

/// Maximum packet size (16MB)
pub const MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;

/// Protocol packet
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet command/type
    pub command: String,
    /// Packet parameters (key-value pairs)
    pub params: Vec<(String, PacketValue)>,
}

/// Packet value types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketValue {
    /// Integer value
    Int(u32),
    /// 64-bit integer
    Int64(u64),
    /// String value
    String(String),
    /// Binary data
    Data(Vec<u8>),
    /// Boolean value
    Bool(bool),
}

impl Packet {
    /// Create new packet with command
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            params: Vec::new(),
        }
    }

    /// Add integer parameter
    pub fn add_int(mut self, key: impl Into<String>, value: u32) -> Self {
        self.params.push((key.into(), PacketValue::Int(value)));
        self
    }

    /// Add 64-bit integer parameter
    pub fn add_int64(mut self, key: impl Into<String>, value: u64) -> Self {
        self.params.push((key.into(), PacketValue::Int64(value)));
        self
    }

    /// Add string parameter
    pub fn add_string(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params
            .push((key.into(), PacketValue::String(value.into())));
        self
    }

    /// Add binary data parameter
    pub fn add_data(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.params.push((key.into(), PacketValue::Data(value)));
        self
    }

    /// Add boolean parameter
    pub fn add_bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.params.push((key.into(), PacketValue::Bool(value)));
        self
    }

    /// Add IPv4 address as 32-bit integer (SoftEther uses LITTLE-ENDIAN/reversed byte order!)
    /// For IP 192.168.1.19, sends as 0x1301A8C0 (bytes: 13 01 A8 C0)
    pub fn add_ip32(mut self, key: impl Into<String>, ip: [u8; 4]) -> Self {
        // SoftEther stores IPs in little-endian format (reversed bytes)
        // IP 192.168.1.19 → [192, 168, 1, 19] → 0x1301A8C0 (little-endian u32)
        let ip_u32 = u32::from_le_bytes(ip);
        self.params.push((key.into(), PacketValue::Int(ip_u32)));
        self
    }

    /// Get integer parameter
    pub fn get_int(&self, key: &str) -> Option<u32> {
        self.params.iter().find_map(|(k, v)| {
            if k == key {
                if let PacketValue::Int(val) = v {
                    Some(*val)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Get 64-bit integer parameter
    pub fn get_int64(&self, key: &str) -> Option<u64> {
        self.params.iter().find_map(|(k, v)| {
            if k == key {
                if let PacketValue::Int64(val) = v {
                    Some(*val)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Get string parameter
    pub fn get_string(&self, key: &str) -> Option<&str> {
        self.params.iter().find_map(|(k, v)| {
            if k == key {
                if let PacketValue::String(val) = v {
                    Some(val.as_str())
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Get binary data parameter
    pub fn get_data(&self, key: &str) -> Option<&[u8]> {
        self.params.iter().find_map(|(k, v)| {
            if k == key {
                if let PacketValue::Data(val) = v {
                    Some(val.as_slice())
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Get boolean parameter
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.params.iter().find_map(|(k, v)| {
            if k == key {
                if let PacketValue::Bool(val) = v {
                    Some(*val)
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    /// Serialize packet to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        // SoftEther PACK format (matching PackToBuf/WritePack from C code):
        // - Element count (4 bytes, big-endian)
        // - For each element (sorted alphabetically by key):
        //   - Key length (4 bytes, big-endian) INCLUDING null terminator
        //   - Key string WITH null terminator
        //   - Padding: 2 bytes (00 00)
        //   - Type: 1 byte
        //   - Padding: 1 byte (00)
        //   - Value data (format depends on type)

        let mut buf = Vec::new();

        // Sort parameters alphabetically by key (critical for SoftEther compatibility!)
        // IMPORTANT: SoftEther uses case-INSENSITIVE comparison (StrCmpi)!
        let mut sorted_params: Vec<_> = self.params.iter().collect();
        sorted_params.sort_by(|a, b| {
            a.0.to_lowercase().cmp(&b.0.to_lowercase())
        });

        // Write element count
        buf.extend_from_slice(&(sorted_params.len() as u32).to_be_bytes());

        // Write each parameter in alphabetical order
        for (key, value) in sorted_params {
            // Write key length (INCLUDING null terminator in count, but NOT in actual bytes!)
            // C code: WriteBufInt(len+1) then WriteBuf(str, len) - NO null byte written!
            let key_bytes = key.as_bytes();
            let key_len_with_null = key_bytes.len() + 1;
            buf.extend_from_slice(&(key_len_with_null as u32).to_be_bytes());
            
            // Write key WITHOUT null terminator (C behavior)
            buf.extend_from_slice(key_bytes);
            // DO NOT write null byte - C code writes len+1 but only outputs len bytes!

            // Write type (4 bytes BE), then num_value (4 bytes BE), then actual value data
            // C struct: [type (4 bytes)][num_value (4 bytes)][value data]
            // IMPORTANT: All integers written in BIG-ENDIAN (network byte order)
            match value {
                PacketValue::Int(v) => {
                    // VALUE_INT: type=0, num_value=1, value (4 bytes)
                    buf.extend_from_slice(&0u32.to_be_bytes());  // type = VALUE_INT (0)
                    buf.extend_from_slice(&1u32.to_be_bytes());  // num_value = 1
                    buf.extend_from_slice(&v.to_be_bytes());     // actual int value (BE)
                }
                PacketValue::Int64(v) => {
                    // VALUE_INT64: type=4, num_value=1, value (8 bytes)
                    buf.extend_from_slice(&4u32.to_be_bytes());  // type = VALUE_INT64 (4)
                    buf.extend_from_slice(&1u32.to_be_bytes());  // num_value = 1
                    buf.extend_from_slice(&v.to_be_bytes());     // actual int64 value (BE)
                }
                PacketValue::String(s) => {
                    // VALUE_STR: type=2, num_value=1, length (4 bytes), string data (no null)
                    buf.extend_from_slice(&2u32.to_be_bytes());  // type = VALUE_STR (2)
                    buf.extend_from_slice(&1u32.to_be_bytes());  // num_value = 1
                    let s_bytes = s.as_bytes();
                    buf.extend_from_slice(&(s_bytes.len() as u32).to_be_bytes());  // string length
                    buf.extend_from_slice(s_bytes);              // string data (no null terminator)
                }
                PacketValue::Data(d) => {
                    // VALUE_DATA: type=1, num_value=1, length (4 bytes), data bytes
                    buf.extend_from_slice(&1u32.to_be_bytes());  // type = VALUE_DATA (1)
                    buf.extend_from_slice(&1u32.to_be_bytes());  // num_value = 1
                    buf.extend_from_slice(&(d.len() as u32).to_be_bytes());  // data length
                    buf.extend_from_slice(d);                    // data bytes
                }
                PacketValue::Bool(b) => {
                    // Bool is stored as VALUE_INT (type=0) with value 0 or 1
                    buf.extend_from_slice(&0u32.to_be_bytes());  // type = VALUE_INT (0)
                    buf.extend_from_slice(&1u32.to_be_bytes());  // num_value = 1
                    let val = if *b { 1u32 } else { 0u32 };
                    buf.extend_from_slice(&val.to_be_bytes());   // 0 or 1 (BE)
                }
            }
        }

        if buf.len() > MAX_PACKET_SIZE {
            return Err(Error::PacketTooLarge);
        }

        Ok(buf)
    }

    /// Deserialize packet from bytes
    /// Automatically detects format (command vs response)
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(Error::PacketTooLarge);
        }

        if data.len() < 4 {
            return Err(Error::BufferTooSmall);
        }

        // Detect format by examining first 4 bytes
        let first_u32 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        
        // Response format has element count < 256 (typically 3-10)
        // Command format has command length > 256 (typically command string length)
        if first_u32 < 256 {
            eprintln!("[PACK] Detected RESPONSE format (element count: {})", first_u32);
            Self::from_bytes_response(data)
        } else {
            eprintln!("[PACK] Detected COMMAND format (command length: {})", first_u32);
            Self::from_bytes_command(data)
        }
    }

    /// Deserialize response format: [element_count][key-value pairs]
    /// No command string, just parameters
    fn from_bytes_response(data: &[u8]) -> Result<Self> {
        let mut cursor = 0;

        // Read element count (BIG-ENDIAN - SoftEther uses network byte order)
        let element_count = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        cursor += 4;

        eprintln!("[PACK] Parsing {} elements from response", element_count);
        
        // Debug: dump first 80 bytes to see full structure
        if data.len() >= 80 {
            eprintln!("[PACK] First 80 bytes:");
            for chunk_start in (0..80).step_by(16) {
                eprint!("[PACK]   {:03}: ", chunk_start);
                for i in 0..16 {
                    if chunk_start + i < 80 {
                        eprint!("{:02X} ", data[chunk_start + i]);
                    }
                }
                eprintln!();
            }
        }

        let mut params = Vec::with_capacity(element_count);

        // Read each key-value pair
        for i in 0..element_count {
            eprintln!("[PACK] === Processing element {} at cursor={} ===", i, cursor);
            
            // Read key length
            if data.len() < cursor + 4 {
                eprintln!("[PACK] ERROR: Not enough bytes for key length. Need 4, have {}", data.len() - cursor);
                return Err(Error::BufferTooSmall);
            }
            eprintln!("[PACK] Reading key_len from positions {}-{}: bytes = {:02X?}", 
                     cursor, cursor+3, &data[cursor..cursor+4]);
            let key_len = u32::from_be_bytes([  // BIG-ENDIAN
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            cursor += 4;

            eprintln!("[PACK] key_len={}, cursor={}, remaining={}", key_len, cursor, data.len() - cursor);

            // Read key (includes null terminator in the length)
            if data.len() < cursor + key_len {
                eprintln!("[PACK] ERROR: Not enough bytes for key. Need {}, have {}", key_len, data.len() - cursor);
                eprintln!("[PACK] Successfully parsed {} out of {} elements", i, element_count);
                eprintln!("[PACK] Parsed elements so far:");
                for (k, v) in &params {
                    match v {
                        PacketValue::Int(val) => eprintln!("[PACK]   {} = {} (Int)", k, val),
                        PacketValue::Int64(val) => eprintln!("[PACK]   {} = {} (Int64)", k, val),
                        PacketValue::String(val) => eprintln!("[PACK]   {} = '{}' (String)", k, val),
                        PacketValue::Data(val) => eprintln!("[PACK]   {} = <{} bytes> (Data)", k, val.len()),
                        PacketValue::Bool(val) => eprintln!("[PACK]   {} = {} (Bool)", k, val),
                    }
                }
                // Check if we already have the important fields
                if let Some((_, v)) = params.iter().find(|(k, _)| k == "error") {
                    eprintln!("[PACK] ✓ Found 'error' field in parsed data");
                    if let PacketValue::Int(err_code) = v {
                        eprintln!("[PACK] ✓ Error code = {}", err_code);
                    }
                }
                
                // If key_len looks unreasonably large (>10000), we might be misaligned
                // Return what we have so far instead of failing completely
                if key_len > 10000 {
                    eprintln!("[PACK] WARNING: key_len={} is unreasonably large, assuming misalignment", key_len);
                    eprintln!("[PACK] Returning {} successfully parsed elements", params.len());
                    return Ok(Self {
                        command: String::new(),
                        params,
                    });
                }
                
                return Err(Error::BufferTooSmall);
            }
            // Strip null terminator from key string
            let key_bytes = &data[cursor..cursor + key_len];
            let key = String::from_utf8(key_bytes.iter()
                .take_while(|&&b| b != 0)  // Take until null terminator
                .cloned()
                .collect())
                .map_err(|_| Error::EncodingError)?;
            cursor += key_len;
            
            eprintln!("[PACK] key='{}' (len={}, raw_bytes={:?}), cursor after reading key={}", 
                     key, key.len(), &data[cursor-key_len..cursor], cursor);

            // Read type structure: [pad(2)][type(1)][pad(1)] = 4 bytes
            // The type byte is at offset +2
            if data.len() < cursor + 8 {
                eprintln!("[PACK] ERROR: Not enough bytes for type+count fields. Need 8, have {}", data.len() - cursor);
                return Err(Error::BufferTooSmall);
            }
            eprintln!("[PACK] Reading type structure from positions {}-{}: bytes = {:02X?}", 
                     cursor, cursor+3, &data[cursor..cursor+4]);
            let value_type = data[cursor + 2] as u32;  // Type is 1 byte at offset +2
            cursor += 4;
            
            // Read value_count structure: [pad(2)][count(1)][pad(1)] = 4 bytes
            // The count byte is at offset +2
            eprintln!("[PACK] Reading value_count structure from positions {}-{}: bytes = {:02X?}", 
                     cursor, cursor+3, &data[cursor..cursor+4]);
            let value_count = data[cursor + 2] as usize;  // Count is 1 byte at offset +2
            cursor += 4;
            
            eprintln!("[PACK] Element {}: key='{}' type={} value_count={} cursor={} remaining={}", 
                     i, key, value_type, value_count, cursor, data.len() - cursor);
            
            // Handle arrays: Read value_count values of the same type
            // For value_count=1, just store a single value. For value_count>1, store as array.
            let value = if value_count == 0 {
                // No values (shouldn't happen but handle gracefully)
                eprintln!("[PACK] Element {}: key='{}' has value_count=0, storing empty", i, key);
                PacketValue::Int(0)
            } else if value_count == 1 {
                // Single value - read based on type
                match value_type {
                0 => {
                    // VALUE_INT in response format: [pad(1)][value_big_endian(2)]
                    if data.len() < cursor + 3 {
                        eprintln!("[PACK] ERROR: Not enough bytes for Int value (need 3, have {})", data.len() - cursor);
                        return Err(Error::BufferTooSmall);
                    }
                    
                    // Skip 1-byte padding
                    let value_start = cursor + 1;
                    
                    // Read 2-byte big-endian value
                    let v = u16::from_be_bytes([data[value_start], data[value_start + 1]]) as u32;
                    cursor += 3;  // Advance past the whole structure (pad + value)
                    
                    eprintln!("[PACK] Element {}: key='{}' type=Int value={}", i, key, v);
                    PacketValue::Int(v)
                }
                1 => {
                    // VALUE_DATA in response format:
                    // - Small data (<256): [pad(2)][size(1)][data...] - size at offset +2
                    // - Large data (≥256): [pad(2)][size(2 big-endian)][data...] - size at offset +1-2
                    // Detection strategy:
                    //   1. If bytes [0,1] are [00,00], definitely small format (size at +2)
                    //   2. If bytes [0,1] are [00,0X] where X>0, could be either:
                    //      - Small: X is padding, size at +2
                    //      - Large: X is high byte of 2-byte size
                    //   3. Use heuristic: If byte[2] < 256 and reasonable, assume small format
                    //   4. Otherwise use 2-byte format
                    if data.len() < cursor + 4 {
                        return Err(Error::BufferTooSmall);
                    }
                    
                    let end = (cursor + 8).min(data.len());
                    eprintln!("[PACK]   Data bytes at cursor={}: {:02X?}", cursor, &data[cursor..end]);
                    
                    let data_len: usize;
                    if data[cursor] == 0 && data[cursor + 1] == 0 {
                        // Definitely small format: [00, 00, size]
                        data_len = data[cursor + 2] as usize;
                        cursor += 3;
                        eprintln!("[PACK]   Data size={} bytes (1-byte: [00,00,size])", data_len);
                    } else if data[cursor] == 0 && data[cursor + 1] <= 0x01 {
                        // Ambiguous: [00, 01, XX, ...] could be:
                        //   - Small: size=XX (up to 255)
                        //   - Large: size=0x01XX (256-511)
                        // Heuristic: If XX < 128, likely small format
                        let candidate_small = data[cursor + 2] as usize;
                        if candidate_small < 128 {
                            data_len = candidate_small;
                            cursor += 3;
                            eprintln!("[PACK]   Data size={} bytes (1-byte heuristic)", data_len);
                        } else {
                            data_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
                            cursor += 3;
                            eprintln!("[PACK]   Data size={} bytes (2-byte heuristic)", data_len);
                        }
                    } else if data[cursor] == 0 {
                        // Large format: [00, HI, LO, ...]
                        data_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
                        cursor += 3;
                        eprintln!("[PACK]   Data size={} bytes (2-byte: [00,HI,LO])", data_len);
                    } else {
                        // Fallback: try 1-byte at offset +2
                        data_len = data[cursor + 2] as usize;
                        cursor += 3;
                        eprintln!("[PACK]   Data size={} bytes (fallback 1-byte)", data_len);
                    }
                    
                    if data.len() < cursor + data_len {
                        eprintln!("[PACK]   ERROR: Not enough data (need {}, have {})", data_len, data.len() - cursor);
                        return Err(Error::BufferTooSmall);
                    }
                    let d = data[cursor..cursor + data_len].to_vec();
                    cursor += data_len;
                    eprintln!("[PACK] Element {}: key='{}' type=Data length={}", i, key, data_len);
                    PacketValue::Data(d)
                }
                2 => {
                    // VALUE_STR in response format: [pad(2)][size(1)][utf8_string(size)]
                    if data.len() < cursor + 3 {
                        return Err(Error::BufferTooSmall);
                    }
                    
                    // Skip 2-byte padding, read 1-byte size
                    let str_len = data[cursor + 2] as usize;
                    cursor += 3;
                    
                    eprintln!("[PACK]   String size={} bytes", str_len);
                    
                    if data.len() < cursor + str_len {
                        eprintln!("[PACK]   ERROR: Not enough data for string (need {}, have {})", str_len, data.len() - cursor);
                        return Err(Error::BufferTooSmall);
                    }
                    
                    let s = String::from_utf8(data[cursor..cursor + str_len].to_vec())
                        .map_err(|e| {
                            eprintln!("[PACK]   ERROR: UTF-8 decode failed: {}", e);
                            Error::EncodingError
                        })?;
                    cursor += str_len;
                    
                    eprintln!("[PACK] Element {}: key='{}' type=String value='{}' (len={})", i, key, s, str_len);
                    PacketValue::String(s)
                }
                _ => {
                    eprintln!("[PACK] WARNING: Unknown value type {} for key '{}'", value_type, key);
                    return Err(Error::InvalidPacketFormat);
                }
                }
            } else {
                // Array case: value_count > 1
                // For now, only support Int arrays (like Port)
                // Use same 3-byte format as single values
                eprintln!("[PACK] Element {}: key='{}' is an array with {} values", i, key, value_count);
                
                match value_type {
                    0 => {
                        // Read all Int values using 3-byte format: [pad(1)][value(2)]
                        let mut values = Vec::new();
                        for _j in 0..value_count {
                            if data.len() < cursor + 3 {
                                return Err(Error::BufferTooSmall);
                            }
                            let v = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as u32;
                            cursor += 3;
                            values.push(v);
                        }
                        eprintln!("[PACK] Element {}: key='{}' type=IntArray values={:?}", i, key, values);
                        // Store first value only (limitation of PacketValue enum)
                        PacketValue::Int(values[0])
                    }
                    _ => {
                        eprintln!("[PACK] WARNING: Array type {} not supported yet, skipping", value_type);
                        return Err(Error::InvalidPacketFormat);
                    }
                }
            };

            params.push((key, value));
        }

        // Response format packets have no command, use empty string
        Ok(Self {
            command: String::new(),
            params,
        })
    }

    /// Deserialize command format: [cmd_len][command][param_count][parameters]
    fn from_bytes_command(data: &[u8]) -> Result<Self> {
        let mut cursor = 0;

        // Read command
        if data.len() < cursor + 4 {
            return Err(Error::BufferTooSmall);
        }
        let cmd_len = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        cursor += 4;

        if data.len() < cursor + cmd_len {
            return Err(Error::BufferTooSmall);
        }
        let command = String::from_utf8(data[cursor..cursor + cmd_len].to_vec())
            .map_err(|_| Error::EncodingError)?;
        cursor += cmd_len;

        eprintln!("[PACK] Command: '{}'", command);

        // Read param count
        if data.len() < cursor + 4 {
            return Err(Error::BufferTooSmall);
        }
        let param_count = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        cursor += 4;

        eprintln!("[PACK] Parameter count: {}", param_count);

        let mut params = Vec::with_capacity(param_count);

        // Read each parameter
        for _ in 0..param_count {
            // Read key
            if data.len() < cursor + 4 {
                return Err(Error::BufferTooSmall);
            }
            let key_len = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            cursor += 4;

            if data.len() < cursor + key_len {
                return Err(Error::BufferTooSmall);
            }
            let key = String::from_utf8(data[cursor..cursor + key_len].to_vec())
                .map_err(|_| Error::EncodingError)?;
            cursor += key_len;

            // Read value type
            if data.len() < cursor + 1 {
                return Err(Error::BufferTooSmall);
            }
            let value_type = data[cursor];
            cursor += 1;

            // Read value data based on type
            let value = match value_type {
                1 => {
                    // Int
                    if data.len() < cursor + 4 {
                        return Err(Error::BufferTooSmall);
                    }
                    let v = u32::from_be_bytes([
                        data[cursor],
                        data[cursor + 1],
                        data[cursor + 2],
                        data[cursor + 3],
                    ]);
                    cursor += 4;
                    PacketValue::Int(v)
                }
                2 => {
                    // Int64
                    if data.len() < cursor + 8 {
                        return Err(Error::BufferTooSmall);
                    }
                    let v = u64::from_be_bytes([
                        data[cursor],
                        data[cursor + 1],
                        data[cursor + 2],
                        data[cursor + 3],
                        data[cursor + 4],
                        data[cursor + 5],
                        data[cursor + 6],
                        data[cursor + 7],
                    ]);
                    cursor += 8;
                    PacketValue::Int64(v)
                }
                3 => {
                    // String
                    if data.len() < cursor + 4 {
                        return Err(Error::BufferTooSmall);
                    }
                    let str_len = u32::from_be_bytes([
                        data[cursor],
                        data[cursor + 1],
                        data[cursor + 2],
                        data[cursor + 3],
                    ]) as usize;
                    cursor += 4;

                    if data.len() < cursor + str_len {
                        return Err(Error::BufferTooSmall);
                    }
                    let s = String::from_utf8(data[cursor..cursor + str_len].to_vec())
                        .map_err(|_| Error::EncodingError)?;
                    cursor += str_len;
                    PacketValue::String(s)
                }
                4 => {
                    // Data
                    if data.len() < cursor + 4 {
                        return Err(Error::BufferTooSmall);
                    }
                    let data_len = u32::from_be_bytes([
                        data[cursor],
                        data[cursor + 1],
                        data[cursor + 2],
                        data[cursor + 3],
                    ]) as usize;
                    cursor += 4;

                    if data.len() < cursor + data_len {
                        return Err(Error::BufferTooSmall);
                    }
                    let d = data[cursor..cursor + data_len].to_vec();
                    cursor += data_len;
                    PacketValue::Data(d)
                }
                5 => {
                    // Bool
                    if data.len() < cursor + 1 {
                        return Err(Error::BufferTooSmall);
                    }
                    let b = data[cursor] != 0;
                    cursor += 1;
                    PacketValue::Bool(b)
                }
                _ => return Err(Error::InvalidPacketFormat),
            };

            params.push((key, value));
        }

        Ok(Self { command, params })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_creation() {
        let packet = Packet::new("HELLO")
            .add_int("version", 4)
            .add_string("client", "test")
            .add_bool("encrypt", true);

        assert_eq!(packet.command, "HELLO");
        assert_eq!(packet.get_int("version"), Some(4));
        assert_eq!(packet.get_string("client"), Some("test"));
        assert_eq!(packet.get_bool("encrypt"), Some(true));
    }

    #[test]
    fn test_packet_serialization_roundtrip() {
        let original = Packet::new("TEST")
            .add_int("num", 42)
            .add_int64("bignum", 1234567890)
            .add_string("text", "hello")
            .add_data("binary", vec![1, 2, 3, 4])
            .add_bool("flag", false);

        let bytes = original.to_bytes().unwrap();
        let decoded = Packet::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.command, "TEST");
        assert_eq!(decoded.get_int("num"), Some(42));
        assert_eq!(decoded.get_int64("bignum"), Some(1234567890));
        assert_eq!(decoded.get_string("text"), Some("hello"));
        assert_eq!(decoded.get_data("binary"), Some(&[1, 2, 3, 4][..]));
        assert_eq!(decoded.get_bool("flag"), Some(false));
    }

    #[test]
    fn test_packet_get_methods() {
        let packet = Packet::new("CMD")
            .add_int("a", 100)
            .add_string("b", "value");

        assert_eq!(packet.get_int("a"), Some(100));
        assert_eq!(packet.get_int("nonexistent"), None);
        assert_eq!(packet.get_string("b"), Some("value"));
        assert_eq!(packet.get_string("a"), None); // Wrong type
    }

    #[test]
    fn test_empty_packet() {
        let packet = Packet::new("EMPTY");

        let bytes = packet.to_bytes().unwrap();
        let decoded = Packet::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.command, "EMPTY");
        assert_eq!(decoded.params.len(), 0);
    }

    #[test]
    fn test_packet_value_int64() {
        let packet = Packet::new("CMD").add_int64("large", u64::MAX);

        assert_eq!(packet.get_int64("large"), Some(u64::MAX));
    }
}
