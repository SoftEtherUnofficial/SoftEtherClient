//! Protocol Module
//!
//! Wire protocol implementation for SoftEther VPN packet format.

use mayaqua::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 4;

/// Cedar protocol signature
pub const CEDAR_SIGNATURE: &str = "SE-VPN4-PROTOCOL";

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
        // Simple serialization format:
        // - Command length (4 bytes)
        // - Command string
        // - Param count (4 bytes)
        // - For each param:
        //   - Key length (4 bytes)
        //   - Key string
        //   - Value type (1 byte)
        //   - Value data

        let mut buf = Vec::new();

        // Write command
        let cmd_bytes = self.command.as_bytes();
        buf.extend_from_slice(&(cmd_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(cmd_bytes);

        // Write param count
        buf.extend_from_slice(&(self.params.len() as u32).to_be_bytes());

        // Write each parameter
        for (key, value) in &self.params {
            // Write key
            let key_bytes = key.as_bytes();
            buf.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(key_bytes);

            // Write value type and data
            match value {
                PacketValue::Int(v) => {
                    buf.push(1); // Type: Int
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                PacketValue::Int64(v) => {
                    buf.push(2); // Type: Int64
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                PacketValue::String(s) => {
                    buf.push(3); // Type: String
                    let s_bytes = s.as_bytes();
                    buf.extend_from_slice(&(s_bytes.len() as u32).to_be_bytes());
                    buf.extend_from_slice(s_bytes);
                }
                PacketValue::Data(d) => {
                    buf.push(4); // Type: Data
                    buf.extend_from_slice(&(d.len() as u32).to_be_bytes());
                    buf.extend_from_slice(d);
                }
                PacketValue::Bool(b) => {
                    buf.push(5); // Type: Bool
                    buf.push(if *b { 1 } else { 0 });
                }
            }
        }

        if buf.len() > MAX_PACKET_SIZE {
            return Err(Error::PacketTooLarge);
        }

        Ok(buf)
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(Error::PacketTooLarge);
        }

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
