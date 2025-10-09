//! Configuration module for SoftEther VPN Client
//!
//! Handles JSON-based configuration matching config.schema.json

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Performance tuning options
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceConfig {
    /// Receive queue buffer size (number of packet slots)
    pub recv_buffer_slots: u32,
    /// Send queue buffer size (number of packet slots)
    pub send_buffer_slots: u32,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            recv_buffer_slots: 128,
            send_buffer_slots: 128,
        }
    }
}

/// IP version preference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    Auto,
    Ipv4,
    Ipv6,
    Dual,
}

impl Default for IpVersion {
    fn default() -> Self {
        IpVersion::Auto
    }
}

/// SoftEther VPN Client Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnConfig {
    pub server: Option<String>,
    pub port: u16,
    pub hub: Option<String>,
    pub account: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub password_hash: Option<String>,
    pub use_encrypt: bool,
    pub use_compress: bool,
    pub max_connection: u32,
    pub ip_version: IpVersion,
    pub static_ipv4: Option<String>,
    pub static_ipv4_netmask: Option<String>,
    pub static_ipv4_gateway: Option<String>,
    pub static_ipv6: Option<String>,
    pub static_ipv6_prefix: Option<u32>,
    pub static_ipv6_gateway: Option<String>,
    pub dns_servers: Option<Vec<String>>,
    pub reconnect: bool,
    pub max_reconnect_attempts: u32,
    pub min_backoff: u32,
    pub max_backoff: u32,
    pub performance: PerformanceConfig,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            server: None,
            port: 443,
            hub: None,
            account: None,
            username: None,
            password: None,
            password_hash: None,
            use_encrypt: true,
            use_compress: true,
            max_connection: 0,
            ip_version: IpVersion::Auto,
            static_ipv4: None,
            static_ipv4_netmask: None,
            static_ipv4_gateway: None,
            static_ipv6: None,
            static_ipv6_prefix: None,
            static_ipv6_gateway: None,
            dns_servers: None,
            reconnect: true,
            max_reconnect_attempts: 0,
            min_backoff: 5,
            max_backoff: 300,
            performance: PerformanceConfig::default(),
        }
    }
}

impl VpnConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = crate::fs::read_all(&path)?;
        let config: VpnConfig = serde_json::from_slice(&data)
            .map_err(|e| Error::ConfigError(format!("JSON parse error: {}", e)))?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let config: VpnConfig = serde_json::from_str(json)
            .map_err(|e| Error::ConfigError(format!("JSON parse error: {}", e)))?;
        config.validate()?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.validate()?;
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::ConfigError(format!("JSON serialization error: {}", e)))?;
        crate::fs::write_all_atomic(&path, json.as_bytes())?;
        crate::fs::set_user_rw_only(&path);
        Ok(())
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| Error::ConfigError(format!("JSON serialization error: {}", e)))
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.is_none() {
            return Err(Error::ConfigError("server is required".to_string()));
        }
        if self.hub.is_none() {
            return Err(Error::ConfigError("hub is required".to_string()));
        }
        if self.username.is_none() {
            return Err(Error::ConfigError("username is required".to_string()));
        }
        if self.password.is_none() && self.password_hash.is_none() {
            return Err(Error::ConfigError(
                "either password or password_hash is required".to_string(),
            ));
        }
        if self.port == 0 {
            return Err(Error::ConfigError(
                "port must be between 1 and 65535".to_string(),
            ));
        }
        if self.max_connection > 32 {
            return Err(Error::ConfigError(
                "max_connection must be between 0 and 32".to_string(),
            ));
        }
        if let Some(prefix) = self.static_ipv6_prefix {
            if prefix == 0 || prefix > 128 {
                return Err(Error::ConfigError(
                    "static_ipv6_prefix must be between 1 and 128".to_string(),
                ));
            }
        }
        if self.min_backoff == 0 || self.max_backoff == 0 {
            return Err(Error::ConfigError(
                "backoff values must be at least 1".to_string(),
            ));
        }
        if self.min_backoff > self.max_backoff {
            return Err(Error::ConfigError(
                "min_backoff must be <= max_backoff".to_string(),
            ));
        }
        if self.performance.recv_buffer_slots < 32 || self.performance.recv_buffer_slots > 2048 {
            return Err(Error::ConfigError(
                "recv_buffer_slots must be between 32 and 2048".to_string(),
            ));
        }
        if self.performance.send_buffer_slots < 16 || self.performance.send_buffer_slots > 1024 {
            return Err(Error::ConfigError(
                "send_buffer_slots must be between 16 and 1024".to_string(),
            ));
        }
        Ok(())
    }

    pub fn get_account(&self) -> Option<&str> {
        self.account.as_deref().or_else(|| self.username.as_deref())
    }

    pub fn has_static_ipv4(&self) -> bool {
        self.static_ipv4.is_some() && self.static_ipv4_netmask.is_some()
    }

    pub fn has_static_ipv6(&self) -> bool {
        self.static_ipv6.is_some() && self.static_ipv6_prefix.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VpnConfig::default();
        assert_eq!(config.port, 443);
        assert!(config.use_encrypt);
        assert!(config.use_compress);
        assert_eq!(config.max_connection, 0);
        assert_eq!(config.ip_version, IpVersion::Auto);
        assert!(config.reconnect);
        assert_eq!(config.performance.recv_buffer_slots, 128);
    }

    #[test]
    fn test_minimal_json() {
        let json = r#"{
            "server": "vpn.example.com",
            "hub": "VPN",
            "username": "testuser",
            "password": "testpass"
        }"#;
        
        let config = VpnConfig::from_json(json).unwrap();
        assert_eq!(config.server.as_deref(), Some("vpn.example.com"));
        assert_eq!(config.hub.as_deref(), Some("VPN"));
        assert_eq!(config.username.as_deref(), Some("testuser"));
        assert_eq!(config.port, 443);
    }

    #[test]
    fn test_validation_missing_server() {
        let json = r#"{"hub": "VPN", "username": "test", "password": "pass"}"#;
        let result = VpnConfig::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_has_static_ipv4() {
        let mut config = VpnConfig::default();
        assert!(!config.has_static_ipv4());
        
        config.static_ipv4 = Some("10.0.0.1".to_string());
        assert!(!config.has_static_ipv4());
        
        config.static_ipv4_netmask = Some("255.255.255.0".to_string());
        assert!(config.has_static_ipv4());
    }
}
