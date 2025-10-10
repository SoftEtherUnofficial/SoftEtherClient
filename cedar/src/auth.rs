//! Authentication Module
//!
//! Handles various authentication methods for VPN connections.

use crate::constants::AuthType;
use mayaqua::crypto;
use mayaqua::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Authentication credentials
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Anonymous authentication (no credentials)
    Anonymous,
    /// Password-based authentication
    Password {
        username: String,
        password: String,
    },
    /// Plain password (not hashed)
    PlainPassword {
        username: String,
        password: String,
    },
    /// Certificate-based authentication
    Certificate {
        username: String,
        cert_data: Vec<u8>,
        key_data: Option<Vec<u8>>,
    },
    /// Secure device authentication (smartcard/token)
    SecureDevice {
        username: String,
        device_id: String,
        pin: Option<String>,
    },
}

impl Credentials {
    /// Get authentication type
    pub fn auth_type(&self) -> AuthType {
        match self {
            Self::Anonymous => AuthType::Anonymous,
            Self::Password { .. } => AuthType::Password,
            Self::PlainPassword { .. } => AuthType::PlainPassword,
            Self::Certificate { .. } => AuthType::Certificate,
            Self::SecureDevice { .. } => AuthType::SecureDevice,
        }
    }

    /// Get username if available
    pub fn username(&self) -> Option<&str> {
        match self {
            Self::Anonymous => None,
            Self::Password { username, .. } => Some(username),
            Self::PlainPassword { username, .. } => Some(username),
            Self::Certificate { username, .. } => Some(username),
            Self::SecureDevice { username, .. } => Some(username),
        }
    }
}

/// Authentication request packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Authentication type
    pub auth_type: u32,
    /// Hub name
    pub hub_name: String,
    /// Username
    pub username: String,
    /// Authentication data (password hash, cert, etc.)
    pub auth_data: Vec<u8>,
    /// Protocol version
    pub protocol_version: u32,
}

/// Authentication response packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Success flag
    pub success: bool,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Session ID if successful
    pub session_id: Option<Vec<u8>>,
    /// Server capabilities
    pub capabilities: Option<Vec<String>>,
}

/// Authentication manager
pub struct AuthManager {
    /// Stored credentials
    credentials: Credentials,
}

impl AuthManager {
    /// Create new authentication manager
    pub fn new(credentials: Credentials) -> Self {
        Self { credentials }
    }

    /// Build authentication request packet
    pub fn build_auth_request(&self, hub_name: &str) -> Result<AuthRequest> {
        let auth_type = self.credentials.auth_type() as u32;
        let username = self
            .credentials
            .username()
            .unwrap_or("anonymous")
            .to_string();

        let auth_data = match &self.credentials {
            Credentials::Anonymous => Vec::new(),

            Credentials::Password { username, password } => {
                // Hash password using SoftEther algorithm
                let hash = crypto::softether_password_hash(password, username);
                hash.to_vec()
            }

            Credentials::PlainPassword { password, .. } => {
                // Send plain password (not recommended)
                password.as_bytes().to_vec()
            }

            Credentials::Certificate { cert_data, .. } => {
                // Send certificate data
                cert_data.clone()
            }

            Credentials::SecureDevice { device_id, pin, .. } => {
                // Combine device ID and PIN
                let mut data = device_id.as_bytes().to_vec();
                if let Some(pin) = pin {
                    data.push(0); // Separator
                    data.extend_from_slice(pin.as_bytes());
                }
                data
            }
        };

        Ok(AuthRequest {
            auth_type,
            hub_name: hub_name.to_string(),
            username,
            auth_data,
            protocol_version: 1,
        })
    }

    /// Validate authentication response
    pub fn validate_response(&self, response: &AuthResponse) -> Result<()> {
        if !response.success {
            let _error_msg = response
                .error_message
                .as_deref()
                .unwrap_or("Authentication failed");
            return Err(Error::AuthenticationFailed);
        }

        if response.session_id.is_none() {
            return Err(Error::InvalidResponse);
        }

        Ok(())
    }

    /// Get credentials reference
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Change password (for password-based auth)
    pub fn change_password(&mut self, new_password: String) -> Result<()> {
        match &mut self.credentials {
            Credentials::Password { password, .. } => {
                *password = new_password;
                Ok(())
            }
            Credentials::PlainPassword { password, .. } => {
                *password = new_password;
                Ok(())
            }
            _ => Err(Error::NotSupported),
        }
    }
}

/// Verify password hash matches
pub fn verify_password_hash(
    username: &str,
    password: &str,
    expected_hash: &[u8],
) -> Result<bool> {
    if expected_hash.len() != 20 {
        return Err(Error::InvalidParameter);
    }

    let computed_hash = crypto::softether_password_hash(password, username);

    Ok(&computed_hash[..] == expected_hash)
}

/// Generate random session ID
pub fn generate_session_id() -> Vec<u8> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Generate pseudo-random session ID based on timestamp
    // In production, use proper CSPRNG
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut session_id = Vec::with_capacity(16);
    session_id.extend_from_slice(&timestamp.to_le_bytes());
    session_id
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_auth_type() {
        let anon = Credentials::Anonymous;
        assert_eq!(anon.auth_type() as u32, 0);

        let pwd = Credentials::Password {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        assert_eq!(pwd.auth_type() as u32, 1);
    }

    #[test]
    fn test_credentials_username() {
        let anon = Credentials::Anonymous;
        assert_eq!(anon.username(), None);

        let pwd = Credentials::Password {
            username: "alice".to_string(),
            password: "secret".to_string(),
        };
        assert_eq!(pwd.username(), Some("alice"));
    }

    #[test]
    fn test_auth_request_anonymous() {
        let creds = Credentials::Anonymous;
        let manager = AuthManager::new(creds);

        let request = manager.build_auth_request("DEFAULT").unwrap();
        assert_eq!(request.auth_type, 0);
        assert_eq!(request.hub_name, "DEFAULT");
        assert!(request.auth_data.is_empty());
    }

    #[test]
    fn test_auth_request_password() {
        let creds = Credentials::Password {
            username: "test".to_string(),
            password: "password123".to_string(),
        };
        let manager = AuthManager::new(creds);

        let request = manager.build_auth_request("VPN").unwrap();
        assert_eq!(request.auth_type, 1);
        assert_eq!(request.username, "test");
        assert_eq!(request.hub_name, "VPN");
        assert_eq!(request.auth_data.len(), 20); // SHA-0 hash size
    }

    #[test]
    fn test_auth_response_validation() {
        let creds = Credentials::Anonymous;
        let manager = AuthManager::new(creds);

        // Successful response
        let success_response = AuthResponse {
            success: true,
            error_message: None,
            session_id: Some(vec![1, 2, 3, 4]),
            capabilities: None,
        };
        assert!(manager.validate_response(&success_response).is_ok());

        // Failed response
        let fail_response = AuthResponse {
            success: false,
            error_message: Some("Invalid credentials".to_string()),
            session_id: None,
            capabilities: None,
        };
        assert!(manager.validate_response(&fail_response).is_err());
    }

    #[test]
    fn test_password_hash_verification() {
        let username = "testuser";
        let password = "testpass";

        // Generate hash
        let hash = crypto::softether_password_hash(password, username);

        // Verify correct password
        assert!(verify_password_hash(username, password, &hash).unwrap());

        // Verify incorrect password
        assert!(!verify_password_hash(username, "wrongpass", &hash).unwrap());
    }

    #[test]
    fn test_session_id_generation() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();

        assert!(!id1.is_empty());
        assert!(!id2.is_empty());
        // IDs should be different (timestamp-based)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_change_password() {
        let creds = Credentials::Password {
            username: "user".to_string(),
            password: "oldpass".to_string(),
        };
        let mut manager = AuthManager::new(creds);

        assert!(manager.change_password("newpass".to_string()).is_ok());

        // Verify password was changed
        match manager.credentials() {
            Credentials::Password { password, .. } => {
                assert_eq!(password, "newpass");
            }
            _ => panic!("Expected Password credentials"),
        }
    }
}
