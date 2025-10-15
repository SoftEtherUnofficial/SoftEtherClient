// Protocol Module - Main Entry Point
// Re-exports all protocol components for easy import

// Core VPN protocol types and utilities
pub const vpn = @import("vpn.zig");
pub const protocol = @import("vpn_protocol.zig");
pub const session = @import("session.zig");
pub const packet = @import("packet.zig");
pub const crypto = @import("crypto.zig");

// Re-export commonly used types
pub const VpnVersion = vpn.VpnVersion;
pub const AuthMethod = vpn.AuthMethod;
pub const AuthCredentials = vpn.AuthCredentials;
pub const SessionState = vpn.SessionState;
pub const SessionInfo = vpn.SessionInfo;

pub const VpnProtocol = protocol.VpnProtocol;
pub const Pack = protocol.Pack;

pub const VpnSession = session.VpnSession;
pub const SessionConfig = session.SessionConfig;
pub const SessionStats = session.SessionStats;

pub const Packet = packet.Packet;
pub const PacketType = packet.PacketType;
pub const PacketHeader = packet.PacketHeader;

pub const CryptoEngine = crypto.CryptoEngine;
pub const EncryptionAlgorithm = crypto.EncryptionAlgorithm;
pub const TlsVersion = crypto.TlsVersion;
pub const CipherSuite = crypto.CipherSuite;
