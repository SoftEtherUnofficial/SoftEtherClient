//! Cedar FFI Exports
//!
//! C-compatible FFI exports for Cedar VPN protocol layer.
//! Provides opaque pointer-based API for use from C/Zig.

use std::ffi::{CStr};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

use crate::session::{Session, SessionConfig, SessionStats, SessionStatus};
use crate::protocol::Packet;
use crate::encryption::{TlsConnection, TlsState};
use crate::compression::{Compressor, CompressionConfig, CompressionAlgorithm};
use crate::udp_accel::{UdpAccelerator, UdpAccelConfig, UdpAccelMode};
use crate::nat_traversal::{NatTraversal, NatType};

// ============================================================================
// Error Handling
// ============================================================================

/// FFI error codes
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CedarErrorCode {
    Success = 0,
    InternalError = 1,
    InvalidParameter = 2,
    NotConnected = 3,
    InvalidState = 4,
    BufferTooSmall = 5,
    PacketTooLarge = 6,
    AuthenticationFailed = 7,
    NotImplemented = 8,
    TimeOut = 9,
    IoError = 10,
}

impl From<mayaqua::Error> for CedarErrorCode {
    fn from(err: mayaqua::Error) -> Self {
        match err {
            mayaqua::Error::NoError => CedarErrorCode::Success,
            mayaqua::Error::InternalError => CedarErrorCode::InternalError,
            mayaqua::Error::InvalidParameter => CedarErrorCode::InvalidParameter,
            mayaqua::Error::NotConnected => CedarErrorCode::NotConnected,
            mayaqua::Error::InvalidState => CedarErrorCode::InvalidState,
            mayaqua::Error::BufferTooSmall => CedarErrorCode::BufferTooSmall,
            mayaqua::Error::PacketTooLarge => CedarErrorCode::PacketTooLarge,
            mayaqua::Error::AuthenticationFailed => CedarErrorCode::AuthenticationFailed,
            mayaqua::Error::NotImplemented => CedarErrorCode::NotImplemented,
            mayaqua::Error::TimeOut => CedarErrorCode::TimeOut,
            mayaqua::Error::IoError(_) => CedarErrorCode::IoError,
            _ => CedarErrorCode::InternalError,
        }
    }
}

// ============================================================================
// Session FFI
// ============================================================================

/// Opaque session handle
pub type CedarSessionHandle = *mut c_void;

/// Session status for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CedarSessionStatus {
    Init = 0,
    Connecting = 1,
    Authenticating = 2,
    Established = 3,
    Reconnecting = 4,
    Closing = 5,
    Terminated = 6,
}

impl From<SessionStatus> for CedarSessionStatus {
    fn from(status: SessionStatus) -> Self {
        match status {
            SessionStatus::Init => CedarSessionStatus::Init,
            SessionStatus::Connecting => CedarSessionStatus::Connecting,
            SessionStatus::Authenticating => CedarSessionStatus::Authenticating,
            SessionStatus::Established => CedarSessionStatus::Established,
            SessionStatus::Reconnecting => CedarSessionStatus::Reconnecting,
            SessionStatus::Closing => CedarSessionStatus::Closing,
            SessionStatus::Terminated => CedarSessionStatus::Terminated,
        }
    }
}

/// Session statistics for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CedarSessionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub duration_secs: u64,
    pub idle_time_secs: u64,
}

impl From<&SessionStats> for CedarSessionStats {
    fn from(stats: &SessionStats) -> Self {
        Self {
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            packets_sent: stats.packets_sent,
            packets_received: stats.packets_received,
            duration_secs: stats.duration().as_secs(),
            idle_time_secs: stats.idle_time().as_secs(),
        }
    }
}

/// Create new session
#[no_mangle]
pub extern "C" fn cedar_session_new(
    server: *const c_char,
    port: u16,
    hub: *const c_char,
) -> CedarSessionHandle {
    cedar_session_new_with_auth(server, port, hub, ptr::null(), ptr::null())
}

/// Create new session with authentication (wrapper for backward compatibility)
#[no_mangle]
pub extern "C" fn cedar_session_new_with_auth(
    server: *const c_char,
    port: u16,
    hub: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> CedarSessionHandle {
    cedar_session_new_with_auth_ex(server, port, hub, username, password, 1)
}

/// Create new session with authentication and encryption control
/// use_encrypt: 0 = no encryption, 1 = use RC4 encryption (default)
#[no_mangle]
pub extern "C" fn cedar_session_new_with_auth_ex(
    server: *const c_char,
    port: u16,
    hub: *const c_char,
    username: *const c_char,
    password: *const c_char,
    use_encrypt: u8,
) -> CedarSessionHandle {
    if server.is_null() || hub.is_null() {
        return ptr::null_mut();
    }

    let server_str = unsafe {
        match CStr::from_ptr(server).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let hub_str = unsafe {
        match CStr::from_ptr(hub).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    use crate::session::AuthConfig;
    use std::time::Duration;

    // Determine authentication method
    let auth = if username.is_null() || password.is_null() {
        AuthConfig::Anonymous
    } else {
        let username_str = unsafe {
            match CStr::from_ptr(username).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };

        let password_str = unsafe {
            match CStr::from_ptr(password).to_str() {
                Ok(s) => s,
                Err(_) => return ptr::null_mut(),
            }
        };

        AuthConfig::Password {
            username: username_str.to_string(),
            password: password_str.to_string(),
        }
    };

    let config = SessionConfig {
        name: "cedar-vpn".to_string(),
        server: server_str.to_string(),
        port,
        hub: hub_str.to_string(),
        auth,
        use_encrypt: use_encrypt != 0,  // 0 = disabled, non-zero = enabled
        use_compress: false, // CRITICAL: Must match C Bridge (sends 0, not 1)
        max_connection: 1,
        keep_alive_interval: Duration::from_secs(30),
        timeout: Duration::from_secs(15),
    };

    let session = Box::new(Session::new(config));
    Box::into_raw(session) as CedarSessionHandle
}

/// Free session
#[no_mangle]
pub extern "C" fn cedar_session_free(handle: CedarSessionHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut Session);
        }
    }
}

/// Get session status
#[no_mangle]
pub extern "C" fn cedar_session_get_status(handle: CedarSessionHandle) -> CedarSessionStatus {
    if handle.is_null() {
        return CedarSessionStatus::Terminated;
    }

    let session = unsafe { &*(handle as *const Session) };
    CedarSessionStatus::from(session.status())
}

/// Get session statistics
#[no_mangle]
pub extern "C" fn cedar_session_get_stats(
    handle: CedarSessionHandle,
    stats: *mut CedarSessionStats,
) -> CedarErrorCode {
    if handle.is_null() || stats.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let session = unsafe { &*(handle as *const Session) };
    let session_stats = session.stats();
    
    unsafe {
        *stats = CedarSessionStats::from(&session_stats);
    }

    CedarErrorCode::Success
}

// ============================================================================
// Packet FFI
// ============================================================================

/// Opaque packet handle
pub type CedarPacketHandle = *mut c_void;

/// Create new packet
#[no_mangle]
pub extern "C" fn cedar_packet_new(command: *const c_char) -> CedarPacketHandle {
    if command.is_null() {
        return ptr::null_mut();
    }

    let command_str = unsafe {
        match CStr::from_ptr(command).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    let packet = Box::new(Packet::new(command_str));
    Box::into_raw(packet) as CedarPacketHandle
}

/// Free packet
#[no_mangle]
pub extern "C" fn cedar_packet_free(handle: CedarPacketHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut Packet);
        }
    }
}

/// Add integer parameter to packet
#[no_mangle]
pub extern "C" fn cedar_packet_add_int(
    handle: CedarPacketHandle,
    key: *const c_char,
    value: u32,
) -> CedarErrorCode {
    if handle.is_null() || key.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let key_str = unsafe {
        match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return CedarErrorCode::InvalidParameter,
        }
    };

    // Take ownership from the handle
    let mut packet = unsafe { Box::from_raw(handle as *mut Packet) };
    
    // Modify in place (packet.add_int consumes self, but we can use the result)
    *packet = packet.clone().add_int(key_str, value);
    
    // Put it back without dropping
    Box::into_raw(packet);
    
    CedarErrorCode::Success
}

/// Add string parameter to packet
#[no_mangle]
pub extern "C" fn cedar_packet_add_string(
    handle: CedarPacketHandle,
    key: *const c_char,
    value: *const c_char,
) -> CedarErrorCode {
    if handle.is_null() || key.is_null() || value.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let key_str = unsafe {
        match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return CedarErrorCode::InvalidParameter,
        }
    };

    let value_str = unsafe {
        match CStr::from_ptr(value).to_str() {
            Ok(s) => s,
            Err(_) => return CedarErrorCode::InvalidParameter,
        }
    };

    // Take ownership from the handle
    let mut packet = unsafe { Box::from_raw(handle as *mut Packet) };
    
    // Modify in place (packet.add_string consumes self, but we can use the result)
    *packet = packet.clone().add_string(key_str, value_str);
    
    // Put it back without dropping
    Box::into_raw(packet);
    
    CedarErrorCode::Success
}

/// Get integer parameter from packet
#[no_mangle]
pub extern "C" fn cedar_packet_get_int(
    handle: CedarPacketHandle,
    key: *const c_char,
    value: *mut u32,
) -> CedarErrorCode {
    if handle.is_null() || key.is_null() || value.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let packet = unsafe { &*(handle as *const Packet) };
    
    let key_str = unsafe {
        match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return CedarErrorCode::InvalidParameter,
        }
    };

    match packet.get_int(key_str) {
        Some(v) => {
            unsafe { *value = v; }
            CedarErrorCode::Success
        }
        None => CedarErrorCode::InvalidParameter,
    }
}

/// Get string parameter from packet (copies to buffer)
#[no_mangle]
pub extern "C" fn cedar_packet_get_string(
    handle: CedarPacketHandle,
    key: *const c_char,
    buffer: *mut c_char,
    buffer_len: usize,
) -> CedarErrorCode {
    if handle.is_null() || key.is_null() || buffer.is_null() || buffer_len == 0 {
        return CedarErrorCode::InvalidParameter;
    }

    let packet = unsafe { &*(handle as *const Packet) };
    
    let key_str = unsafe {
        match CStr::from_ptr(key).to_str() {
            Ok(s) => s,
            Err(_) => return CedarErrorCode::InvalidParameter,
        }
    };

    match packet.get_string(key_str) {
        Some(s) => {
            let bytes = s.as_bytes();
            if bytes.len() + 1 > buffer_len {
                return CedarErrorCode::BufferTooSmall;
            }
            
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len());
                *buffer.add(bytes.len()) = 0; // Null terminator
            }
            
            CedarErrorCode::Success
        }
        None => CedarErrorCode::InvalidParameter,
    }
}

// ============================================================================
// Encryption FFI
// ============================================================================

/// Opaque TLS connection handle
pub type CedarTlsHandle = *mut c_void;

/// TLS state for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CedarTlsState {
    Disconnected = 0,
    Handshaking = 1,
    Connected = 2,
    Error = 3,
}

impl From<TlsState> for CedarTlsState {
    fn from(state: TlsState) -> Self {
        match state {
            TlsState::Disconnected => CedarTlsState::Disconnected,
            TlsState::Handshaking => CedarTlsState::Handshaking,
            TlsState::Connected => CedarTlsState::Connected,
            TlsState::Error => CedarTlsState::Error,
        }
    }
}

/// Create new TLS connection
#[no_mangle]
pub extern "C" fn cedar_tls_new() -> CedarTlsHandle {
    let tls = Box::new(TlsConnection::with_defaults());
    Box::into_raw(tls) as CedarTlsHandle
}

/// Free TLS connection
#[no_mangle]
pub extern "C" fn cedar_tls_free(handle: CedarTlsHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut TlsConnection);
        }
    }
}

/// Get TLS state
#[no_mangle]
pub extern "C" fn cedar_tls_get_state(handle: CedarTlsHandle) -> CedarTlsState {
    if handle.is_null() {
        return CedarTlsState::Disconnected;
    }

    let tls = unsafe { &*(handle as *const TlsConnection) };
    CedarTlsState::from(tls.state())
}

/// Encrypt data
#[no_mangle]
pub extern "C" fn cedar_tls_encrypt(
    handle: CedarTlsHandle,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext: *mut u8,
    ciphertext_len: usize,
    bytes_written: *mut usize,
) -> CedarErrorCode {
    if handle.is_null() || plaintext.is_null() || ciphertext.is_null() || bytes_written.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let tls = unsafe { &mut *(handle as *mut TlsConnection) };
    let plaintext_slice = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    let ciphertext_slice = unsafe { std::slice::from_raw_parts_mut(ciphertext, ciphertext_len) };

    match tls.encrypt(plaintext_slice, ciphertext_slice) {
        Ok(written) => {
            unsafe { *bytes_written = written; }
            CedarErrorCode::Success
        }
        Err(e) => CedarErrorCode::from(e),
    }
}

// ============================================================================
// Compression FFI
// ============================================================================

/// Opaque compressor handle
pub type CedarCompressorHandle = *mut c_void;

/// Compression algorithm for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CedarCompressionAlgorithm {
    CompressionNone = 0,
    Deflate = 1,
    Gzip = 2,
    Lz4 = 3,
}

impl From<CedarCompressionAlgorithm> for CompressionAlgorithm {
    fn from(algo: CedarCompressionAlgorithm) -> Self {
        match algo {
            CedarCompressionAlgorithm::CompressionNone => CompressionAlgorithm::None,
            CedarCompressionAlgorithm::Deflate => CompressionAlgorithm::Deflate,
            CedarCompressionAlgorithm::Gzip => CompressionAlgorithm::Gzip,
            CedarCompressionAlgorithm::Lz4 => CompressionAlgorithm::Lz4,
        }
    }
}

/// Create new compressor
#[no_mangle]
pub extern "C" fn cedar_compressor_new(
    algorithm: CedarCompressionAlgorithm,
) -> CedarCompressorHandle {
    let mut config = CompressionConfig::default();
    config.algorithm = CompressionAlgorithm::from(algorithm);
    
    let compressor = Box::new(Compressor::new(config));
    Box::into_raw(compressor) as CedarCompressorHandle
}

/// Free compressor
#[no_mangle]
pub extern "C" fn cedar_compressor_free(handle: CedarCompressorHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut Compressor);
        }
    }
}

/// Compress data
#[no_mangle]
pub extern "C" fn cedar_compressor_compress(
    handle: CedarCompressorHandle,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    bytes_written: *mut usize,
) -> CedarErrorCode {
    if handle.is_null() || input.is_null() || output.is_null() || bytes_written.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let compressor = unsafe { &mut *(handle as *mut Compressor) };
    let input_slice = unsafe { std::slice::from_raw_parts(input, input_len) };
    let output_slice = unsafe { std::slice::from_raw_parts_mut(output, output_len) };

    match compressor.compress(input_slice, output_slice) {
        Ok(written) => {
            unsafe { *bytes_written = written; }
            CedarErrorCode::Success
        }
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Decompress data
#[no_mangle]
pub extern "C" fn cedar_compressor_decompress(
    handle: CedarCompressorHandle,
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
    bytes_written: *mut usize,
) -> CedarErrorCode {
    if handle.is_null() || input.is_null() || output.is_null() || bytes_written.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let compressor = unsafe { &mut *(handle as *mut Compressor) };
    let input_slice = unsafe { std::slice::from_raw_parts(input, input_len) };
    let output_slice = unsafe { std::slice::from_raw_parts_mut(output, output_len) };

    match compressor.decompress(input_slice, output_slice) {
        Ok(written) => {
            unsafe { *bytes_written = written; }
            CedarErrorCode::Success
        }
        Err(e) => CedarErrorCode::from(e),
    }
}

// ============================================================================
// UDP Acceleration FFI
// ============================================================================

/// Opaque UDP accelerator handle
pub type CedarUdpAccelHandle = *mut c_void;

/// UDP acceleration mode for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CedarUdpAccelMode {
    Disabled = 0,
    Hybrid = 1,
    UdpOnly = 2,
}

impl From<CedarUdpAccelMode> for UdpAccelMode {
    fn from(mode: CedarUdpAccelMode) -> Self {
        match mode {
            CedarUdpAccelMode::Disabled => UdpAccelMode::Disabled,
            CedarUdpAccelMode::Hybrid => UdpAccelMode::Hybrid,
            CedarUdpAccelMode::UdpOnly => UdpAccelMode::UdpOnly,
        }
    }
}

/// Create new UDP accelerator
#[no_mangle]
pub extern "C" fn cedar_udp_accel_new(mode: CedarUdpAccelMode) -> CedarUdpAccelHandle {
    let mut config = UdpAccelConfig::default();
    config.mode = UdpAccelMode::from(mode);
    
    let accel = Box::new(UdpAccelerator::new(config));
    Box::into_raw(accel) as CedarUdpAccelHandle
}

/// Free UDP accelerator
#[no_mangle]
pub extern "C" fn cedar_udp_accel_free(handle: CedarUdpAccelHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut UdpAccelerator);
        }
    }
}

/// Check if UDP acceleration is healthy
#[no_mangle]
pub extern "C" fn cedar_udp_accel_is_healthy(handle: CedarUdpAccelHandle) -> c_int {
    if handle.is_null() {
        return 0;
    }

    let accel = unsafe { &*(handle as *const UdpAccelerator) };
    if accel.is_healthy() { 1 } else { 0 }
}

// ============================================================================
// NAT Traversal FFI
// ============================================================================

/// Opaque NAT traversal handle
pub type CedarNatTraversalHandle = *mut c_void;

/// NAT type for FFI
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CedarNatType {
    NatNone = 0,
    FullCone = 1,
    RestrictedCone = 2,
    PortRestrictedCone = 3,
    Symmetric = 4,
    Unknown = 5,
}

impl From<NatType> for CedarNatType {
    fn from(nat_type: NatType) -> Self {
        match nat_type {
            NatType::None => CedarNatType::NatNone,
            NatType::FullCone => CedarNatType::FullCone,
            NatType::RestrictedCone => CedarNatType::RestrictedCone,
            NatType::PortRestrictedCone => CedarNatType::PortRestrictedCone,
            NatType::Symmetric => CedarNatType::Symmetric,
            NatType::Unknown => CedarNatType::Unknown,
        }
    }
}

/// Create new NAT traversal engine
#[no_mangle]
pub extern "C" fn cedar_nat_traversal_new() -> CedarNatTraversalHandle {
    let nat = Box::new(NatTraversal::with_defaults());
    Box::into_raw(nat) as CedarNatTraversalHandle
}

/// Free NAT traversal engine
#[no_mangle]
pub extern "C" fn cedar_nat_traversal_free(handle: CedarNatTraversalHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle as *mut NatTraversal);
        }
    }
}

/// Detect NAT type
#[no_mangle]
pub extern "C" fn cedar_nat_traversal_detect(handle: CedarNatTraversalHandle) -> CedarNatType {
    if handle.is_null() {
        return CedarNatType::Unknown;
    }

    let nat = unsafe { &mut *(handle as *mut NatTraversal) };
    match nat.detect_nat_type() {
        Ok(nat_type) => CedarNatType::from(nat_type),
        Err(_) => CedarNatType::Unknown,
    }
}

/// Check if NAT traversal is supported
#[no_mangle]
pub extern "C" fn cedar_nat_traversal_is_supported(handle: CedarNatTraversalHandle) -> c_int {
    if handle.is_null() {
        return 0;
    }

    let nat = unsafe { &*(handle as *const NatTraversal) };
    if nat.is_supported() { 1 } else { 0 }
}

// ============================================================================
// Version Information
// ============================================================================

/// Get Cedar version string
#[no_mangle]
pub extern "C" fn cedar_version() -> *const c_char {
    static VERSION: &str = "0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

/// Get Cedar protocol version
#[no_mangle]
pub extern "C" fn cedar_protocol_version() -> u32 {
    crate::protocol::PROTOCOL_VERSION
}

// ============================================================================
// Network I/O Functions (NEW - For Phase 4.1 Step 2)
// ============================================================================

/// Connect TLS connection to server
/// Returns Success on successful connection, error code otherwise
#[no_mangle]
pub extern "C" fn cedar_tls_connect(
    handle: CedarTlsHandle,
    host: *const c_char,
    port: u16,
) -> CedarErrorCode {
    if handle.is_null() || host.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let host_str = match unsafe { CStr::from_ptr(host) }.to_str() {
        Ok(s) => s,
        Err(_) => return CedarErrorCode::InvalidParameter,
    };

    let tls = unsafe { &mut *(handle as *mut TlsConnection) };
    
    match tls.connect(host_str, port) {
        Ok(_) => CedarErrorCode::Success,
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Send data over TLS connection
/// Returns number of bytes sent, or -1 on error
#[no_mangle]
pub extern "C" fn cedar_tls_send(
    handle: CedarTlsHandle,
    data: *const u8,
    len: usize,
) -> c_int {
    if handle.is_null() || data.is_null() {
        return -1;
    }

    let tls = unsafe { &mut *(handle as *mut TlsConnection) };
    let data_slice = unsafe { std::slice::from_raw_parts(data, len) };

    match tls.send(data_slice) {
        Ok(sent) => sent as c_int,
        Err(_) => -1,
    }
}

/// Receive data from TLS connection
/// Returns number of bytes received, 0 on EOF, or -1 on error
#[no_mangle]
pub extern "C" fn cedar_tls_receive(
    handle: CedarTlsHandle,
    buffer: *mut u8,
    buffer_size: usize,
) -> c_int {
    if handle.is_null() || buffer.is_null() {
        return -1;
    }

    let tls = unsafe { &mut *(handle as *mut TlsConnection) };
    let buffer_slice = unsafe { std::slice::from_raw_parts_mut(buffer, buffer_size) };

    match tls.receive(buffer_slice) {
        Ok(received) => received as c_int,
        Err(_) => -1,
    }
}

/// Connect session to server (TLS + initial handshake)
/// This performs the full connection sequence:
/// 1. TLS connection
/// 2. Protocol hello exchange
#[no_mangle]
pub extern "C" fn cedar_session_connect(
    handle: CedarSessionHandle,
) -> CedarErrorCode {
    if handle.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let session = unsafe { &mut *(handle as *mut Session) };
    
    match session.connect() {
        Ok(_) => CedarErrorCode::Success,
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Send packet over session
#[no_mangle]
pub extern "C" fn cedar_session_send_packet(
    handle: CedarSessionHandle,
    packet: CedarPacketHandle,
) -> CedarErrorCode {
    if handle.is_null() || packet.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let session = unsafe { &mut *(handle as *mut Session) };
    let packet_ref = unsafe { &*(packet as *const Packet) };
    
    match session.send_packet(packet_ref) {
        Ok(_) => CedarErrorCode::Success,
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Receive packet from session
/// On success, writes packet handle to out_packet
/// Caller must free the returned packet with cedar_packet_free()
#[no_mangle]
pub extern "C" fn cedar_session_receive_packet(
    handle: CedarSessionHandle,
    out_packet: *mut CedarPacketHandle,
) -> CedarErrorCode {
    if handle.is_null() || out_packet.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let session = unsafe { &mut *(handle as *mut Session) };
    
    match session.receive_packet() {
        Ok(packet) => {
            let packet_handle = Box::into_raw(Box::new(packet)) as CedarPacketHandle;
            unsafe { *out_packet = packet_handle; }
            CedarErrorCode::Success
        }
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Send data packet to VPN server (for TUN device integration)
/// data should point to raw packet bytes (e.g., IP packet from TUN device)
#[no_mangle]
pub extern "C" fn cedar_session_send_data_packet(
    handle: CedarSessionHandle,
    data: *const u8,
    data_len: usize,
) -> CedarErrorCode {
    if handle.is_null() || data.is_null() || data_len == 0 {
        return CedarErrorCode::InvalidParameter;
    }

    let session = unsafe { &*(handle as *const Session) };
    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len) };

    match session.send_data_packet(data_slice) {
        Ok(_) => CedarErrorCode::Success,
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Try to receive data packet from VPN server (non-blocking)
/// Returns Success and writes packet data if available
/// Returns TimeOut if no packet available
/// buffer should be at least 65536 bytes for typical packets
#[no_mangle]
pub extern "C" fn cedar_session_try_receive_data_packet(
    handle: CedarSessionHandle,
    buffer: *mut u8,
    buffer_size: usize,
    out_size: *mut usize,
) -> CedarErrorCode {
    if handle.is_null() || buffer.is_null() || out_size.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let session = unsafe { &*(handle as *const Session) };
    let buffer_slice = unsafe { std::slice::from_raw_parts_mut(buffer, buffer_size) };

    match session.try_receive_data_packet() {
        Ok(Some((packet_type, data))) => {
            if packet_type == "data" && !data.is_empty() {
                if data.len() > buffer_size {
                    return CedarErrorCode::BufferTooSmall;
                }
                buffer_slice[..data.len()].copy_from_slice(&data);
                unsafe { *out_size = data.len() };
                CedarErrorCode::Success
            } else {
                // Keepalive or empty packet
                unsafe { *out_size = 0 };
                CedarErrorCode::TimeOut
            }
        }
        Ok(None) => {
            unsafe { *out_size = 0 };
            CedarErrorCode::TimeOut
        }
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Poll session for keep-alive (call periodically from forwarding loop)
/// interval_secs: Seconds between keep-alive packets (e.g., 30)
#[no_mangle]
pub extern "C" fn cedar_session_poll_keepalive(
    handle: CedarSessionHandle,
    interval_secs: u64,
) -> CedarErrorCode {
    if handle.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    let session = unsafe { &*(handle as *const Session) };
    match session.poll_keepalive(interval_secs) {
        Ok(_) => CedarErrorCode::Success,
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Authenticate with the server
/// password_hash should be SHA-1 hash of password (20 bytes)
#[no_mangle]
pub extern "C" fn cedar_session_authenticate(
    handle: CedarSessionHandle,
    username: *const c_char,
    password_hash: *const u8,
    hash_len: usize,
) -> CedarErrorCode {
    if handle.is_null() || username.is_null() || password_hash.is_null() {
        return CedarErrorCode::InvalidParameter;
    }

    if hash_len != 20 {
        return CedarErrorCode::InvalidParameter; // SHA-1 is 20 bytes
    }

    let username_str = match unsafe { CStr::from_ptr(username) }.to_str() {
        Ok(s) => s,
        Err(_) => return CedarErrorCode::InvalidParameter,
    };

    let hash_slice = unsafe { std::slice::from_raw_parts(password_hash, hash_len) };

    let session = unsafe { &mut *(handle as *mut Session) };
    
    match session.authenticate(username_str, hash_slice) {
        Ok(_) => CedarErrorCode::Success,
        Err(e) => CedarErrorCode::from(e),
    }
}

/// Poll received packets from background receive thread
/// Returns number of packets retrieved (0 if none available)
/// Each packet is written to buffers[i] with length in lengths[i]
/// max_packets specifies array size
#[no_mangle]
pub extern "C" fn cedar_session_poll_packets(
    handle: CedarSessionHandle,
    buffers: *mut *mut u8,      // Array of buffer pointers (caller allocates)
    lengths: *mut usize,         // Array to store packet lengths
    max_packets: usize,
) -> usize {
    if handle.is_null() || buffers.is_null() || lengths.is_null() || max_packets == 0 {
        return 0;
    }

    let session = unsafe { &*(handle as *const Session) };
    let packets = session.poll_received_packets();
    
    let buffers_slice = unsafe { std::slice::from_raw_parts_mut(buffers, max_packets) };
    let lengths_slice = unsafe { std::slice::from_raw_parts_mut(lengths, max_packets) };
    
    let num_packets = packets.len().min(max_packets);
    
    for (i, packet_data) in packets.iter().take(num_packets).enumerate() {
        // Allocate buffer for packet (caller must free with cedar_free_packet_buffer)
        let packet_len = packet_data.len();
        let packet_buf = unsafe {
            let layout = std::alloc::Layout::from_size_align_unchecked(packet_len, 1);
            std::alloc::alloc(layout)
        };
        
        if packet_buf.is_null() {
            // Allocation failed, return packets retrieved so far
            return i;
        }
        
        // Copy packet data to allocated buffer
        unsafe {
            std::ptr::copy_nonoverlapping(packet_data.as_ptr(), packet_buf, packet_len);
        }
        
        buffers_slice[i] = packet_buf;
        lengths_slice[i] = packet_len;
    }
    
    num_packets
}

/// Free packet buffer allocated by cedar_session_poll_packets
#[no_mangle]
pub extern "C" fn cedar_free_packet_buffer(buffer: *mut u8, length: usize) {
    if !buffer.is_null() && length > 0 {
        unsafe {
            let layout = std::alloc::Layout::from_size_align_unchecked(length, 1);
            std::alloc::dealloc(buffer, layout);
        }
    }
}

/// Queue an outbound packet to send to server (upstream: client → server)
/// This is called by Zig when it reads a packet from TUN that needs to be sent to VPN server
#[no_mangle]
pub extern "C" fn cedar_session_queue_outbound_packet(
    handle: CedarSessionHandle,
    data: *const u8,
    length: usize,
) -> CedarErrorCode {
    if handle.is_null() || data.is_null() || length == 0 {
        return CedarErrorCode::InvalidParameter;
    }
    
    let session = unsafe { &*(handle as *const Session) };
    let packet_data = unsafe { std::slice::from_raw_parts(data, length) }.to_vec();
    
    session.queue_outbound_packet(packet_data);
    
    CedarErrorCode::Success
}

/// Stop background receive thread (called during disconnect)
#[no_mangle]
pub extern "C" fn cedar_session_stop_background_thread(handle: CedarSessionHandle) {
    if handle.is_null() {
        return;
    }

    let session = unsafe { &*(handle as *const Session) };
    session.stop_background_thread();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_conversion() {
        assert_eq!(
            CedarErrorCode::from(mayaqua::Error::NoError),
            CedarErrorCode::Success
        );
        assert_eq!(
            CedarErrorCode::from(mayaqua::Error::InvalidParameter),
            CedarErrorCode::InvalidParameter
        );
    }

    #[test]
    fn test_session_creation_null_ptr() {
        let handle = cedar_session_new(ptr::null(), 443, ptr::null());
        assert!(handle.is_null());
    }

    #[test]
    fn test_packet_creation() {
        let cmd = CString::new("hello").unwrap();
        let handle = cedar_packet_new(cmd.as_ptr());
        assert!(!handle.is_null());
        cedar_packet_free(handle);
    }

    #[test]
    fn test_version_info() {
        let version_ptr = cedar_version();
        assert!(!version_ptr.is_null());
        
        let protocol_ver = cedar_protocol_version();
        assert_eq!(protocol_ver, 4);
    }
}
