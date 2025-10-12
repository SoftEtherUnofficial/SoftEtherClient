//! FFI bindings for ZigTapTun packet adapter integration
//! 
//! This module provides Rust bindings to the C Bridge's ZigAdapter functions,
//! enabling Cedar to use the same adapter callbacks as the C Bridge.

use std::ffi::c_void;

/// Opaque handle to the ZigPacketAdapter
#[repr(C)]
pub struct ZigPacketAdapter {
    _private: [u8; 0],
}

/// Adapter configuration structure
#[repr(C)]
pub struct ZigAdapterConfig {
    pub mtu: u32,
    pub mac_address: [u8; 6],
    pub enable_dhcp: bool,
    pub log_level: u32,
}

/// Packet buffer structure for adapter communication
#[repr(C)]
pub struct ZigPacketBuffer {
    pub data: *mut u8,
    pub size: u32,
    pub capacity: u32,
}

extern "C" {
    /// Create a new ZigPacketAdapter instance
    pub fn zig_adapter_create(config: *const ZigAdapterConfig) -> *mut ZigPacketAdapter;
    
    /// Destroy a ZigPacketAdapter instance
    pub fn zig_adapter_destroy(adapter: *mut ZigPacketAdapter);
    
    /// Get the next packet to send to the server (FROM adapter TO server)
    /// Returns true if a packet is available, false otherwise
    pub fn zig_adapter_get_packet(
        adapter: *mut ZigPacketAdapter,
        buffer: *mut ZigPacketBuffer
    ) -> bool;
    
    /// Put a received packet into the adapter (FROM server TO adapter)
    /// Returns true on success, false on error
    pub fn zig_adapter_put_packet(
        adapter: *mut ZigPacketAdapter,
        data: *const u8,
        size: u32
    ) -> bool;
    
    /// Check if the adapter has pending packets to send
    pub fn zig_adapter_has_pending_packets(adapter: *mut ZigPacketAdapter) -> bool;
    
    /// Get adapter statistics
    pub fn zig_adapter_get_stats(
        adapter: *mut ZigPacketAdapter,
        packets_sent: *mut u64,
        packets_received: *mut u64,
        bytes_sent: *mut u64,
        bytes_received: *mut u64
    );
}

/// Safe Rust wrapper for ZigPacketAdapter
pub struct PacketAdapter {
    adapter: *mut ZigPacketAdapter,
}

impl PacketAdapter {
    /// Create a new PacketAdapter with the given configuration
    pub fn new(config: ZigAdapterConfig) -> Result<Self, String> {
        let adapter = unsafe { zig_adapter_create(&config as *const _) };
        
        if adapter.is_null() {
            return Err("Failed to create ZigPacketAdapter".to_string());
        }
        
        eprintln!("[ADAPTER] ✅ Created ZigPacketAdapter with DHCP enabled");
        Ok(PacketAdapter { adapter })
    }
    
    /// Get the next packet to send to the server
    pub fn get_next_packet(&mut self) -> Option<Vec<u8>> {
        let mut buffer = ZigPacketBuffer {
            data: std::ptr::null_mut(),
            size: 0,
            capacity: 0,
        };
        
        let has_packet = unsafe { zig_adapter_get_packet(self.adapter, &mut buffer as *mut _) };
        
        if !has_packet || buffer.data.is_null() || buffer.size == 0 {
            return None;
        }
        
        // Copy the packet data
        let packet = unsafe {
            std::slice::from_raw_parts(buffer.data, buffer.size as usize).to_vec()
        };
        
        eprintln!("[ADAPTER] 📤 Got packet from adapter: {} bytes", packet.len());
        Some(packet)
    }
    
    /// Put a received packet into the adapter
    pub fn put_received_packet(&mut self, data: &[u8]) -> Result<(), String> {
        let success = unsafe {
            zig_adapter_put_packet(self.adapter, data.as_ptr(), data.len() as u32)
        };
        
        if success {
            eprintln!("[ADAPTER] 📥 Put packet into adapter: {} bytes", data.len());
            Ok(())
        } else {
            Err("Failed to put packet into adapter".to_string())
        }
    }
    
    /// Check if the adapter has pending packets to send
    pub fn has_pending_packets(&self) -> bool {
        unsafe { zig_adapter_has_pending_packets(self.adapter) }
    }
    
    /// Get adapter statistics
    pub fn get_statistics(&self) -> AdapterStats {
        let mut stats = AdapterStats::default();
        
        unsafe {
            zig_adapter_get_stats(
                self.adapter,
                &mut stats.packets_sent as *mut _,
                &mut stats.packets_received as *mut _,
                &mut stats.bytes_sent as *mut _,
                &mut stats.bytes_received as *mut _,
            );
        }
        
        stats
    }
}

impl Drop for PacketAdapter {
    fn drop(&mut self) {
        if !self.adapter.is_null() {
            eprintln!("[ADAPTER] 🔻 Destroying ZigPacketAdapter");
            unsafe { zig_adapter_destroy(self.adapter) };
            self.adapter = std::ptr::null_mut();
        }
    }
}

unsafe impl Send for PacketAdapter {}
unsafe impl Sync for PacketAdapter {}

/// Adapter statistics
#[derive(Debug, Default, Clone)]
pub struct AdapterStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl std::fmt::Display for AdapterStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Packets: ↑{} ↓{}, Bytes: ↑{} ↓{}",
            self.packets_sent, self.packets_received, self.bytes_sent, self.bytes_received
        )
    }
}
