//! VPN Configuration Management
//!
//! Safe wrappers around Mayaqua config FFI functions.

const std = @import("std");
const mayaqua = @import("../mayaqua.zig");
const c = mayaqua.c;
const MayaquaError = mayaqua.MayaquaError;
const checkResult = mayaqua.checkResult;

/// VPN Configuration with RAII cleanup
pub const VpnConfig = struct {
    handle: *c.MayaquaConfig,
    
    /// Load config from file
    ///
    /// ## Parameters
    /// - `path`: Path to config JSON file
    ///
    /// ## Returns
    /// - Loaded config (caller must call free())
    ///
    /// ## Example
    /// ```zig
    /// var config = try VpnConfig.load("/path/to/config.json");
    /// defer config.free();
    /// ```
    pub fn load(path: []const u8) MayaquaError!VpnConfig {
        var path_buf: [4096]u8 = undefined;
        if (path.len >= path_buf.len) {
            return MayaquaError.InvalidParameter;
        }
        
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;
        
        var config_ptr: ?*c.MayaquaConfig = null;
        
        const result = c.mayaqua_config_load(
            @ptrCast(&path_buf),
            @ptrCast(&config_ptr),
        );
        try checkResult(result);
        
        if (config_ptr == null) {
            return MayaquaError.NullPointer;
        }
        
        return .{ .handle = config_ptr.? };
    }
    
    /// Save config to file
    ///
    /// ## Parameters
    /// - `path`: Path to save config JSON file
    ///
    /// ## Example
    /// ```zig
    /// try config.save("/path/to/config.json");
    /// ```
    pub fn save(self: VpnConfig, path: []const u8) MayaquaError!void {
        var path_buf: [4096]u8 = undefined;
        if (path.len >= path_buf.len) {
            return MayaquaError.InvalidParameter;
        }
        
        @memcpy(path_buf[0..path.len], path);
        path_buf[path.len] = 0;
        
        const result = c.mayaqua_config_save(
            self.handle,
            @ptrCast(&path_buf),
        );
        try checkResult(result);
    }
    
    /// Validate config
    ///
    /// ## Example
    /// ```zig
    /// try config.validate();
    /// ```
    pub fn validate(self: VpnConfig) MayaquaError!void {
        const result = c.mayaqua_config_validate(self.handle);
        try checkResult(result);
    }
    
    /// Get string field from config
    ///
    /// ## Parameters
    /// - `allocator`: Allocator for the returned string
    /// - `field`: Field name (e.g., "server", "hub", "username")
    ///
    /// ## Returns
    /// - Field value as string, or error if field is None
    ///
    /// ## Example
    /// ```zig
    /// const server = try config.getString(allocator, "server");
    /// defer allocator.free(server);
    /// ```
    pub fn getString(self: VpnConfig, allocator: std.mem.Allocator, field: []const u8) MayaquaError![]u8 {
        var field_buf: [64]u8 = undefined;
        if (field.len >= field_buf.len) {
            return MayaquaError.InvalidParameter;
        }
        
        @memcpy(field_buf[0..field.len], field);
        field_buf[field.len] = 0;
        
        var value_ptr: [*c]u8 = null;
        
        const result = c.mayaqua_config_get_string(
            self.handle,
            @ptrCast(&field_buf),
            @ptrCast(&value_ptr),
        );
        try checkResult(result);
        
        if (value_ptr == null) {
            return MayaquaError.NullPointer;
        }
        
        // Copy from Rust allocation
        const value_len = std.mem.len(value_ptr);
        const value = try allocator.dupe(u8, value_ptr[0..value_len]);
        
        // Free Rust allocation
        c.mayaqua_free_string(value_ptr);
        
        return value;
    }
    
    /// Get integer field from config
    ///
    /// ## Parameters
    /// - `field`: Field name (e.g., "port", "max_connection")
    ///
    /// ## Returns
    /// - Field value as integer
    ///
    /// ## Example
    /// ```zig
    /// const port = try config.getInt("port");
    /// ```
    pub fn getInt(self: VpnConfig, field: []const u8) MayaquaError!i32 {
        var field_buf: [64]u8 = undefined;
        if (field.len >= field_buf.len) {
            return MayaquaError.InvalidParameter;
        }
        
        @memcpy(field_buf[0..field.len], field);
        field_buf[field.len] = 0;
        
        var value: i32 = 0;
        
        const result = c.mayaqua_config_get_int(
            self.handle,
            @ptrCast(&field_buf),
            &value,
        );
        try checkResult(result);
        
        return value;
    }
    
    /// Get boolean field from config
    ///
    /// ## Parameters
    /// - `field`: Field name (e.g., "use_encrypt", "use_compress")
    ///
    /// ## Returns
    /// - Field value as boolean
    ///
    /// ## Example
    /// ```zig
    /// const use_encrypt = try config.getBool("use_encrypt");
    /// ```
    pub fn getBool(self: VpnConfig, field: []const u8) MayaquaError!bool {
        var field_buf: [64]u8 = undefined;
        if (field.len >= field_buf.len) {
            return MayaquaError.InvalidParameter;
        }
        
        @memcpy(field_buf[0..field.len], field);
        field_buf[field.len] = 0;
        
        var value: bool = false;
        
        const result = c.mayaqua_config_get_bool(
            self.handle,
            @ptrCast(&field_buf),
            &value,
        );
        try checkResult(result);
        
        return value;
    }
    
    /// Free config
    pub fn free(self: VpnConfig) void {
        c.mayaqua_config_free(self.handle);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "config load and validate" {
    // Try to load example config
    var config = VpnConfig.load("config.example.json") catch |err| {
        if (err == MayaquaError.OperationFailed) {
            // File might not exist, skip test
            return error.SkipZigTest;
        }
        return err;
    };
    defer config.free();
    
    // Validate loaded config
    try config.validate();
}

test "config get fields" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    // Try to load example config
    var config = VpnConfig.load("config.example.json") catch |err| {
        if (err == MayaquaError.OperationFailed) {
            return error.SkipZigTest;
        }
        return err;
    };
    defer config.free();
    
    // Try to get string field
    const server = config.getString(allocator, "server") catch |err| {
        if (err == MayaquaError.FieldIsNone) {
            // Field might be None in example config
            return error.SkipZigTest;
        }
        return err;
    };
    defer allocator.free(server);
    
    try testing.expect(server.len > 0);
    
    // Get integer field
    const port = try config.getInt("port");
    try testing.expect(port > 0 and port <= 65535);
    
    // Get boolean field
    const use_encrypt = try config.getBool("use_encrypt");
    _ = use_encrypt; // Just verify it returns without error
}
