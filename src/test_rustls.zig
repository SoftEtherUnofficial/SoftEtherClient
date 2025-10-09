const std = @import("std");
const rustls = @import("rustls.zig");

test "rustls module import" {
    // Test that we can import the module
    _ = rustls;
}

test "rustls init and version" {
    try rustls.init();

    const ver = rustls.version();
    try std.testing.expect(ver.len > 0);

    std.debug.print("\nrustls version: {s}\n", .{ver});
}

test "rustls-ffi version struct" {
    const ver = rustls.rustlsVersion();
    const slice = ver.slice();

    try std.testing.expect(slice.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, slice, "rustls") != null);

    std.debug.print("\nrustls-ffi version: {s}\n", .{slice});
}
