const std = @import("std");

const SHA0_SIZE: usize = 20;

pub const Sha0Context = struct {
    count: u64,
    buf: [64]u8,
    state: [5]u32,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .count = 0,
            .buf = [_]u8{0} ** 64,
            .state = [5]u32{
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            },
        };
    }

    fn rol(bits: u5, value: u32) u32 {
        if (bits == 0) return value;
        const right_shift: u6 = 32 - @as(u6, bits);
        return (value << bits) | (value >> @intCast(right_shift));
    }

    fn transform(self: *Self) void {
        var W: [80]u32 = undefined;
        var p: usize = 0;

        // Load first 16 words (big-endian)
        var t: usize = 0;
        while (t < 16) : (t += 1) {
            W[t] = (@as(u32, self.buf[p]) << 24) |
                (@as(u32, self.buf[p + 1]) << 16) |
                (@as(u32, self.buf[p + 2]) << 8) |
                @as(u32, self.buf[p + 3]);
            p += 4;
        }

        // Extend to 80 words (NOTE: SHA-0 bug - no rotation!)
        while (t < 80) : (t += 1) {
            // SHA-0 BUG: Missing rol(1, ...) that SHA-1 has
            W[t] = W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16];
        }

        var A = self.state[0];
        var B = self.state[1];
        var C = self.state[2];
        var D = self.state[3];
        var E = self.state[4];

        t = 0;
        while (t < 80) : (t += 1) {
            var tmp = rol(5, A) +% E +% W[t];
            if (t < 20) {
                tmp +%= (D ^ (B & (C ^ D))) +% 0x5A827999;
            } else if (t < 40) {
                tmp +%= (B ^ C ^ D) +% 0x6ED9EBA1;
            } else if (t < 60) {
                tmp +%= ((B & C) | (D & (B | C))) +% 0x8F1BBCDC;
            } else {
                tmp +%= (B ^ C ^ D) +% 0xCA62C1D6;
            }
            E = D;
            D = C;
            C = rol(30, B);
            B = A;
            A = tmp;
        }

        self.state[0] +%= A;
        self.state[1] +%= B;
        self.state[2] +%= C;
        self.state[3] +%= D;
        self.state[4] +%= E;
    }

    pub fn update(self: *Self, data: []const u8) void {
        var i = @as(usize, @intCast(self.count & 63));
        var p: usize = 0;
        var len = data.len;

        self.count += @as(u64, len);

        while (len > 0) {
            self.buf[i] = data[p];
            i += 1;
            p += 1;
            len -= 1;

            if (i == 64) {
                self.transform();
                i = 0;
            }
        }
    }

    pub fn final(self: *Self, output: *[SHA0_SIZE]u8) void {
        std.debug.print("final() called, count before padding: {}\n", .{self.count});

        // Padding
        const padding = [_]u8{0x80} ++ [_]u8{0} ** 63;

        // Calculate length BEFORE modifying count
        const cnt = self.count * 8;
        std.debug.print("length in bits: {}\n", .{cnt});

        self.update(padding[0..1]);
        std.debug.print("after 0x80, count: {}\n", .{self.count});

        while ((self.count & 63) != 56) {
            self.update(padding[1..2]);
        }
        std.debug.print("after padding zeros, count: {}\n", .{self.count});

        // Append length in bits (big-endian)
        var length_bytes: [8]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            length_bytes[i] = @as(u8, @truncate(cnt >> @as(u6, @intCast((7 - i) * 8))));
        }

        std.debug.print("length bytes: ", .{});
        for (length_bytes) |b| {
            std.debug.print("{x:0>2} ", .{b});
        }
        std.debug.print("\n", .{});

        self.update(&length_bytes);
        std.debug.print("after length, count: {}\n", .{self.count});

        // Output hash (big-endian)
        i = 0;
        var p: usize = 0;
        while (i < 5) : (i += 1) {
            const tmp = self.state[i];
            output[p] = @as(u8, @truncate(tmp >> 24));
            output[p + 1] = @as(u8, @truncate(tmp >> 16));
            output[p + 2] = @as(u8, @truncate(tmp >> 8));
            output[p + 3] = @as(u8, @truncate(tmp));
            p += 4;
        }

        std.debug.print("final state: ", .{});
        for (self.state) |s| {
            std.debug.print("{x:0>8} ", .{s});
        }
        std.debug.print("\n", .{});
    }

    pub fn hash(data: []const u8, output: *[SHA0_SIZE]u8) void {
        var ctx = Sha0Context.init();
        ctx.update(data);
        ctx.final(output);
    }
};

pub fn main() !void {
    var output: [SHA0_SIZE]u8 = undefined;

    // Test empty string
    Sha0Context.hash("", &output);
    std.debug.print("SHA-0(\"\"): ", .{});
    for (output) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    // Test "abc"
    Sha0Context.hash("abc", &output);
    std.debug.print("SHA-0(\"abc\"): ", .{});
    for (output) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});
}
