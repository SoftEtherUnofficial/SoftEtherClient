//! Session Key Derivation Example
//! Demonstrates SoftEther VPN's password-based authentication flow
//!
//! Usage: zig build-exe examples/key_derivation_example.zig && ./key_derivation_example

const std = @import("std");
const crypto = @import("../src/protocol/crypto.zig");

pub fn main() !void {
    std.debug.print("\n=== SoftEther VPN Key Derivation Example ===\n\n", .{});

    // ============================================================================
    // Step 1: Client prepares password (done once, hashed password can be stored)
    // ============================================================================
    const username = "vpn_user";
    const plaintext_password = "MySecurePassword123!";

    std.debug.print("1. Client Authentication Setup\n", .{});
    std.debug.print("   Username: {s}\n", .{username});
    std.debug.print("   Password: {s}\n", .{plaintext_password});

    // Hash the password with SHA-0 (first layer)
    var hashed_password: [crypto.SHA0_SIZE]u8 = undefined;
    crypto.KeyDerivation.hashPassword(plaintext_password, &hashed_password);

    std.debug.print("   Hashed Password (SHA-0): ", .{});
    for (hashed_password) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    // ============================================================================
    // Step 2: Server sends random challenge (20 bytes)
    // ============================================================================
    std.debug.print("2. Server Challenge\n", .{});

    var server_random: [crypto.SHA0_SIZE]u8 = undefined;
    try crypto.KeyDerivation.generateRandom(&server_random);

    std.debug.print("   Server Random: ", .{});
    for (server_random) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    // ============================================================================
    // Step 3: Client derives secure password (authentication proof)
    // ============================================================================
    std.debug.print("3. Client Response (Secure Password Derivation)\n", .{});

    var secure_password: [crypto.SHA0_SIZE]u8 = undefined;
    crypto.KeyDerivation.securePassword(&hashed_password, &server_random, &secure_password);

    std.debug.print("   Formula: SecurePassword = SHA-0(HashedPassword || ServerRandom)\n", .{});
    std.debug.print("   Secure Password: ", .{});
    for (secure_password) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n\n", .{});

    // ============================================================================
    // Step 4: Server verifies (re-computes secure password from stored hash)
    // ============================================================================
    std.debug.print("4. Server Verification\n", .{});

    // Server has stored hashed_password from user database
    var server_computed: [crypto.SHA0_SIZE]u8 = undefined;
    crypto.KeyDerivation.securePassword(&hashed_password, &server_random, &server_computed);

    const authenticated = std.mem.eql(u8, &secure_password, &server_computed);
    std.debug.print("   Authentication: {s}\n", .{if (authenticated) "✓ SUCCESS" else "✗ FAILED"});
    std.debug.print("\n", .{});

    // ============================================================================
    // Step 5: Use secure password as RC4 encryption key (if authenticated)
    // ============================================================================
    if (authenticated) {
        std.debug.print("5. Session Encryption Key Setup\n", .{});
        std.debug.print("   Using secure_password as RC4 key (20 bytes)\n", .{});
        std.debug.print("   RC4 Key: ", .{});
        for (secure_password) |byte| {
            std.debug.print("{x:0>2}", .{byte});
        }
        std.debug.print("\n", .{});

        // Demonstrate RC4 encryption with this key
        var gpa = std.heap.GeneralPurposeAllocator(.{}){};
        defer _ = gpa.deinit();
        const allocator = gpa.allocator();

        var rc4 = try crypto.Rc4Cipher.init(allocator, &secure_password);
        defer rc4.deinit();

        const plaintext = "Hello from SoftEther VPN!";
        const ciphertext = try allocator.alloc(u8, plaintext.len);
        defer allocator.free(ciphertext);

        rc4.encrypt(ciphertext, plaintext);

        std.debug.print("   Plaintext: {s}\n", .{plaintext});
        std.debug.print("   Ciphertext: ", .{});
        for (ciphertext) |byte| {
            std.debug.print("{x:0>2}", .{byte});
        }
        std.debug.print("\n\n", .{});
    }

    // ============================================================================
    // Alternative: One-step authentication key derivation
    // ============================================================================
    std.debug.print("6. Alternative: One-Step Derivation\n", .{});

    var auth_key: [crypto.SHA0_SIZE]u8 = undefined;
    crypto.KeyDerivation.deriveAuthKey(plaintext_password, &server_random, &auth_key);

    std.debug.print("   Formula: AuthKey = SHA-0(SHA-0(Password) || ServerRandom)\n", .{});
    std.debug.print("   Auth Key: ", .{});
    for (auth_key) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n", .{});

    const keys_match = std.mem.eql(u8, &secure_password, &auth_key);
    std.debug.print("   Matches secure_password: {s}\n\n", .{if (keys_match) "✓ YES" else "✗ NO"});

    // ============================================================================
    // Security Notes
    // ============================================================================
    std.debug.print("=== Security Notes ===\n", .{});
    std.debug.print("⚠ SHA-0 is DEPRECATED and cryptographically broken (collisions exist)\n", .{});
    std.debug.print("⚠ RC4 is DEPRECATED and insecure (biased keystream, NOMORE attack)\n", .{});
    std.debug.print("⚠ This implementation is for SoftEther VPN compatibility only\n", .{});
    std.debug.print("✓ For new protocols, use: Argon2/PBKDF2 + AES-256-GCM/ChaCha20-Poly1305\n", .{});
    std.debug.print("\n", .{});
}
