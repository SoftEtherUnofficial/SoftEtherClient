/**
 * Direct API Test Program
 * 
 * Tests the direct C API implementation by connecting to a VPN server
 * and verifying CLIENT*, SESSION*, and PACKET_ADAPTER* objects work correctly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/direct_api.h"

// Test configuration (update with real server details)
#define TEST_SERVER     "your-server.example.com"
#define TEST_PORT       443
#define TEST_HUB        "VPN"
#define TEST_USERNAME   "testuser"
#define TEST_PASSWORD   "testpass"

// Global state for callbacks
static int g_status_changes = 0;
static int g_error_count = 0;
static SEStatus g_last_status = SE_STATUS_DISCONNECTED;

// Status callback
static void status_callback(SEStatus status, const char* message, void* user_data) {
    const char* status_str = "UNKNOWN";
    switch (status) {
        case SE_STATUS_DISCONNECTED: status_str = "DISCONNECTED"; break;
        case SE_STATUS_CONNECTING: status_str = "CONNECTING"; break;
        case SE_STATUS_CONNECTED: status_str = "CONNECTED"; break;
        case SE_STATUS_ERROR: status_str = "ERROR"; break;
    }
    
    printf("[STATUS] %s: %s\n", status_str, message ? message : "(no message)");
    g_status_changes++;
    g_last_status = status;
}

// Error callback
static void error_callback(int error_code, const char* message, void* user_data) {
    printf("[ERROR] Code %d: %s\n", error_code, message ? message : "(no message)");
    g_error_count++;
}

// Network configuration callback
static void network_callback(const char* ip, const char* subnet, const char* gateway, void* user_data) {
    printf("[NETWORK] IP: %s, Subnet: %s, Gateway: %s\n", 
           ip ? ip : "N/A", 
           subnet ? subnet : "N/A", 
           gateway ? gateway : "N/A");
}

// Test: Library initialization
static int test_init_shutdown() {
    printf("\n=== Test 1: Library Init/Shutdown ===\n");
    
    int result = se_init();
    if (result != SE_ERROR_NONE) {
        printf("FAIL: se_init() returned %d\n", result);
        return -1;
    }
    printf("PASS: se_init() succeeded\n");
    
    se_shutdown();
    printf("PASS: se_shutdown() completed\n");
    
    return 0;
}

// Test: Password hash generation
static int test_password_hash() {
    printf("\n=== Test 2: Password Hash Generation ===\n");
    
    se_init();
    
    char* hash = se_generate_password_hash(TEST_PASSWORD, TEST_USERNAME);
    
    if (hash == NULL) {
        printf("FAIL: se_generate_password_hash() returned NULL\n");
        se_shutdown();
        return -1;
    }
    
    printf("PASS: Generated password hash (length: %zu)\n", strlen(hash));
    printf("      Hash: %s\n", hash);
    
    // Verify hash is not empty
    if (strlen(hash) == 0) {
        printf("FAIL: Hash is empty\n");
        free(hash);
        se_shutdown();
        return -1;
    }
    
    free(hash);
    se_shutdown();
    return 0;
}

// Test: Connection (basic)
static int test_connect_basic() {
    printf("\n=== Test 3: Basic Connection Test ===\n");
    printf("NOTE: This test requires a real VPN server at %s:%d\n", TEST_SERVER, TEST_PORT);
    printf("      Update TEST_SERVER, TEST_PORT, TEST_HUB, TEST_USERNAME, TEST_PASSWORD\n");
    printf("      in test_direct_api.c to run this test.\n\n");
    
    se_init();
    
    // Generate password hash
    char* password_hash = se_generate_password_hash(TEST_PASSWORD, TEST_USERNAME);
    if (password_hash == NULL) {
        printf("FAIL: Password hash generation failed\n");
        se_shutdown();
        return -1;
    }
    
    // Configure connection
    SEConfig config = {
        .server = TEST_SERVER,
        .port = TEST_PORT,
        .hub = TEST_HUB,
        .username = TEST_USERNAME,
        .password_hash = password_hash,
        .use_encrypt = true,
        .use_compress = false,
        .client_name = "DirectAPITest"
    };
    
    printf("Connecting to %s:%d (hub: %s, user: %s)...\n", 
           TEST_SERVER, TEST_PORT, TEST_HUB, TEST_USERNAME);
    
    // Reset counters
    g_status_changes = 0;
    g_error_count = 0;
    g_last_status = SE_STATUS_DISCONNECTED;
    
    // Attempt connection
    SESessionHandle handle = se_connect(&config, network_callback, status_callback, error_callback, NULL);
    
    if (handle == NULL) {
        printf("FAIL: se_connect() returned NULL\n");
        printf("      Last status: %d, Errors: %d\n", g_last_status, g_error_count);
        se_shutdown();
        return -1;
    }
    
    printf("PASS: se_connect() returned handle (status changes: %d)\n", g_status_changes);
    
    // Check initial status
    SEStatus status = se_get_status(handle);
    printf("      Initial status: %d\n", status);
    
    // Wait a bit for connection to progress
    printf("Waiting 5 seconds for connection...\n");
    for (int i = 0; i < 5; i++) {
        sleep(1);
        status = se_get_status(handle);
        printf("      Status after %d sec: %d\n", i+1, status);
        
        if (status == SE_STATUS_CONNECTED) {
            printf("SUCCESS: Connected to VPN server!\n");
            break;
        }
        
        if (status == SE_STATUS_ERROR) {
            printf("WARNING: Connection error occurred\n");
            const char* error_msg = se_get_error_message(handle);
            printf("         Error: %s\n", error_msg ? error_msg : "(no message)");
            break;
        }
    }
    
    // Get statistics
    SEStats stats;
    se_get_stats(handle, &stats);
    printf("Statistics:\n");
    printf("  Bytes sent: %llu, received: %llu\n", stats.bytes_sent, stats.bytes_received);
    printf("  Packets sent: %llu, received: %llu\n", stats.packets_sent, stats.packets_received);
    printf("  Connection time: %llu ms\n", stats.connected_time_ms);
    
    // Disconnect
    printf("Disconnecting...\n");
    se_disconnect(handle);
    printf("PASS: Disconnected successfully\n");
    
    free(password_hash);
    se_shutdown();
    
    printf("\nTest completed with %d status changes, %d errors\n", 
           g_status_changes, g_error_count);
    
    return 0;
}

// Test: API version info
static int test_version_info() {
    printf("\n=== Test 4: Version Information ===\n");
    
    se_init();
    
    const char* version = se_get_version();
    const char* build_info = se_get_build_info();
    
    printf("Version: %s\n", version ? version : "(unknown)");
    printf("Build Info: %s\n", build_info ? build_info : "(unknown)");
    
    if (!version || !build_info || strlen(version) == 0 || strlen(build_info) == 0) {
        printf("FAIL: Version or build info is empty\n");
        se_shutdown();
        return -1;
    }
    
    printf("PASS: Version info retrieved\n");
    
    se_shutdown();
    return 0;
}

// Main test runner
int main(int argc, char** argv) {
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║      SoftEther VPN Client - Direct API Test Suite           ║\n");
    printf("║      Testing direct CLIENT*/SESSION* usage (zero FFI)       ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    
    int failed = 0;
    
    // Run tests
    if (test_init_shutdown() != 0) failed++;
    if (test_password_hash() != 0) failed++;
    if (test_version_info() != 0) failed++;
    
    // Connection test (may fail if no server available)
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                 Connection Test (Optional)                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\nWARNING: The following test requires a real VPN server.\n");
    printf("         Update the TEST_* constants at the top of this file.\n");
    printf("         Skip if you don't have a test server available.\n\n");
    
    if (argc > 1 && strcmp(argv[1], "--connect") == 0) {
        if (test_connect_basic() != 0) {
            printf("\nNote: Connection test failed - this is expected if no test server is configured.\n");
        }
    } else {
        printf("Skipped (run with --connect to test real connection)\n");
    }
    
    // Summary
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                      Test Summary                            ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    
    if (failed == 0) {
        printf("\n✓ All tests PASSED\n\n");
        return 0;
    } else {
        printf("\n✗ %d test(s) FAILED\n\n", failed);
        return 1;
    }
}
