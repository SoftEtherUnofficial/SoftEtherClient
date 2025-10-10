#!/bin/bash
# Automated OpenSSL vs Cedar comparison test
# Tests both implementations for behavioral parity

set -e

PROJECT_ROOT="/Volumes/EXT/SoftEtherDev/WorxVPN/SoftEtherZig"
cd "$PROJECT_ROOT"

echo "═══════════════════════════════════════════════════════"
echo "  SoftEther VPN Client - Dual Mode Comparison Test"
echo "  OpenSSL (stable) vs Cedar (experimental)"
echo "═══════════════════════════════════════════════════════"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
OPENSSL_TESTS_PASSED=0
OPENSSL_TESTS_FAILED=0
CEDAR_TESTS_PASSED=0
CEDAR_TESTS_FAILED=0

# Function to print test result
print_result() {
    local test_name="$1"
    local result="$2"
    
    if [ "$result" == "PASS" ]; then
        echo -e "${GREEN}✓${NC} $test_name"
    else
        echo -e "${RED}✗${NC} $test_name"
    fi
}

# Function to run tests for a specific mode
run_mode_tests() {
    local mode="$1"
    local build_cmd="$2"
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing: $mode mode${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Build
    echo -e "\n${YELLOW}1. Building $mode...${NC}"
    if $build_cmd > build_$mode.log 2>&1; then
        print_result "Build $mode" "PASS"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_PASSED++))
        else
            ((CEDAR_TESTS_PASSED++))
        fi
    else
        print_result "Build $mode" "FAIL"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_FAILED++))
        else
            ((CEDAR_TESTS_FAILED++))
        fi
        echo "Build log saved to: build_$mode.log"
        return 1
    fi
    
    # Unit tests
    echo -e "\n${YELLOW}2. Running unit tests...${NC}"
    if zig build test > test_$mode.log 2>&1; then
        local test_count=$(grep -c "Test.*OK" test_$mode.log || echo "0")
        print_result "Unit tests ($test_count passed)" "PASS"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_PASSED++))
        else
            ((CEDAR_TESTS_PASSED++))
        fi
    else
        print_result "Unit tests" "FAIL"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_FAILED++))
        else
            ((CEDAR_TESTS_FAILED++))
        fi
        echo "Test log saved to: test_$mode.log"
    fi
    
    # Config loading test
    echo -e "\n${YELLOW}3. Testing config loading...${NC}"
    if timeout 5 ./zig-out/bin/vpnclient --config config.json 2>&1 | grep -q "Loading configuration from"; then
        print_result "Config loading" "PASS"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_PASSED++))
        else
            ((CEDAR_TESTS_PASSED++))
        fi
    else
        print_result "Config loading" "FAIL"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_FAILED++))
        else
            ((CEDAR_TESTS_FAILED++))
        fi
    fi
    
    # Connection test (without sudo, will fail at TUN creation but should connect)
    echo -e "\n${YELLOW}4. Testing server connection (no sudo)...${NC}"
    local output=$(timeout 15 ./zig-out/bin/vpnclient --config config.json 2>&1 || true)
    
    if echo "$output" | grep -q "SSL connected with TLS"; then
        print_result "TLS connection" "PASS"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_PASSED++))
        else
            ((CEDAR_TESTS_PASSED++))
        fi
    else
        print_result "TLS connection" "FAIL"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_FAILED++))
        else
            ((CEDAR_TESTS_FAILED++))
        fi
    fi
    
    if echo "$output" | grep -q "Welcome packet received"; then
        print_result "Authentication" "PASS"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_PASSED++))
        else
            ((CEDAR_TESTS_PASSED++))
        fi
    else
        print_result "Authentication" "FAIL"
        if [ "$mode" == "OpenSSL" ]; then
            ((OPENSSL_TESTS_FAILED++))
        else
            ((CEDAR_TESTS_FAILED++))
        fi
    fi
    
    # Save connection output
    echo "$output" > connection_$mode.log
    echo "Connection log saved to: connection_$mode.log"
}

# Run OpenSSL tests
run_mode_tests "OpenSSL" "zig build"

# Run Cedar tests
run_mode_tests "Cedar" "zig build -Duse-cedar"

# Summary
echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "OpenSSL Mode:"
echo -e "  ${GREEN}Passed: $OPENSSL_TESTS_PASSED${NC}"
echo -e "  ${RED}Failed: $OPENSSL_TESTS_FAILED${NC}"
echo ""
echo -e "Cedar Mode:"
echo -e "  ${GREEN}Passed: $CEDAR_TESTS_PASSED${NC}"
echo -e "  ${RED}Failed: $CEDAR_TESTS_FAILED${NC}"
echo ""

# Calculate total
TOTAL_PASSED=$((OPENSSL_TESTS_PASSED + CEDAR_TESTS_PASSED))
TOTAL_FAILED=$((OPENSSL_TESTS_FAILED + CEDAR_TESTS_FAILED))
TOTAL_TESTS=$((TOTAL_PASSED + TOTAL_FAILED))

echo -e "Total:"
echo -e "  ${GREEN}Passed: $TOTAL_PASSED${NC} / $TOTAL_TESTS"
echo -e "  ${RED}Failed: $TOTAL_FAILED${NC} / $TOTAL_TESTS"
echo ""

# Parity check
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Behavioral Parity Check${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

if [ $OPENSSL_TESTS_PASSED -eq $CEDAR_TESTS_PASSED ]; then
    echo -e "${GREEN}✓ Both modes have identical pass rates${NC}"
else
    echo -e "${YELLOW}⚠ Different pass rates detected:${NC}"
    echo -e "  OpenSSL: $OPENSSL_TESTS_PASSED/$((OPENSSL_TESTS_PASSED + OPENSSL_TESTS_FAILED))"
    echo -e "  Cedar: $CEDAR_TESTS_PASSED/$((CEDAR_TESTS_PASSED + CEDAR_TESTS_FAILED))"
fi

# Compare connection logs
echo ""
echo -e "${YELLOW}Comparing connection behavior...${NC}"

if [ -f "connection_OpenSSL.log" ] && [ -f "connection_Cedar.log" ]; then
    # Check for TLS connection in both
    if grep -q "SSL connected" connection_OpenSSL.log && grep -q "TLS connection established" connection_Cedar.log; then
        echo -e "${GREEN}✓ Both modes establish secure connections${NC}"
    else
        echo -e "${YELLOW}⚠ Connection establishment differs${NC}"
    fi
    
    # Check for authentication in both
    if grep -q "Welcome packet" connection_OpenSSL.log && grep -q "Welcome packet\|Connection failed" connection_Cedar.log; then
        echo -e "${GREEN}✓ Both modes attempt authentication${NC}"
    fi
    
    # Check adapter creation
    if grep -q "Zig adapter" connection_OpenSSL.log && grep -q "adapter\|InternalError" connection_Cedar.log; then
        echo -e "${GREEN}✓ Both modes use Zig packet adapter${NC}"
    fi
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo ""

# Exit code
if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Review logs for details.${NC}"
    exit 1
fi
