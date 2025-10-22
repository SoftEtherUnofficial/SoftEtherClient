#!/bin/bash
# Test script for GARP keep-alive functionality
# Usage: sudo ./scripts/test_keepalive.sh

set -e

echo "========================================="
echo "Testing GARP Keep-Alive (Phase 1)"
echo "========================================="
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root (sudo)" 
   exit 1
fi

echo "1. Starting VPN client..."
./zig-out/bin/vpnclient --config config.json &
VPN_PID=$!
echo "   VPN PID: $VPN_PID"
echo ""

# Wait for connection to establish
sleep 5

# Find the utun device
UTUN_DEV=$(ifconfig | grep -o 'utun[0-9]*' | head -1)
if [ -z "$UTUN_DEV" ]; then
    echo "❌ No utun device found - VPN not connected?"
    kill $VPN_PID 2>/dev/null || true
    exit 1
fi

echo "2. VPN device detected: $UTUN_DEV"
echo ""

# Start tcpdump in background to capture GARP
echo "3. Capturing GARP packets on $UTUN_DEV for 35 seconds..."
echo "   (Expecting 3-4 GARP packets with 10-second interval)"
echo ""

timeout 35 tcpdump -i $UTUN_DEV -n -e arp 2>&1 | tee garp_capture.log &
TCPDUMP_PID=$!

# Wait for 35 seconds (should see ~3 GARP packets)
sleep 35

echo ""
echo "========================================="
echo "4. Analyzing Results"
echo "========================================="

# Count GARP packets
GARP_COUNT=$(grep -c "is-at" garp_capture.log 2>/dev/null || echo "0")

echo ""
echo "📊 Results:"
echo "   GARP packets captured: $GARP_COUNT"
echo ""

if [ "$GARP_COUNT" -ge 3 ]; then
    echo "✅ SUCCESS: Keep-alive working! ($GARP_COUNT GARP packets in 35 seconds)"
    echo "   Expected: ~3-4 packets (10-second interval)"
else
    echo "⚠️  WARNING: Only $GARP_COUNT GARP packets detected"
    echo "   Expected: ~3-4 packets (10-second interval)"
    echo "   This might indicate keep-alive is not working correctly"
fi

echo ""
echo "========================================="
echo "5. Cleanup"
echo "========================================="

# Kill VPN and tcpdump
kill $VPN_PID 2>/dev/null || true
kill $TCPDUMP_PID 2>/dev/null || true
wait $VPN_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

echo "✅ Cleanup complete"
echo ""
echo "Log file saved: garp_capture.log"
echo ""

if [ "$GARP_COUNT" -ge 3 ]; then
    exit 0
else
    exit 1
fi
