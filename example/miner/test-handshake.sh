#!/bin/bash

# Test X25519 handshake with Python pool
echo "Testing X25519 handshake with Python pool simulator..."
echo ""

# Check if Python pool is running
if ! nc -z localhost 2000 2>/dev/null; then
    echo "❌ Python pool is not running on localhost:2000"
    echo "   Start it with: cd py-miner && python simulate-pool.py"
    exit 1
fi

echo "✓ Python pool is running"
echo ""
echo "Testing Go miner with X25519 protocol..."
echo ""

# Run miner in test mode (will fail after handshake due to protocol differences, but handshake should work)
timeout 5s ./miner -host localhost -port 2000 -worker test-x25519 || true

echo ""
echo "If you see '✓ X25519 handshake completed successfully!' above, the test passed!"
