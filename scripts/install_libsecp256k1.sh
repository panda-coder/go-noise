#!/bin/bash

set -e

echo "Installing libsecp256k1 with ElligatorSwift support (BIP324)..."

SECP256K1_VERSION="v0.4.1"
BUILD_DIR="/tmp/secp256k1-build"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Cloning libsecp256k1..."
git clone --depth 1 --branch "$SECP256K1_VERSION" https://github.com/bitcoin-core/secp256k1.git
cd secp256k1

echo "Configuring libsecp256k1..."
./autogen.sh
./configure \
    --enable-module-ellswift \
    --enable-module-schnorrsig \
    --enable-experimental \
    --disable-tests \
    --disable-benchmark

echo "Building libsecp256k1..."
make -j$(nproc 2>/dev/null || echo 2)

echo "Installing libsecp256k1..."
sudo make install

sudo ldconfig 2>/dev/null || true

echo ""
echo "✓ libsecp256k1 installed successfully!"
echo ""
echo "Installation location:"
echo "  Headers: /usr/local/include/"
echo "  Library: /usr/local/lib/"
echo ""
echo "You can now build the Go project with: go build ./..."
