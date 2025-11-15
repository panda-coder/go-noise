# Go Stratum V2 Miner

A Stratum V2 mining client implementation in Go with support for both ElligatorSwift and X25519 protocols.

## Features

- Dual protocol support:
  - **ElligatorSwift** (Stratum V2 spec): For production Stratum V2 pools
  - **X25519** (Standard Noise): For testing with Python pool simulator
- Noise protocol encryption
- Mining job management
- Share submission

## Usage

### Basic Usage

```bash
# Connect to Python pool simulator (uses X25519 by default)
go run . -host localhost -port 2000

# Connect to real Stratum V2 pool (use ElligatorSwift)
go run . -host pool.example.com -port 3333 -ellswift
```

### Command Line Flags

- `-host` - Pool host address (default: `localhost`)
- `-port` - Pool port (default: `2000`)
- `-worker` - Worker name (default: `go-miner.worker`)
- `-hashrate` - Hashrate in GH/s (default: `0.000250` = 250 kH/s)
- `-encryption` - Enable Noise protocol encryption (default: `true`)
- `-ellswift` - Use ElligatorSwift protocol (default: `false`)

### Protocol Selection

**X25519 (default):**
- Compatible with Python pool simulator (`py-miner/simulate-pool.py`)
- Uses 32-byte public keys
- Standard Noise protocol

**ElligatorSwift:**
- Compatible with real Stratum V2 pools
- Uses 64-byte public keys  
- Official Stratum V2 specification

### Examples

```bash
# Test with Python simulator
go run . -host localhost -port 2000 -worker test-miner

# Connect to production pool with ElligatorSwift
go run . -host pool.sv2.com -port 3333 -ellswift -worker my-worker

# Run without encryption (testing only)
go run . -host localhost -port 2000 -encryption=false
```

## Docker Usage

```bash
# Build and run with docker-compose
docker-compose up

# Run miner separately
docker-compose run miner go run /app/main.go -host pool -port 2000
```

## Testing with Python Pool Simulator

1. Start the Python pool simulator:
```bash
cd py-miner
python simulate-pool.py
```

2. Connect the Go miner (X25519 mode):
```bash
go run . -host localhost -port 2000
```

The miner will automatically use X25519 protocol which is compatible with the Python simulator.

## Protocol Details

### X25519 Handshake (Blake2s Hash)
- **Protocol:** `Noise_NX_25519_ChaChaPoly_BLAKE2s`
- **Hash Function:** Blake2s (compatible with Python dissononce library)
- **Act 1:** 32 bytes (ephemeral public key)
- **Act 2:** 80 bytes (32 bytes ephemeral + 48 bytes encrypted static + MAC)

### ElligatorSwift Handshake (SHA256 Hash)
- **Protocol:** `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256`
- **Hash Function:** SHA256 (Stratum V2 specification)
- **Act 1:** 64 bytes (ephemeral public key)
- **Act 2:** 144 bytes (64 bytes ephemeral + 80 bytes encrypted static + MAC)

## Testing

### Quick Test

```bash
# Run the handshake test script
./test-handshake.sh
```  
- **Act 1:** 64 bytes (ephemeral public key)
- **Act 2:** 144 bytes (64 bytes ephemeral + 80 bytes encrypted static)

## Logging

The miner provides detailed logging for the handshake process:

```
[my-worker] Using X25519 handshake (Standard Noise)
[my-worker] Starting X25519 Noise handshake
[my-worker] Protocol: Noise_NX_25519_ChaChaPoly_SHA256
[my-worker] Sending Act 1: 32 bytes (payload) + 2 bytes (length prefix) = 34 bytes total
[my-worker] Act 1 sent successfully
[my-worker] Received Act 2 length: 96 bytes
[my-worker] Successfully received Act 2 message
[my-worker] ✓ X25519 handshake completed successfully!
```
