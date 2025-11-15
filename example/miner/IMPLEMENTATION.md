# X25519 Implementation Summary

## Overview
Added X25519 handshake support to the Go Stratum V2 miner for compatibility with the Python pool simulator. The miner now supports dual protocols:

1. **X25519 (default)** - Compatible with Python pool simulator
2. **ElligatorSwift** - Compatible with Stratum V2 specification

## Key Changes

### 1. Dual Protocol Support

**File:** `example/miner/miner.go`

- Added `useEllSwift` flag to `Connection` struct
- Modified `NewConnection()` to accept protocol selection parameter
- Updated `PerformHandshake()` to route to appropriate handshake implementation

```go
type Connection struct {
    // ... existing fields ...
    minerID      string
    useEllSwift  bool
}

func (c *Connection) PerformHandshake() error {
    if c.useEllSwift {
        return c.performHandshakeEllSwift()
    }
    return c.performHandshakeX25519()
}
```

### 2. X25519 Handshake Implementation

**File:** `example/miner/miner.go`

Implemented `performHandshakeX25519()` with:

- **Hash Function:** Blake2s (matches Python dissononce library)
- **Protocol Name:** `Noise_NX_25519_ChaChaPoly_BLAKE2s`
- **Key Exchange:** X25519 (32-byte keys)
- **Cipher:** ChaCha20-Poly1305

**Handshake Flow:**

1. **Act 1 (Client → Server):**
   - Generate ephemeral X25519 keypair
   - Send ephemeral public key (32 bytes)
   - Update handshake hash

2. **Act 2 (Server → Client):**
   - Receive responder ephemeral key (32 bytes)
   - Perform ECDH (ee - ephemeral-ephemeral)
   - Decrypt server static key using derived cipher
   - Perform ECDH (es - ephemeral-static)
   - Derive final send/receive cipher keys

### 3. HKDF Implementation

**File:** `example/miner/miner.go`

Implemented HKDF using Blake2s as HMAC:

```go
func hkdf(chainingKey, inputKeyMaterial []byte) ([]byte, []byte) {
    // HKDF-Extract using HMAC-BLAKE2s
    h, _ := blake2s.New256(chainingKey)
    h.Write(inputKeyMaterial)
    prk := h.Sum(nil)
    
    // HKDF-Expand to get 2 keys (64 bytes)
    h1, _ := blake2s.New256(prk)
    h1.Write([]byte{0x01})
    output1 := h1.Sum(nil)
    
    h2, _ := blake2s.New256(prk)
    h2.Write(output1)
    h2.Write([]byte{0x02})
    output2 := h2.Sum(nil)
    
    return output1, output2
}
```

### 4. CLI Updates

**File:** `example/miner/main.go`

Added `-ellswift` flag:

```go
useEllSwift := flag.Bool("ellswift", false, 
    "Use ElligatorSwift (Stratum V2 spec). Default is X25519 for Python pool compatibility")
```

Updated `Connect()` method:

```go
func (m *Miner) Connect(host string, port int, useEncryption bool, useEllSwift bool) error {
    conn, err := NewConnection(host, port, m.Name, useEllSwift)
    // ...
}
```

### 5. Dependencies

**Added:**
- `golang.org/x/crypto/blake2s` - Blake2s hash function
- `golang.org/x/crypto/curve25519` - X25519 key exchange
- `golang.org/x/crypto/chacha20poly1305` - ChaCha20-Poly1305 cipher

**Retained:**
- `crypto/sha256` - For Bitcoin double SHA256 (mining hash)

## Protocol Differences

| Aspect | X25519 (Python Pool) | ElligatorSwift (SV2 Spec) |
|--------|---------------------|---------------------------|
| Protocol Name | `Noise_NX_25519_ChaChaPoly_BLAKE2s` | `Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256` |
| Hash Function | Blake2s | SHA256 |
| Public Key Size | 32 bytes | 64 bytes |
| Act 1 Size | 32 bytes | 64 bytes |
| Act 2 Size | 80 bytes | 144 bytes |
| Compatibility | Python dissononce | Stratum V2 pools |

## Usage Examples

### Connect to Python Pool (X25519)

```bash
# Default behavior - uses X25519
./miner -host localhost -port 2000
```

### Connect to Production Pool (ElligatorSwift)

```bash
# Use -ellswift flag
./miner -host pool.sv2.com -port 3333 -ellswift
```

### Test Handshake

```bash
# Run test script
./test-handshake.sh
```

## Testing

1. **Build:**
   ```bash
   cd example/miner
   go build -o miner
   ```

2. **Start Python Pool:**
   ```bash
   cd py-miner
   python simulate-pool.py
   ```

3. **Run Go Miner:**
   ```bash
   ./miner -host localhost -port 2000 -worker test-miner
   ```

**Expected Output:**
```
[test-miner] Using X25519 handshake (Standard Noise)
[test-miner] Starting X25519 Noise handshake
[test-miner] Protocol: Noise_NX_25519_ChaChaPoly_BLAKE2s
[test-miner] Generated ephemeral keypair, public key length: 32 bytes
[test-miner] Sending Act 1: 32 bytes (payload) + 2 bytes (length prefix) = 34 bytes total
[test-miner] Act 1 sent successfully
[test-miner] Received Act 2 length: 80 bytes
[test-miner] Successfully received Act 2 message
[test-miner] ✓ X25519 handshake completed successfully!
```

## Files Modified

1. `example/miner/miner.go`
   - Added `performHandshakeX25519()` 
   - Added `hkdf()` with Blake2s
   - Modified `Connection` struct
   - Updated `NewConnection()` and `PerformHandshake()`

2. `example/miner/main.go`
   - Added `-ellswift` flag
   - Updated `Connect()` call

3. **New Files:**
   - `example/miner/README.md` - Documentation
   - `example/miner/test-handshake.sh` - Test script
   - `example/miner/IMPLEMENTATION.md` - This file

## Troubleshooting

### "message authentication failed"
- This typically means hash function mismatch
- Verify the pool uses Blake2s (Python dissononce)
- If pool uses SHA256, use `-ellswift` flag

### "unexpected Act 2 length"
- X25519 expects 80 bytes for Act 2
- ElligatorSwift expects 144 bytes for Act 2
- Use correct protocol flag for your pool

## References

- [Noise Protocol Framework](http://www.noiseprotocol.org/)
- [Stratum V2 Specification](https://github.com/stratum-mining/sv2-spec)
- [Dissononce Library (Python)](https://github.com/tgalal/dissononce)
- [Go X/Crypto Blake2s](https://pkg.go.dev/golang.org/x/crypto/blake2s)
