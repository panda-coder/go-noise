# Cryptographic Fix: ElligatorSwift Support for Stratum V2

## Problem

The original implementation had a critical cryptographic issue: it was using 32-byte X-only encoded public keys for the handshake instead of 64-byte ElligatorSwift encoded keys as required by the Stratum V2 security specification (BIP324).

### Issues Fixed

1. **Missing ElligatorSwift Encoding**: The handshake protocol requires 64-byte ElligatorSwift encoded public keys for key exchange, but the implementation was using 32-byte X-only encoding
2. **Incorrect ECDH Implementation**: The `ECDH` function in `handshake.go` was a placeholder that didn't implement `ellswift_ecdh_xonly` from BIP324
3. **Non-compliant Key Generation**: Keys were generated without ElligatorSwift encoding support

## Solution

Implemented proper BIP324 support using C bindings to `libsecp256k1`, which provides native ElligatorSwift support:

### New Files

- **`sv2/ellswift.go`**: C bindings to libsecp256k1 providing:
  - `GenerateEllSwiftKeyPair()`: Generates keys with 64-byte ElligatorSwift encoding
  - `EllSwiftECDH()`: Proper BIP324 ellswift_ecdh_xonly implementation
  - `SignSchnorrBIP340()` / `VerifySchnorrBIP340()`: BIP340 Schnorr signatures
  - `DecodeEllSwiftToXOnly()`: Converts ElligatorSwift to X-only for certificates

### Modified Files

- **`sv2/secp256k1.go`**: 
  - Updated `KeyPair` struct to include `ellswiftPubKey` field
  - Updated `GenerateKeyPair()` to use `GenerateEllSwiftKeyPair()`
  - Added `V2ECDHEllSwift()` for ElligatorSwift-based ECDH
  - Updated `SignSchnorr()` and `VerifySchnorr()` to use BIP340 implementation

- **`sv2/handshake.go`**:
  - Updated `HandshakeState` to use `*KeyPair` instead of `*ecdsa.PrivateKey` for ephemeral/static keys
  - Changed remote key storage from `*ecdsa.PublicKey` to `[]byte` (64-byte ElligatorSwift)
  - Added `ECDHEllSwift()` method for proper BIP324 key exchange

## Installation

### Prerequisites

You need `libsecp256k1` with ElligatorSwift support (v0.4.0 or later).

### Install libsecp256k1

Run the provided installation script:

```bash
chmod +x scripts/install_libsecp256k1.sh
./scripts/install_libsecp256k1.sh
```

Or install manually:

```bash
git clone --depth 1 --branch v0.4.1 https://github.com/bitcoin-core/secp256k1.git
cd secp256k1
./autogen.sh
./configure --enable-module-ellswift --enable-module-schnorrsig --enable-experimental
make
sudo make install
sudo ldconfig
```

### Build the Project

```bash
go build ./...
```

## Security Compliance

The implementation now correctly follows the Stratum V2 security specification:

✅ **BIP324 ElligatorSwift encoding** (64 bytes) for handshake key exchange
✅ **BIP340 Schnorr signatures** (64 bytes) for certificate signing/verification  
✅ **X-only encoding** (32 bytes) for certificate public keys
✅ **Proper ellswift_ecdh_xonly** with BIP324 tagged hash
✅ **secp256k1 curve** with implicit Y-coordinate handling

## Usage Example

```go
// Generate a keypair with ElligatorSwift support
kp, err := sv2.GenerateKeyPair()
if err != nil {
    log.Fatal(err)
}

// Get the 64-byte ElligatorSwift public key for handshake
ellswiftPubKey := kp.EllSwiftPublicKey() // 64 bytes

// Get the 32-byte X-only public key for certificates
xOnlyPubKey := kp.PublicKey() // 32 bytes

// Perform ElligatorSwift ECDH
sharedSecret, err := sv2.V2ECDHEllSwift(kp, remoteEllSwiftPubKey, isInitiator)
if err != nil {
    log.Fatal(err)
}

// Sign with BIP340 Schnorr
signature, err := sv2.SignMessage(kp.SerializePrivateKey(), message)
if err != nil {
    log.Fatal(err)
}

// Verify BIP340 Schnorr signature
valid, err := sv2.VerifyMessage(xOnlyPubKey, message, signature)
```

## Technical Details

### ElligatorSwift Encoding

ElligatorSwift provides a uniform encoding of secp256k1 public keys that:
- Produces 64-byte encodings that are indistinguishable from random data
- Enables non-interactive key exchange without Y-coordinate grinding
- Is used in BIP324 for Bitcoin P2P v2 encrypted transport

### Key Sizes by Use Case

| Use Case | Encoding | Size | Function |
|----------|----------|------|----------|
| Handshake ephemeral keys | ElligatorSwift | 64 bytes | `kp.EllSwiftPublicKey()` |
| Handshake static keys | ElligatorSwift | 64 bytes | `kp.EllSwiftPublicKey()` |
| Certificate authority key | X-only | 32 bytes | `kp.PublicKey()` |
| Certificate server key | X-only | 32 bytes | `kp.PublicKey()` |
| Signatures | BIP340 | 64 bytes | `SignMessage()` |

## References

- [BIP324: Version 2 P2P Encrypted Transport Protocol](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
- [BIP340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
- [Stratum V2 Security Specification](../security.md)
- [libsecp256k1](https://github.com/bitcoin-core/secp256k1)
