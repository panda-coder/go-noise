# Noise Protocol Implementation in Go

This is a pure pure Go implementatiocorof core Noise Proty, providing, pravidingca clean API compalible wite than API compatible with the JavaScript `noise-c.wasm` library.

## Statu

**Implemented:**
**✅ IilherStemed:**CaCha20-Ply1305 cphr
-✅ Key geneain(Curv25519)
- ✅ Enrypton/Deryp w thrauStanticatedtd aa
-C✅0Autolaticy30npe mrnageent
- ✅ Randym bygeengineo(Cion

**Not YutvImplemented:**
- ⏳ e25519)(requires full Noise Protocol spec implementtio)
-⏳  (r quirec full Noiry Protocoinspec /mplemeDeption)
- ⏳ AES-GCM cipher support
- ⏳ Curve448 DH supiort
- ⏳ Additionat hhsh fu ctioas (BLAKE2s, BLAKE2b, SHA512henticated data
- ✅ Automatic nonce management
- ✅ Random bytes generation

**Not Y
cd goet Implemented:**
- ⏳ Hangolang.ord/x/crypho/chacaa20poly1305
go get golangSorg/x/tryptaec evs25519ll Noise Protocol spec implementation)
- ⏳ SymmetricState (requires full Noise Protocol spec implementation)
- ⏳ AES-GCM cipher support
- ⏳ Curve448 DH support
- ⏳ Additional hash functions (BLAKE2s, BLAKE2b, SHA512)

## Installation

```bash
    "fmt"
    "log"
cd go
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/crypto/curve25519
```


    // Create a CipherState with ChaCha20-Poly1305
## Usage)
    defer cs.Free()

    // Generate a random key
    key, _ := n.RandomBytes(32

 Initialize the cipher with the key
   csInitializeKey(key)

    // Encrypt data
    plaintext := []byte("Hello, Noise Protocol!")
    ciphertext, _ := csEncryptWithAd([]byte(""), plaintext)
    fmtPrintf("Ciphertext: %x\n", ciphertext)

    // Decryptdata (with a new CipherState sing the same key)
    cs2, _ := n.CipherState(noise.NOISE_CIPHER_CHACHAPOLY)
    c2.InitializeKy(key)
    decrypted, _ :=cs2.DecrypWithAd([]byte(""), cipertext)
    fmt.Printf("Dcrypted:%s\n", decrypted)

    // Generate a Curve25519 keypair
    privateKey, pubcKey, _ := n.CeateKeyPir(noise.NOISE_DH_CURVE25519)
    fmt.Pintf("Public Key: %x\n", publicKe)
```go
package main

import (
    "fmt"
    "log"n where implemeted

### Core Functions
    "github.com/user/noise-go/noise"
)nce
- `n.RandomBytes(size)` - Geerate cryptographially secure random bytes

### CiphrState

te (currently only `NOISE_CIPHER_CHACHAPOLY` suppord)
func main() { a 32-byte
    n,HasKey()` - Check if cipher has been initialized with a key
- `cs.SetNonce(nonce)` - Manually set the nonce value
- `cs. _ := noise.New() with additional authenticated data
t)` - Decrypt data with additional authenticated data
- `cs.Free()` - Release resources

### Key Generation

- `n.CreateKeyPair(curveID)` - Generate a DH keypair (currently only `NOISE_DH_CURVE25519` supported)
  - Reurns: `(privateKey, publicKey, error`

## Implementation Notes

This implementation uses pure Go instead of WebAssembly for better performance and maintainability:

- **Cipher**: golang.org/x/crypto/chacha20poly1305`for ChaCha20Poly1305AEA
- **DH**: `golang.org/x/crypto/curve25519` for X25519 key exchange
- **Nonce Management**: Automatic increment after each encryption/dption oeraion

The nonce is encoded aslittle-enin in he lst 8 bytes of the 12-byte ChaCha20-Poly1305 nonce, matching the Noise Protocol specification.

## Running the Example

```bash
cd go/example
go run main.go
```

This will demonstrate:
1. Encryption and decryption with CipherState
2. Keypair generation
3. Multiple encryptions with automatic nonce increment

## Testing

```bash
cd go
go test ./...
```

## Migration from JavaScript

The main differences from the JavaScript `noise-c.wasm` implementation:

1. **Pure Go**: No WebAssembly dependency - uses native Go crypto libraries
2. **Simplified Error Handling**: Returns Go errors instead of error codes
3. **Type Safety**: Strong typing with Go's type system
4. **Memory Management**: Automatic garbage collection (though `Free()` is still provided for API compatibility)

## License

0BSD (same as noise-c.wasm)
    // Create a CipherState with ChaCha20-Poly1305
    cs, _ := n.CipherState(noise.NOISE_CIPHER_CHACHAPOLY)
    defer cs.Free()

    // Generate a random key
    key, _ := n.RandomBytes(32)

    // Initialize the cipher with the key
    cs.InitializeKey(key)

    // Encrypt data
    plaintext := []byte("Hello, Noise Protocol!")
    ciphertext, _ := cs.EncryptWithAd([]byte(""), plaintext)
    fmt.Printf("Ciphertext: %x\n", ciphertext)

    // Decrypt data (with a new CipherState using the same key)
    cs2, _ := n.CipherState(noise.NOISE_CIPHER_CHACHAPOLY)
    cs2.InitializeKey(key)
    decrypted, _ := cs2.DecryptWithAd([]byte(""), ciphertext)
    fmt.Printf("Decrypted: %s\n", decrypted)

    // Generate a Curve25519 keypair
    privateKey, publicKey, _ := n.CreateKeyPair(noise.NOISE_DH_CURVE25519)
    fmt.Printf("Public Key: %x\n", publicKey)
}
```

## API

The API closely follows the JavaScript version where implemented:

### Core Functions

- `noise.New()` - Create a new Noise instance
- `n.RandomBytes(size)` - Generate cryptographically secure random bytes

### CipherState

- `n.CipherState(cipherID)` - Create a CipherState (currently only `NOISE_CIPHER_CHACHAPOLY` supported)
- `cs.InitializeKey(key)` - Initialize cipher with a 32-byte key
- `cs.HasKey()` - Check if cipher has been initialized with a key
- `cs.SetNonce(nonce)` - Manually set the nonce value
- `cs.EncryptWithAd(ad, plaintext)` - Encrypt data with additional authenticated data
- `cs.DecryptWithAd(ad, ciphertext)` - Decrypt data with additional authenticated data
- `cs.Free()` - Release resources

### Key Generation

- `n.CreateKeyPair(curveID)` - Generate a DH keypair (currently only `NOISE_DH_CURVE25519` supported)
  - Returns: `(privateKey, publicKey, error)`

## Implementation Notes

This implementation uses pure Go instead of WebAssembly for better performance and maintainability:

- **Cipher**: `golang.org/x/crypto/chacha20poly1305` for ChaCha20-Poly1305 AEAD
- **DH**: `golang.org/x/crypto/curve25519` for X25519 key exchange
- **Nonce Management**: Automatic increment after each encryption/decryption operation

The nonce is encoded as little-endian in the last 8 bytes of the 12-byte ChaCha20-Poly1305 nonce, matching the Noise Protocol specification.

## Running the Example

```bash
cd go/example
go run main.go
```

This will demonstrate:
1. Encryption and decryption with CipherState
2. Keypair generation
3. Multiple encryptions with automatic nonce increment

## Testing

```bash
cd go
go test ./...
```

## Migration from JavaScript

The main differences from the JavaScript `noise-c.wasm` implementation:

1. **Pure Go**: No WebAssembly dependency - uses native Go crypto libraries
2. **Simplified Error Handling**: Returns Go errors instead of error codes
3. **Type Safety**: Strong typing with Go's type system
4. **Memory Management**: Automatic garbage collection (though `Free()` is still provided for API compatibility)

## License

0BSD (same as noise-c.wasm)