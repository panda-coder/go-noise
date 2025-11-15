package sv2

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lsecp256k1
// #include <stdlib.h>
// #include <secp256k1.h>
// #include <secp256k1_ellswift.h>
// #include <secp256k1_extrakeys.h>
// #include <secp256k1_schnorrsig.h>
import "C"
import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"unsafe"
)

const (
	EllSwiftEncodedSize = 64
	PrivateKeySize      = 32
)

type EllSwiftKeyPair struct {
	privateKey      [PrivateKeySize]byte
	ellswiftPubKey  [EllSwiftEncodedSize]byte
	xOnlyPubKey     [32]byte
}

func GenerateEllSwiftKeyPair() (*EllSwiftKeyPair, error) {
	ctx := C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create secp256k1 context")
	}
	defer C.secp256k1_context_destroy(ctx)

	privKey := make([]byte, PrivateKeySize)
	_, err := rand.Read(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	if C.secp256k1_ec_seckey_verify(ctx, (*C.uchar)(unsafe.Pointer(&privKey[0]))) != 1 {
		return nil, fmt.Errorf("invalid private key generated")
	}

	var pubkey C.secp256k1_pubkey
	if C.secp256k1_ec_pubkey_create(ctx, &pubkey, (*C.uchar)(unsafe.Pointer(&privKey[0]))) != 1 {
		return nil, fmt.Errorf("failed to create public key")
	}

	var ellswiftPubKey [EllSwiftEncodedSize]byte
	var auxRand [32]byte
	rand.Read(auxRand[:])

	if C.secp256k1_ellswift_create(ctx, (*C.uchar)(unsafe.Pointer(&ellswiftPubKey[0])), 
		(*C.uchar)(unsafe.Pointer(&privKey[0])), (*C.uchar)(unsafe.Pointer(&auxRand[0]))) != 1 {
		return nil, fmt.Errorf("failed to create ellswift encoding")
	}

	var xonlyPubKey C.secp256k1_xonly_pubkey
	if C.secp256k1_xonly_pubkey_from_pubkey(ctx, &xonlyPubKey, nil, &pubkey) != 1 {
		return nil, fmt.Errorf("failed to convert to x-only pubkey")
	}

	var xOnlyBytes [32]byte
	if C.secp256k1_xonly_pubkey_serialize(ctx, (*C.uchar)(unsafe.Pointer(&xOnlyBytes[0])), &xonlyPubKey) != 1 {
		return nil, fmt.Errorf("failed to serialize x-only pubkey")
	}

	var kp EllSwiftKeyPair
	copy(kp.privateKey[:], privKey)
	copy(kp.ellswiftPubKey[:], ellswiftPubKey[:])
	copy(kp.xOnlyPubKey[:], xOnlyBytes[:])

	return &kp, nil
}

func (kp *EllSwiftKeyPair) PrivateKeyBytes() []byte {
	return kp.privateKey[:]
}

func (kp *EllSwiftKeyPair) EllSwiftPublicKey() []byte {
	return kp.ellswiftPubKey[:]
}

func (kp *EllSwiftKeyPair) XOnlyPublicKey() []byte {
	return kp.xOnlyPubKey[:]
}

func EllSwiftECDH(privateKey []byte, localEllSwift []byte, remoteEllSwift []byte, isInitiator bool) ([]byte, error) {
	if len(privateKey) != PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: expected %d, got %d", PrivateKeySize, len(privateKey))
	}
	if len(localEllSwift) != EllSwiftEncodedSize {
		return nil, fmt.Errorf("invalid local ellswift length: expected %d, got %d", EllSwiftEncodedSize, len(localEllSwift))
	}
	if len(remoteEllSwift) != EllSwiftEncodedSize {
		return nil, fmt.Errorf("invalid remote ellswift length: expected %d, got %d", EllSwiftEncodedSize, len(remoteEllSwift))
	}

	ctx := C.secp256k1_context_create(C.SECP256K1_CONTEXT_VERIFY)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create secp256k1 context")
	}
	defer C.secp256k1_context_destroy(ctx)

	var sharedSecret [32]byte
	var party C.int
	var ellA, ellB *C.uchar

	if isInitiator {
		party = 0
		ellA = (*C.uchar)(unsafe.Pointer(&localEllSwift[0]))
		ellB = (*C.uchar)(unsafe.Pointer(&remoteEllSwift[0]))
	} else {
		party = 1
		ellA = (*C.uchar)(unsafe.Pointer(&remoteEllSwift[0]))
		ellB = (*C.uchar)(unsafe.Pointer(&localEllSwift[0]))
	}

	result := C.secp256k1_ellswift_xdh(
		ctx,
		(*C.uchar)(unsafe.Pointer(&sharedSecret[0])),
		ellA,
		ellB,
		(*C.uchar)(unsafe.Pointer(&privateKey[0])),
		party,
		C.secp256k1_ellswift_xdh_hash_function_bip324,
		nil,
	)

	if result != 1 {
		return nil, fmt.Errorf("ellswift ECDH failed")
	}

	return sharedSecret[:], nil
}

func DecodeEllSwiftToXOnly(ellswiftPubKey []byte) ([]byte, error) {
	if len(ellswiftPubKey) != EllSwiftEncodedSize {
		return nil, fmt.Errorf("invalid ellswift length: expected %d, got %d", EllSwiftEncodedSize, len(ellswiftPubKey))
	}

	ctx := C.secp256k1_context_create(C.SECP256K1_CONTEXT_VERIFY)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create secp256k1 context")
	}
	defer C.secp256k1_context_destroy(ctx)

	var pubkey C.secp256k1_pubkey
	if C.secp256k1_ellswift_decode(ctx, &pubkey, (*C.uchar)(unsafe.Pointer(&ellswiftPubKey[0]))) != 1 {
		return nil, fmt.Errorf("failed to decode ellswift public key")
	}

	var xonlyPubKey C.secp256k1_xonly_pubkey
	if C.secp256k1_xonly_pubkey_from_pubkey(ctx, &xonlyPubKey, nil, &pubkey) != 1 {
		return nil, fmt.Errorf("failed to convert to x-only pubkey")
	}

	var xOnlyBytes [32]byte
	if C.secp256k1_xonly_pubkey_serialize(ctx, (*C.uchar)(unsafe.Pointer(&xOnlyBytes[0])), &xonlyPubKey) != 1 {
		return nil, fmt.Errorf("failed to serialize x-only pubkey")
	}

	return xOnlyBytes[:], nil
}

func SignSchnorrBIP340(privateKey []byte, messageHash []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32, got %d", len(privateKey))
	}
	if len(messageHash) != 32 {
		return nil, fmt.Errorf("invalid message hash length: expected 32, got %d", len(messageHash))
	}

	ctx := C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create secp256k1 context")
	}
	defer C.secp256k1_context_destroy(ctx)

	var keypair C.secp256k1_keypair
	if C.secp256k1_keypair_create(ctx, &keypair, (*C.uchar)(unsafe.Pointer(&privateKey[0]))) != 1 {
		return nil, fmt.Errorf("failed to create keypair")
	}

	var auxRand [32]byte
	rand.Read(auxRand[:])

	var signature [64]byte
	if C.secp256k1_schnorrsig_sign32(ctx, (*C.uchar)(unsafe.Pointer(&signature[0])), 
		(*C.uchar)(unsafe.Pointer(&messageHash[0])), &keypair, (*C.uchar)(unsafe.Pointer(&auxRand[0]))) != 1 {
		return nil, fmt.Errorf("failed to sign message")
	}

	return signature[:], nil
}

func VerifySchnorrBIP340(xOnlyPubKey []byte, messageHash []byte, signature []byte) (bool, error) {
	if len(xOnlyPubKey) != 32 {
		return false, fmt.Errorf("invalid public key length: expected 32, got %d", len(xOnlyPubKey))
	}
	if len(messageHash) != 32 {
		return false, fmt.Errorf("invalid message hash length: expected 32, got %d", len(messageHash))
	}
	if len(signature) != 64 {
		return false, fmt.Errorf("invalid signature length: expected 64, got %d", len(signature))
	}

	ctx := C.secp256k1_context_create(C.SECP256K1_CONTEXT_VERIFY)
	if ctx == nil {
		return false, fmt.Errorf("failed to create secp256k1 context")
	}
	defer C.secp256k1_context_destroy(ctx)

	var xonlyPubKey C.secp256k1_xonly_pubkey
	if C.secp256k1_xonly_pubkey_parse(ctx, &xonlyPubKey, (*C.uchar)(unsafe.Pointer(&xOnlyPubKey[0]))) != 1 {
		return false, fmt.Errorf("failed to parse x-only pubkey")
	}

	result := C.secp256k1_schnorrsig_verify(ctx, (*C.uchar)(unsafe.Pointer(&signature[0])), 
		(*C.uchar)(unsafe.Pointer(&messageHash[0])), 32, &xonlyPubKey)

	return result == 1, nil
}

func V2ECDHWithEllSwift(privKey *ecdsa.PrivateKey, localEllSwift []byte, remoteEllSwift []byte, isInitiator bool) ([]byte, error) {
	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}

	ecdhResult, err := EllSwiftECDH(privKeyBytes, localEllSwift, remoteEllSwift, isInitiator)
	if err != nil {
		return nil, fmt.Errorf("ellswift ECDH failed: %w", err)
	}

	return ecdhResult, nil
}

func SignMessage(privateKey []byte, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return SignSchnorrBIP340(privateKey, hash[:])
}

func VerifyMessage(xOnlyPubKey []byte, message []byte, signature []byte) (bool, error) {
	hash := sha256.Sum256(message)
	return VerifySchnorrBIP340(xOnlyPubKey, hash[:], signature)
}
