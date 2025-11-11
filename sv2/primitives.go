package sv2

import (
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

// HASH implements the SHA-256 hash function.
func HASH(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// HMAC_HASH implements the HMAC-SHA-256 function.
func HMAC_HASH(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// HKDF implements the HKDF function with HMAC-SHA-256.
// It returns two keys as specified in the security document.
func HKDF(chainingKey, inputKeyMaterial []byte) ([]byte, []byte) {
	r := hkdf.New(sha256.New, inputKeyMaterial, chainingKey, nil)
	output1 := make([]byte, 32)
	output2 := make([]byte, 32)
	r.Read(output1)
	r.Read(output2)
	return output1, output2
}