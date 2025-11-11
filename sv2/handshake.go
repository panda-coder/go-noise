package sv2

import (
	"crypto/ecdsa"
)

// HandshakeState holds the state of the handshake.
type HandshakeState struct {
	ck []byte // chaining key
	h  []byte // handshake hash

	e  *ecdsa.PrivateKey // ephemeral key
	re *ecdsa.PublicKey  // remote ephemeral key
	s  *ecdsa.PrivateKey // static key
	rs *ecdsa.PublicKey  // remote static key

	cs1 *CipherState
	cs2 *CipherState
}

// MixKey executes the MixKey step of the Noise protocol.
func (hs *HandshakeState) MixKey(inputKeyMaterial []byte) {
	output1, output2 := HKDF(hs.ck, inputKeyMaterial)
	hs.ck = output1
	var key [32]byte
	copy(key[:], output2)
	hs.cs1.InitializeKey(key)
}

// MixHash executes the MixHash step of the Noise protocol.
func (hs *HandshakeState) MixHash(data []byte) {
	hs.h = HASH(append(hs.h, data...))
}

// EncryptAndHash encrypts a plaintext and mixes its ciphertext into the handshake hash.
func (hs *HandshakeState) EncryptAndHash(plaintext []byte) []byte {
	ciphertext := hs.cs1.EncryptWithAd(hs.h, plaintext)
	hs.MixHash(ciphertext)
	return ciphertext
}

// DecryptAndHash decrypts a ciphertext and mixes it into the handshake hash.
func (hs *HandshakeState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := hs.cs1.DecryptWithAd(hs.h, ciphertext)
	if err != nil {
		return nil, err
	}
	hs.MixHash(ciphertext)
	return plaintext, nil
}

// ECDH performs an Elliptic-Curve Diffie-Hellman operation.
// This is a placeholder and needs a proper implementation of ellswift_ecdh_xonly.
func ECDH(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	// TODO: Implement ellswift_ecdh_xonly from BIP324.
	// This is a placeholder implementation.
	temp, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return temp.Bytes()
}