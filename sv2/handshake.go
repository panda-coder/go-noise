package sv2

import (
	"crypto/ecdsa"
)

type HandshakeState struct {
	ck []byte
	h  []byte

	e  *KeyPair
	re []byte
	s  *KeyPair
	rs []byte

	cs1 *CipherState
	cs2 *CipherState

	isInitiator bool
}

func (hs *HandshakeState) MixKey(inputKeyMaterial []byte) {
	output1, output2 := HKDF(hs.ck, inputKeyMaterial)
	hs.ck = output1
	var key [32]byte
	copy(key[:], output2)
	hs.cs1.InitializeKey(key)
}

func (hs *HandshakeState) MixHash(data []byte) {
	hs.h = HASH(append(hs.h, data...))
}

func (hs *HandshakeState) EncryptAndHash(plaintext []byte) []byte {
	ciphertext := hs.cs1.EncryptWithAd(hs.h, plaintext)
	hs.MixHash(ciphertext)
	return ciphertext
}

func (hs *HandshakeState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	plaintext, err := hs.cs1.DecryptWithAd(hs.h, ciphertext)
	if err != nil {
		return nil, err
	}
	hs.MixHash(ciphertext)
	return plaintext, nil
}

func (hs *HandshakeState) ECDHEllSwift(localKp *KeyPair, remoteEllSwift []byte) ([]byte, error) {
	return V2ECDHEllSwift(localKp, remoteEllSwift, hs.isInitiator)
}

func ECDH(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	temp, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return temp.Bytes()
}