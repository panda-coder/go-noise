package sv2

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

type CipherState struct {
	k [32]byte
	n uint64
	aead cipher.AEAD
}

func (c *CipherState) InitializeKey(key [32]byte) error {
	c.k = key
	c.n = 0
	aead, err := chacha20poly1305.New(c.k[:])
	if err != nil {
		return err
	}
	c.aead = aead
	return nil
}

func (c *CipherState) EncryptWithAd(ad, plaintext []byte) []byte {
	if c.aead == nil {
		return plaintext
	}

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	c.n++

	return c.aead.Seal(nil, nonce, plaintext, ad)
}

func (c *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if c.aead == nil {
		return ciphertext, nil
	}

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	c.n++

	return c.aead.Open(nil, nonce, ciphertext, ad)
}