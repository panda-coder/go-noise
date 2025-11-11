package sv2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHandshakeStateMixHash(t *testing.T) {
	hs := &HandshakeState{
		h:   make([]byte, 32),
		cs1: &CipherState{},
	}

	initialHash := make([]byte, 32)
	copy(initialHash, hs.h)

	data := []byte("test data")
	hs.MixHash(data)

	if bytes.Equal(hs.h, initialHash) {
		t.Error("Hash should change after MixHash")
	}

	if len(hs.h) != 32 {
		t.Errorf("Hash length = %d, want 32", len(hs.h))
	}
}

func TestHandshakeStateMixHashDeterministic(t *testing.T) {
	hs1 := &HandshakeState{
		h:   make([]byte, 32),
		cs1: &CipherState{},
	}
	hs2 := &HandshakeState{
		h:   make([]byte, 32),
		cs1: &CipherState{},
	}

	data := []byte("test data")
	hs1.MixHash(data)
	hs2.MixHash(data)

	if !bytes.Equal(hs1.h, hs2.h) {
		t.Error("MixHash should be deterministic")
	}
}

func TestHandshakeStateMixKey(t *testing.T) {
	hs := &HandshakeState{
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}

	rand.Read(hs.ck)
	initialCK := make([]byte, 32)
	copy(initialCK, hs.ck)

	ikm := make([]byte, 32)
	rand.Read(ikm)

	hs.MixKey(ikm)

	if bytes.Equal(hs.ck, initialCK) {
		t.Error("Chaining key should change after MixKey")
	}

	if len(hs.ck) != 32 {
		t.Errorf("Chaining key length = %d, want 32", len(hs.ck))
	}

	if hs.cs1.aead == nil {
		t.Error("Cipher should be initialized after MixKey")
	}
}

func TestHandshakeStateMixKeyDeterministic(t *testing.T) {
	ck := make([]byte, 32)
	rand.Read(ck)

	hs1 := &HandshakeState{
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}
	copy(hs1.ck, ck)

	hs2 := &HandshakeState{
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}
	copy(hs2.ck, ck)

	ikm := make([]byte, 32)
	rand.Read(ikm)

	hs1.MixKey(ikm)
	hs2.MixKey(ikm)

	if !bytes.Equal(hs1.ck, hs2.ck) {
		t.Error("MixKey should be deterministic")
	}
}

func TestHandshakeStateEncryptAndHash(t *testing.T) {
	hs := &HandshakeState{
		h:   make([]byte, 32),
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}

	rand.Read(hs.h)
	rand.Read(hs.ck)
	
	ikm := make([]byte, 32)
	rand.Read(ikm)
	hs.MixKey(ikm)

	plaintext := []byte("test message")
	initialHash := make([]byte, len(hs.h))
	copy(initialHash, hs.h)

	ciphertext := hs.EncryptAndHash(plaintext)

	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should differ from plaintext")
	}

	if bytes.Equal(hs.h, initialHash) {
		t.Error("Hash should change after EncryptAndHash")
	}

	expectedLen := len(plaintext) + 16
	if len(ciphertext) != expectedLen {
		t.Errorf("Ciphertext length = %d, want %d", len(ciphertext), expectedLen)
	}
}

func TestHandshakeStateEncryptAndHashEmptyKey(t *testing.T) {
	hs := &HandshakeState{
		h:   make([]byte, 32),
		cs1: &CipherState{},
	}

	plaintext := []byte("test message")
	ciphertext := hs.EncryptAndHash(plaintext)

	if !bytes.Equal(plaintext, ciphertext) {
		t.Error("With empty key, ciphertext should equal plaintext")
	}
}
func TestHandshakeStateDecryptAndHash(t *testing.T) {
	initialH := make([]byte, 32)
	initialCK := make([]byte, 32)
	rand.Read(initialH)
	rand.Read(initialCK)

	ikm := make([]byte, 32)
	rand.Read(ikm)

	hs1 := &HandshakeState{
		h:   make([]byte, 32),
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}
	copy(hs1.h, initialH)
	copy(hs1.ck, initialCK)
	hs1.MixKey(ikm)

	hs2 := &HandshakeState{
		h:   make([]byte, 32),
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}
	copy(hs2.h, initialH)
	copy(hs2.ck, initialCK)
	hs2.MixKey(ikm)

	plaintext := []byte("test message")
	ciphertext := hs1.EncryptAndHash(plaintext)

	decrypted, err := hs2.DecryptAndHash(ciphertext)
	if err != nil {
		t.Fatalf("DecryptAndHash failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted = %s, want %s", string(decrypted), string(plaintext))
	}

	if !bytes.Equal(hs1.h, hs2.h) {
		t.Error("Handshake states should have matching hashes after encrypt/decrypt")
	}
}

func TestHandshakeStateDecryptAndHashEmptyKey(t *testing.T) {
	hs := &HandshakeState{
		h:   make([]byte, 32),
		cs1: &CipherState{},
	}

	ciphertext := []byte("test message")
	plaintext, err := hs.DecryptAndHash(ciphertext)
	if err != nil {
		t.Fatalf("DecryptAndHash failed: %v", err)
	}

	if !bytes.Equal(plaintext, ciphertext) {
		t.Error("With empty key, plaintext should equal ciphertext")
	}
}

func TestHandshakeStateDecryptAndHashInvalidCiphertext(t *testing.T) {
	hs := &HandshakeState{
		h:   make([]byte, 32),
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}

	rand.Read(hs.h)
	rand.Read(hs.ck)
	
	ikm := make([]byte, 32)
	rand.Read(ikm)
	hs.MixKey(ikm)

	invalidCiphertext := make([]byte, 32)
	rand.Read(invalidCiphertext)

	_, err := hs.DecryptAndHash(invalidCiphertext)
	if err == nil {
		t.Error("Expected error for invalid ciphertext")
	}
}

func TestHandshakeStateSequence(t *testing.T) {
	hs := &HandshakeState{
		h:   make([]byte, 32),
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}

	rand.Read(hs.h)
	rand.Read(hs.ck)

	data1 := []byte("data 1")
	hs.MixHash(data1)
	hash1 := make([]byte, len(hs.h))
	copy(hash1, hs.h)

	ikm1 := make([]byte, 32)
	rand.Read(ikm1)
	hs.MixKey(ikm1)
	ck1 := make([]byte, len(hs.ck))
	copy(ck1, hs.ck)

	data2 := []byte("data 2")
	hs.MixHash(data2)
	hash2 := make([]byte, len(hs.h))
	copy(hash2, hs.h)

	ikm2 := make([]byte, 32)
	rand.Read(ikm2)
	hs.MixKey(ikm2)

	if bytes.Equal(hash1, hash2) {
		t.Error("Hashes should differ after mixing different data")
	}

	if bytes.Equal(ck1, hs.ck) {
		t.Error("Chaining keys should differ after mixing different key material")
	}
}

func TestECDH(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	result := ECDH(kp1.PrivateKey(), &kp2.PrivateKey().PublicKey)

	if result == nil {
		t.Error("ECDH returned nil")
	}

	if len(result) == 0 {
		t.Error("ECDH result is empty")
	}
}

func TestECDHConsistency(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	result1 := ECDH(kp1.PrivateKey(), &kp2.PrivateKey().PublicKey)
	result2 := ECDH(kp1.PrivateKey(), &kp2.PrivateKey().PublicKey)

	if !bytes.Equal(result1, result2) {
		t.Error("ECDH should be deterministic")
	}
}

func TestHandshakeStateFullFlow(t *testing.T) {
	initiator := &HandshakeState{
		h:   make([]byte, 32),
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}
	responder := &HandshakeState{
		h:   make([]byte, 32),
		ck:  make([]byte, 32),
		cs1: &CipherState{},
	}

	rand.Read(initiator.h)
	rand.Read(initiator.ck)
	copy(responder.h, initiator.h)
	copy(responder.ck, initiator.ck)

	ephemeralData := make([]byte, 32)
	rand.Read(ephemeralData)
	initiator.MixHash(ephemeralData)
	responder.MixHash(ephemeralData)

	if !bytes.Equal(initiator.h, responder.h) {
		t.Error("Initiator and responder hashes should match after same operations")
	}

	ikm := make([]byte, 32)
	rand.Read(ikm)
	initiator.MixKey(ikm)
	responder.MixKey(ikm)

	if !bytes.Equal(initiator.ck, responder.ck) {
		t.Error("Initiator and responder chaining keys should match after same operations")
	}

	message := []byte("test message")
	encrypted := initiator.EncryptAndHash(message)

	decrypted, err := responder.DecryptAndHash(encrypted)
	if err != nil {
		t.Fatalf("DecryptAndHash failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Error("Decrypted message doesn't match original")
	}

	if !bytes.Equal(initiator.h, responder.h) {
		t.Error("Initiator and responder hashes should match after encrypt/decrypt")
	}
}
