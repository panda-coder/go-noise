package sv2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCipherStateInitializeKey(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	cs := &CipherState{}
	err := cs.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	if cs.aead == nil {
		t.Error("AEAD cipher not initialized")
	}

	if cs.n != 0 {
		t.Errorf("Initial nonce = %d, want 0", cs.n)
	}

	if !bytes.Equal(cs.k[:], key[:]) {
		t.Error("Key not set correctly")
	}
}

func TestCipherStateEncryptDecrypt(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	cs := &CipherState{}
	err := cs.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	plaintext := []byte("test message")
	ad := []byte("associated data")

	ciphertext := cs.EncryptWithAd(ad, plaintext)
	
	if bytes.Equal(plaintext, ciphertext) {
		t.Error("Ciphertext should differ from plaintext")
	}

	expectedLength := len(plaintext) + 16
	if len(ciphertext) != expectedLength {
		t.Errorf("Ciphertext length = %d, want %d", len(ciphertext), expectedLength)
	}

	cs2 := &CipherState{}
	err = cs2.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	decrypted, err := cs2.DecryptWithAd(ad, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithAd failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted = %s, want %s", string(decrypted), string(plaintext))
	}
}

func TestCipherStateNonceIncrement(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	cs := &CipherState{}
	err := cs.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	plaintext := []byte("message")
	
	ct1 := cs.EncryptWithAd(nil, plaintext)
	if cs.n != 1 {
		t.Errorf("Nonce after first encryption = %d, want 1", cs.n)
	}

	ct2 := cs.EncryptWithAd(nil, plaintext)
	if cs.n != 2 {
		t.Errorf("Nonce after second encryption = %d, want 2", cs.n)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("Ciphertexts should differ when nonce changes")
	}
}

func TestCipherStateDecryptWithWrongKey(t *testing.T) {
	var key1, key2 [32]byte
	rand.Read(key1[:])
	rand.Read(key2[:])

	cs1 := &CipherState{}
	err := cs1.InitializeKey(key1)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	plaintext := []byte("secret message")
	ciphertext := cs1.EncryptWithAd(nil, plaintext)

	cs2 := &CipherState{}
	err = cs2.InitializeKey(key2)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	_, err = cs2.DecryptWithAd(nil, ciphertext)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

func TestCipherStateDecryptWithWrongAD(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	cs1 := &CipherState{}
	err := cs1.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	plaintext := []byte("message")
	ad1 := []byte("associated data 1")
	ciphertext := cs1.EncryptWithAd(ad1, plaintext)

	cs2 := &CipherState{}
	err = cs2.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	ad2 := []byte("associated data 2")
	_, err = cs2.DecryptWithAd(ad2, ciphertext)
	if err == nil {
		t.Error("Expected decryption to fail with wrong associated data")
	}
}

func TestCipherStateEmptyKey(t *testing.T) {
	cs := &CipherState{}
	
	plaintext := []byte("test message")
	ciphertext := cs.EncryptWithAd(nil, plaintext)
	
	if !bytes.Equal(plaintext, ciphertext) {
		t.Error("With empty key, ciphertext should equal plaintext")
	}

	decrypted, err := cs.DecryptWithAd(nil, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithAd failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("With empty key, decrypted should equal ciphertext")
	}
}

func TestCipherStateDecryptInvalidCiphertext(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	cs := &CipherState{}
	err := cs.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	invalidCiphertext := make([]byte, 32)
	rand.Read(invalidCiphertext)

	_, err = cs.DecryptWithAd(nil, invalidCiphertext)
	if err == nil {
		t.Error("Expected decryption to fail with invalid ciphertext")
	}
}

func TestCipherStateMultipleMessages(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	sender := &CipherState{}
	err := sender.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	receiver := &CipherState{}
	err = receiver.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
	}

	var ciphertexts [][]byte
	for _, msg := range messages {
		ct := sender.EncryptWithAd(nil, msg)
		ciphertexts = append(ciphertexts, ct)
	}

	for i, ct := range ciphertexts {
		pt, err := receiver.DecryptWithAd(nil, ct)
		if err != nil {
			t.Fatalf("DecryptWithAd failed for message %d: %v", i, err)
		}
		if !bytes.Equal(messages[i], pt) {
			t.Errorf("Message %d: decrypted = %s, want %s", i, string(pt), string(messages[i]))
		}
	}
}

func TestCipherStateZeroLengthMessage(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	cs := &CipherState{}
	err := cs.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	plaintext := []byte{}
	ciphertext := cs.EncryptWithAd(nil, plaintext)

	if len(ciphertext) != 16 {
		t.Errorf("Ciphertext length for empty message = %d, want 16 (MAC only)", len(ciphertext))
	}

	cs2 := &CipherState{}
	err = cs2.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	decrypted, err := cs2.DecryptWithAd(nil, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithAd failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Decrypted length = %d, want 0", len(decrypted))
	}
}

func TestCipherStateLargeMessage(t *testing.T) {
	var key [32]byte
	rand.Read(key[:])

	cs := &CipherState{}
	err := cs.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	plaintext := make([]byte, 65519)
	rand.Read(plaintext)

	ciphertext := cs.EncryptWithAd(nil, plaintext)

	cs2 := &CipherState{}
	err = cs2.InitializeKey(key)
	if err != nil {
		t.Fatalf("InitializeKey failed: %v", err)
	}

	decrypted, err := cs2.DecryptWithAd(nil, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithAd failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Large message not decrypted correctly")
	}
}
