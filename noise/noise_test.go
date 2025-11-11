package noise

import (
	"bytes"
	"testing"
)

func TestNew(t *testing.T) {
	n, err := New()
	if err != nil {
		t.Fatalf("Failed to create Noise instance: %v", err)
	}
	if n == nil {
		t.Fatal("Noise instance is nil")
	}
}

func TestRandomBytes(t *testing.T) {
	n, _ := New()
	
	bytes1, err := n.RandomBytes(32)
	if err != nil {
		t.Fatalf("Failed to generate random bytes: %v", err)
	}
	if len(bytes1) != 32 {
		t.Fatalf("Expected 32 bytes, got %d", len(bytes1))
	}
	
	bytes2, _ := n.RandomBytes(32)
	if bytes.Equal(bytes1, bytes2) {
		t.Fatal("Random bytes should be different")
	}
}

func TestCipherStateEncryptDecrypt(t *testing.T) {
	n, _ := New()
	
	cs1, err := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	if err != nil {
		t.Fatalf("Failed to create CipherState: %v", err)
	}
	defer cs1.Free()
	
	key, _ := n.RandomBytes(32)
	
	if cs1.HasKey() {
		t.Fatal("CipherState should not have key before initialization")
	}
	
	err = cs1.InitializeKey(key)
	if err != nil {
		t.Fatalf("Failed to initialize key: %v", err)
	}
	
	if !cs1.HasKey() {
		t.Fatal("CipherState should have key after initialization")
	}
	
	plaintext := []byte("Hello, Noise Protocol!")
	ad := []byte("additional data")
	
	ciphertext, err := cs1.EncryptWithAd(ad, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	
	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("Ciphertext should be different from plaintext")
	}
	
	cs2, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs2.Free()
	cs2.InitializeKey(key)
	
	decrypted, err := cs2.DecryptWithAd(ad, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted text doesn't match plaintext.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestCipherStateNonceIncrement(t *testing.T) {
	n, _ := New()
	cs, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs.Free()
	
	key, _ := n.RandomBytes(32)
	cs.InitializeKey(key)
	
	plaintext := []byte("test message")
	
	ct1, _ := cs.EncryptWithAd([]byte(""), plaintext)
	ct2, _ := cs.EncryptWithAd([]byte(""), plaintext)
	ct3, _ := cs.EncryptWithAd([]byte(""), plaintext)
	
	if bytes.Equal(ct1, ct2) || bytes.Equal(ct2, ct3) || bytes.Equal(ct1, ct3) {
		t.Fatal("Ciphertexts should be different due to nonce increment")
	}
}

func TestCipherStateSetNonce(t *testing.T) {
	n, _ := New()
	cs, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs.Free()
	
	key, _ := n.RandomBytes(32)
	cs.InitializeKey(key)
	
	err := cs.SetNonce(100)
	if err != nil {
		t.Fatalf("Failed to set nonce: %v", err)
	}
	
	plaintext := []byte("test")
	ct1, _ := cs.EncryptWithAd([]byte(""), plaintext)
	
	cs.SetNonce(100)
	ct2, _ := cs.EncryptWithAd([]byte(""), plaintext)
	
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("Ciphertexts with same nonce should be equal")
	}
}

func TestCipherStateWithoutKey(t *testing.T) {
	n, _ := New()
	cs, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs.Free()
	
	_, err := cs.EncryptWithAd([]byte(""), []byte("test"))
	if err == nil {
		t.Fatal("Should fail to encrypt without key")
	}
	
	_, err = cs.DecryptWithAd([]byte(""), []byte("test"))
	if err == nil {
		t.Fatal("Should fail to decrypt without key")
	}
}

func TestCipherStateInvalidKeySize(t *testing.T) {
	n, _ := New()
	cs, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs.Free()
	
	invalidKey := []byte("short key")
	err := cs.InitializeKey(invalidKey)
	if err == nil {
		t.Fatal("Should fail with invalid key size")
	}
}

func TestCreateKeyPair(t *testing.T) {
	n, _ := New()
	
	privateKey, publicKey, err := n.CreateKeyPair(NOISE_DH_CURVE25519)
	if err != nil {
		t.Fatalf("Failed to create keypair: %v", err)
	}
	
	if len(privateKey) != 32 {
		t.Fatalf("Expected private key length 32, got %d", len(privateKey))
	}
	
	if len(publicKey) != 32 {
		t.Fatalf("Expected public key length 32, got %d", len(publicKey))
	}
	
	_, publicKey2, _ := n.CreateKeyPair(NOISE_DH_CURVE25519)
	if bytes.Equal(publicKey, publicKey2) {
		t.Fatal("Different keypairs should have different public keys")
	}
}

func TestUnsupportedCipher(t *testing.T) {
	n, _ := New()
	
	_, err := n.CipherState(NOISE_CIPHER_AESGCM)
	if err == nil {
		t.Fatal("Should fail with unsupported cipher")
	}
}

func TestUnsupportedCurve(t *testing.T) {
	n, _ := New()
	
	_, _, err := n.CreateKeyPair(NOISE_DH_CURVE448)
	if err == nil {
		t.Fatal("Should fail with unsupported curve")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	n, _ := New()
	
	cs1, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs1.Free()
	key1, _ := n.RandomBytes(32)
	cs1.InitializeKey(key1)
	
	plaintext := []byte("secret message")
	ciphertext, _ := cs1.EncryptWithAd([]byte(""), plaintext)
	
	cs2, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs2.Free()
	key2, _ := n.RandomBytes(32)
	cs2.InitializeKey(key2)
	
	_, err := cs2.DecryptWithAd([]byte(""), ciphertext)
	if err == nil {
		t.Fatal("Should fail to decrypt with wrong key")
	}
}

func TestDecryptWithWrongAD(t *testing.T) {
	n, _ := New()
	
	cs1, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs1.Free()
	key, _ := n.RandomBytes(32)
	cs1.InitializeKey(key)
	
	plaintext := []byte("secret message")
	ciphertext, _ := cs1.EncryptWithAd([]byte("correct ad"), plaintext)
	
	cs2, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs2.Free()
	cs2.InitializeKey(key)
	
	_, err := cs2.DecryptWithAd([]byte("wrong ad"), ciphertext)
	if err == nil {
		t.Fatal("Should fail to decrypt with wrong additional data")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	n, _ := New()
	cs, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs.Free()
	key, _ := n.RandomBytes(32)
	cs.InitializeKey(key)
	
	plaintext := []byte("benchmark message for encryption performance testing")
	ad := []byte("")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.SetNonce(0)
		_, _ = cs.EncryptWithAd(ad, plaintext)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	n, _ := New()
	cs, _ := n.CipherState(NOISE_CIPHER_CHACHAPOLY)
	defer cs.Free()
	key, _ := n.RandomBytes(32)
	cs.InitializeKey(key)
	
	plaintext := []byte("benchmark message for decryption performance testing")
	ad := []byte("")
	ciphertext, _ := cs.EncryptWithAd(ad, plaintext)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.SetNonce(1)
		_, _ = cs.DecryptWithAd(ad, ciphertext)
	}
}
