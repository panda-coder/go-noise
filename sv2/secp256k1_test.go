package sv2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if kp.privateKey == nil {
		t.Error("Private key is nil")
	}

	if len(kp.publicKey) != 32 {
		t.Errorf("Public key length = %d, want 32", len(kp.publicKey))
	}
}

func TestSerializePrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	privBytes := kp.SerializePrivateKey()
	if len(privBytes) != 32 {
		t.Errorf("Serialized private key length = %d, want 32", len(privBytes))
	}
}

func TestParsePrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	privBytes := kp.SerializePrivateKey()
	parsedKey, err := ParsePrivateKey(privBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey failed: %v", err)
	}

	if parsedKey.D.Cmp(kp.privateKey.D) != 0 {
		t.Error("Parsed private key doesn't match original")
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	tests := []struct {
		name    string
		keyData []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 64)},
		{"zero key", make([]byte, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePrivateKey(tt.keyData)
			if err == nil {
				t.Error("Expected error for invalid key, got nil")
			}
		})
	}
}

func TestParsePublicKeyXOnly(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pubKey, err := ParsePublicKeyXOnly(kp.PublicKey())
	if err != nil {
		t.Fatalf("ParsePublicKeyXOnly failed: %v", err)
	}

	if pubKey.X.Cmp(kp.privateKey.PublicKey.X) != 0 {
		t.Error("Parsed public key X coordinate doesn't match original")
	}
}

func TestSignAndVerifySchnorr(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("test message")
	
	signature, err := Sign(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !Verify(&kp.PrivateKey().PublicKey, message, signature) {
		t.Error("Signature verification failed")
	}
}

func TestSignVerifySchnorrInvalidSignature(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte("test message")
	invalidSig := make([]byte, 64)
	rand.Read(invalidSig)

	if Verify(&kp.PrivateKey().PublicKey, message, invalidSig) {
		t.Error("Invalid signature verified successfully")
	}
}

func TestV2ECDH(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	result1, err := V2ECDH(kp1.PrivateKey(), kp2.PublicKey(), true)
	if err != nil {
		t.Fatalf("V2ECDH failed: %v", err)
	}

	result2, err := V2ECDH(kp2.PrivateKey(), kp1.PublicKey(), false)
	if err != nil {
		t.Fatalf("V2ECDH failed: %v", err)
	}

	if !bytes.Equal(result1, result2) {
		t.Error("ECDH results should match when roles are reversed")
	}

	if len(result1) != 32 {
		t.Errorf("ECDH result length = %d, want 32", len(result1))
	}
}

func TestV2ECDHInvalidKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	invalidKey := make([]byte, 16)
	_, err = V2ECDH(kp.PrivateKey(), invalidKey, true)
	if err == nil {
		t.Error("Expected error for invalid remote public key, got nil")
	}
}

func TestBase58CheckEncode(t *testing.T) {
	version := []byte{1, 0}
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	encoded := Base58CheckEncode(version, pubKey)
	if encoded == "" {
		t.Error("Base58CheckEncode returned empty string")
	}

	decodedVersion, decodedKey, err := Base58CheckDecode(encoded)
	if err != nil {
		t.Fatalf("Base58CheckDecode failed: %v", err)
	}

	if !bytes.Equal(version, decodedVersion) {
		t.Errorf("Version mismatch: got %v, want %v", decodedVersion, version)
	}

	if !bytes.Equal(pubKey, decodedKey) {
		t.Error("Decoded public key doesn't match original")
	}
}

func TestBase58CheckEncodeInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		version []byte
		pubKey  []byte
	}{
		{"invalid version length", []byte{1}, make([]byte, 32)},
		{"invalid pubkey length", []byte{1, 0}, make([]byte, 16)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base58CheckEncode(tt.version, tt.pubKey)
			if encoded != "" {
				t.Error("Expected empty string for invalid input")
			}
		})
	}
}

func TestBase58CheckDecodeInvalidChecksum(t *testing.T) {
	encoded := "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6INVALID"
	_, _, err := Base58CheckDecode(encoded)
	if err == nil {
		t.Error("Expected error for invalid checksum, got nil")
	}
}

func TestBase58CheckTestVector(t *testing.T) {
	rawCAPublicKey := []byte{118, 99, 112, 0, 151, 156, 28, 17, 175, 12, 48, 11, 205, 140, 127, 228, 134, 16, 252, 233, 185, 193, 30, 61, 174, 227, 90, 224, 176, 138, 116, 85}
	expectedEncoded := "9bXiEd8boQVhq7WddEcERUL5tyyJVFYdU8th3HfbNXK3Yw6GRXh"

	version := []byte{1, 0}
	encoded := Base58CheckEncode(version, rawCAPublicKey)

	if encoded != expectedEncoded {
		t.Errorf("Base58Check encoding = %s, want %s", encoded, expectedEncoded)
	}

	decodedVersion, decodedKey, err := Base58CheckDecode(encoded)
	if err != nil {
		t.Fatalf("Base58CheckDecode failed: %v", err)
	}

	if !bytes.Equal(version, decodedVersion) {
		t.Errorf("Decoded version = %v, want %v", decodedVersion, version)
	}

	if !bytes.Equal(rawCAPublicKey, decodedKey) {
		t.Errorf("Decoded key = %s, want %s", hex.EncodeToString(decodedKey), hex.EncodeToString(rawCAPublicKey))
	}
}

func TestCreateCertificate(t *testing.T) {
	authorityKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	cert, err := CreateCertificate(
		1,
		1000000,
		2000000,
		serverKP.PublicKey(),
		authorityKP.SerializePrivateKey(),
	)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	if cert.Version != 1 {
		t.Errorf("Certificate version = %d, want 1", cert.Version)
	}

	if cert.ValidFrom != 1000000 {
		t.Errorf("Certificate ValidFrom = %d, want 1000000", cert.ValidFrom)
	}

	if cert.NotValidAfter != 2000000 {
		t.Errorf("Certificate NotValidAfter = %d, want 2000000", cert.NotValidAfter)
	}

	if len(cert.Signature) != 64 {
		t.Errorf("Certificate signature length = %d, want 64", len(cert.Signature))
	}
}

func TestCertificateVerify(t *testing.T) {
	authorityKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	cert, err := CreateCertificate(
		1,
		1000000,
		2000000,
		serverKP.PublicKey(),
		authorityKP.SerializePrivateKey(),
	)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	if !cert.Verify() {
		t.Error("Certificate verification failed")
	}
}

func TestCertificateVerifyInvalidSignature(t *testing.T) {
	authorityKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	serverKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	cert, err := CreateCertificate(
		1,
		1000000,
		2000000,
		serverKP.PublicKey(),
		authorityKP.SerializePrivateKey(),
	)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	cert.Signature[0] ^= 0xFF

	if cert.Verify() {
		t.Error("Invalid certificate verified successfully")
	}
}

func TestCertificateSerialize(t *testing.T) {
	cert := &Certificate{
		Version:         1,
		ValidFrom:       1000000,
		NotValidAfter:   2000000,
		ServerPublicKey: make([]byte, 32),
	}

	serialized := cert.Serialize()
	expectedLength := 2 + 4 + 4 + 32

	if len(serialized) != expectedLength {
		t.Errorf("Serialized certificate length = %d, want %d", len(serialized), expectedLength)
	}
}

func TestSerializePublicKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	serialized := SerializePublicKey(&kp.privateKey.PublicKey)
	if len(serialized) != 32 {
		t.Errorf("Serialized public key length = %d, want 32", len(serialized))
	}
}

func TestTaggedHashBIP324(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	c := make([]byte, 32)

	for i := range a {
		a[i] = byte(i)
		b[i] = byte(i + 32)
		c[i] = byte(i + 64)
	}

	result := taggedHashBIP324(a, b, c)
	if len(result) != 32 {
		t.Errorf("Tagged hash length = %d, want 32", len(result))
	}

	result2 := taggedHashBIP324(a, b, c)
	if !bytes.Equal(result, result2) {
		t.Error("Tagged hash should be deterministic")
	}

	result3 := taggedHashBIP324(b, a, c)
	if bytes.Equal(result, result3) {
		t.Error("Tagged hash should be different for different input order")
	}
}
