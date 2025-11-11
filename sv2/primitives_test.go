package sv2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHASH(t *testing.T) {
	data := []byte("test data")
	hash := HASH(data)

	if len(hash) != 32 {
		t.Errorf("HASH length = %d, want 32", len(hash))
	}

	hash2 := HASH(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("HASH should be deterministic")
	}

	differentData := []byte("different data")
	hash3 := HASH(differentData)
	if bytes.Equal(hash, hash3) {
		t.Error("HASH of different data should be different")
	}
}

func TestHASHEmpty(t *testing.T) {
	hash := HASH([]byte{})
	if len(hash) != 32 {
		t.Errorf("HASH length = %d, want 32", len(hash))
	}

	expectedEmpty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	expected, _ := hex.DecodeString(expectedEmpty)
	if !bytes.Equal(hash, expected) {
		t.Errorf("HASH of empty data = %s, want %s", hex.EncodeToString(hash), expectedEmpty)
	}
}

func TestHMACHASH(t *testing.T) {
	key := []byte("secret key")
	data := []byte("test data")

	mac := HMAC_HASH(key, data)

	if len(mac) != 32 {
		t.Errorf("HMAC_HASH length = %d, want 32", len(mac))
	}

	mac2 := HMAC_HASH(key, data)
	if !bytes.Equal(mac, mac2) {
		t.Error("HMAC_HASH should be deterministic")
	}

	differentKey := []byte("different key")
	mac3 := HMAC_HASH(differentKey, data)
	if bytes.Equal(mac, mac3) {
		t.Error("HMAC_HASH with different key should be different")
	}

	differentData := []byte("different data")
	mac4 := HMAC_HASH(key, differentData)
	if bytes.Equal(mac, mac4) {
		t.Error("HMAC_HASH with different data should be different")
	}
}

func TestHMACHASHEmpty(t *testing.T) {
	key := []byte("key")
	mac := HMAC_HASH(key, []byte{})

	if len(mac) != 32 {
		t.Errorf("HMAC_HASH length = %d, want 32", len(mac))
	}
}

func TestHKDF(t *testing.T) {
	chainingKey := make([]byte, 32)
	for i := range chainingKey {
		chainingKey[i] = byte(i)
	}

	inputKeyMaterial := make([]byte, 32)
	for i := range inputKeyMaterial {
		inputKeyMaterial[i] = byte(i + 32)
	}

	output1, output2 := HKDF(chainingKey, inputKeyMaterial)

	if len(output1) != 32 {
		t.Errorf("HKDF output1 length = %d, want 32", len(output1))
	}

	if len(output2) != 32 {
		t.Errorf("HKDF output2 length = %d, want 32", len(output2))
	}

	if bytes.Equal(output1, output2) {
		t.Error("HKDF outputs should be different")
	}

	if bytes.Equal(output1, chainingKey) {
		t.Error("HKDF output1 should differ from chaining key")
	}

	if bytes.Equal(output1, inputKeyMaterial) {
		t.Error("HKDF output1 should differ from input key material")
	}
}

func TestHKDFDeterministic(t *testing.T) {
	chainingKey := make([]byte, 32)
	inputKeyMaterial := make([]byte, 32)

	output1a, output2a := HKDF(chainingKey, inputKeyMaterial)
	output1b, output2b := HKDF(chainingKey, inputKeyMaterial)

	if !bytes.Equal(output1a, output1b) {
		t.Error("HKDF output1 should be deterministic")
	}

	if !bytes.Equal(output2a, output2b) {
		t.Error("HKDF output2 should be deterministic")
	}
}

func TestHKDFDifferentInputs(t *testing.T) {
	ck1 := make([]byte, 32)
	ck2 := make([]byte, 32)
	ck2[0] = 1

	ikm := make([]byte, 32)

	out1a, out2a := HKDF(ck1, ikm)
	out1b, out2b := HKDF(ck2, ikm)

	if bytes.Equal(out1a, out1b) {
		t.Error("HKDF output1 should differ with different chaining key")
	}

	if bytes.Equal(out2a, out2b) {
		t.Error("HKDF output2 should differ with different chaining key")
	}
}

func TestHKDFEmptyInputKeyMaterial(t *testing.T) {
	chainingKey := make([]byte, 32)
	for i := range chainingKey {
		chainingKey[i] = byte(i)
	}

	output1, output2 := HKDF(chainingKey, []byte{})

	if len(output1) != 32 {
		t.Errorf("HKDF output1 length = %d, want 32", len(output1))
	}

	if len(output2) != 32 {
		t.Errorf("HKDF output2 length = %d, want 32", len(output2))
	}

	if bytes.Equal(output1, output2) {
		t.Error("HKDF outputs should be different even with empty input")
	}
}

func TestHKDFWithNilInputs(t *testing.T) {
	output1, output2 := HKDF(nil, nil)

	if len(output1) != 32 {
		t.Errorf("HKDF output1 length = %d, want 32", len(output1))
	}

	if len(output2) != 32 {
		t.Errorf("HKDF output2 length = %d, want 32", len(output2))
	}
}

func TestHMACHASHTestVector(t *testing.T) {
	key := []byte{0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b}
	data := []byte("Hi There")

	expected := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	result := HMAC_HASH(key, data)

	if hex.EncodeToString(result) != expected {
		t.Errorf("HMAC_HASH = %s, want %s", hex.EncodeToString(result), expected)
	}
}

func TestHASHTestVector(t *testing.T) {
	data := []byte("abc")
	expected := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	result := HASH(data)

	if hex.EncodeToString(result) != expected {
		t.Errorf("HASH = %s, want %s", hex.EncodeToString(result), expected)
	}
}

func TestHKDFChaining(t *testing.T) {
	ck := make([]byte, 32)
	for i := range ck {
		ck[i] = byte(i)
	}

	ikm1 := make([]byte, 32)
	for i := range ikm1 {
		ikm1[i] = byte(100 + i)
	}

	ck1, temp1 := HKDF(ck, ikm1)

	ikm2 := make([]byte, 32)
	for i := range ikm2 {
		ikm2[i] = byte(200 + i)
	}

	ck2, temp2 := HKDF(ck1, ikm2)

	if bytes.Equal(temp1, temp2) {
		t.Error("Chained HKDF temp keys should be different")
	}

	if bytes.Equal(ck1, ck2) {
		t.Error("Chained HKDF chaining keys should be different")
	}

	if bytes.Equal(ck, ck1) || bytes.Equal(ck, ck2) {
		t.Error("Chained keys should differ from original")
	}
}
