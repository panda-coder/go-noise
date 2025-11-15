package sv2

import (
	"bytes"
	"testing"
)

func TestGenerateEllSwiftKeyPair(t *testing.T) {
	kp, err := GenerateEllSwiftKeyPair()
	if err != nil {
		t.Fatalf("GenerateEllSwiftKeyPair failed: %v", err)
	}

	if len(kp.privateKey) != PrivateKeySize {
		t.Errorf("Expected private key size %d, got %d", PrivateKeySize, len(kp.privateKey))
	}

	if len(kp.ellswiftPubKey) != EllSwiftEncodedSize {
		t.Errorf("Expected ElligatorSwift public key size %d, got %d", EllSwiftEncodedSize, len(kp.ellswiftPubKey))
	}

	if len(kp.xOnlyPubKey) != 32 {
		t.Errorf("Expected X-only public key size 32, got %d", len(kp.xOnlyPubKey))
	}
}

func TestEllSwiftECDH(t *testing.T) {
	kp1, err := GenerateEllSwiftKeyPair()
	if err != nil {
		t.Fatalf("GenerateEllSwiftKeyPair failed: %v", err)
	}

	kp2, err := GenerateEllSwiftKeyPair()
	if err != nil {
		t.Fatalf("GenerateEllSwiftKeyPair failed: %v", err)
	}

	sharedSecret1, err := EllSwiftECDH(
		kp1.privateKey[:],
		kp1.ellswiftPubKey[:],
		kp2.ellswiftPubKey[:],
		true,
	)
	if err != nil {
		t.Fatalf("EllSwiftECDH failed: %v", err)
	}

	sharedSecret2, err := EllSwiftECDH(
		kp2.privateKey[:],
		kp2.ellswiftPubKey[:],
		kp1.ellswiftPubKey[:],
		false,
	)
	if err != nil {
		t.Fatalf("EllSwiftECDH failed: %v", err)
	}

	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Errorf("ECDH shared secrets don't match:\n  Party 1: %x\n  Party 2: %x",
			sharedSecret1, sharedSecret2)
	}

	if len(sharedSecret1) != 32 {
		t.Errorf("Expected shared secret size 32, got %d", len(sharedSecret1))
	}
}

func TestDecodeEllSwiftToXOnly(t *testing.T) {
	kp, err := GenerateEllSwiftKeyPair()
	if err != nil {
		t.Fatalf("GenerateEllSwiftKeyPair failed: %v", err)
	}

	xOnly, err := DecodeEllSwiftToXOnly(kp.ellswiftPubKey[:])
	if err != nil {
		t.Fatalf("DecodeEllSwiftToXOnly failed: %v", err)
	}

	if len(xOnly) != 32 {
		t.Errorf("Expected X-only key size 32, got %d", len(xOnly))
	}

	if !bytes.Equal(xOnly, kp.xOnlyPubKey[:]) {
		t.Errorf("Decoded X-only key doesn't match generated X-only key:\n  Generated: %x\n  Decoded:   %x",
			kp.xOnlyPubKey, xOnly)
	}
}

func TestSignSchnorrBIP340(t *testing.T) {
	kp, err := GenerateEllSwiftKeyPair()
	if err != nil {
		t.Fatalf("GenerateEllSwiftKeyPair failed: %v", err)
	}

	message := []byte("test message")
	messageHash := HASH(message)

	signature, err := SignSchnorrBIP340(kp.privateKey[:], messageHash)
	if err != nil {
		t.Fatalf("SignSchnorrBIP340 failed: %v", err)
	}

	if len(signature) != 64 {
		t.Errorf("Expected signature size 64, got %d", len(signature))
	}

	valid, err := VerifySchnorrBIP340(kp.xOnlyPubKey[:], messageHash, signature)
	if err != nil {
		t.Fatalf("VerifySchnorrBIP340 failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}

func TestVerifySchnorrBIP340InvalidSignature(t *testing.T) {
	kp, err := GenerateEllSwiftKeyPair()
	if err != nil {
		t.Fatalf("GenerateEllSwiftKeyPair failed: %v", err)
	}

	message := []byte("test message")
	messageHash := HASH(message)

	signature, err := SignSchnorrBIP340(kp.privateKey[:], messageHash)
	if err != nil {
		t.Fatalf("SignSchnorrBIP340 failed: %v", err)
	}

	signature[0] ^= 0xFF

	valid, err := VerifySchnorrBIP340(kp.xOnlyPubKey[:], messageHash, signature)
	if err != nil {
		t.Fatalf("VerifySchnorrBIP340 failed: %v", err)
	}

	if valid {
		t.Error("Invalid signature was verified as valid")
	}
}
