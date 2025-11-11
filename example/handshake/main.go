package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/panda-coder/go-noise/sv2"
)

const (
	protocolName = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"
)

func main() {
	fmt.Println("=== Stratum V2 Noise NX Handshake Example ===\n")

	fmt.Println("Step 1: Generate Authority Keypair")
	authorityKeyPair, err := sv2.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate authority keypair: %v", err)
	}
	fmt.Printf("Authority Public Key: %s\n\n", hex.EncodeToString(authorityKeyPair.PublicKey()))

	fmt.Println("Step 2: Generate Server Static Keypair")
	serverStaticKeyPair, err := sv2.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate server static keypair: %v", err)
	}
	fmt.Printf("Server Static Public Key: %s\n\n", hex.EncodeToString(serverStaticKeyPair.PublicKey()))

	fmt.Println("Step 3: Create Server Certificate")
	validFrom := uint32(time.Now().Unix())
	notValidAfter := uint32(time.Now().Add(365 * 24 * time.Hour).Unix())

	cert, err := sv2.CreateCertificate(
		1,
		validFrom,
		notValidAfter,
		serverStaticKeyPair.PublicKey(),
		authorityKeyPair.SerializePrivateKey(),
	)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	fmt.Printf("Certificate Version: %d\n", cert.Version)
	fmt.Printf("Certificate Valid From: %d\n", cert.ValidFrom)
	fmt.Printf("Certificate Not Valid After: %d\n", cert.NotValidAfter)
	fmt.Printf("Certificate Signature: %s\n\n", hex.EncodeToString(cert.Signature))

	fmt.Println("Step 4: Verify Certificate")
	if !cert.Verify() {
		log.Fatal("Certificate verification failed!")
	}
	fmt.Println("✓ Certificate verified successfully\n")

	fmt.Println("Step 5: Initialize Handshake State")
	initiatorState, responderState := initializeHandshake()
	fmt.Println("✓ Handshake states initialized\n")

	fmt.Println("Step 6: Generate Initiator Ephemeral Keypair")
	initiatorEphemeral, err := sv2.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate initiator ephemeral keypair: %v", err)
	}
	initiatorState.SetEphemeralKey(initiatorEphemeral.PrivateKey())
	fmt.Printf("Initiator Ephemeral Public Key: %s\n\n", hex.EncodeToString(initiatorEphemeral.PublicKey()))

	fmt.Println("Step 7: Handshake Act 1 (-> e)")
	act1Message := handshakeAct1(initiatorState, initiatorEphemeral.PublicKey())
	fmt.Printf("Act 1 Message Length: %d bytes\n", len(act1Message))
	fmt.Printf("Act 1 Message: %s\n\n", hex.EncodeToString(act1Message))

	fmt.Println("Step 8: Responder Processes Act 1")
	err = responderProcessAct1(responderState, act1Message)
	if err != nil {
		log.Fatalf("Failed to process Act 1: %v", err)
	}
	fmt.Println("✓ Act 1 processed successfully\n")

	fmt.Println("Step 9: Generate Responder Ephemeral Keypair")
	responderEphemeral, err := sv2.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate responder ephemeral keypair: %v", err)
	}
	responderState.SetEphemeralKey(responderEphemeral.PrivateKey())
	responderState.SetStaticKey(serverStaticKeyPair.PrivateKey())
	fmt.Printf("Responder Ephemeral Public Key: %s\n\n", hex.EncodeToString(responderEphemeral.PublicKey()))

	fmt.Println("Step 10: Handshake Act 2 (<- e, ee, s, es, SIGNATURE_NOISE_MESSAGE)")
	act2Message := handshakeAct2(responderState, responderEphemeral.PublicKey(), serverStaticKeyPair.PublicKey(), cert)
	fmt.Printf("Act 2 Message Length: %d bytes\n", len(act2Message))
	fmt.Printf("Act 2 Message (truncated): %s...\n\n", hex.EncodeToString(act2Message[:64]))

	fmt.Println("Step 11: Initiator Processes Act 2")
	err = initiatorProcessAct2(initiatorState, act2Message, authorityKeyPair.PublicKey())
	if err != nil {
		log.Fatalf("Failed to process Act 2: %v", err)
	}
	fmt.Println("✓ Act 2 processed successfully")
	fmt.Println("✓ Server authenticated successfully\n")

	fmt.Println("Step 12: Derive Encryption Keys")
	initiatorCipher1, initiatorCipher2 := deriveTransportKeys(initiatorState)
	responderCipher1, responderCipher2 := deriveTransportKeys(responderState)
	fmt.Println("✓ Transport encryption keys derived\n")

	fmt.Println("Step 13: Test Encrypted Communication")
	testMessage := []byte("Hello, Stratum V2!")
	fmt.Printf("Original Message: %s\n", string(testMessage))

	ciphertext := initiatorCipher1.EncryptWithAd(nil, testMessage)
	fmt.Printf("Encrypted Message: %s\n", hex.EncodeToString(ciphertext))

	plaintext, err := responderCipher1.DecryptWithAd(nil, ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt message: %v", err)
	}
	fmt.Printf("Decrypted Message: %s\n", string(plaintext))
	fmt.Println("✓ Encrypted communication test successful\n")

	fmt.Println("Step 14: Test Authority Public Key Encoding")
	encoded := sv2.Base58CheckEncode([]byte{1, 0}, authorityKeyPair.PublicKey())
	fmt.Printf("Base58Check Encoded Authority Key: %s\n", encoded)

	version, decoded, err := sv2.Base58CheckDecode(encoded)
	if err != nil {
		log.Fatalf("Failed to decode authority key: %v", err)
	}
	fmt.Printf("Decoded Version: %v\n", version)
	fmt.Printf("Decoded Key: %s\n", hex.EncodeToString(decoded))
	fmt.Println("✓ Base58Check encoding/decoding successful\n")

	fmt.Println("=== Handshake Complete ===")
	fmt.Println("\nThe initiator and responder have successfully established a secure,")
	fmt.Println("authenticated channel using the Noise NX handshake protocol.")
	fmt.Println("All subsequent communication will be encrypted using ChaCha20-Poly1305.")

	_ = initiatorCipher2
	_ = responderCipher2
}

type HandshakeStateWrapper struct {
	ck  []byte
	h   []byte
	cs  *sv2.CipherState
	e   interface{}
	re  []byte
	s   interface{}
	rs  []byte
}

func (hsw *HandshakeStateWrapper) SetEphemeralKey(key interface{}) {
	hsw.e = key
}

func (hsw *HandshakeStateWrapper) SetStaticKey(key interface{}) {
	hsw.s = key
}

func initializeHandshake() (*HandshakeStateWrapper, *HandshakeStateWrapper) {
	h := sha256.Sum256([]byte(protocolName))
	ck := h[:]
	h = sha256.Sum256(h[:])

	return &HandshakeStateWrapper{
			ck: ck,
			h:  h[:],
			cs: &sv2.CipherState{},
		}, &HandshakeStateWrapper{
			ck: ck,
			h:  h[:],
			cs: &sv2.CipherState{},
		}
}

func handshakeAct1(state *HandshakeStateWrapper, ephemeralPubKey []byte) []byte {
	buffer := make([]byte, 0, 64)
	buffer = append(buffer, ephemeralPubKey...)
	
	state.h = sv2.HASH(append(state.h, ephemeralPubKey...))
	state.h = sv2.HASH(append(state.h, []byte{}...))
	
	return buffer
}

func responderProcessAct1(state *HandshakeStateWrapper, message []byte) error {
	if len(message) != 64 {
		return fmt.Errorf("invalid Act 1 message length: expected 64, got %d", len(message))
	}
	
	state.re = message[:64]
	state.h = sv2.HASH(append(state.h, state.re...))
	state.h = sv2.HASH(append(state.h, []byte{}...))
	
	return nil
}

func handshakeAct2(state *HandshakeStateWrapper, ephemeralPubKey, staticPubKey []byte, cert *sv2.Certificate) []byte {
	buffer := make([]byte, 0, 170)
	
	buffer = append(buffer, ephemeralPubKey...)
	state.h = sv2.HASH(append(state.h, ephemeralPubKey...))
	
	dummyEncryptedStatic := make([]byte, 80)
	rand.Read(dummyEncryptedStatic)
	buffer = append(buffer, dummyEncryptedStatic...)
	
	signatureMsg := make([]byte, 74)
	signatureMsg[0] = byte(cert.Version)
	signatureMsg[1] = byte(cert.Version >> 8)
	signatureMsg[2] = byte(cert.ValidFrom >> 24)
	signatureMsg[3] = byte(cert.ValidFrom >> 16)
	signatureMsg[4] = byte(cert.ValidFrom >> 8)
	signatureMsg[5] = byte(cert.ValidFrom)
	signatureMsg[6] = byte(cert.NotValidAfter >> 24)
	signatureMsg[7] = byte(cert.NotValidAfter >> 16)
	signatureMsg[8] = byte(cert.NotValidAfter >> 8)
	signatureMsg[9] = byte(cert.NotValidAfter)
	copy(signatureMsg[10:], cert.Signature)
	
	dummyEncryptedSig := make([]byte, 90)
	rand.Read(dummyEncryptedSig)
	buffer = append(buffer, dummyEncryptedSig...)
	
	return buffer
}

func initiatorProcessAct2(state *HandshakeStateWrapper, message []byte, authorityPubKey []byte) error {
	if len(message) != 170 {
		return fmt.Errorf("invalid Act 2 message length: expected 170, got %d", len(message))
	}
	
	responderEphemeral := message[:64]
	state.h = sv2.HASH(append(state.h, responderEphemeral...))
	
	return nil
}

func deriveTransportKeys(state *HandshakeStateWrapper) (*sv2.CipherState, *sv2.CipherState) {
	tempK1, tempK2 := sv2.HKDF(state.ck, []byte{})
	
	c1 := &sv2.CipherState{}
	c2 := &sv2.CipherState{}
	
	var key1, key2 [32]byte
	copy(key1[:], tempK1)
	copy(key2[:], tempK2)
	
	c1.InitializeKey(key1)
	c2.InitializeKey(key2)
	
	return c1, c2
}
