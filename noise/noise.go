package noise

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type Noise struct {
	Constants Constants
}

type Constants struct {
	NOISE_CIPHER_NONE                int
	NOISE_CIPHER_CHACHAPOLY          int
	NOISE_CIPHER_AESGCM              int
	NOISE_HASH_BLAKE2s               int
	NOISE_HASH_BLAKE2b               int
	NOISE_HASH_SHA256                int
	NOISE_HASH_SHA512                int
	NOISE_DH_CURVE25519              int
	NOISE_DH_CURVE448                int
	NOISE_PATTERN_NX                 int
	NOISE_PATTERN_XX_FALLBACK        int
	NOISE_PATTERN_XX_FALLBACK_HFS    int
	NOISE_ROLE_INITIATOR             int
	NOISE_ROLE_RESPONDER             int
	NOISE_ACTION_NONE                int
	NOISE_ACTION_WRITE_MESSAGE       int
	NOISE_ACTION_READ_MESSAGE        int
	NOISE_ACTION_FAILED              int
	NOISE_ACTION_SPLIT               int
	NOISE_ERROR_NONE                 int
	NOISE_ERROR_NO_MEMORY            int
	NOISE_ERROR_UNKNOWN_ID           int
	NOISE_ERROR_UNKNOWN_NAME         int
	NOISE_ERROR_MAC_FAILURE          int
	NOISE_ERROR_NOT_APPLICABLE       int
	NOISE_ERROR_SYSTEM               int
	NOISE_ERROR_REMOTE_KEY_REQUIRED  int
	NOISE_ERROR_LOCAL_KEY_REQUIRED   int
	NOISE_ERROR_PSK_REQUIRED         int
	NOISE_ERROR_INVALID_LENGTH       int
	NOISE_ERROR_INVALID_PARAM        int
	NOISE_ERROR_INVALID_STATE        int
	NOISE_ERROR_INVALID_NONCE        int
	NOISE_ERROR_INVALID_PRIVATE_KEY  int
	NOISE_ERROR_INVALID_PUBLIC_KEY   int
	NOISE_ERROR_INVALID_FORMAT       int
	NOISE_ERROR_INVALID_SIGNATURE    int
}

type CipherState struct {
	aead  cipher.AEAD
	nonce uint64
	noise *Noise
}

type HandshakeState struct {
	noise               *Noise
	role                int
	symmetricState      *SymmetricState
	localStatic         *KeyPair
	localEphemeral      *KeyPair
	remoteStatic        []byte
	remoteEphemeral     []byte
	preSharedKey        []byte
	prologue            []byte
	action              int
	requirements        int
	tokens              []byte
	dhLocalStatic       *DHState
	dhLocalEphemeral    *DHState
	dhRemoteStatic      *DHState
	dhRemoteEphemeral   *DHState
	dhFixedEphemeral    *DHState
	dhFixedHybrid       *DHState
	preSharedKeyLen     int
	prologueLen         int
}

type KeyPair struct {
	privateKey []byte
	publicKey  []byte
}

type DHState struct {
	keyPair *KeyPair
}

type SymmetricState struct {
	noise        *Noise
	protocolID   []byte
	cipherState  *CipherState
	hashState    []byte
	chainingKey  []byte
	handshakeHash []byte
}

func New() (*Noise, error) {
	n := &Noise{
		Constants: getDefaultConstants(),
	}
	return n, nil
}

func getDefaultConstants() Constants {
	return Constants{
		NOISE_CIPHER_NONE:                NOISE_CIPHER_NONE,
		NOISE_CIPHER_CHACHAPOLY:          NOISE_CIPHER_CHACHAPOLY,
		NOISE_CIPHER_AESGCM:              NOISE_CIPHER_AESGCM,
		NOISE_HASH_BLAKE2s:               NOISE_HASH_BLAKE2s,
		NOISE_HASH_BLAKE2b:               NOISE_HASH_BLAKE2b,
		NOISE_HASH_SHA256:                NOISE_HASH_SHA256,
		NOISE_HASH_SHA512:                NOISE_HASH_SHA512,
		NOISE_DH_CURVE25519:              NOISE_DH_CURVE25519,
		NOISE_DH_CURVE448:                NOISE_DH_CURVE448,
		NOISE_PATTERN_NX:                 NOISE_PATTERN_NX,
		NOISE_PATTERN_XX_FALLBACK:        NOISE_PATTERN_XX_FALLBACK,
		NOISE_PATTERN_XX_FALLBACK_HFS:    NOISE_PATTERN_XX_FALLBACK_HFS,
		NOISE_ROLE_INITIATOR:             NOISE_ROLE_INITIATOR,
		NOISE_ROLE_RESPONDER:             NOISE_ROLE_RESPONDER,
		NOISE_ACTION_NONE:                NOISE_ACTION_NONE,
		NOISE_ACTION_WRITE_MESSAGE:       NOISE_ACTION_WRITE_MESSAGE,
		NOISE_ACTION_READ_MESSAGE:        NOISE_ACTION_READ_MESSAGE,
		NOISE_ACTION_FAILED:              NOISE_ACTION_FAILED,
		NOISE_ACTION_SPLIT:               NOISE_ACTION_SPLIT,
		NOISE_ERROR_NONE:                 NOISE_ERROR_NONE,
		NOISE_ERROR_NO_MEMORY:            NOISE_ERROR_NO_MEMORY,
		NOISE_ERROR_UNKNOWN_ID:           NOISE_ERROR_UNKNOWN_ID,
		NOISE_ERROR_UNKNOWN_NAME:         NOISE_ERROR_UNKNOWN_NAME,
		NOISE_ERROR_MAC_FAILURE:          NOISE_ERROR_MAC_FAILURE,
		NOISE_ERROR_NOT_APPLICABLE:       NOISE_ERROR_NOT_APPLICABLE,
		NOISE_ERROR_SYSTEM:               NOISE_ERROR_SYSTEM,
		NOISE_ERROR_REMOTE_KEY_REQUIRED:  NOISE_ERROR_REMOTE_KEY_REQUIRED,
		NOISE_ERROR_LOCAL_KEY_REQUIRED:   NOISE_ERROR_LOCAL_KEY_REQUIRED,
		NOISE_ERROR_PSK_REQUIRED:         NOISE_ERROR_PSK_REQUIRED,
		NOISE_ERROR_INVALID_LENGTH:       NOISE_ERROR_INVALID_LENGTH,
		NOISE_ERROR_INVALID_PARAM:        NOISE_ERROR_INVALID_PARAM,
		NOISE_ERROR_INVALID_STATE:        NOISE_ERROR_INVALID_STATE,
		NOISE_ERROR_INVALID_NONCE:        NOISE_ERROR_INVALID_NONCE,
		NOISE_ERROR_INVALID_PRIVATE_KEY:  NOISE_ERROR_INVALID_PRIVATE_KEY,
		NOISE_ERROR_INVALID_PUBLIC_KEY:   NOISE_ERROR_INVALID_PUBLIC_KEY,
		NOISE_ERROR_INVALID_FORMAT:       NOISE_ERROR_INVALID_FORMAT,
		NOISE_ERROR_INVALID_SIGNATURE:    NOISE_ERROR_INVALID_SIGNATURE,
	}
}

func (n *Noise) RandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

func (n *Noise) CipherState(cipherID int) (*CipherState, error) {
	if cipherID != NOISE_CIPHER_CHACHAPOLY {
		return nil, fmt.Errorf("unsupported cipher ID: %d (only ChaCha20-Poly1305 is currently supported)", cipherID)
	}

	cs := &CipherState{
		nonce: 0,
		noise: n,
	}
	return cs, nil
}

func (cs *CipherState) InitializeKey(key []byte) error {
	if len(key) != chacha20poly1305.KeySize {
		return fmt.Errorf("invalid key size: expected %d, got %d", chacha20poly1305.KeySize, len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	cs.aead = aead
	cs.nonce = 0
	return nil
}

func (cs *CipherState) HasKey() bool {
	return cs.aead != nil
}

func (cs *CipherState) SetNonce(nonce uint64) error {
	cs.nonce = nonce
	return nil
}

func (cs *CipherState) EncryptWithAd(ad, plaintext []byte) ([]byte, error) {
	if cs.aead == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	nonceBytes := make([]byte, chacha20poly1305.NonceSize)
	for i := 0; i < 8; i++ {
		nonceBytes[4+i] = byte(cs.nonce >> (uint(i) * 8))
	}

	ciphertext := cs.aead.Seal(nil, nonceBytes, plaintext, ad)
	cs.nonce++
	return ciphertext, nil
}

func (cs *CipherState) DecryptWithAd(ad, ciphertext []byte) ([]byte, error) {
	if cs.aead == nil {
		return nil, fmt.Errorf("cipher not initialized")
	}

	nonceBytes := make([]byte, chacha20poly1305.NonceSize)
	for i := 0; i < 8; i++ {
		nonceBytes[4+i] = byte(cs.nonce >> (uint(i) * 8))
	}

	plaintext, err := cs.aead.Open(nil, nonceBytes, ciphertext, ad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	cs.nonce++
	return plaintext, nil
}

func (cs *CipherState) Rekey() error {
	return fmt.Errorf("rekey not implemented")
}

func (cs *CipherState) Free() {
	cs.aead = nil
}

func (n *Noise) CreateKeyPair(curveID int) ([]byte, []byte, error) {
	if curveID != NOISE_DH_CURVE25519 {
		return nil, nil, fmt.Errorf("unsupported curve ID: %d (only Curve25519 is currently supported)", curveID)
	}

	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute public key: %w", err)
	}

	return privateKey, publicKey, nil
}

func (n *Noise) HandshakeState(protocolName string, role int) (*HandshakeState, error) {
	return n.NewHandshakeState(protocolName, role)
}

func (hs *HandshakeState) Split() (*CipherState, *CipherState, error) {
	if hs.action != hs.noise.Constants.NOISE_ACTION_SPLIT {
		return nil, nil, fmt.Errorf("handshake not complete")
	}

	// In a real implementation, we would use a KDF to derive the keys.
	// For this simplified example, we'll just use a dummy key.
	dummyKey := make([]byte, 32)

	cs1, err := hs.noise.CipherState(hs.noise.Constants.NOISE_CIPHER_CHACHAPOLY)
	if err != nil {
		return nil, nil, err
	}
	err = cs1.InitializeKey(dummyKey)
	if err != nil {
		return nil, nil, err
	}

	cs2, err := hs.noise.CipherState(hs.noise.Constants.NOISE_CIPHER_CHACHAPOLY)
	if err != nil {
		return nil, nil, err
	}
	err = cs2.InitializeKey(dummyKey)
	if err != nil {
		return nil, nil, err
	}

	if hs.role == hs.noise.Constants.NOISE_ROLE_INITIATOR {
		return cs1, cs2, nil
	} else {
		return cs2, cs1, nil
	}
}

func (hs *HandshakeState) ReadMessage(message []byte) ([]byte, error) {
	if hs.action != hs.noise.Constants.NOISE_ACTION_READ_MESSAGE {
		return nil, fmt.Errorf("not ready to read message")
	}

	if hs.role == hs.noise.Constants.NOISE_ROLE_INITIATOR {
		hs.remoteEphemeral = message

		// In a real implementation, we would mix the public key into the handshake hash
		// and calculate the shared secret.
		// For this simplified example, we'll just set the action.

		hs.action = hs.noise.Constants.NOISE_ACTION_SPLIT
		return nil, nil
	} else {
		hs.remoteEphemeral = message
		hs.action = hs.noise.Constants.NOISE_ACTION_WRITE_MESSAGE
		return nil, nil
	}
}

func (hs *HandshakeState) WriteMessage(payload []byte) ([]byte, error) {
	if hs.action != hs.noise.Constants.NOISE_ACTION_WRITE_MESSAGE {
		return nil, fmt.Errorf("not ready to write message")
	}

	if hs.role == hs.noise.Constants.NOISE_ROLE_INITIATOR {
		// Generate ephemeral key pair
		privateKey, publicKey, err := hs.noise.CreateKeyPair(hs.noise.Constants.NOISE_DH_CURVE25519)
		if err != nil {
			return nil, err
		}
		hs.localEphemeral = &KeyPair{privateKey, publicKey}

		// In a real implementation, we would mix the public key into the handshake hash.
		// For this simplified example, we'll just return the public key.

		hs.action = hs.noise.Constants.NOISE_ACTION_READ_MESSAGE
		return hs.localEphemeral.publicKey, nil
	} else {
		// Generate ephemeral key pair
		privateKey, publicKey, err := hs.noise.CreateKeyPair(hs.noise.Constants.NOISE_DH_CURVE25519)
		if err != nil {
			return nil, err
		}
		hs.localEphemeral = &KeyPair{privateKey, publicKey}

		// In a real implementation, we would mix the public key into the handshake hash
		// and calculate the shared secret.
		// For this simplified example, we'll just return the public key.

		hs.action = hs.noise.Constants.NOISE_ACTION_SPLIT
		return hs.localEphemeral.publicKey, nil
	}
}

func (hs *HandshakeState) Start() error {
	if hs.action != hs.noise.Constants.NOISE_ACTION_NONE {
		return fmt.Errorf("handshake already started")
	}

	// In a real implementation, we would hash the prologue and pre-shared key here.
	// For this simplified example, we'll just set the action.

	if hs.role == hs.noise.Constants.NOISE_ROLE_INITIATOR {
		hs.action = hs.noise.Constants.NOISE_ACTION_WRITE_MESSAGE
	} else {
		hs.action = hs.noise.Constants.NOISE_ACTION_READ_MESSAGE
	}

	return nil
}

func (hs *HandshakeState) Free() {
}

func (n *Noise) NewHandshakeState(protocolName string, role int) (*HandshakeState, error) {
	ss, err := n.NewSymmetricState(protocolName)
	if err != nil {
		return nil, err
	}

	hs := &HandshakeState{
		noise: n,
		role: role,
		symmetricState: ss,
		action: n.Constants.NOISE_ACTION_NONE,
	}

	return hs, nil
}

func (n *Noise) SymmetricState(protocolName string) (*SymmetricState, error) {
	return nil, fmt.Errorf("SymmetricState not yet implemented - requires full Noise Protocol spec")
}

func (ss *SymmetricState) Free() {
}

func (n *Noise) NewSymmetricState(protocolName string) (*SymmetricState, error) {
	// This is a simplified implementation that only supports the NX pattern.
	if protocolName != "Noise_NX_25519_ChaChaPoly_BLAKE2s" {
		return nil, fmt.Errorf("unsupported protocol name: %s", protocolName)
	}

	ss := &SymmetricState{
		noise: n,
		protocolID: []byte(protocolName),
	}

	return ss, nil
}