package sv2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"github.com/dustinxie/ecc"
)

type KeyPair struct {
	privateKey *ecdsa.PrivateKey
	publicKey  []byte
}

func GenerateKeyPair() (*KeyPair, error) {
	p256k1 := ecc.P256k1()
	privKey, err := ecdsa.GenerateKey(p256k1, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	if privKey.D.Sign() == 0 || privKey.D.Cmp(p256k1.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid private key")
	}

	pubKeyBytes := serializePublicKeyXOnly(privKey.PublicKey)

	return &KeyPair{
		privateKey: privKey,
		publicKey:  pubKeyBytes,
	}, nil
}

func (kp *KeyPair) PrivateKey() *ecdsa.PrivateKey {
	return kp.privateKey
}

func (kp *KeyPair) PublicKey() []byte {
	return kp.publicKey
}

func (kp *KeyPair) SerializePrivateKey() []byte {
	keyBytes := kp.privateKey.D.Bytes()
	if len(keyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(keyBytes):], keyBytes)
		return padded
	}
	return keyBytes[:32]
}

func serializePublicKeyXOnly(pubKey ecdsa.PublicKey) []byte {
	xBytes := pubKey.X.Bytes()
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		return padded
	}
	return xBytes[:32]
}

func SerializePublicKey(pubKey *ecdsa.PublicKey) []byte {
	return serializePublicKeyXOnly(*pubKey)
}

func SignSchnorr(privKey *ecdsa.PrivateKey, messageHash []byte) ([]byte, error) {
	sig, err := ecc.SignBytes(privKey, messageHash, ecc.LowerS)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return sig, nil
}

func VerifySchnorr(pubKey *ecdsa.PublicKey, messageHash []byte, signature []byte) bool {
	return ecc.VerifyBytes(pubKey, messageHash, signature, ecc.LowerS)
}

func Sign(privKey *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return SignSchnorr(privKey, hash[:])
}

func Verify(pubKey *ecdsa.PublicKey, message []byte, signature []byte) bool {
	hash := sha256.Sum256(message)
	return VerifySchnorr(pubKey, hash[:], signature)
}

func V2ECDH(privKey *ecdsa.PrivateKey, remotePubKey []byte, isInitiator bool) ([]byte, error) {
	if len(remotePubKey) != 32 {
		return nil, fmt.Errorf("invalid remote public key length: expected 32, got %d", len(remotePubKey))
	}

	p256k1 := ecc.P256k1()

	remoteX := new(big.Int).SetBytes(remotePubKey)
	remoteY := deriveYCoordinate(remoteX, p256k1)
	if remoteY == nil {
		return nil, fmt.Errorf("failed to derive Y coordinate from X-only public key")
	}

	remotePub := &ecdsa.PublicKey{
		Curve: p256k1,
		X:     remoteX,
		Y:     remoteY,
	}

	sharedX, _ := p256k1.ScalarMult(remotePub.X, remotePub.Y, privKey.D.Bytes())
	sharedSecret := sharedX.Bytes()
	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	} else {
		sharedSecret = sharedSecret[:32]
	}

	localPubKey := serializePublicKeyXOnly(privKey.PublicKey)

	var result []byte
	if isInitiator {
		result = taggedHashBIP324(localPubKey, remotePubKey, sharedSecret)
	} else {
		result = taggedHashBIP324(remotePubKey, localPubKey, sharedSecret)
	}

	return result, nil
}

func taggedHashBIP324(a, b, c []byte) []byte {
	tag := "bip324_ellswift_xonly_ecdh"
	tagHash := sha256.Sum256([]byte(tag))

	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(a)
	h.Write(b)
	h.Write(c)

	return h.Sum(nil)
}

func deriveYCoordinate(x *big.Int, curve elliptic.Curve) *big.Int {
	p := curve.Params().P
	three := big.NewInt(3)
	
	xCubed := new(big.Int).Exp(x, three, p)
	seven := big.NewInt(7)
	ySq := new(big.Int).Add(xCubed, seven)
	ySq.Mod(ySq, p)

	y := new(big.Int).ModSqrt(ySq, p)
	if y == nil {
		return nil
	}

	if y.Bit(0) == 1 {
		y.Sub(p, y)
	}

	return y
}

func ParsePrivateKey(keyBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32, got %d", len(keyBytes))
	}

	p256k1 := ecc.P256k1()
	d := new(big.Int).SetBytes(keyBytes)

	if d.Sign() == 0 || d.Cmp(p256k1.Params().N) >= 0 {
		return nil, fmt.Errorf("invalid private key value")
	}

	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: p256k1,
		},
		D: d,
	}

	privKey.PublicKey.X, privKey.PublicKey.Y = p256k1.ScalarBaseMult(d.Bytes())

	return privKey, nil
}

func ParsePublicKeyXOnly(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid public key length: expected 32, got %d", len(pubKeyBytes))
	}

	p256k1 := ecc.P256k1()
	x := new(big.Int).SetBytes(pubKeyBytes)
	y := deriveYCoordinate(x, p256k1)
	if y == nil {
		return nil, fmt.Errorf("failed to derive Y coordinate")
	}

	return &ecdsa.PublicKey{
		Curve: p256k1,
		X:     x,
		Y:     y,
	}, nil
}

func Base58CheckEncode(version []byte, pubKey []byte) string {
	if len(version) != 2 || len(pubKey) != 32 {
		return ""
	}

	payload := append(version, pubKey...)
	
	checksum := sha256.Sum256(payload)
	checksum = sha256.Sum256(checksum[:])
	
	fullPayload := append(payload, checksum[:4]...)
	
	return base58Encode(fullPayload)
}

func Base58CheckDecode(encoded string) ([]byte, []byte, error) {
	decoded := base58Decode(encoded)
	if len(decoded) < 6 {
		return nil, nil, fmt.Errorf("invalid base58check encoded string")
	}

	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]

	computedChecksum := sha256.Sum256(payload)
	computedChecksum = sha256.Sum256(computedChecksum[:])

	for i := 0; i < 4; i++ {
		if checksum[i] != computedChecksum[i] {
			return nil, nil, fmt.Errorf("checksum mismatch")
		}
	}

	if len(payload) < 2 {
		return nil, nil, fmt.Errorf("invalid payload length")
	}

	version := payload[:2]
	pubKey := payload[2:]

	return version, pubKey, nil
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	var result []byte
	
	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}

	for _, b := range input {
		if b != 0 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

func base58Decode(input string) []byte {
	result := big.NewInt(0)
	base := big.NewInt(58)

	for _, c := range input {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx == -1 {
			return nil
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}

	decoded := result.Bytes()

	for _, c := range input {
		if c != rune(base58Alphabet[0]) {
			break
		}
		decoded = append([]byte{0}, decoded...)
	}

	return decoded
}

type Certificate struct {
	Version            uint16
	ValidFrom          uint32
	NotValidAfter      uint32
	ServerPublicKey    []byte
	AuthorityPublicKey []byte
	Signature          []byte
}

func (c *Certificate) Serialize() []byte {
	buf := make([]byte, 2+4+4+32)
	binary.LittleEndian.PutUint16(buf[0:2], c.Version)
	binary.BigEndian.PutUint32(buf[2:6], c.ValidFrom)
	binary.BigEndian.PutUint32(buf[6:10], c.NotValidAfter)
	copy(buf[10:42], c.ServerPublicKey)
	return buf
}

func (c *Certificate) MessageHash() []byte {
	serialized := c.Serialize()
	hash := sha256.Sum256(serialized)
	return hash[:]
}

func (c *Certificate) Verify() bool {
	if len(c.Signature) != 64 {
		return false
	}

	authPubKey, err := ParsePublicKeyXOnly(c.AuthorityPublicKey)
	if err != nil {
		return false
	}

	messageHash := c.MessageHash()
	return VerifySchnorr(authPubKey, messageHash, c.Signature)
}

func CreateCertificate(version uint16, validFrom, notValidAfter uint32, serverPubKey, authorityPrivKey []byte) (*Certificate, error) {
	privKey, err := ParsePrivateKey(authorityPrivKey)
	if err != nil {
		return nil, fmt.Errorf("invalid authority private key: %w", err)
	}

	cert := &Certificate{
		Version:            version,
		ValidFrom:          validFrom,
		NotValidAfter:      notValidAfter,
		ServerPublicKey:    serverPubKey,
		AuthorityPublicKey: serializePublicKeyXOnly(privKey.PublicKey),
	}

	messageHash := cert.MessageHash()
	signature, err := SignSchnorr(privKey, messageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	cert.Signature = signature

	return cert, nil
}
