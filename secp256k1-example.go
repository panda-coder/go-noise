package anyname

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/dustinxie/ecc"
)

func signVerify(msg []byte) error {
	// generate secp256k1 private key
	p256k1 := ecc.P256k1()
	privKey, err := ecdsa.GenerateKey(p256k1, rand.Reader)
	if err != nil {
		// handle error
		return err
	}

	// sign message
	hash := sha256.Sum256(msg)
	sig, err := ecc.SignBytes(privKey, hash[:], ecc.Normal)
	if err != nil {
		return err
	}

	// verify message
	if !ecc.VerifyBytes(&privKey.PublicKey, hash[:], sig, ecc.Normal) {
		return fmt.Errorf("failed to verify secp256k1 signature")
	}
	return nil
}
