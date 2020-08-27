package ed25519

import (
	"crypto/rand"
	"golang.org/x/crypto/ed25519"
)

func GenerateKeyPair() (pk *ed25519.PublicKey, sk *ed25519.PrivateKey, err error) {
	pkOri, skOri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &pkOri, &skOri, nil
}

func Sign(sk *ed25519.PrivateKey, message []byte) []byte {
	signature := ed25519.Sign(*sk, message)
	return signature
}

func Verify(pk *ed25519.PublicKey, message []byte, signature []byte) bool {
	return ed25519.Verify(*pk, message, signature)
}
