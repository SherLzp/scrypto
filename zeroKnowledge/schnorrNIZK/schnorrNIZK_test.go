package schnorrNIZK

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"shercrypto/ecc/p256Utils"
	"testing"
)

func TestSchnorrNIZK_Prove(t *testing.T) {
	p256 := elliptic.P256()
	nizk := NewSchnorrNIZK(p256)
	secret := new(big.Int).SetBytes([]byte("Sher Lin"))
	aPriKey, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		fmt.Println("Generate key error:", err)
	}
	A := aPriKey.PublicKey
	X, V, r, err := nizk.Prove(secret, &A)
	if err != nil {
		fmt.Println("Prove error:", err)
	}
	fmt.Println("X:", p256Utils.Marshal(X))
	fmt.Println("V:", p256Utils.Marshal(V))
	fmt.Println("r:", r)
}

func TestSchnorrNIZK_Verify(t *testing.T) {
	p256 := elliptic.P256()
	nizk := NewSchnorrNIZK(p256)
	secret := new(big.Int).SetBytes([]byte("Sher Lin"))
	aPriKey, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		fmt.Println("Generate key error:", err)
	}
	A := aPriKey.PublicKey
	X, V, r, err := nizk.Prove(secret, &A)
	if err != nil {
		fmt.Println("Generate prove error:", err)
	}
	res, err := nizk.Verify(&A, X, V, r)
	if err != nil {
		fmt.Println("Verify error:", err)
	}
	fmt.Println("Verify result:", res)
}
