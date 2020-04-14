package schnorrNIZK

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"shercrypto/ecc/p256Utils"
	"testing"
)

func TestSchnorrNIZK_Prove(t *testing.T) {
	p256 := elliptic.P256()
	nizk := NewSchnorrNIZK(p256)
	secret := new(big.Int).SetBytes([]byte("Sher Lin"))
	X, V, r, err := nizk.Prove(secret)
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
	X, V, r, err := nizk.Prove(secret)
	if err != nil {
		fmt.Println("Generate prove error:", err)
	}
	res, err := nizk.Verify(X, V, r)
	if err != nil {
		fmt.Println("Verify error:", err)
	}
	fmt.Println("Verify result:", res)
}
