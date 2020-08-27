package algebraicMAC

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"
)

func TestMacWBB_KeyGen(t *testing.T) {
	p256 := elliptic.P256()
	mac := NewMacWBB(p256)
	sk, pk, err := mac.KeyGen(3)
	if err != nil {
		fmt.Println("Key gen error:", err)
	}
	fmt.Println("sk size:", len(sk))
	fmt.Println("sk:", sk)
	fmt.Println("pk size:", len(pk))
	fmt.Println("pk:", pk)
}

func TestMacWBB_Mac(t *testing.T) {
	p256 := elliptic.P256()
	mac := NewMacWBB(p256)
	sk, _, err := mac.KeyGen(3)
	if err != nil {
		fmt.Println("Key gen error:", err)
	}
	mVec := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		mVec[i] = new(big.Int).SetInt64(int64(i + 2))
	}
	sigmas, err := mac.Mac(sk, mVec)
	if err != nil {
		fmt.Println("Mac error:", err)
	}
	fmt.Println("sigmas size:", len(sigmas))
	fmt.Println("sigmas:", sigmas)
}

func TestMacWBB_Verify(t *testing.T) {
	p256 := elliptic.P256()
	mac := NewMacWBB(p256)
	sk, _, err := mac.KeyGen(3)
	if err != nil {
		fmt.Println("Key gen error:", err)
	}
	mVec := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		mVec[i] = new(big.Int).SetInt64(int64(i + 2))
	}
	sigmas, err := mac.Mac(sk, mVec)
	sigma := sigmas[0]
	res, err := mac.Verify(sk, mVec, sigma)
	if err != nil {
		fmt.Println("Verify error:", err)
	}
	fmt.Println("Verify result:", res)
}
