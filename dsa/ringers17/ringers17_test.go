package ringers17

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

func TestSigOfRingers_KeyGen(t *testing.T) {
	ringersSigner := NewSigOfRingers()
	sk, pk, err := ringersSigner.KeyGen(10)
	if err != nil {
		panic(err)
	}
	fmt.Println("sk:", sk)
	fmt.Println("pk:", pk)
}

func TestSigOfRingers_Sign(t *testing.T) {
	ringersSigner := NewSigOfRingers()
	sk, _, err := ringersSigner.KeyGen(2)
	if err != nil {
		panic(err)
	}
	var ks []*big.Int
	ks = append(ks, new(big.Int).SetUint64(100))
	ks = append(ks, new(big.Int).SetUint64(200))
	sigma, err := ringersSigner.Sign(ks, sk)
	if err != nil {
		panic(err)
	}
	sigmaBytes, err := json.Marshal(sigma)
	if err != nil {
		panic(err)
	}
	fmt.Println("sigma:", string(sigmaBytes))
}

func TestSigOfRingers_ReRandomizeSignature(t *testing.T) {
	ringersSigner := NewSigOfRingers()
	sk, _, err := ringersSigner.KeyGen(2)
	if err != nil {
		panic(err)
	}
	var ks []*big.Int
	ks = append(ks, new(big.Int).SetUint64(100))
	ks = append(ks, new(big.Int).SetUint64(200))
	sigma, err := ringersSigner.Sign(ks, sk)
	if err != nil {
		panic(err)
	}
	beta, newSigma, err := ringersSigner.ReRandomizeSignature(sigma)
	if err != nil {
		panic(err)
	}
	fmt.Println("beta:", beta)
	newSigmaBytes, err := json.Marshal(newSigma)
	if err != nil {
		panic(err)
	}
	fmt.Println("new sigma:", string(newSigmaBytes))
}

func TestSigOfRingers_Verify(t *testing.T) {
	ringersSigner := NewSigOfRingers()
	sk, pk, err := ringersSigner.KeyGen(2)
	if err != nil {
		panic(err)
	}
	var ks []*big.Int
	ks = append(ks, new(big.Int).SetUint64(100))
	ks = append(ks, new(big.Int).SetUint64(200))
	sigma, err := ringersSigner.Sign(ks, sk)
	if err != nil {
		panic(err)
	}
	res, err := ringersSigner.Verify(ks, sigma, pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("verify result:", res)
}

func TestTryOnce(t *testing.T) {
	TryOnce()
}
