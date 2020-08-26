package ed25519

import (
	"fmt"
	"testing"
)

func TestTryOnce(t *testing.T) {
	pk, sk, _ := GenerateKeyPair()
	fmt.Println("pk:", pk)
	fmt.Println("sk:", sk)
	signature := Sign(sk, []byte("hello"))
	fmt.Println("sig:", signature)
	res := Verify(pk, []byte("hello"), signature)
	fmt.Println("res:", res)
}

func TestGenerateKeyPair(t *testing.T) {
	pk, sk, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	fmt.Println("sk:", sk)
	fmt.Println("pk:", pk)
}

func TestSign(t *testing.T) {
	_, sk, _ := GenerateKeyPair()
	signature := Sign(sk, []byte("hello"))
	fmt.Println("sig:", signature)
}

func TestVerify(t *testing.T) {
	pk, sk, _ := GenerateKeyPair()
	signature := Sign(sk, []byte("hello"))
	res := Verify(pk, []byte("hello"), signature)
	fmt.Println("res:", res)
}
