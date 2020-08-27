package bls

import (
	"fmt"
	"testing"
)

func TestTryOnce(t *testing.T) {
	k, K, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	m := []byte("hello")
	delta, err := Sign(k, m)
	if err != nil {
		panic(err)
	}
	res := Verify(K, m, delta)
	fmt.Println("res:", res)
}
