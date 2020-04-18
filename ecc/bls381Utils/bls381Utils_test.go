package bls381Utils

import (
	"fmt"
	"math/big"
	"testing"
)

func TestBLSPair(t *testing.T) {
	a := G1ScalarBaseMult(new(big.Int).SetInt64(1))
	b := G2ScalarBaseMult(new(big.Int).SetInt64(2))
	c := new(big.Int).SetBytes([]byte("Hello"))
	at := G1ScalarMult(a, c)
	bt := G2ScalarMult(b, c)
	acb := BLSPair(at, b)
	abc := BLSPair(a, bt)
	fmt.Println("pair result:", acb.Equal(abc))
}
