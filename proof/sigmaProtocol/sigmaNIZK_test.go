package sigmaProtocol

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"shercrypto/ecc/bn256Utils"
	"testing"
)

func TestSchnorrNIZK_Prove(t *testing.T) {
	nizk := NewSigmaNIZK(bn256.Order)
	// we generate prove: A = g^{a}
	base := bn256Utils.G1ScalarBaseMult(new(big.Int).SetInt64(1))
	a, A, err := bn256.RandomG1(rand.Reader)
	fmt.Println("Alice public key and proof relation: ", A.String())
	if err != nil {
		panic(err)
	}
	nizk.AddPair(a, base)
	prove, err := nizk.Prove(A, A, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Prove owner:", prove.Owner.String())
	fmt.Println("Prove s.t.:", prove.Relation.String())
	fmt.Println("Prove commitment:", prove.Commitment)
}

func TestSchnorrNIZK_Verify(t *testing.T) {
	nizk := NewSigmaNIZK(bn256.Order)
	// we generate prove: A = g^{a}
	base := bn256Utils.G1ScalarBaseMult(new(big.Int).SetInt64(1))
	a, A, err := bn256.RandomG1(rand.Reader)
	fmt.Println("Alice public key and proof relation: ", A.String())
	if err != nil {
		panic(err)
	}
	nizk.AddPair(a, base)
	prove, err := nizk.Prove(A, A, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Prove owner:", prove.Owner.String())
	fmt.Println("Prove s.t.:", prove.Relation.String())
	fmt.Println("Prove commitment:", prove.Commitment)
	prove.Relation = A
	res, err := nizk.Verify(prove, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify result:", res)

}
