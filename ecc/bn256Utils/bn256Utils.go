package bn256Utils

import (
	"golang.org/x/crypto/bn256"
	"math/big"
)

func G1ScalarBaseMult(a *big.Int) *bn256.G1 {
	return new(bn256.G1).ScalarBaseMult(a)
}

func G1ScalarMult(a *bn256.G1, b *big.Int) *bn256.G1 {
	return new(bn256.G1).ScalarMult(a, b)
}

func G1Add(a, b *bn256.G1) *bn256.G1 {
	return new(bn256.G1).Add(a, b)
}

func G1Neg(a *bn256.G1) *bn256.G1 {
	return new(bn256.G1).Neg(a)
}

func G2ScalarBaseMult(a *big.Int) *bn256.G2 {
	return new(bn256.G2).ScalarBaseMult(a)
}

func G2ScalarMult(a *bn256.G2, b *big.Int) *bn256.G2 {
	return new(bn256.G2).ScalarMult(a, b)
}

func G2Add(a, b *bn256.G2) *bn256.G2 {
	return new(bn256.G2).Add(a, b)
}

func GTScalarMult(a *bn256.GT, b *big.Int) *bn256.GT {
	return new(bn256.GT).ScalarMult(a, b)
}

func GTAdd(a, b *bn256.GT) *bn256.GT {
	return new(bn256.GT).Add(a, b)
}
