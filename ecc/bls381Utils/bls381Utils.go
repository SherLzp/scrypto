package bls381Utils

import (
	"math/big"
	"shercrypto/ecc/bls381"
	"shercrypto/ecc/bls381/fr"
)

var BLSCurve = bls381.BLS381()

type G1 = bls381.G1Jac
type G2 = bls381.G2Jac
type GT = bls381.PairingResult

func G1ScalarBaseMult(a *big.Int) *G1 {
	var b fr.Element
	b.SetBigInt(a)

	return new(G1).ScalarMulByGen(BLSCurve, b)
}

func G1ScalarMult(a *G1, b *big.Int) *G1 {
	var c fr.Element
	c.SetBigInt(b)
	return new(G1).ScalarMul(BLSCurve, a, c)
}

func G1Add(a, b *G1) *G1 {
	a1 := new(G1).Set(a)
	return a1.Add(BLSCurve, b)
}

func G1Neg(a *G1) *G1 {
	return new(G1).Neg(a)
}

func G1Equal(a, b *G1) bool {
	return a.Equal(b)
}

func G2ScalarBaseMult(a *big.Int) *G2 {
	var b fr.Element
	b.SetBigInt(a)
	return new(G2).ScalarMulByGen(BLSCurve, b)
}

func G2ScalarMult(a *G2, b *big.Int) *G2 {
	var c fr.Element
	c.SetBigInt(b)
	return new(G2).ScalarMul(BLSCurve, a, c)
}

func G2Add(a, b *G2) *G2 {
	a1 := new(G2).Set(a)
	return a1.Add(BLSCurve, b)
}

func G2Neg(a *G2) *G2 {
	return new(G2).Neg(a)
}

func G2Equal(a, b *G2) bool {
	return a.Equal(b)
}

func BLSPair(a *G1, b *G2) *GT {
	var res GT
	var aA bls381.G1Affine
	var bA bls381.G2Affine
	a.ToAffineFromJac(&aA)
	b.ToAffineFromJac(&bA)
	res = BLSCurve.FinalExponentiation(BLSCurve.MillerLoop(aA, bA, &res))
	return &res
}
