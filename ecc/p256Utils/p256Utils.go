package p256Utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
)

type CurvePoint = ecdsa.PublicKey

var p256 = elliptic.P256()

func ScalarBaseMult(a *big.Int) (*CurvePoint) {
	x, y := p256.ScalarBaseMult(a.Bytes())
	return &CurvePoint{
		Curve: p256,
		X:     x,
		Y:     y,
	}
}

func ScalarMult(a *CurvePoint, b *big.Int) (*CurvePoint) {
	x, y := p256.ScalarMult(a.X, a.Y, b.Bytes())
	return &CurvePoint{
		Curve: p256,
		X:     x,
		Y:     y,
	}
}

func ScalarAdd(a, b *CurvePoint) (*CurvePoint) {
	x, y := p256.Add(a.X, a.Y, b.X, b.Y)
	return &CurvePoint{
		Curve: p256,
		X:     x,
		Y:     y,
	}
}

func IsOnCurve(a *CurvePoint) bool {
	isOnCurve := p256.IsOnCurve(a.X, a.Y)
	return isOnCurve
}

func Marshal(a *CurvePoint) (res []byte) {
	res = elliptic.Marshal(p256, a.X, a.Y)
	return res
}

func Unmarshal(aBytes []byte) (point *CurvePoint) {
	x, y := elliptic.Unmarshal(p256, aBytes)
	point = &CurvePoint{
		Curve: p256,
		X:     x,
		Y:     y,
	}
	return point
}
