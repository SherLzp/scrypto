package p256Utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
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

func IsEqual(a, b *CurvePoint) (res bool) {
	return hex.EncodeToString(Marshal(a)) == hex.EncodeToString(Marshal(b))
}

// convert private key to string
func PrivateKeyToString(privateKey *ecdsa.PrivateKey) string {
	return hex.EncodeToString(privateKey.D.Bytes())
}

// convert string to private key
func PrivateKeyStrToKey(privateKeyStr string) (*ecdsa.PrivateKey, error) {
	priKeyAsBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(priKeyAsBytes)
	// compute public key
	pubKey := ScalarBaseMult(d)
	key := &ecdsa.PrivateKey{
		D:         d,
		PublicKey: *pubKey,
	}
	return key, nil
}

// convert public key to string
func PublicKeyToString(publicKey *ecdsa.PublicKey) (pubKeyStr string) {
	pubKeyBytes := Marshal(publicKey)
	pubKeyStr = hex.EncodeToString(pubKeyBytes)
	return pubKeyStr
}

// convert public key string to key
func PublicKeyStrToKey(pubKeyStr string) (pubKey *ecdsa.PublicKey, err error) {
	pubKeyAsBytes, err := hex.DecodeString(pubKeyStr)
	if err != nil {
		return nil, err
	}
	key := Unmarshal(pubKeyAsBytes)
	return key, nil
}

// map hash value to curve
func HashToCurve(hash []byte) (*big.Int) {
	hashInt := new(big.Int).SetBytes(hash)
	N := p256.Params().N
	return hashInt.Mod(hashInt, N)
}
