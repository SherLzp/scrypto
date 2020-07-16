package p256Utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/bn256"
	"math/big"
	"regexp"
)

type CurvePoint = ecdsa.PublicKey

const (
	HEX_PREFIX = "0x"
)

var (
	p256 = elliptic.P256()
	N    = p256.Params().N
	two  = new(big.Int).SetInt64(2)
)

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

// CheckHex : check whether a string is a hex number with prefix "0x"
func CheckHex(s string, length int) bool {
	hexPattern, _ := regexp.Compile("\\b0x[0-9a-fA-F]+\\b")
	return hexPattern.MatchString(s) && len(s) == length+2
}

// convert private key to string
func ConvertSkToStr(privateKey *ecdsa.PrivateKey) string {
	return HEX_PREFIX + hex.EncodeToString(privateKey.D.Bytes())
}

// convert string to private key
func ConvertSkStrToSk(privateKeyStr string) (sk *ecdsa.PrivateKey, err error) {
	if !CheckHex(privateKeyStr, 64) {
		return nil, errors.New("private key str length not match")
	}
	priKeyAsBytes, err := hex.DecodeString(privateKeyStr[2:])
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(priKeyAsBytes)
	// compute public key
	pubKey := ScalarBaseMult(d)
	sk = &ecdsa.PrivateKey{
		D:         d,
		PublicKey: *pubKey,
	}
	return sk, nil
}

// convert public key to string
func ConvertPkToStr(publicKey *ecdsa.PublicKey) (pubKeyStr string) {
	pubKeyBytes := Marshal(publicKey)
	pubKeyStr = hex.EncodeToString(pubKeyBytes)
	return HEX_PREFIX + pubKeyStr
}

// convert public key string to key
func ConvertPkStrToPk(pubKeyStr string) (pubKey *ecdsa.PublicKey, err error) {
	if !CheckHex(pubKeyStr, 130) {
		return nil, errors.New("public key str not match")
	}
	pubKeyAsBytes, err := hex.DecodeString(pubKeyStr[2:])
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

func RandomKeyPair() (sk *big.Int, pk *CurvePoint, err error) {
	// 生成公私钥
	priKey, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pk = &priKey.PublicKey
	sk = priKey.D
	return sk, pk, nil
}

func GenerateKeys() (sk, pk string, err error) {
	// 生成公私钥
	priKey, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		return "", "", err
	}
	pubKey := priKey.PublicKey
	sk = ConvertSkToStr(priKey)
	pk = ConvertPkToStr(&pubKey)
	return sk, pk, nil
}

func GetBaseGenerator() (base *CurvePoint) {
	baseX := p256.Params().Gx
	baseY := p256.Params().Gy
	base = &CurvePoint{
		Curve: p256,
		X:     baseX,
		Y:     baseY,
	}
	return base
}

func ComputeH() (h *CurvePoint) {
	h = ScalarBaseMult(two)
	return h
}

func ComputeGAndHVec(n int) (gs []*CurvePoint, hs []*CurvePoint) {
	h := ComputeH()
	for i := 0; i < n; i++ {
		index := new(big.Int).SetInt64(int64(i + 2))
		gi := ScalarBaseMult(index)
		hi := ScalarMult(h, index)
		gs = append(gs, gi)
		hs = append(hs, hi)
	}
	return gs, hs
}

func ConvertG1ToP256(a *bn256.G1) (point *CurvePoint) {
	aInt := new(big.Int).SetBytes(a.Marshal())
	point = ScalarBaseMult(aInt)
	return point
}
