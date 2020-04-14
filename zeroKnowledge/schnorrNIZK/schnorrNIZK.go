package schnorrNIZK

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"shercrypto/ecc/p256Utils"
	sherMath "shercrypto/math"
	sherUtils "shercrypto/utils"
)

const ONE = int64(1)

type CurvePoint = ecdsa.PublicKey

type schnorrNIZK struct {
	curve elliptic.Curve
}

func NewSchnorrNIZK(curve elliptic.Curve) (nizk *schnorrNIZK) {
	nizk = &schnorrNIZK{
		curve: curve,
	}
	return nizk
}

func (this *schnorrNIZK) Prove(secret *big.Int, A *CurvePoint) (X, V *CurvePoint, r *big.Int, err error) {
	// g is the generator of G
	g := p256Utils.ScalarBaseMult(new(big.Int).SetInt64(ONE))
	gBytes := p256Utils.Marshal(g)
	// p is the prime order of G
	p := this.curve.Params().N
	// v \in_R Z_p
	v, err := rand.Int(rand.Reader, p)
	if err != nil {
		return nil, nil, nil, err
	}
	X = p256Utils.ScalarBaseMult(secret)
	XBytes := p256Utils.Marshal(X)
	V = p256Utils.ScalarBaseMult(v)
	VBytes := p256Utils.Marshal(V)
	// A is Prover public key
	ABytes := p256Utils.Marshal(A)
	g_X_V_A_Bytes := sherUtils.ContactBytes(gBytes, XBytes, VBytes, ABytes)
	// c = H(g || X || V || A )
	c, err := sherUtils.Sha3Hash(g_X_V_A_Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	cInt := new(big.Int).SetBytes(c)
	// r = v - cx
	cx := sherMath.Mul(cInt, secret, p)
	r = sherMath.Sub(v, cx, p)
	return X, V, r, nil
}

func (this *schnorrNIZK) Verify(A, X, V *CurvePoint, r *big.Int) (res bool, err error) {
	g := p256Utils.ScalarBaseMult(new(big.Int).SetInt64(ONE))
	gBytes := p256Utils.Marshal(g)
	XBytes := p256Utils.Marshal(X)
	VBytes := p256Utils.Marshal(V)
	ABytes := p256Utils.Marshal(A)
	g_X_V_Bytes := sherUtils.ContactBytes(gBytes, XBytes, VBytes, ABytes)
	// c = H(g || X || V || A)
	c, err := sherUtils.Sha3Hash(g_X_V_Bytes)
	cInt := new(big.Int).SetBytes(c)
	if err != nil {
		return false, err
	}
	// check if V == g^r X^c
	cX := p256Utils.ScalarMult(X, cInt)
	gr := p256Utils.ScalarBaseMult(r)
	gr_cX := p256Utils.ScalarAdd(gr, cX)
	gr_cX_Bytes := p256Utils.Marshal(gr_cX)
	res = hex.EncodeToString(VBytes) == hex.EncodeToString(gr_cX_Bytes)
	return res, nil
}

func TryOnce() {
	fmt.Println("-----------Schnorr NIZK start-------------")
	// start prove
	p256 := elliptic.P256()
	//type Point = ecdsa.PublicKey
	// get g
	g_x, g_y := p256.ScalarBaseMult(new(big.Int).SetInt64(1).Bytes())
	gBytes := elliptic.Marshal(p256, g_x, g_y)
	//g := Point{p256, g_x, g_y}
	sha := sha256.New()
	sha.Write([]byte("Lin"))
	secret := sha.Sum(nil)
	// get y
	y_x, y_y := p256.ScalarBaseMult(secret)
	yBytes := elliptic.Marshal(p256, y_x, y_y)
	//y := Point{p256, y_x, y_y}
	v, _ := rand.Int(rand.Reader, p256.Params().N)
	t_x, t_y := p256.ScalarBaseMult(v.Bytes())
	tBytes := elliptic.Marshal(p256, t_x, t_y)
	//t := Point{p256, t_x, t_y}
	var cPre []byte
	cPre = append(cPre, gBytes...)
	cPre = append(cPre, yBytes...)
	cPre = append(cPre, tBytes...)
	sha = sha256.New()
	sha.Write(cPre)
	// c = H(g || y || t)
	c := sha.Sum(nil)
	cInt := new(big.Int).SetBytes(c)
	secretInt := new(big.Int).SetBytes(secret)
	cx := new(big.Int).Mul(cInt, secretInt)
	cx.Mod(cx, p256.Params().N)
	r := new(big.Int).Sub(v, cx)
	r.Mod(r, p256.Params().N)
	// send r to verifier
	// start verify(v), verifier knows y,t
	// calculate c first
	v_c := c
	gr_x, gr_y := p256.ScalarBaseMult(r.Bytes())
	yc_x, yc_y := p256.ScalarMult(y_x, y_y, v_c)
	gryc_x, gryc_y := p256.Add(gr_x, gr_y, yc_x, yc_y)
	t := elliptic.Marshal(p256, t_x, t_y)
	gryc := elliptic.Marshal(p256, gryc_x, gryc_y)
	fmt.Println("t == gryc:", hex.EncodeToString(t) == hex.EncodeToString(gryc))
	fmt.Println("-----------Schnorr NIZK end-------------")
}
