package schnorrNIZK

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

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
	sha.Write(new(big.Int).SetBytes([]byte("Lin")).Bytes())
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
