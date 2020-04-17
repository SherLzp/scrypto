package schnorrNIZK

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"shercrypto/ecc/bn256Utils"
	sherMath "shercrypto/math"
	sherUtils "shercrypto/utils"
)

//const ONE = int64(1)
//
//type CurvePoint = ecdsa.PublicKey
//
//type schnorrNIZK struct {
//	curve elliptic.Curve
//}

//func NewSchnorrNIZK(curve elliptic.Curve) (nizk *schnorrNIZK) {
//	nizk = &schnorrNIZK{
//		curve: curve,
//	}
//	return nizk
//}
//
//func (this *schnorrNIZK) Prove(secret *big.Int, A *CurvePoint) (X, V *CurvePoint, r *big.Int, err error) {
//	// g is the generator of G
//	g := p256Utils.ScalarBaseMult(new(big.Int).SetInt64(ONE))
//	gBytes := p256Utils.Marshal(g)
//	// p is the prime order of G
//	p := this.curve.Params().N
//	// v \in_R Z_p
//	v, err := rand.Int(rand.Reader, p)
//	if err != nil {
//		return nil, nil, nil, err
//	}
//	X = p256Utils.ScalarBaseMult(secret)
//	XBytes := p256Utils.Marshal(X)
//	V = p256Utils.ScalarBaseMult(v)
//	VBytes := p256Utils.Marshal(V)
//	// A is Prover public key
//	ABytes := p256Utils.Marshal(A)
//	g_X_V_A_Bytes := sherUtils.ContactBytes(gBytes, XBytes, VBytes, ABytes)
//	// c = H(g || X || V || A )
//	c, err := sherUtils.Sha3Hash(g_X_V_A_Bytes)
//	if err != nil {
//		return nil, nil, nil, err
//	}
//	cInt := new(big.Int).SetBytes(c)
//	// r = v - cx
//	cx := sherMath.Mul(cInt, secret, p)
//	r = sherMath.Sub(v, cx, p)
//	return X, V, r, nil
//}
//
//func (this *schnorrNIZK) Verify(A, X, V *CurvePoint, r *big.Int) (res bool, err error) {
//	g := p256Utils.ScalarBaseMult(new(big.Int).SetInt64(ONE))
//	gBytes := p256Utils.Marshal(g)
//	XBytes := p256Utils.Marshal(X)
//	VBytes := p256Utils.Marshal(V)
//	ABytes := p256Utils.Marshal(A)
//	g_X_V_Bytes := sherUtils.ContactBytes(gBytes, XBytes, VBytes, ABytes)
//	// c = H(g || X || V || A)
//	c, err := sherUtils.Sha3Hash(g_X_V_Bytes)
//	cInt := new(big.Int).SetBytes(c)
//	if err != nil {
//		return false, err
//	}
//	// check if V == g^r X^c
//	cX := p256Utils.ScalarMult(X, cInt)
//	gr := p256Utils.ScalarBaseMult(r)
//	gr_cX := p256Utils.ScalarAdd(gr, cX)
//	gr_cX_Bytes := p256Utils.Marshal(gr_cX)
//	res = hex.EncodeToString(VBytes) == hex.EncodeToString(gr_cX_Bytes)
//	return res, nil
//}
//
//func TryOnce() {
//	fmt.Println("-----------Schnorr NIZK start-------------")
//	// start prove
//	p256 := elliptic.P256()
//	//type Point = ecdsa.PublicKey
//	// get g
//	g_x, g_y := p256.ScalarBaseMult(new(big.Int).SetInt64(1).Bytes())
//	gBytes := elliptic.Marshal(p256, g_x, g_y)
//	//g := Point{p256, g_x, g_y}
//	sha := sha256.New()
//	sha.Write([]byte("Lin"))
//	secret := sha.Sum(nil)
//	// get y
//	y_x, y_y := p256.ScalarBaseMult(secret)
//	yBytes := elliptic.Marshal(p256, y_x, y_y)
//	//y := Point{p256, y_x, y_y}
//	v, _ := rand.Int(rand.Reader, p256.Params().N)
//	t_x, t_y := p256.ScalarBaseMult(v.Bytes())
//	tBytes := elliptic.Marshal(p256, t_x, t_y)
//	//t := Point{p256, t_x, t_y}
//	var cPre []byte
//	cPre = append(cPre, gBytes...)
//	cPre = append(cPre, yBytes...)
//	cPre = append(cPre, tBytes...)
//	sha = sha256.New()
//	sha.Write(cPre)
//	// c = H(g || y || t)
//	c := sha.Sum(nil)
//	cInt := new(big.Int).SetBytes(c)
//	secretInt := new(big.Int).SetBytes(secret)
//	cx := new(big.Int).Mul(cInt, secretInt)
//	cx.Mod(cx, p256.Params().N)
//	r := new(big.Int).Sub(v, cx)
//	r.Mod(r, p256.Params().N)
//	// send r to verifier
//	// start verify(v), verifier knows y,t
//	// calculate c first
//	v_c := c
//	gr_x, gr_y := p256.ScalarBaseMult(r.Bytes())
//	yc_x, yc_y := p256.ScalarMult(y_x, y_y, v_c)
//	gryc_x, gryc_y := p256.Add(gr_x, gr_y, yc_x, yc_y)
//	t := elliptic.Marshal(p256, t_x, t_y)
//	gryc := elliptic.Marshal(p256, gryc_x, gryc_y)
//	fmt.Println("t == gryc:", hex.EncodeToString(t) == hex.EncodeToString(gryc))
//	fmt.Println("-----------Schnorr NIZK end-------------")
//}

type schnorrNIZK struct {
	Pairs []*Pair
	P     *big.Int
}

func NewSchnorrNIZK(p *big.Int) (nizk *schnorrNIZK) {
	nizk = &schnorrNIZK{
		P: p,
	}
	return nizk
}

type Pair struct {
	Secret *big.Int
	Public *bn256.G1
}

type ProveScheme struct {
	Commitment *bn256.G1
	Challenge  *big.Int
	Proofs     []*big.Int
	PubValues  []*bn256.G1
	Relation   *bn256.G1
	Owner      *bn256.G1
}

func (this *schnorrNIZK) AddPair(secret *big.Int, public *bn256.G1) {
	pair := &Pair{
		Secret: secret,
		Public: public,
	}
	this.Pairs = append(this.Pairs, pair)
}

func (this *schnorrNIZK) Prove(R *bn256.G1, pk *bn256.G1, optionData []byte) (prove *ProveScheme, err error) {
	pairs := this.Pairs
	if len(pairs) <= 0 {
		return nil, errors.New("Pairs count should larger than 0")
	}
	prove = new(ProveScheme)
	// R = \prod (pairs[i].Secret)^{pairs[i].Public}
	secretCount := len(pairs)
	// generate random numbers
	rs := make([]*big.Int, secretCount)
	rs[0], _ = rand.Int(rand.Reader, this.P)
	t := bn256Utils.G1ScalarMult(pairs[0].Public, rs[0])
	for i := 1; i < secretCount; i++ {
		rs[i], _ = rand.Int(rand.Reader, this.P)
		// t_i = (pairs[i].Public)^{randNums[i]}
		// t = \prod t_i
		ti := bn256Utils.G1ScalarMult(pairs[i].Public, rs[i])
		t = bn256Utils.G1Add(t, ti)
	}
	// c = H(g || t || A || optionData)
	base := bn256Utils.G1ScalarBaseMult(new(big.Int).SetInt64(1))
	cPre := sherUtils.ContactBytes(base.Marshal(), t.Marshal(), pk.Marshal(), optionData)
	c, err := sherUtils.Sha3Hash(cPre)
	if err != nil {
		return nil, err
	}
	cInt := new(big.Int).SetBytes(c)
	for i := 0; i < secretCount; i++ {
		// si = ri - c secret
		c_secret := sherMath.Mul(cInt, pairs[i].Secret, this.P)
		si := sherMath.Sub(rs[i], c_secret, this.P)
		prove.Proofs = append(prove.Proofs, si)
		prove.PubValues = append(prove.PubValues, pairs[i].Public)
	}
	prove.Challenge = cInt
	prove.Commitment = t
	prove.Relation = R
	prove.Owner = pk
	return prove, nil
}

func (this *schnorrNIZK) Verify(prove *ProveScheme, optionData []byte) (res bool, err error) {
	if len(prove.Proofs) != len(prove.PubValues) {
		return false, nil
	}
	// check t == (pubValue)^{s[i]} * R^c
	tVer := bn256Utils.G1ScalarMult(prove.Relation, prove.Challenge)
	keyCount := len(prove.PubValues)
	ss := prove.Proofs
	pubValues := prove.PubValues
	for i := 0; i < keyCount; i++ {
		pubValue_si := bn256Utils.G1ScalarMult(pubValues[i], ss[i])
		tVer = bn256Utils.G1Add(tVer, pubValue_si)
	}
	res = prove.Commitment.String() == tVer.String()
	return res, nil
}

func TryOnce() {
	fmt.Println("-----------Schnorr NIZK start-------------")
	//optionData := []byte("Hello NIZK")
	a, A, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		panic(err)
	}
	base := bn256Utils.G1ScalarBaseMult(new(big.Int).SetInt64(1))
	nizk := NewSchnorrNIZK(bn256.Order)
	nizk.AddPair(a, base)
	prove, err := nizk.Prove(A, A, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("prove scheme:", prove)
	res, err := nizk.Verify(prove, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify result:", res)
	fmt.Println("-----------Schnorr NIZK end-------------")
}
