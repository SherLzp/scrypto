package algebraicMAC

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"scrypto/ecc/p256Utils"
	"scrypto/smath"
)

type macWBB struct {
	curve elliptic.Curve
}

func NewMacWBB(curve elliptic.Curve) (mac *macWBB) {
	return &macWBB{curve: curve}
}

type CurvePoint = ecdsa.PublicKey

// macWBB.KeyGen algorithm
// goal: generate n key pairs
// sk = (x_0,...,x_n), x_i \gets_R Z_q
// pk = ipar = (X_0,...,X_n), X_i = g^{x_i}
func (this *macWBB) KeyGen(n int) (sk []*big.Int, pk []*CurvePoint, err error) {
	if n <= 0 {
		return nil, nil, errors.New("n should larger than 0")
	}
	// initialize sk,pk array
	for i := 0; i <= n; i++ {
		// our curve is P256
		// we use ecdsa to generate key pairs
		privateKey, err := ecdsa.GenerateKey(this.curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		publicKey := privateKey.PublicKey
		sk = append(sk, privateKey.D)
		pk = append(pk, &publicKey)
	}
	return sk, pk, nil
}

func (this *macWBB) Mac(sk []*big.Int, mVec []*big.Int) (sigmas []*CurvePoint, err error) {
	size := len(sk)
	if len(sk) <= 0 || len(mVec) <= 0 || len(sk) != len(mVec)+1 {
		return nil, errors.New("params size error")
	}
	// calculate sigma first
	// sigma = g^{1/(x_0 + \sum_{i=1}^{n} m_i x_i)}
	// prime number
	N := this.curve.Params().N
	sum := new(big.Int).SetInt64(0)
	for i, m := range mVec {
		mi_mul_xi := smath.Mul(m, sk[i+1], N)
		sum = smath.Add(sum, mi_mul_xi, N)
	}
	x0_add_sum := smath.Add(sk[0], sum, N)
	x0_add_sum_inverse := smath.ModInverse(x0_add_sum, N)
	// calculate sigma
	sigma := p256Utils.ScalarBaseMult(x0_add_sum_inverse)
	sigmas = append(sigmas, sigma)
	// sigma_i = sigma^{x_i}
	for i := 1; i < size; i++ {
		sigma_i := p256Utils.ScalarMult(sigma, sk[i])
		sigmas = append(sigmas, sigma_i)
	}
	return sigmas, nil
}

func (this *macWBB) Verify(sk, mVec []*big.Int, sigma *CurvePoint) (res bool, err error) {
	if len(sk) <= 0 || len(mVec) <= 0 || len(sk) != len(mVec)+1 {
		return false, errors.New("params size error")
	}
	// get base generator: g
	g := p256Utils.ScalarBaseMult(new(big.Int).SetInt64(1))
	// calculate vSigma = sigma^{x_0 + \sum+{i=1}^{n} m_i x_i}
	// prime number
	N := this.curve.Params().N
	sum := new(big.Int).SetInt64(0)
	for i, m := range mVec {
		mi_mul_xi := smath.Mul(m, sk[i+1], N)
		sum = smath.Add(sum, mi_mul_xi, N)
	}
	x0_add_sum := smath.Add(sk[0], sum, N)
	vSigma := p256Utils.ScalarMult(sigma, x0_add_sum)
	// check if g == vSigma
	gBytes := p256Utils.Marshal(g)
	vSigmaBytes := p256Utils.Marshal(vSigma)
	res = hex.EncodeToString(gBytes) == hex.EncodeToString(vSigmaBytes)
	return res, nil
}

func TryOnce() {
	fmt.Println("-----------MacWBB start-------------")
	p256 := elliptic.P256()
	mac := NewMacWBB(p256)
	sk, pk, err := mac.KeyGen(3)
	if err != nil {
		panic(err)
	}
	fmt.Println("sk size:", len(sk))
	fmt.Println("sk:", sk)
	fmt.Println("pk size:", len(pk))
	fmt.Println("pk:", pk)
	mVec := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		mVec[i] = new(big.Int).SetInt64(int64(i + 5))
		fmt.Println("mVec(i+5) ", i, ":", int64(i+5))
	}
	fmt.Println("mVec size:", len(mVec))
	sigmas, err := mac.Mac(sk, mVec)
	if err != nil {
		panic(err)
	}
	for i, sigma := range sigmas {
		fmt.Println("sigma ", i, ":", p256Utils.Marshal(sigma))
	}
	fmt.Println("sigmas size:", len(sigmas))
	res, err := mac.Verify(sk, mVec, sigmas[0])
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify result:", res)
	fmt.Println("-----------MacWBB end-------------")
}
