package ringers17

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"shercrypto/ecc/bn256Utils"
	sherMath "shercrypto/math"
)

type SigOfRingers struct {
	P *big.Int
}

type RingersPK struct {
	Q  *bn256.G2
	A  *bn256.G2
	As []*bn256.G2
	N  int
	Z  *bn256.G2
}

type Sigma struct {
	Kappa *big.Int
	K     *bn256.G1
	S     *bn256.G1
	Ss    []*bn256.G1
	N     int
	C     *bn256.G1
	T     *bn256.G1
}

func NewSigOfRingers() (ringersSigner *SigOfRingers) {
	ringersSigner = &SigOfRingers{
		P: bn256.Order,
	}
	return ringersSigner
}

func (this *SigOfRingers) KeyGen(n int) (sk []*big.Int, pk *RingersPK, err error) {
	// new RingersPK
	pk = new(RingersPK)
	// Q \in_R G_2
	_, Q, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// generate a,a_0,...,a_n,z \in_R Z_p
	a, err := rand.Int(rand.Reader, this.P)
	if err != nil {
		return nil, nil, err
	}
	sk = append(sk, a)
	for i := 0; i <= n; i++ {
		ai, err := rand.Int(rand.Reader, this.P)
		if err != nil {
			return nil, nil, err
		}
		sk = append(sk, ai)
		// calculate Q^{a_i}
		Ai := bn256Utils.G2ScalarMult(Q, ai)
		pk.As = append(pk.As, Ai)
	}
	z, err := rand.Int(rand.Reader, this.P)
	if err != nil {
		return nil, nil, err
	}
	sk = append(sk, z)
	// generate public keys
	// A = Q^a
	A := bn256Utils.G2ScalarMult(Q, a)
	// Z = Q^z
	Z := bn256Utils.G2ScalarMult(Q, z)
	pk.Q = Q
	pk.A = A
	pk.Z = Z
	pk.N = n + 1
	// sk = a,a_0,...,a_n,z
	return sk, pk, nil
}

func (this *SigOfRingers) Sign(ks []*big.Int, sk []*big.Int) (sigma *Sigma, err error) {
	// k_0,...,k_t
	// t should less or equal than len(sk) - 2
	skSize := len(sk)
	if skSize-2 < len(ks) {
		return nil, err
	}
	sigma = new(Sigma)
	// kappa \in_R Z_p
	kappa, err := rand.Int(rand.Reader, this.P)
	if err != nil {
		return nil, err
	}
	// K \in_R G_1
	_, K, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, err
	}
	// S = K^a
	a := sk[0]
	S := bn256Utils.G1ScalarMult(K, a)
	// C = K S^{kappa} \prod_{i=0}^n S_i^{k_i}
	C := bn256Utils.G1ScalarMult(S, kappa)
	C = bn256Utils.G1Add(K, C)
	// S_i = K^{a_i}
	for i := 0; i < len(ks); i++ {
		Si := bn256Utils.G1ScalarMult(K, sk[i+1])
		sigma.Ss = append(sigma.Ss, Si)
		// Si_ki_prod = \prod_{i=0}^n S_i^{k_i}
		Si_ki := bn256Utils.G1ScalarMult(Si, ks[i])
		C = bn256Utils.G1Add(C, Si_ki)
	}
	// T = C^z
	z := sk[skSize-1]
	T := bn256Utils.G1ScalarMult(C, z)
	// set sigma = (kappa,K,S,S_0,...,S_n,T)
	sigma.Kappa = kappa
	sigma.K = K
	sigma.S = S
	sigma.C = C
	sigma.T = T
	sigma.N = len(sigma.Ss)
	return sigma, nil
}

func (this *SigOfRingers) Verify(ks []*big.Int, sigma *Sigma, pk *RingersPK) (res bool, err error) {
	// check K \neq 1
	one := bn256Utils.G1ScalarBaseMult(sherMath.Sub(this.P, new(big.Int).SetInt64(1), this.P))
	if sigma.K.String() == one.String() {
		return false, errors.New("K should not equal to 1")
	}
	// C = K S^{kappa} \prod_{i=0}^n S_i^{k_i}
	C := bn256Utils.G1ScalarMult(sigma.S, sigma.Kappa)
	C = bn256Utils.G1Add(sigma.K, C)
	for i := 0; i < len(ks); i++ {
		// Si_ki_prod = \prod_{i=0}^n S_i^{k_i}
		Si_ki := bn256Utils.G1ScalarMult(sigma.Ss[i], ks[i])
		C = bn256Utils.G1Add(C, Si_ki)
	}
	// check C \neq 1
	if C.String() == one.String() {
		return false, err
	}
	// generate random numbers r,r_0,...,r_n \in_R Z_p
	r, err := rand.Int(rand.Reader, this.P)
	if err != nil {
		return false, err
	}
	// S^r \prod_{i=0}^n S_i^{r_i}
	Sr_Si_ri_prod := bn256Utils.G1ScalarMult(sigma.S, r)
	// A^r \prod_{i=0}^n A_i^{r_i}
	Ar_Ai_ri_prod := bn256Utils.G2ScalarMult(pk.A, r)
	for i := 0; i < sigma.N; i++ {
		ri, _ := rand.Int(rand.Reader, this.P)
		Si_ri := bn256Utils.G1ScalarMult(sigma.Ss[i], ri)
		Ai_ri := bn256Utils.G2ScalarMult(pk.As[i], ri)
		Sr_Si_ri_prod = bn256Utils.G1Add(Sr_Si_ri_prod, Si_ri)
		Ar_Ai_ri_prod = bn256Utils.G2Add(Ar_Ai_ri_prod, Ai_ri)
	}
	eSQ := bn256.Pair(Sr_Si_ri_prod, pk.Q)
	eKA := bn256.Pair(sigma.K, Ar_Ai_ri_prod)
	if eSQ.String() != eKA.String() {
		return false, nil
	}
	eTQ := bn256.Pair(sigma.T, pk.Q)
	eCZ := bn256.Pair(C, pk.Z)
	if eTQ.String() != eCZ.String() {
		return false, nil
	}
	return true, nil
}

func TryOnce() {
	fmt.Println("-----------Ringers17 Signature Scheme start-------------")
	ringersSigner := NewSigOfRingers()
	sk, pk, err := ringersSigner.KeyGen(2)
	if err != nil {
		panic(err)
	}
	fmt.Println("sk size:", len(sk))
	fmt.Println("pk:", pk)
	var ks []*big.Int
	for i := 0; i < 2; i++ {
		ki := new(big.Int).SetInt64(int64(i + 5))
		ks = append(ks, ki)
	}
	sigma, err := ringersSigner.Sign(ks, sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("sigma:", sigma)
	res, err := ringersSigner.Verify(ks, sigma, pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify result:", res)
	fmt.Println("-----------Ringers17 Signature Scheme end-------------")
}

func TryOnce2() {
	fmt.Println("-----------Self-blindable Attribute-based Credential start-------------")
	// private keys
	a, _ := rand.Int(rand.Reader, bn256.Order)
	a1, _ := rand.Int(rand.Reader, bn256.Order)
	a2, _ := rand.Int(rand.Reader, bn256.Order)
	z, _ := rand.Int(rand.Reader, bn256.Order)
	// public keys: Q,A,A_1,Z
	_, P, _ := bn256.RandomG1(rand.Reader)
	_, Q, _ := bn256.RandomG2(rand.Reader)
	// ---------pair test start--------------
	ePaQ := bn256.Pair(bn256Utils.G1ScalarMult(P, a), Q)
	ePQa := bn256.Pair(P, bn256Utils.G2ScalarMult(Q, a))
	ePQ := bn256.Pair(P, Q)
	ePQ = new(bn256.GT).ScalarMult(ePQ, a)
	fmt.Println("-----------Pair test start-------------")
	fmt.Println("ePaQ == ePQa == ePQ:", hex.EncodeToString(ePaQ.Marshal()) == hex.EncodeToString(ePQa.Marshal()) &&
		hex.EncodeToString(ePaQ.Marshal()) == hex.EncodeToString(ePQ.Marshal()) &&
		hex.EncodeToString(ePQ.Marshal()) == hex.EncodeToString(ePQa.Marshal()))
	fmt.Println("-----------Pair test end-------------")
	//fmt.Println("ePaQ == ePQ:", hex.EncodeToString(ePaQ.Marshal()) == hex.EncodeToString(ePQ.Marshal()))
	//fmt.Println("ePQ == ePQa:", hex.EncodeToString(ePQ.Marshal()) == hex.EncodeToString(ePQa.Marshal()))
	// ---------pair test end--------------
	A := bn256Utils.G2ScalarMult(Q, a)
	A1 := bn256Utils.G2ScalarMult(Q, a1)
	A2 := bn256Utils.G2ScalarMult(Q, a2)
	Z := bn256Utils.G2ScalarMult(Q, z)
	// kappa \in Z_p
	kappa, _ := rand.Int(rand.Reader, bn256.Order)
	// K \in G_1
	_, K, _ := bn256.RandomG1(rand.Reader)
	// S = K^a
	S := bn256Utils.G1ScalarMult(K, a)
	// S_i = K^{a_i}
	S1 := bn256Utils.G1ScalarMult(K, a1)
	S2 := bn256Utils.G1ScalarMult(K, a2)
	// attribute1
	k1 := new(big.Int).SetBytes([]byte("Lin"))
	k2 := new(big.Int).SetBytes([]byte("100"))
	// C = K*S^{kappa}*S_i^{k_i}
	Skappa := bn256Utils.G1ScalarMult(S, kappa)
	S1k1 := bn256Utils.G1ScalarMult(S1, k1)
	S2k2 := bn256Utils.G1ScalarMult(S2, k2)
	Skappa_S1k1_S2k2 := bn256Utils.G1Add(Skappa, S1k1)
	Skappa_S1k1_S2k2 = bn256Utils.G1Add(Skappa_S1k1_S2k2, S2k2)
	C := bn256Utils.G1Add(K, Skappa_S1k1_S2k2)
	// T = C^z
	T := bn256Utils.G1ScalarMult(C, z)
	// sigma = (kappa,K,S,S_i,T)
	// verify
	// check if e(S,Q) == e(K,A)
	eSQ := bn256.Pair(S, Q)
	eKA := bn256.Pair(K, A)
	fmt.Println("-----------Verify signature test start-------------")
	fmt.Println("eSQ==eKA:", eSQ.String() == eKA.String())
	// check if e(S_i,Q) == e(K,A_i)
	// eS1Q eKA1
	eS1Q := bn256.Pair(S1, Q)
	eKA1 := bn256.Pair(K, A1)
	fmt.Println("eS1Q==eKA1:", eS1Q.String() == eKA1.String())
	// eS2Q eKA2
	eS2Q := bn256.Pair(S2, Q)
	eKA2 := bn256.Pair(K, A2)
	fmt.Println("eS2Q==eKA2:", eS2Q.String() == eKA2.String())
	// check if e(T,Q) == e(C,Z)
	eTQ := bn256.Pair(T, Q)
	eCZ := bn256.Pair(C, Z)
	fmt.Println("eTQ==eCZ:", eTQ.String() == eCZ.String())
	fmt.Println("-----------Verify signature test end-------------")

	// start privacy attribute
	alpha, _ := rand.Int(rand.Reader, bn256.Order)
	beta, _ := rand.Int(rand.Reader, bn256.Order)
	K_ba := bn256Utils.G1ScalarMult(K, alpha)
	//S_ba := bn256Utils.G1ScalarMult(S, alpha)
	//S1_ba := bn256Utils.G1ScalarMult(S1, alpha)
	//S2_ba := bn256Utils.G1ScalarMult(S2, alpha)
	Calpha := bn256Utils.G1ScalarMult(C, alpha)
	C_ba := bn256Utils.G1ScalarMult(Calpha, beta)
	//Talpha := bn256Utils.G1ScalarMult(T, alpha)
	//T_ba := bn256Utils.G1ScalarMult(Talpha, beta)
	// new sigma = (kappa,K_ba,S_ba,S1_ba,S2_ba,C_ba,T_ba)
	S_ba := bn256Utils.G1ScalarMult(K_ba, a)
	S1_ba := bn256Utils.G1ScalarMult(K_ba, a1)
	S2_ba := bn256Utils.G1ScalarMult(K_ba, a2)
	T_ba := bn256Utils.G1ScalarMult(C_ba, z)
	// verify signatures
	// check if e(S_ba,Q) == e(K_ba,A)
	eS_baQ := bn256.Pair(S_ba, Q)
	eK_baA := bn256.Pair(K_ba, A)
	fmt.Println("-----------Verify modified signature start-------------")
	fmt.Println("eS_baQ == eK_baA:", eS_baQ.String() == eK_baA.String())
	eS1_baQ := bn256.Pair(S1_ba, Q)
	eK_baA1 := bn256.Pair(K_ba, A1)
	fmt.Println("eS1_baQ == eK_baA1:", eS1_baQ.String() == eK_baA1.String())
	eS2_baQ := bn256.Pair(S2_ba, Q)
	eK_baA2 := bn256.Pair(K_ba, A2)
	fmt.Println("eS2_baQ == eK_baA2:", eS2_baQ.String() == eK_baA2.String())
	eT_baQ := bn256.Pair(T_ba, Q)
	eC_baZ := bn256.Pair(C_ba, Z)
	fmt.Println("eS2_baQ == eK_baA2:", eT_baQ.String() == eC_baZ.String())
	fmt.Println("-----------Verify modified signature end-------------")
	fmt.Println("-----------Self-blindable Attribute-based Credential end-------------")
}
