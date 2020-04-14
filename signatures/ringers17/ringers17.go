package ringers17

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
)

func TryOnce() {
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
	ePaQ := bn256.Pair(new(bn256.G1).ScalarMult(P, a), Q)
	ePQa := bn256.Pair(P, new(bn256.G2).ScalarMult(Q, a))
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
	A := new(bn256.G2).ScalarMult(Q, a)
	A1 := new(bn256.G2).ScalarMult(Q, a1)
	A2 := new(bn256.G2).ScalarMult(Q, a2)
	Z := new(bn256.G2).ScalarMult(Q, z)
	// kappa \in Z_p
	kappa, _ := rand.Int(rand.Reader, bn256.Order)
	// K \in G_1
	_, K, _ := bn256.RandomG1(rand.Reader)
	// S = K^a
	S := new(bn256.G1).ScalarMult(K, a)
	// S_i = K^{a_i}
	S1 := new(bn256.G1).ScalarMult(K, a1)
	S2 := new(bn256.G1).ScalarMult(K, a2)
	// attribute1
	k1 := new(big.Int).SetBytes([]byte("Lin"))
	k2 := new(big.Int).SetBytes([]byte("100"))
	// C = K*S^{kappa}*S_i^{k_i}
	Skappa := new(bn256.G1).ScalarMult(S, kappa)
	S1k1 := new(bn256.G1).ScalarMult(S1, k1)
	S2k2 := new(bn256.G1).ScalarMult(S2, k2)
	Skappa_S1k1 := new(bn256.G1).Add(Skappa, S1k1)
	Skappa_S1k1_S2k2 := new(bn256.G1).Add(Skappa_S1k1, S2k2)
	C := new(bn256.G1).Add(K, Skappa_S1k1_S2k2)
	// T = C^z
	T := new(bn256.G1).ScalarMult(C, z)
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
	K_ba := new(bn256.G1).ScalarMult(K, alpha)
	//S_ba := new(bn256.G1).ScalarMult(S, alpha)
	//S1_ba := new(bn256.G1).ScalarMult(S1, alpha)
	//S2_ba := new(bn256.G1).ScalarMult(S2, alpha)
	Calpha := new(bn256.G1).ScalarMult(C, alpha)
	C_ba := new(bn256.G1).ScalarMult(Calpha, beta)
	//Talpha := new(bn256.G1).ScalarMult(T, alpha)
	//T_ba := new(bn256.G1).ScalarMult(Talpha, beta)
	// new sigma = (kappa,K_ba,S_ba,S1_ba,S2_ba,C_ba,T_ba)
	S_ba := new(bn256.G1).ScalarMult(K_ba, a)
	S1_ba := new(bn256.G1).ScalarMult(K_ba, a1)
	S2_ba := new(bn256.G1).ScalarMult(K_ba, a2)
	T_ba := new(bn256.G1).ScalarMult(C_ba, z)
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
