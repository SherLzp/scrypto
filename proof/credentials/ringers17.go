package credentials

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"shercrypto/ecc/bn256Utils"
	sherMath "shercrypto/math"
	"shercrypto/proof/schnorrNIZK"
	"shercrypto/signatures/ringers17"
	sherUtils "shercrypto/utils"
)

type ringersCredential struct {
	P *big.Int
}

type Credential struct {
	Attributes []*big.Int
	Sigma      *ringers17.Sigma
}

type SelectiveCredential struct {
	Credential *Credential
	Proof      *schnorrNIZK.ProveScheme
}

func NewRingersCredential() (credentialScheme *ringersCredential) {
	credentialScheme = &ringersCredential{
		P: bn256.Order,
	}
	return credentialScheme
}

func (this *ringersCredential) ProverKeyGen() (sk *big.Int, pk *bn256.G1, err error) {
	sk, pk, err = bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return sk, pk, nil
}

func (this *ringersCredential) Issue(ks []*big.Int, sk []*big.Int) (credential *Credential, err error) {
	ringersSigner := ringers17.NewSigOfRingers()
	sigma, err := ringersSigner.Sign(ks, sk)
	if err != nil {
		return nil, err
	}
	credential = new(Credential)
	credential.Attributes = ks
	credential.Sigma = sigma
	return credential, nil
}

func hideAttributes(attributes []*big.Int, D []int) (hidedSet []*big.Int, err error) {
	if len(attributes) != len(D) {
		return nil, errors.New("attributes count not match, len(attributes) != len(D)")
	}
	count := len(D)
	for i := 0; i < count; i++ {
		// hide attribute
		if D[i] == 0 {
			hidedAttr, err := sherUtils.Sha3Hash(attributes[i].Bytes())
			if err != nil {
				return nil, err
			}
			ai := new(big.Int).SetBytes(hidedAttr)
			hidedSet = append(hidedSet, ai)
			continue
		}
		hidedSet = append(hidedSet, attributes[i])
	}
	return hidedSet, nil
}

func (this *ringersCredential) ShowCredential(credential *Credential, pk *bn256.G1, D []int) (selectiveCredential *SelectiveCredential, err error) {
	selectiveCredential = new(SelectiveCredential)
	// create a new credential
	newCredential := new(Credential)
	oldSigma := credential.Sigma
	// hide attributes
	// subSet is the hided attributes set
	hidedSet, err := hideAttributes(credential.Attributes, D)
	if err != nil {
		return nil, err
	}
	// re-randomize sigma
	ringersSigner := ringers17.NewSigOfRingers()
	beta, newSigma, err := ringersSigner.ReRandomizeSignature(oldSigma)
	if err != nil {
		return nil, err
	}
	newCredential.Sigma = newSigma
	newCredential.Attributes = hidedSet
	// SPK{(\beta,\kappa,(k_i)_{i \in \mathcal{C}}): D = \tilde{C}^{\beta} * \bar{S}^{\kappa} * \bar{S_i}^{k_i} }
	// i \in \mathcal{C}
	nizk := schnorrNIZK.NewSchnorrNIZK(this.P)
	// secret: \beta, \kappa * \beta , k_i * \beta
	// public: D, \bar{S}, \bar{S_i}
	// D = \bar{K} * \prod_{i \in \mathcal{D}} \bar{S_i}^{k_i}
	R := newSigma.K
	//var optionDataPre []byte
	for i := 0; i < len(D); i++ {
		if D[i] == 0 { // attribute which needs to hide
			attr := credential.Attributes[i]
			ki_beta := sherMath.Mul(attr, beta, this.P)
			nizk.AddPair(ki_beta, newSigma.Ss[i])
			//optionDataPre = append(optionDataPre, credential.Attributes[i].Bytes()...)
		} else {
			Si_ki := bn256Utils.G1ScalarMult(newSigma.Ss[i], credential.Attributes[i])
			R = bn256Utils.G1Add(R, Si_ki)
		}
	}
	nizk.AddPair(beta, R)
	kappa_beta := sherMath.Mul(newSigma.Kappa, beta, this.P)
	nizk.AddPair(kappa_beta, newSigma.S)
	// optionData H(k_i) i \in \mathcal{C}
	//optionData, err := sherUtils.Sha3Hash(optionDataPre)
	//if err != nil {
	//	return nil, err
	//}
	prove, err := nizk.Prove(newSigma.C, pk, nil)
	if err != nil {
		return nil, err
	}
	selectiveCredential.Credential = newCredential
	selectiveCredential.Proof = prove
	return selectiveCredential, nil
}

func (this *ringersCredential) Verify(credential *SelectiveCredential, optionData []byte, pk *ringers17.RingersPK) (res bool, err error) {
	// verify zk proof
	nizk := schnorrNIZK.NewSchnorrNIZK(this.P)
	zkRes, err := nizk.Verify(credential.Proof, optionData)
	if err != nil {
		return false, err
	}
	if !zkRes {
		return false, err
	}
	ringersSigner := ringers17.NewSigOfRingers()
	ks := credential.Credential.Attributes
	sigma := credential.Credential.Sigma
	//choose \ r,r_0,...,r_n \in_R \mathbb{Z}_p^* \\
	//verify \ e(\tilde{C},Z) \overset{?}{=} e(\tilde{T},Q) \\
	//and \ e(\bar{S}^r \prod_{i=0}^n \bar{S_i}^{r_i},Q) \overset{?}{=} e(\bar{K},A^r \prod_{i=0}^n A_i^{r_i})
	res, err = ringersSigner.Verify(ks, sigma, pk)
	if err != nil {
		return false, err
	}
	return res, nil
}

func TryOnce() {
	fmt.Println("-----------Anonymous Credential start-------------")
	ringersSigner := ringers17.NewSigOfRingers()
	sk, pk, err := ringersSigner.KeyGen(2)
	if err != nil {
		panic(err)
	}
	var ks []*big.Int
	for i := 0; i < 3; i++ {
		ki := new(big.Int).SetInt64(int64(i + 3))
		ks = append(ks, ki)
	}
	credentialScheme := NewRingersCredential()
	credential, err := credentialScheme.Issue(ks, sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Credential:", credential)
	for i, attr := range credential.Attributes {
		fmt.Println("attr ", i, " :", attr)
	}
	// verify signature
	newCredVerify, err := ringersSigner.Verify(credential.Attributes, credential.Sigma, pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify origin credential:", newCredVerify)
	_, A, _ := credentialScheme.ProverKeyGen()
	D := []int{1, 1, 0}
	selectiveCredential, err := credentialScheme.ShowCredential(credential, A, D)
	if err != nil {
		panic(err)
	}
	fmt.Println("SelectiveCredential:", selectiveCredential)
	for i, attr := range selectiveCredential.Credential.Attributes {
		fmt.Println("attr ", string(i), " :", attr)
	}
	res, err := credentialScheme.Verify(selectiveCredential, nil, pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify selective credential result:", res)
	fmt.Println("-----------Anonymous Credential end-------------")
}
