package credentials

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"shercrypto/ecc/bn256Utils"
	"shercrypto/proof/sigmaProtocol"
	"shercrypto/sherUtils"
	"shercrypto/signatures/ringers17"
	sherMath "shercrypto/xmath"
)

type ringersCredential struct {
	P *big.Int
}

type Credential struct {
	Keys        []string
	Claim       map[string]*big.Int
	Sigma       *ringers17.Sigma
	Proof       *sigmaProtocol.ProveScheme
	IsSelective bool
}

func (credential *Credential) AddClaimInfo(key string, value *big.Int) {
	if credential.Claim != nil {
		if _, ok := credential.Claim[key]; ok { // if key already exists
			credential.Claim[key] = value
		} else { // if key not exists
			credential.Claim[key] = value
			credential.Keys = append(credential.Keys, key)
		}
	}
}

func NewRingersCredential() (credentialScheme *ringersCredential) {
	credentialScheme = &ringersCredential{
		P: bn256.Order,
	}
	return credentialScheme
}

func (ringers *ringersCredential) ProverKeyGen() (sk *big.Int, pk *bn256.G1, err error) {
	sk, pk, err = bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return sk, pk, nil
}

// issue credential
func (ringers *ringersCredential) Issue(claim map[string]*big.Int, sk []*big.Int) (credential *Credential, err error) {
	ringersSigner := ringers17.NewSigOfRingers()
	var keys []string
	var ks []*big.Int
	for key, attribute := range claim {
		keys = append(keys, key)
		ks = append(ks, attribute)
	}
	sigma, err := ringersSigner.Sign(ks, sk)
	if err != nil {
		return nil, err
	}
	credential = new(Credential)
	credential.Keys = keys
	credential.Claim = claim
	credential.Sigma = sigma
	return credential, nil
}

// hide attributes
func hideAttributes(claim map[string]*big.Int, C map[string]bool) (hidedPairs map[string]*big.Int, err error) {
	hidedPairs = make(map[string]*big.Int)
	// find which attribute needs to be hided
	for key, attribute := range claim {
		if _, ok := C[key]; ok {
			// calculate commitment
			commitmentBytes, err := sherUtils.ComputeCommitmentBytes(claim[key])
			if err != nil {
				return nil, err
			}
			ai := new(big.Int).SetBytes(commitmentBytes)
			hidedPairs[key] = ai
		} else {
			hidedPairs[key] = attribute
		}
	}
	return hidedPairs, nil
}

// 展示凭证，选择性披露
func (ringers *ringersCredential) ShowCredential(credential *Credential, pk *bn256.G1, C map[string]bool) (selectiveCredential *Credential, err error) {
	// create a new credential
	selectiveCredential = new(Credential)
	// get signature
	oldSigma := credential.Sigma
	// hide attributes
	// subSet is the hided attributes set
	hidedPairs, err := hideAttributes(credential.Claim, C)
	if err != nil {
		return nil, err
	}
	// re-randomize sigma
	ringersSigner := ringers17.NewSigOfRingers()
	beta, newSigma, err := ringersSigner.ReRandomizeSignature(oldSigma)
	if err != nil {
		return nil, err
	}
	selectiveCredential.Sigma = newSigma
	selectiveCredential.Keys = credential.Keys
	selectiveCredential.Claim = hidedPairs
	// SPK{(\beta,\kappa,(k_i)_{i \in \mathcal{C}}): C = \tilde{C}^{\beta} * \bar{S}^{\kappa} * \bar{S_i}^{k_i} }
	// i \in \mathcal{C}
	nizk := sigmaProtocol.NewSigmaNIZK(ringers.P)
	// secret: \beta, \kappa * \beta , k_i * \beta
	// public: C, \bar{S}, \bar{S_i}
	// C = \bar{K} * \prod_{i \in \mathcal{C}} \bar{S_i}^{k_i}
	R := newSigma.K
	//var optionDataPre []byte
	for i, key := range credential.Keys {
		attr := credential.Claim[key]
		if _, ok := C[key]; ok {
			ki_beta := sherMath.Mul(attr, beta, nizk.P)
			ssi := newSigma.Ss[i]
			nizk.AddPair(ki_beta, ssi)
		} else {
			Si_ki := bn256Utils.G1ScalarMult(newSigma.Ss[i], attr)
			R = bn256Utils.G1Add(R, Si_ki)
		}
	}
	nizk.AddPair(beta, R)
	kappa_beta := sherMath.Mul(newSigma.Kappa, beta, ringers.P)
	nizk.AddPair(kappa_beta, newSigma.S)
	// optionData H(k_i) i \in \mathcal{C}
	//optionData, err := sherUtils.GetSha3HashBytes(optionDataPre)
	//if err != nil {
	//	return nil, err
	//}
	prove, err := nizk.Prove(newSigma.C, pk, nil)
	if err != nil {
		return nil, err
	}
	selectiveCredential.Proof = prove
	selectiveCredential.IsSelective = true
	return selectiveCredential, nil
}

func (ringers *ringersCredential) Verify(credential *Credential, optionData []byte, pk *ringers17.RingersPK) (res bool, err error) {
	var ks []*big.Int
	for _, key := range credential.Keys {
		if _, ok := credential.Claim[key]; !ok {
			return false, errors.New("error with the mapping keys")
		}
		ks = append(ks, credential.Claim[key])
	}
	// verify credential signature
	ringersSigner := ringers17.NewSigOfRingers()
	res, err = ringersSigner.Verify(ks, credential.Sigma, pk)
	// verify selective credential
	if credential.IsSelective && credential.Proof != nil {
		// verify zk proof
		nizk := sigmaProtocol.NewSigmaNIZK(ringers.P)
		zkRes, err := nizk.Verify(credential.Proof, optionData)
		if err != nil {
			return false, err
		}
		res = res && zkRes
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
	claim := make(map[string]*big.Int)
	claim["name"] = new(big.Int).SetBytes([]byte("Sher"))
	claim["identity number"] = new(big.Int).SetBytes([]byte("330xxxxxxxxx"))
	claim["birthday"] = new(big.Int).SetBytes([]byte("1995-05-09"))
	credentialScheme := NewRingersCredential()
	credential, err := credentialScheme.Issue(claim, sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Credential:", credential)
	for k, v := range credential.Claim {
		fmt.Printf("Key is: %s, Value is: %s \n", k, v.Bytes())
	}
	// verify signature
	var attributes []*big.Int
	for _, attribute := range credential.Claim {
		attributes = append(attributes, attribute)
	}
	newCredVerify, err := credentialScheme.Verify(credential, nil, pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify origin credential:", newCredVerify)
	_, A, _ := credentialScheme.ProverKeyGen()
	C := make(map[string]bool)
	C["name"] = true
	C["birthday"] = true
	selectiveCredential, err := credentialScheme.ShowCredential(credential, A, C)
	if err != nil {
		panic(err)
	}
	fmt.Println("SelectiveCredential:", selectiveCredential)
	for k, v := range selectiveCredential.Claim {
		fmt.Printf("Key is: %s, Value is: %s \n", k, v.Bytes())
	}
	res, err := credentialScheme.Verify(selectiveCredential, nil, pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verify selective credential result:", res)
	fmt.Println("-----------Anonymous Credential end-------------")
}
