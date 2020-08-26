package sigmaProtocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"shercrypto/ecc/bn256Utils"
	"shercrypto/xutils"
	sherMath "shercrypto/xmath"
	"strings"
)

type sigmaNIZK struct {
	Pairs []*Pair
	P     *big.Int
}

func NewSigmaNIZK(p *big.Int) (nizk *sigmaNIZK) {
	nizk = &sigmaNIZK{
		P: p,
	}
	return nizk
}

type Pair struct {
	Secret *big.Int
	Public *bn256.G1
}

type ProveScheme struct {
	Commitment *bn256.G1   `json:"Commitment"`
	Challenge  *big.Int    `json:"Challenge"`
	Proofs     []*big.Int  `json:"Proofs"`
	PubValues  []*bn256.G1 `json:"PubValues"`
	Relation   *bn256.G1   `json:"Relation"`
	Owner      *bn256.G1   `json:"Owner"`
}

const (
	ProveScheme_Commitment = "Commitment"
	ProveScheme_Challenge  = "Challenge"
	ProveScheme_Proofs     = "Proofs"
	ProveScheme_PubValues  = "PubValues"
	ProveScheme_Relation   = "Relation"
	ProveScheme_Owner      = "Owner"
)

// serialize scheme
func (scheme *ProveScheme) MarshalJSON() ([]byte, error) {
	kv := make(map[string]string)
	// Commitment
	kv[ProveScheme_Commitment] = hex.EncodeToString(scheme.Commitment.Marshal())
	// Challenge
	kv[ProveScheme_Challenge] = hex.EncodeToString(scheme.Challenge.Bytes())
	// Proofs
	var proofsSlice []string
	for _, v := range scheme.Proofs {
		proof := hex.EncodeToString(v.Bytes())
		proofsSlice = append(proofsSlice, proof)
	}
	proofsStr := strings.Join(proofsSlice, ",")
	kv[ProveScheme_Proofs] = proofsStr
	// PubValues
	var pubValuesSlice []string
	for _, v := range scheme.PubValues {
		pubValue := hex.EncodeToString(v.Marshal())
		pubValuesSlice = append(pubValuesSlice, pubValue)
	}
	pubValuesStr := strings.Join(pubValuesSlice, ",")
	kv[ProveScheme_PubValues] = pubValuesStr
	// Relation
	kv[ProveScheme_Relation] = hex.EncodeToString(scheme.Relation.Marshal())
	// Owner
	kv[ProveScheme_Owner] = hex.EncodeToString(scheme.Owner.Marshal())
	return json.Marshal(kv)
}

// deserialize scheme
func (scheme *ProveScheme) UnmarshalJSON(data []byte) error {
	// get kv first
	kv := make(map[string]string)
	err := json.Unmarshal(data, &kv)
	if err != nil {
		return err
	}
	// get attributes of ProveScheme
	// Commitment
	CommitmentBytes, err := hex.DecodeString(kv[ProveScheme_Commitment])
	// Challenge
	ChallengeBytes, err := hex.DecodeString(kv[ProveScheme_Challenge])
	if err != nil {
		return err
	}
	Commitment, res := new(bn256.G1).Unmarshal(CommitmentBytes)
	if !res {
		return errors.New("error when unmarshal G1 of CommitmentBytes")
	}
	scheme.Commitment = Commitment
	Challenge := new(big.Int).SetBytes(ChallengeBytes)
	scheme.Challenge = Challenge
	// Proofs
	proofsSlice := strings.Split(kv[ProveScheme_Proofs], ",")
	for _, v := range proofsSlice {
		ProofBytes, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		Proof := new(big.Int).SetBytes(ProofBytes)
		scheme.Proofs = append(scheme.Proofs, Proof)
	}
	// PubValues
	pubValuesSlice := strings.Split(kv[ProveScheme_PubValues], ",")
	for _, v := range pubValuesSlice {
		pubValueBytes, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		pubValue, res := new(bn256.G1).Unmarshal(pubValueBytes)
		if !res {
			return errors.New("error when unmarshal G1 of PubValueBytes")
		}
		scheme.PubValues = append(scheme.PubValues, pubValue)
	}
	// Relation
	RelationBytes, err := hex.DecodeString(kv[ProveScheme_Relation])
	// Owner
	OwnerBytes, err := hex.DecodeString(kv[ProveScheme_Owner])
	Relation, res := new(bn256.G1).Unmarshal(RelationBytes)
	if !res {
		return errors.New("error when unmarshal G1 of RelationBytes")
	}
	Owner, res := new(bn256.G1).Unmarshal(OwnerBytes)
	if !res {
		return errors.New("error when unmarshal G1 of OwnerBytes")
	}
	scheme.Relation = Relation
	scheme.Owner = Owner
	return nil
}

func (this *sigmaNIZK) AddPair(secret *big.Int, public *bn256.G1) {
	pair := &Pair{
		Secret: secret,
		Public: public,
	}
	this.Pairs = append(this.Pairs, pair)
}

func (this *sigmaNIZK) Prove(R *bn256.G1, pk *bn256.G1, optionData []byte) (prove *ProveScheme, err error) {
	pairs := this.Pairs
	if len(pairs) <= 0 {
		return nil, errors.New("claim count should larger than 0")
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
	cPre := xutils.ContactBytes(base.Marshal(), t.Marshal(), pk.Marshal(), optionData)
	c, err := xutils.GetSha3HashBytes(cPre)
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

func (this *sigmaNIZK) Verify(prove *ProveScheme, optionData []byte) (res bool, err error) {
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
	fmt.Println("-----------Sigma NIZK start-------------")
	//optionData := []byte("Hello NIZK")

	a, A, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		panic(err)
	}
	base := bn256Utils.G1ScalarBaseMult(new(big.Int).SetInt64(1))
	nizk := NewSigmaNIZK(bn256.Order)
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
	fmt.Println("-----------Sigma NIZK end-------------")
}
