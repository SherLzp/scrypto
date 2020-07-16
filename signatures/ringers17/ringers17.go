package ringers17

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bn256"
	"math/big"
	"shercrypto/ecc/bn256Utils"
	sherMath "shercrypto/xmath"
	"strconv"
	"strings"
)

type sigOfRingers struct {
	P *big.Int
}

const (
	RingersPK_Q  = "Q"
	RingersPK_A  = "A"
	RingersPK_As = "As"
	RingersPK_N  = "N"
	RingersPK_Z  = "Z"
	Sigma_Kappa  = "Kappa"
	Sigma_K      = "K"
	Sigma_S      = "S"
	Sigma_Ss     = "Ss"
	Sigma_N      = "N"
	Sigma_C      = "C"
	Sigma_T      = "T"
)

type RingersPK struct {
	Q  *bn256.G2   `json:"Q"`
	A  *bn256.G2   `json:"A"`
	As []*bn256.G2 `json:"As"`
	N  int         `json:"N"`
	Z  *bn256.G2   `json:"Z"`
}

// Serialize RingersPK
func (pk *RingersPK) MarshalJSON() ([]byte, error) {
	kv := make(map[string]string)
	kv[RingersPK_Q] = hex.EncodeToString(pk.Q.Marshal())
	kv[RingersPK_A] = hex.EncodeToString(pk.A.Marshal())
	var AsSlice []string
	for _, A := range pk.As {
		AiStr := hex.EncodeToString(A.Marshal())
		AsSlice = append(AsSlice, AiStr)
	}
	AsStr := strings.Join(AsSlice, ",")
	kv[RingersPK_As] = AsStr
	kv[RingersPK_N] = strconv.FormatInt(int64(pk.N), 10)
	kv[RingersPK_Z] = hex.EncodeToString(pk.Z.Marshal())
	return json.Marshal(kv)
}

// Deserialize RingersPK
func (pk *RingersPK) UnmarshalJSON(data []byte) error {
	// get kv first
	kv := make(map[string]string)
	err := json.Unmarshal(data, &kv)
	if err != nil {
		return err
	}
	// get attributes of RingersPK
	Qbytes, err := hex.DecodeString(kv[RingersPK_Q])
	Abytes, err := hex.DecodeString(kv[RingersPK_A])
	Zbytes, err := hex.DecodeString(kv[RingersPK_Z])
	N, err := strconv.Atoi(kv[RingersPK_N])
	if err != nil {
		return err
	}
	Q, res := new(bn256.G2).Unmarshal(Qbytes)
	A, res := new(bn256.G2).Unmarshal(Abytes)
	Z, res := new(bn256.G2).Unmarshal(Zbytes)
	if !res {
		return errors.New("error when unmarshal G2 point")
	}
	AsSlice := strings.Split(kv[RingersPK_As], ",")
	for _, v := range AsSlice {
		AiBytes, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		Ai, res := new(bn256.G2).Unmarshal(AiBytes)
		if !res {
			return errors.New("error when unmarshal G2 point")
		}
		pk.As = append(pk.As, Ai)
	}
	pk.Q = Q
	pk.A = A
	pk.Z = Z
	pk.N = N
	return nil
}

// Ringers Algorithm Signature
type Sigma struct {
	Kappa *big.Int    `json:"Kappa"`
	K     *bn256.G1   `json:"K"`
	S     *bn256.G1   `json:"S"`
	Ss    []*bn256.G1 `json:"Ss"`
	N     int         `json:"N"`
	C     *bn256.G1   `json:"C"`
	T     *bn256.G1   `json:"T"`
}

// serialize Sigma
func (sigma *Sigma) MarshalJSON() ([]byte, error) {
	kv := make(map[string]string)
	kv[Sigma_Kappa] = hex.EncodeToString(sigma.Kappa.Bytes())
	kv[Sigma_K] = hex.EncodeToString(sigma.K.Marshal())
	kv[Sigma_S] = hex.EncodeToString(sigma.S.Marshal())
	kv[Sigma_N] = strconv.FormatInt(int64(sigma.N), 10)
	kv[Sigma_C] = hex.EncodeToString(sigma.C.Marshal())
	kv[Sigma_T] = hex.EncodeToString(sigma.T.Marshal())
	var slice []string
	for _, Si := range sigma.Ss {
		SiStr := hex.EncodeToString(Si.Marshal())
		slice = append(slice, SiStr)
	}
	SsStr := strings.Join(slice, ",")
	kv[Sigma_Ss] = SsStr
	return json.Marshal(kv)
}

// deserialize Sigma
func (sigma *Sigma) UnmarshalJSON(data []byte) error {
	// get kv map first
	kv := make(map[string]string)
	err := json.Unmarshal(data, &kv)
	if err != nil {
		return err
	}
	// get attributes of Sigma
	KappaBytes, err := hex.DecodeString(kv[Sigma_Kappa])
	KBytes, err := hex.DecodeString(kv[Sigma_K])
	SBytes, err := hex.DecodeString(kv[Sigma_S])
	N, err := strconv.Atoi(kv[Sigma_N])
	if err != nil {
		return err
	}
	CBytes, err := hex.DecodeString(kv[Sigma_C])
	TBytes, err := hex.DecodeString(kv[Sigma_T])
	if err != nil {
		return err
	}
	Kappa := new(big.Int).SetBytes(KappaBytes)
	K, res := new(bn256.G1).Unmarshal(KBytes)
	S, res := new(bn256.G1).Unmarshal(SBytes)
	C, res := new(bn256.G1).Unmarshal(CBytes)
	T, res := new(bn256.G1).Unmarshal(TBytes)
	if !res {
		return errors.New("error when unmarshal G2 point")
	}
	SsSlice := strings.Split(kv[Sigma_Ss], ",")
	for _, v := range SsSlice {
		SiBytes, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		Si, res := new(bn256.G1).Unmarshal(SiBytes)
		if !res {
			return errors.New("error when unmarshal G2 point")
		}
		sigma.Ss = append(sigma.Ss, Si)
	}
	sigma.Kappa = Kappa
	sigma.K = K
	sigma.S = S
	sigma.C = C
	sigma.T = T
	sigma.N = N
	return nil
}

func NewSigOfRingers() (ringersSigner *sigOfRingers) {
	ringersSigner = &sigOfRingers{
		P: bn256.Order,
	}
	return ringersSigner
}

func (this *sigOfRingers) KeyGen(n int) (sk []*big.Int, pk *RingersPK, err error) {
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

func (this *sigOfRingers) Sign(ks []*big.Int, sk []*big.Int) (sigma *Sigma, err error) {
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

func (this *sigOfRingers) Verify(ks []*big.Int, sigma *Sigma, pk *RingersPK) (res bool, err error) {
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
	for i := 0; i < len(ks); i++ {
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
	eCZ := bn256.Pair(sigma.C, pk.Z)
	if eTQ.String() != eCZ.String() {
		return false, nil
	}
	return true, nil
}

func (this *sigOfRingers) ReRandomizeSignature(sigma *Sigma) (beta *big.Int, newSigma *Sigma, err error) {
	newSigma = new(Sigma)
	// \alpha, \beta \in_R Z_p
	alpha, err := rand.Int(rand.Reader, this.P)
	beta, err = rand.Int(rand.Reader, this.P)
	if err != nil {
		return nil, nil, err
	}
	// \bar{K} = K^{\alpha},\bar{S} = S^{\alpha}, \bar{S_i} = S_i^{\alpha}
	K_bar := bn256Utils.G1ScalarMult(sigma.K, alpha)
	S_bar := bn256Utils.G1ScalarMult(sigma.S, alpha)
	newSigma.K = K_bar
	newSigma.S = S_bar
	for i := 0; i < sigma.N; i++ {
		Si_bar := bn256Utils.G1ScalarMult(sigma.Ss[i], alpha)
		newSigma.Ss = append(newSigma.Ss, Si_bar)
	}
	// - \alpha / \beta
	//beta_inverse := sherMath.ModInverse(beta, this.P)
	//alpha_beta_inverse := sherMath.Mul(alpha, beta_inverse, this.P)
	//neg_alpha_beta_inverse := sherMath.Neg(alpha_beta_inverse)
	alpha_beta := sherMath.Mul(alpha, beta, this.P)
	// \tilde{C} = C^{ \alpha * \beta}
	C_tilde := bn256Utils.G1ScalarMult(sigma.C, alpha_beta)
	// \tilde{T} = T^{\alpha * \beta}
	T_tilde := bn256Utils.G1ScalarMult(sigma.T, alpha_beta)
	newSigma.C = C_tilde
	newSigma.T = T_tilde
	newSigma.N = len(newSigma.Ss)
	newSigma.Kappa = sigma.Kappa
	return beta, newSigma, nil
}

func TryOnce() {
	fmt.Println("-----------Ringers17 Signature Scheme start-------------")
	ringersSigner := NewSigOfRingers()
	sk, pk, err := ringersSigner.KeyGen(2)
	if err != nil {
		panic(err)
	}
	fmt.Println("sk size:", len(sk))
	pkBytes, err := json.Marshal(pk)
	if err != nil {
		panic(err)
	}
	fmt.Println("pk json:", string(pkBytes))
	var pkCopy RingersPK
	err = json.Unmarshal(pkBytes, &pkCopy)
	if err != nil {
		panic(err)
	}
	fmt.Println("pk copy:", pkCopy)
	var ks []*big.Int
	for i := 0; i < 2; i++ {
		ki := new(big.Int).SetInt64(int64(i + 5))
		ks = append(ks, ki)
	}
	sigma, err := ringersSigner.Sign(ks, sk)
	if err != nil {
		panic(err)
	}
	sigmaBytes, err := json.Marshal(sigma)
	if err != nil {
		panic(err)
	}
	fmt.Println("sigma json:", string(sigmaBytes))
	var sigmaCopy Sigma
	err = json.Unmarshal(sigmaBytes, &sigmaCopy)
	if err != nil {
		panic(err)
	}
	fmt.Println("sigma copy:", sigmaCopy)
	res, err := ringersSigner.Verify(ks, &sigmaCopy, &pkCopy)
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
