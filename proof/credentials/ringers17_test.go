package credentials

import (
	"fmt"
	"math/big"
	"scrypto/dsa/ringers17"
	"testing"
	"time"
)

func TestRingersCredential_ProverKeyGen(t *testing.T) {
	ringersCredential := NewRingersCredential()
	sk, pk, err := ringersCredential.ProverKeyGen()
	if err != nil {
		panic(err)
	}
	fmt.Println("sk:", sk)
	fmt.Println("pk:", pk)
}

func TestRingersCredential_Issue(t *testing.T) {
	ringersSigner := ringers17.NewSigOfRingers()
	sks, _, err := ringersSigner.KeyGen(5)
	ringersCredential := NewRingersCredential()
	claim := make(map[string]*big.Int)
	claim["name"] = new(big.Int).SetBytes([]byte("Sher"))
	claim["identityNumber"] = new(big.Int).SetBytes([]byte("1995-05-09"))
	credential, err := ringersCredential.Issue(claim, sks)
	if err != nil {
		panic(err)
	}
	fmt.Println("credential:", credential)
}

func TestRingersCredential_ShowCredential(t *testing.T) {
	ringersSigner := ringers17.NewSigOfRingers()
	sks, _, err := ringersSigner.KeyGen(5)
	ringersCredential := NewRingersCredential()
	_, pk, err := ringersCredential.ProverKeyGen()
	if err != nil {
		panic(err)
	}
	claim := make(map[string]*big.Int)
	claim["name"] = new(big.Int).SetBytes([]byte("Sher"))
	claim["identityNumber"] = new(big.Int).SetBytes([]byte("1995-05-09"))
	credential, err := ringersCredential.Issue(claim, sks)
	if err != nil {
		panic(err)
	}
	fmt.Println("credential:", credential)
	C := make(map[string]bool)
	C["identityNumber"] = true
	selectiveCredential, err := ringersCredential.ShowCredential(credential, pk, C)
	if err != nil {
		panic(err)
	}
	fmt.Println("selective credential:", selectiveCredential)
}

func TestRingersCredential_Verify(t *testing.T) {
	ringersSigner := ringers17.NewSigOfRingers()
	sks, ringersPk, err := ringersSigner.KeyGen(5)
	ringersCredential := NewRingersCredential()
	_, pk, err := ringersCredential.ProverKeyGen()
	if err != nil {
		panic(err)
	}
	claim := make(map[string]*big.Int)
	claim["name"] = new(big.Int).SetBytes([]byte("Sher"))
	claim["identityNumber"] = new(big.Int).SetBytes([]byte("1995-05-09"))
	credential, err := ringersCredential.Issue(claim, sks)
	if err != nil {
		panic(err)
	}
	// 验证原始凭证
	res, err := ringersCredential.Verify(credential, nil, ringersPk)
	if err != nil {
		panic(err)
	}
	fmt.Println("原始凭证验证结果: ", res)
	C := make(map[string]bool)
	C["identityNumber"] = true
	selectiveCredential, err := ringersCredential.ShowCredential(credential, pk, C)
	if err != nil {
		panic(err)
	}
	// 验证子凭证
	res, err = ringersCredential.Verify(selectiveCredential, nil, ringersPk)
	if err != nil {
		panic(err)
	}
	fmt.Println("子凭证验证结果: ", res)
}

func TestTryOnce(t *testing.T) {
	TryOnce()
}

// 测试隐藏属性的性能
func BenchmarkRingersCredential_Issue(b *testing.B) {
	b.N = 20
	generateTime := int64(0)
	issueTime := int64(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ringersSigner := ringers17.NewSigOfRingers()
		t1 := time.Now() // get current time
		sks, _, err := ringersSigner.KeyGen(100)
		elapsed := time.Since(t1)
		generateTime = generateTime + elapsed.Milliseconds()
		ringersCredential := NewRingersCredential()
		t2 := time.Now() // get current time
		// 大属性集
		claim := make(map[string]*big.Int)
		claim["1"] = new(big.Int).SetUint64(1)
		claim["2"] = new(big.Int).SetUint64(2)
		claim["3"] = new(big.Int).SetUint64(3)
		claim["4"] = new(big.Int).SetUint64(4)
		claim["5"] = new(big.Int).SetUint64(5)
		claim["6"] = new(big.Int).SetUint64(6)
		claim["7"] = new(big.Int).SetUint64(7)
		claim["8"] = new(big.Int).SetUint64(8)
		claim["9"] = new(big.Int).SetUint64(9)
		claim["10"] = new(big.Int).SetUint64(10)
		claim["11"] = new(big.Int).SetUint64(11)
		claim["12"] = new(big.Int).SetUint64(12)
		claim["13"] = new(big.Int).SetUint64(13)
		claim["14"] = new(big.Int).SetUint64(14)
		claim["15"] = new(big.Int).SetUint64(15)
		_, err = ringersCredential.Issue(claim, sks)
		elapsed = time.Since(t2)
		issueTime += elapsed.Milliseconds()
		if err != nil {
			panic(err)
		}
	}
	fmt.Println("生成100把密钥的平均时间(ms)：", generateTime/int64(b.N))
	fmt.Println("颁发15个属性凭证的平均时间(ms)：", issueTime/int64(b.N))
}

func BenchmarkRingersCredential_ShowCredential(b *testing.B) {
	b.N = 20
	showTime := int64(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ringersSigner := ringers17.NewSigOfRingers()
		sks, _, err := ringersSigner.KeyGen(50)
		ringersCredential := NewRingersCredential()
		_, pk, _ := ringersCredential.ProverKeyGen()
		// 大属性集
		claim := make(map[string]*big.Int)
		claim["1"] = new(big.Int).SetUint64(1)
		claim["2"] = new(big.Int).SetUint64(2)
		claim["3"] = new(big.Int).SetUint64(3)
		claim["4"] = new(big.Int).SetUint64(4)
		claim["5"] = new(big.Int).SetUint64(5)
		claim["6"] = new(big.Int).SetUint64(6)
		claim["7"] = new(big.Int).SetUint64(7)
		claim["8"] = new(big.Int).SetUint64(8)
		claim["9"] = new(big.Int).SetUint64(9)
		claim["10"] = new(big.Int).SetUint64(10)
		claim["11"] = new(big.Int).SetUint64(11)
		claim["12"] = new(big.Int).SetUint64(12)
		claim["13"] = new(big.Int).SetUint64(13)
		claim["14"] = new(big.Int).SetUint64(14)
		claim["15"] = new(big.Int).SetUint64(15)
		credential, err := ringersCredential.Issue(claim, sks)
		if err != nil {
			panic(err)
		}
		t1 := time.Now()
		C := make(map[string]bool)
		C["1"] = true
		C["2"] = true
		C["3"] = true
		C["4"] = true
		C["5"] = true
		C["6"] = true
		C["7"] = true
		C["8"] = true
		C["9"] = true
		C["10"] = true
		ringersCredential.ShowCredential(credential, pk, C)
		elapsed := time.Since(t1)
		showTime += elapsed.Milliseconds()
	}
	fmt.Println("隐藏10个属性的平均时间(ms):", showTime/int64(b.N))
}

// 测试验证原始凭证性能
func BenchmarkRingersCredential_Verify(b *testing.B) {
	b.N = 20
	verifyOriginTime := int64(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ringersSigner := ringers17.NewSigOfRingers()
		sks, ringersPk, err := ringersSigner.KeyGen(50)
		ringersCredential := NewRingersCredential()
		// 大属性集
		claim := make(map[string]*big.Int)
		claim["1"] = new(big.Int).SetUint64(1)
		claim["2"] = new(big.Int).SetUint64(2)
		claim["3"] = new(big.Int).SetUint64(3)
		claim["4"] = new(big.Int).SetUint64(4)
		claim["5"] = new(big.Int).SetUint64(5)
		claim["6"] = new(big.Int).SetUint64(6)
		claim["7"] = new(big.Int).SetUint64(7)
		claim["8"] = new(big.Int).SetUint64(8)
		claim["9"] = new(big.Int).SetUint64(9)
		claim["10"] = new(big.Int).SetUint64(10)
		claim["11"] = new(big.Int).SetUint64(11)
		claim["12"] = new(big.Int).SetUint64(12)
		claim["13"] = new(big.Int).SetUint64(13)
		claim["14"] = new(big.Int).SetUint64(14)
		claim["15"] = new(big.Int).SetUint64(15)
		credential, err := ringersCredential.Issue(claim, sks)
		if err != nil {
			panic(err)
		}
		t1 := time.Now()
		ringersCredential.Verify(credential, nil, ringersPk)
		elapsed := time.Since(t1)
		verifyOriginTime += elapsed.Milliseconds()
	}
	fmt.Println("验证15个属性集凭证的平均时间（ms），不含零知识证明: ", verifyOriginTime/int64(b.N))
}

// 测试验证子凭证的性能
func BenchmarkRingersCredential_Verify2(b *testing.B) {
	b.N = 20
	verifyTime := int64(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ringersSigner := ringers17.NewSigOfRingers()
		sks, ringersPk, err := ringersSigner.KeyGen(50)
		ringersCredential := NewRingersCredential()
		_, pk, _ := ringersCredential.ProverKeyGen()
		// 大属性集
		claim := make(map[string]*big.Int)
		claim["1"] = new(big.Int).SetUint64(1)
		claim["2"] = new(big.Int).SetUint64(2)
		claim["3"] = new(big.Int).SetUint64(3)
		claim["4"] = new(big.Int).SetUint64(4)
		claim["5"] = new(big.Int).SetUint64(5)
		claim["6"] = new(big.Int).SetUint64(6)
		claim["7"] = new(big.Int).SetUint64(7)
		claim["8"] = new(big.Int).SetUint64(8)
		claim["9"] = new(big.Int).SetUint64(9)
		claim["10"] = new(big.Int).SetUint64(10)
		claim["11"] = new(big.Int).SetUint64(11)
		claim["12"] = new(big.Int).SetUint64(12)
		claim["13"] = new(big.Int).SetUint64(13)
		claim["14"] = new(big.Int).SetUint64(14)
		claim["15"] = new(big.Int).SetUint64(15)
		credential, err := ringersCredential.Issue(claim, sks)
		if err != nil {
			panic(err)
		}
		C := make(map[string]bool)
		C["1"] = true
		C["2"] = true
		C["3"] = true
		C["4"] = true
		C["5"] = true
		C["6"] = true
		C["7"] = true
		C["8"] = true
		C["9"] = true
		C["10"] = true
		selectiveCredential, err := ringersCredential.ShowCredential(credential, pk, C)
		if err != nil {
			panic(err)
		}
		t1 := time.Now()
		ringersCredential.Verify(selectiveCredential, nil, ringersPk)
		elapsed := time.Since(t1)
		verifyTime += elapsed.Milliseconds()
	}
	fmt.Println("验证15个属性隐藏10个属性的凭证平均耗时(ms)，含零知识证明:", verifyTime/int64(b.N))
}
