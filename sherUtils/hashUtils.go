package sherUtils

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"shercrypto/ecc/p256Utils"
)

/**
	计算SHA3哈希值
 */
func GetSha3HashBytes(m []byte) (hash []byte, err error) {
	sha := sha256.New()
	_, err = sha.Write(m)
	if err != nil {
		return nil, err
	}
	return sha.Sum(nil), nil
}

/**
	计算SHA3哈希值并转换为字符串
 */
func GetSha3HashStr(m string) (hash string, err error) {
	hashBytes, err := GetSha3HashBytes([]byte(m))
	if err != nil {
		return "", err
	}
	hash = hex.EncodeToString(hashBytes)
	return hash, nil
}

/**
	计算单个值的Pedersen承诺
 */
func ComputeCommitmentBytes(value *big.Int) (c []byte, err error) {
	// c = g^m h^{\alpha}
	alpha, err := rand.Int(rand.Reader, elliptic.P256().Params().N)
	if err != nil {
		return nil, err
	}
	g_m := p256Utils.ScalarBaseMult(value)
	h_alpha := p256Utils.ScalarMult(p256Utils.ComputeH(), alpha)
	commitment := p256Utils.ScalarAdd(g_m, h_alpha)
	c = p256Utils.Marshal(commitment)
	return c, nil
}

/**
	计算向量的Pedersen承诺
 */
func ComputeVecCommitmentBytes(values []*big.Int) (c []byte, err error) {
	n := len(values)
	gs, hs := p256Utils.ComputeGAndHVec(n)
	zero := new(big.Int).SetInt64(0)
	commitment := &p256Utils.CurvePoint{
		elliptic.P256(), zero, zero,
	}
	for i := 0; i < n; i++ {
		alphai, err := rand.Int(rand.Reader, elliptic.P256().Params().N)
		if err != nil {
			return nil, err
		}
		gi_m := p256Utils.ScalarMult(gs[i], values[i])
		hi_alpha := p256Utils.ScalarMult(hs[i], alphai)
		commitment_i := p256Utils.ScalarAdd(gi_m, hi_alpha)
		commitment = p256Utils.ScalarAdd(commitment, commitment_i)
	}
	c = p256Utils.Marshal(commitment)
	return c, nil
}

/**
	计算Pedersen Commitment并转换为字符串
 */
func ComputeVecCommitmentStr(values []*big.Int) (c string, err error) {
	cBytes, err := ComputeVecCommitmentBytes(values)
	if err != nil {
		return "", err
	}
	c = hex.EncodeToString(cBytes)
	return c, nil
}
