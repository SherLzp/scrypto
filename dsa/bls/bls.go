package bls

import (
	"crypto/sha256"
	"math/big"
	"scrypto/ecc/bls381Utils"
	"scrypto/sutils"
)

func GenerateKeyPair() (k *big.Int, K *bls381Utils.G2, err error) {
	// (sk,pk) = (k,K = g_2^{x})
	return bls381Utils.RandomG2()
}

func G1Hash(message []byte) (h *bls381Utils.G1, err error) {
	mhash, err := sutils.GetHashValue(message, sha256.New)
	if err != nil {
		return nil, err
	}
	r := new(big.Int).SetBytes(mhash)
	h = bls381Utils.G1ScalarBaseMult(r)
	return h, nil
}

func Sign(k *big.Int, message []byte) (delta *bls381Utils.G1, err error) {
	// h = H(m)
	h, err := G1Hash(message)
	if err != nil {
		return nil, err
	}
	// \delta = h^{k}
	delta = bls381Utils.G1ScalarMult(h, k)
	return delta, nil
}

func Verify(K *bls381Utils.G2, message []byte, delta *bls381Utils.G1) bool {
	h, err := G1Hash(message)
	if err != nil {
		return false
	}
	// e(\delta, g_2) = e(h,K)
	p1 := bls381Utils.BLSPair(delta, &bls381Utils.BaseG2)
	p2 := bls381Utils.BLSPair(h, K)
	return p1.Equal(p2)
}
