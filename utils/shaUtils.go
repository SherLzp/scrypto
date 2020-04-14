package utils

import "crypto/sha256"

func Sha3Hash(m []byte) (hash []byte, err error) {
	sha := sha256.New()
	_, err = sha.Write(m)
	if err != nil {
		return nil, err
	}
	return sha.Sum(nil), nil
}
