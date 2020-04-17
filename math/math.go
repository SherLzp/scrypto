package math

import "math/big"

func Add(a, b, N *big.Int) (res *big.Int) {
	res = new(big.Int).Add(a, b)
	res.Mod(res, N)
	return res
}

func Sub(a, b, N *big.Int) (res *big.Int) {
	res = new(big.Int).Sub(a, b)
	res.Mod(res, N)
	return res
}

func Mul(a, b, N *big.Int) (res *big.Int) {
	res = new(big.Int).Mul(a, b)
	res.Mod(res, N)
	return res
}

func ModInverse(a, N *big.Int) (res *big.Int) {
	res = new(big.Int).ModInverse(a, N)
	return res
}

func Neg(a *big.Int) (res *big.Int) {
	return new(big.Int).Neg(a)
}
