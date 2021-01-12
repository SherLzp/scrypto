package ouEnc

import (
	"crypto/rand"
	"math/big"
)

type OUKeyPair struct {
	Sk *OUSk `json:"sk"`
	Pk *OUPk `json:"pk"`
}

type OUSk struct {
	P, Q *big.Int
}

type OUPk struct {
	N, G *big.Int
}

var (
	ONE = big.NewInt(1)
)

func KeyGen(k int) (keyPair *OUKeyPair, err error) {
	p, err := rand.Prime(rand.Reader, k)
	q, err := rand.Prime(rand.Reader, k)
	if err != nil {
		return nil, err
	}
	pSquare := new(big.Int).Mul(p, p)
	n := new(big.Int).Mul(pSquare, q)
	var g *big.Int
	pSubOne := new(big.Int).Sub(p, ONE)
	lowBound := new(big.Int).Div(n, big.NewInt(2))
	for {
		g, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}
		if g.Cmp(lowBound) < 0 {
			continue
		}
		temp := new(big.Int).Exp(g, pSubOne, pSquare)
		if temp.Cmp(ONE) != 0 {
			break
		}
	}
	return &OUKeyPair{Sk: &OUSk{p, q}, Pk: &OUPk{n, g}}, nil
}

func Enc(pk OUPk, m *big.Int) (c *big.Int, err error) {
	n, g := new(big.Int).Set(pk.N), new(big.Int).Set(pk.G)
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, err
	}
	nMulR := r.Mul(n, r)
	c = new(big.Int).Exp(g, m.Add(m, nMulR), n)
	return c, nil
}

func Dec(sk OUSk, pk OUPk, c *big.Int) (m *big.Int, err error) {
	p := new(big.Int).Set(sk.P)
	g := new(big.Int).Set(pk.G)
	pSubOne, pSquare := new(big.Int), new(big.Int)
	pSubOne.Sub(p, new(big.Int).SetInt64(1))
	pSquare.Mul(p, p)
	one := new(big.Int).SetInt64(1)
	a := new(big.Int).Exp(c, pSubOne, pSquare)
	a = new(big.Int).Sub(a, one)
	a = new(big.Int).Div(a, p)
	a = new(big.Int).Mod(a, p)
	b := new(big.Int).Exp(g, pSubOne, pSquare)
	b = new(big.Int).Sub(b, one)
	b = new(big.Int).Div(b, p)
	b = new(big.Int).Mod(b, p)
	bPrime := new(big.Int).ModInverse(b, p)
	m = new(big.Int).Mul(a, bPrime)
	m = new(big.Int).Mod(m, p)
	return m, nil
}

func TryOnce() {
	keyPair, err := KeyGen(256)
	if err != nil {
		panic(err)
	}
	//keyPair := OUKeyPair{Sk: &OUSk{P: new(big.Int).SetInt64(3), Q: new(big.Int).SetInt64(5)}, Pk: &OUPk{N: new(big.Int).SetInt64(45), G: new(big.Int).SetInt64(22), H: new(big.Int).SetInt64(37)}}
	c1, err := Enc(*keyPair.Pk, big.NewInt(100))
	c2, err := Enc(*keyPair.Pk, big.NewInt(200))
	if err != nil {
		panic(err)
	}
	c1c2 := new(big.Int).Mul(c1, c2)
	m, err := Dec(*keyPair.Sk, *keyPair.Pk, c1c2)
	if err != nil {
		panic(err)
	}
	println("plain text:", m.String())
}
