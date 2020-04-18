// Most algos for points operations are taken from http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html

package bls381

import (
	"runtime"
	"sync"

	"shercrypto/ecc/bls381/fr"
	"shercrypto/ecc/internal/debug"
	"shercrypto/ecc/internal/pool"
)

// G2Jac is a point with e2 coordinates
type G2Jac struct {
	X, Y, Z e2
}

// G2Affine point in affine coordinates
type G2Affine struct {
	X, Y e2
}

// Set set p to the provided point
func (p *G2Jac) Set(a *G2Jac) *G2Jac {
	p.X.Set(&a.X)
	p.Y.Set(&a.Y)
	p.Z.Set(&a.Z)
	return p
}

// Equal tests if two points (in Jacobian coordinates) are equal
func (p *G2Jac) Equal(a *G2Jac) bool {

	if p.Z.IsZero() && a.Z.IsZero() {
		return true
	}
	_p := G2Affine{}
	p.ToAffineFromJac(&_p)

	_a := G2Affine{}
	a.ToAffineFromJac(&_a)

	return _p.X.Equal(&_a.X) && _p.Y.Equal(&_a.Y)
}

// Equal tests if two points (in Affine coordinates) are equal
func (p *G2Affine) Equal(a *G2Affine) bool {
	return p.X.Equal(&a.X) && p.Y.Equal(&a.Y)
}

// Clone returns a copy of self
func (p *G2Jac) Clone() *G2Jac {
	return &G2Jac{
		p.X, p.Y, p.Z,
	}
}

// Neg computes -G
func (p *G2Jac) Neg(a *G2Jac) *G2Jac {
	p.Set(a)
	p.Y.Neg(&a.Y)
	return p
}

// Neg computes -G
func (p *G2Affine) Neg(a *G2Affine) *G2Affine {
	p.X.Set(&a.X)
	p.Y.Neg(&a.Y)
	return p
}

// Sub substracts two points on the curve
func (p *G2Jac) Sub(curve *Curve, a G2Jac) *G2Jac {
	a.Y.Neg(&a.Y)
	p.Add(curve, &a)
	return p
}

// ToAffineFromJac rescale a point in Jacobian coord in z=1 plane
// WARNING super slow function (due to the division)
func (p *G2Jac) ToAffineFromJac(res *G2Affine) *G2Affine {

	var bufs [3]e2

	if p.Z.IsZero() {
		res.X.SetZero()
		res.Y.SetZero()
		return res
	}

	bufs[0].Inverse(&p.Z)
	bufs[2].Square(&bufs[0])
	bufs[1].Mul(&bufs[2], &bufs[0])

	res.Y.Mul(&p.Y, &bufs[1])
	res.X.Mul(&p.X, &bufs[2])

	return res
}

// ToProjFromJac converts a point from Jacobian to projective coordinates
func (p *G2Jac) ToProjFromJac() *G2Jac {
	// memalloc
	var buf e2
	buf.Square(&p.Z)

	p.X.Mul(&p.X, &p.Z)
	p.Z.Mul(&p.Z, &buf)

	return p
}

func (p *G2Jac) String(curve *Curve) string {
	if p.Z.IsZero() {
		return "O"
	}
	_p := G2Affine{}
	p.ToAffineFromJac(&_p)
	_p.X.FromMont()
	_p.Y.FromMont()
	return "E([" + _p.X.String() + "," + _p.Y.String() + "]),"
}

// ToJacobian sets Q = p, Q in Jacboian, p in affine
func (p *G2Affine) ToJacobian(Q *G2Jac) *G2Jac {
	if p.X.IsZero() && p.Y.IsZero() {
		Q.Z.SetZero()
		Q.X.SetOne()
		Q.Y.SetOne()
		return Q
	}
	Q.Z.SetOne()
	Q.X.Set(&p.X)
	Q.Y.Set(&p.Y)
	return Q
}

func (p *G2Affine) String(curve *Curve) string {
	var x, y e2
	x.Set(&p.X)
	y.Set(&p.Y)
	return "E([" + x.FromMont().String() + "," + y.FromMont().String() + "]),"
}

// IsInfinity checks if the point is infinity (in affine, it's encoded as (0,0))
func (p *G2Affine) IsInfinity() bool {
	return p.X.IsZero() && p.Y.IsZero()
}

// Add point addition in montgomery form
// no assumptions on z
// Note: calling Add with p.Equal(a) produces [0, 0, 0], call p.Double() instead
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
func (p *G2Jac) Add(curve *Curve, a *G2Jac) *G2Jac {
	// p is infinity, return a
	if p.Z.IsZero() {
		p.Set(a)
		return p
	}

	// a is infinity, return p
	if a.Z.IsZero() {
		return p
	}

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V e2

	// Z1Z1 = a.Z ^ 2
	Z1Z1.Square(&a.Z)

	// Z2Z2 = p.Z ^ 2
	Z2Z2.Square(&p.Z)

	// U1 = a.X * Z2Z2
	U1.Mul(&a.X, &Z2Z2)

	// U2 = p.X * Z1Z1
	U2.Mul(&p.X, &Z1Z1)

	// S1 = a.Y * p.Z * Z2Z2
	S1.Mul(&a.Y, &p.Z).
		MulAssign(&Z2Z2)

	// S2 = p.Y * a.Z * Z1Z1
	S2.Mul(&p.Y, &a.Z).
		MulAssign(&Z1Z1)

	// if p == a, we double instead
	if U1.Equal(&U2) && S1.Equal(&S2) {
		return p.Double()
	}

	// H = U2 - U1
	H.Sub(&U2, &U1)

	// I = (2*H)^2
	I.Double(&H).
		Square(&I)

	// J = H*I
	J.Mul(&H, &I)

	// r = 2*(S2-S1)
	r.Sub(&S2, &S1).Double(&r)

	// V = U1*I
	V.Mul(&U1, &I)

	// res.X = r^2-J-2*V
	p.X.Square(&r).
		SubAssign(&J).
		SubAssign(&V).
		SubAssign(&V)

	// res.Y = r*(V-X3)-2*S1*J
	p.Y.Sub(&V, &p.X).
		MulAssign(&r)
	S1.MulAssign(&J).Double(&S1)
	p.Y.SubAssign(&S1)

	// res.Z = ((a.Z+p.Z)^2-Z1Z1-Z2Z2)*H
	p.Z.AddAssign(&a.Z)
	p.Z.Square(&p.Z).
		SubAssign(&Z1Z1).
		SubAssign(&Z2Z2).
		MulAssign(&H)

	return p
}

// AddMixed point addition in montgomery form
// assumes a is in affine coordinates (i.e a.z == 1)
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
func (p *G2Jac) AddMixed(a *G2Affine) *G2Jac {

	//if a is infinity return p
	if a.X.IsZero() && a.Y.IsZero() {
		return p
	}
	// p is infinity, return a
	if p.Z.IsZero() {
		p.X = a.X
		p.Y = a.Y
		// p.Z.Set(&curve.g2sZero.X)
		p.Z.SetOne()
		return p
	}

	// get some Element from our pool
	var Z1Z1, U2, S2, H, HH, I, J, r, V e2

	// Z1Z1 = p.Z ^ 2
	Z1Z1.Square(&p.Z)

	// U2 = a.X * Z1Z1
	U2.Mul(&a.X, &Z1Z1)

	// S2 = a.Y * p.Z * Z1Z1
	S2.Mul(&a.Y, &p.Z).
		MulAssign(&Z1Z1)

	// if p == a, we double instead
	if U2.Equal(&p.X) && S2.Equal(&p.Y) {
		return p.Double()
	}

	// H = U2 - p.X
	H.Sub(&U2, &p.X)
	HH.Square(&H)

	// I = 4*HH
	I.Double(&HH).Double(&I)

	// J = H*I
	J.Mul(&H, &I)

	// r = 2*(S2-Y1)
	r.Sub(&S2, &p.Y).Double(&r)

	// V = X1*I
	V.Mul(&p.X, &I)

	// res.X = r^2-J-2*V
	p.X.Square(&r).
		SubAssign(&J).
		SubAssign(&V).
		SubAssign(&V)

	// res.Y = r*(V-X3)-2*Y1*J
	J.MulAssign(&p.Y).Double(&J)
	p.Y.Sub(&V, &p.X).
		MulAssign(&r)
	p.Y.SubAssign(&J)

	// res.Z =  (p.Z+H)^2-Z1Z1-HH
	p.Z.AddAssign(&H)
	p.Z.Square(&p.Z).
		SubAssign(&Z1Z1).
		SubAssign(&HH)

	return p
}

// Double doubles a point in Jacobian coordinates
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2007-bl
func (p *G2Jac) Double() *G2Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T e2

	// XX = a.X^2
	XX.Square(&p.X)

	// YY = a.Y^2
	YY.Square(&p.Y)

	// YYYY = YY^2
	YYYY.Square(&YY)

	// ZZ = Z1^2
	ZZ.Square(&p.Z)

	// S = 2*((X1+YY)^2-XX-YYYY)
	S.Add(&p.X, &YY)
	S.Square(&S).
		SubAssign(&XX).
		SubAssign(&YYYY).
		Double(&S)

	// M = 3*XX+a*ZZ^2
	M.Double(&XX).AddAssign(&XX)

	// res.Z = (Y1+Z1)^2-YY-ZZ
	p.Z.AddAssign(&p.Y).
		Square(&p.Z).
		SubAssign(&YY).
		SubAssign(&ZZ)

	// T = M2-2*S && res.X = T
	T.Square(&M)
	p.X = T
	T.Double(&S)
	p.X.SubAssign(&T)

	// res.Y = M*(S-T)-8*YYYY
	p.Y.Sub(&S, &p.X).
		MulAssign(&M)
	YYYY.Double(&YYYY).Double(&YYYY).Double(&YYYY)
	p.Y.SubAssign(&YYYY)

	return p
}

// ScalarMul multiplies a by scalar
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *G2Jac) ScalarMul(curve *Curve, a *G2Jac, scalar fr.Element) *G2Jac {
	// see MultiExp and pippenger documentation for more details about these constants / variables
	const s = 4
	const b = s
	const TSize = (1 << b) - 1
	var T [TSize]G2Jac
	computeT := func(T []G2Jac, t0 *G2Jac) {
		T[0].Set(t0)
		for j := 1; j < (1<<b)-1; j = j + 2 {
			T[j].Set(&T[j/2]).Double()
			T[j+1].Set(&T[(j+1)/2]).Add(curve, &T[j/2])
		}
	}
	return p.pippenger(curve, []G2Jac{*a}, []fr.Element{scalar}, s, b, T[:], computeT)
}

// ScalarMulByGen multiplies curve.g2Gen by scalar
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *G2Jac) ScalarMulByGen(curve *Curve, scalar fr.Element) *G2Jac {
	computeT := func(T []G2Jac, t0 *G2Jac) {}
	return p.pippenger(curve, []G2Jac{curve.g2Gen}, []fr.Element{scalar}, sGen, bGen, curve.tGenG2[:], computeT)
}

func (p *G2Jac) MultiExp(curve *Curve, points []G2Affine, scalars []fr.Element) chan G2Jac {
	debug.Assert(len(scalars) == len(points))
	chRes := make(chan G2Jac, 1)
	// call windowed multi exp if input not large enough
	// we may want to force the API user to call the proper method in the first place
	const minPoints = 50 // under 50 points, the windowed multi exp performs better
	if len(scalars) <= minPoints {
		_points := make([]G2Jac, len(points))
		for i := 0; i < len(points); i++ {
			points[i].ToJacobian(&_points[i])
		}
		go func() {
			p.WindowedMultiExp(curve, _points, scalars)
			chRes <- *p
		}()
		return chRes

	}
	// compute nbCalls and nbPointsPerBucket as a function of available CPUs
	const chunkSize = 64
	const totalSize = chunkSize * fr.ElementLimbs
	var nbBits, nbCalls uint64
	nbPoints := len(scalars)
	nbPointsPerBucket := 20 // empirical parameter to chose nbBits
	// set nbBbits and nbCalls
	nbBits = 0
	for len(scalars)/(1<<nbBits) >= nbPointsPerBucket {
		nbBits++
	}
	nbCalls = totalSize / nbBits
	if totalSize%nbBits > 0 {
		nbCalls++
	}
	const useAllCpus = false
	// if we need to use all CPUs
	if useAllCpus {
		nbCpus := uint64(runtime.NumCPU())
		// goal here is to have at least as many calls as number of go routine we're allowed to spawn
		for nbCalls < nbCpus && nbPointsPerBucket < nbPoints {
			nbBits = 0
			for len(scalars)/(1<<nbBits) >= nbPointsPerBucket {
				nbBits++
			}
			nbCalls = totalSize / nbBits
			if totalSize%nbBits > 0 {
				nbCalls++
			}
			nbPointsPerBucket *= 2
		}
	}

	// result (1 per go routine)
	tmpRes := make([]G2Jac, nbCalls)
	work := func(iStart, iEnd int) {
		chunks := make([]uint64, nbBits)
		offsets := make([]uint64, nbBits)
		for i := uint64(iStart); i < uint64(iEnd); i++ {
			start := i * nbBits
			debug.Assert(start != totalSize)
			var counter uint64
			for j := start; counter < nbBits && (j < totalSize); j++ {
				chunks[counter] = j / chunkSize
				offsets[counter] = j % chunkSize
				counter++
			}
			c := 1 << counter
			buckets := make([]G2Jac, c-1)
			for j := 0; j < c-1; j++ {
				buckets[j].X.SetOne()
				buckets[j].Y.SetOne()
			}
			var l uint64
			for j := 0; j < nbPoints; j++ {
				var index uint64
				for k := uint64(0); k < counter; k++ {
					l = scalars[j][chunks[k]] >> offsets[k]
					l &= 1
					l <<= k
					index += l
				}
				if index != 0 {
					buckets[index-1].AddMixed(&points[j])
				}
			}
			sum := curve.g2Infinity
			for j := len(buckets) - 1; j >= 0; j-- {
				sum.Add(curve, &buckets[j])
				tmpRes[i].Add(curve, &sum)
			}
		}
	}
	chDone := pool.ExecuteAsync(0, len(tmpRes), work, false)
	go func() {
		<-chDone // that's making a "go routine" in the pool block, uncool
		p.Set(&curve.g2Infinity)
		for i := len(tmpRes) - 1; i >= 0; i-- {
			for j := uint64(0); j < nbBits; j++ {
				p.Double()
			}
			p.Add(curve, &tmpRes[i])
		}
		chRes <- *p
	}()
	return chRes
}

// MultiExp set p = scalars[0]*points[0] + ... + scalars[n]*points[n]
// see: https://eprint.iacr.org/2012/549.pdf
// if maxGoRoutine is not provided, uses all available CPUs
func (p *G2Jac) MultiExpNew(curve *Curve, points []G2Affine, scalars []fr.Element) chan G2Jac {
	debug.Assert(len(scalars) == len(points))
	chRes := make(chan G2Jac, 1)
	// call windowed multi exp if input not large enough
	// we may want to force the API user to call the proper method in the first place
	const minPoints = 50 // under 50 points, the windowed multi exp performs better
	if len(scalars) <= minPoints {
		_points := make([]G2Jac, len(points))
		for i := 0; i < len(points); i++ {
			points[i].ToJacobian(&_points[i])
		}
		go func() {
			p.WindowedMultiExp(curve, _points, scalars)
			chRes <- *p
		}()
		return chRes
	}
	// if we have m points and n cpus, m/n points per cpu
	nbCpus := runtime.NumCPU()
	// nb points processed by one cpu
	pointsPerCPU := len(scalars) / nbCpus
	// each cpu has its own bucket
	sharedBuckets := make([][32][255]G2Jac, nbCpus)
	// bucket to gather cpus work
	var commonBucket [32][255]G2Jac
	var emptyBucket [255]G2Jac
	var almostThere [32]G2Jac
	for i := 0; i < 255; i++ {
		emptyBucket[i].Set(&curve.g2Infinity)
	}

	const mask = 255
	// id: cpu id, start, end: point nb start to point nb end, chunk: i-th digit (in corresponding basis)
	worker := func(id, start, end int) {
		// ...[chunk*8..(chunk+1)*8-1]... -th bits
		for chunk := 0; chunk < 32; chunk++ {
			limb := chunk / 8
			offset := (chunk % 8) * 8
			sharedBuckets[id][chunk] = emptyBucket
			var index uint64
			for i := start; i < end; i++ {
				index = (scalars[i][limb] >> uint64(offset))
				index &= mask
				if index != 0 {
					sharedBuckets[id][chunk][index-1].AddMixed(&points[i])
				}
			}
		}
	}
	var wg sync.WaitGroup

	// each cpu works on a small part of the bucket
	for j := 0; j < nbCpus; j++ {
		var nextStart, nextEnd int
		nextStart = j * pointsPerCPU
		if j < nbCpus-1 {
			nextEnd = nextStart + pointsPerCPU
		} else {
			nextEnd = len(scalars)
		}
		_j := j
		wg.Add(1)
		pool.Push(func() {
			worker(_j, nextStart, nextEnd)
			wg.Done()
		}, false)
	}
	go func() {
		for i := 0; i < 32; i++ {
			// initialize the common bucket for the current chunk
			commonBucket[i] = emptyBucket
		}
		copy(almostThere[:], emptyBucket[:])
		wg.Wait()
		// ...[chunk*8..(chunk+1)*8-1]... -th bits
		for i := 0; i < 32; i++ {
			// fill the i-th chunk of the common bucket by gathering cpus work
			for j := 0; j < 255; j++ {
				for k := 0; k < nbCpus; k++ {
					commonBucket[i][j].Add(curve, &sharedBuckets[k][i][j])
				}
			}
		}

		// ...[chunk*8..(chunk+1)*8-1]... -th bits
		var acc G2Jac
		for i := 0; i < 32; i++ {
			acc.Set(&curve.g2Infinity)
			for j := 254; j >= 0; j-- {
				acc.Add(curve, &commonBucket[i][j])
				almostThere[i].Add(curve, &acc)
			}
		}

		// double and add to compute p
		p.Set(&curve.g2Infinity)
		for i := 31; i >= 0; i-- {
			for j := 0; j < 8; j++ {
				p.Double()
			}
			p.Add(curve, &almostThere[i])
		}
		chRes <- *p
	}()

	return chRes
}

// WindowedMultiExp set p = scalars[0]*points[0] + ... + scalars[n]*points[n]
// assume: scalars in non-Montgomery form!
// assume: len(points)==len(scalars)>0, len(scalars[i]) equal for all i
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
// uses all availables runtime.NumCPU()
func (p *G2Jac) WindowedMultiExp(curve *Curve, points []G2Jac, scalars []fr.Element) *G2Jac {
	var lock sync.Mutex
	pool.Execute(0, len(points), func(start, end int) {
		var t G2Jac
		t.multiExp(curve, points[start:end], scalars[start:end])
		lock.Lock()
		p.Add(curve, &t)
		lock.Unlock()
	}, false)
	return p
}

// multiExp set p = scalars[0]*points[0] + ... + scalars[n]*points[n]
// assume: scalars in non-Montgomery form!
// assume: len(points)==len(scalars)>0, len(scalars[i]) equal for all i
// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *G2Jac) multiExp(curve *Curve, points []G2Jac, scalars []fr.Element) *G2Jac {
	const s = 4 // s from Bootle, we choose s divisible by scalar bit length
	const b = s // b from Bootle, we choose b equal to s
	// WARNING! This code breaks if you switch to b!=s
	// Because we chose b=s, each set S_i from Bootle is simply the set of points[i]^{2^j} for each j in [0:s]
	// This choice allows for simpler code
	// If you want to use b!=s then the S_i from Bootle are different
	const TSize = (1 << b) - 1 // TSize is size of T_i sets from Bootle, equal to 2^b - 1
	// Store only one set T_i at a time---don't store them all!
	var T [TSize]G2Jac // a set T_i from Bootle, the set of g^j for j in [1:2^b] for some choice of g
	computeT := func(T []G2Jac, t0 *G2Jac) {
		T[0].Set(t0)
		for j := 1; j < (1<<b)-1; j = j + 2 {
			T[j].Set(&T[j/2]).Double()
			T[j+1].Set(&T[(j+1)/2]).Add(curve, &T[j/2])
		}
	}
	return p.pippenger(curve, points, scalars, s, b, T[:], computeT)
}

// algorithm: a special case of Pippenger described by Bootle:
// https://jbootle.github.io/Misc/pippenger.pdf
func (p *G2Jac) pippenger(curve *Curve, points []G2Jac, scalars []fr.Element, s, b uint64, T []G2Jac, computeT func(T []G2Jac, t0 *G2Jac)) *G2Jac {
	var t, selectorIndex, ks int
	var selectorMask, selectorShift, selector uint64

	t = fr.ElementLimbs * 64 / int(s) // t from Bootle, equal to (scalar bit length) / s
	selectorMask = (1 << b) - 1       // low b bits are 1
	morePoints := make([]G2Jac, t)    // morePoints is the set of G'_k points from Bootle
	for k := 0; k < t; k++ {
		morePoints[k].Set(&curve.g2Infinity)
	}
	for i := 0; i < len(points); i++ {
		// compute the set T_i from Bootle: all possible combinations of elements from S_i from Bootle
		computeT(T, &points[i])
		// for each morePoints: find the right T element and add it
		for k := 0; k < t; k++ {
			ks = k * int(s)
			selectorIndex = ks / 64
			selectorShift = uint64(ks - (selectorIndex * 64))
			selector = (scalars[i][selectorIndex] & (selectorMask << selectorShift)) >> selectorShift
			if selector != 0 {
				morePoints[k].Add(curve, &T[selector-1])
			}
		}
	}
	// combine morePoints to get the final result
	p.Set(&morePoints[t-1])
	for k := t - 2; k >= 0; k-- {
		for j := uint64(0); j < s; j++ {
			p.Double()
		}
		p.Add(curve, &morePoints[k])
	}
	return p
}
