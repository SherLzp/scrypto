package bls381

import (
	"math/bits"

	"shercrypto/ecc/bls381/fp"
)

// e12 is a degree-two finite field extension of fp6:
// C0 + C1w where w^3-v is irrep in fp6

// fp2, fp12 are both quadratic field extensions
// template code is duplicated in fp2, fp12
// TODO make an abstract quadratic extension template

type e12 struct {
	C0, C1 e6
}

// Equal compares two e12 elements
// TODO can this be deleted?
func (z *e12) Equal(x *e12) bool {
	return z.C0.Equal(&x.C0) && z.C1.Equal(&x.C1)
}

// String puts e12 in string form
func (z *e12) String() string {
	return (z.C0.String() + "+(" + z.C1.String() + ")*w")
}

// SetString sets a e12 from string
func (z *e12) SetString(s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11 string) *e12 {
	z.C0.SetString(s0, s1, s2, s3, s4, s5)
	z.C1.SetString(s6, s7, s8, s9, s10, s11)
	return z
}

// Set copies x into z and returns z
func (z *e12) Set(x *e12) *e12 {
	z.C0 = x.C0
	z.C1 = x.C1
	return z
}

// SetOne sets z to 1 in e12 in Montgomery form and returns z
func (z *e12) SetOne() *e12 {
	z.C0.B0.A0.SetOne()
	z.C0.B0.A1.SetZero()
	z.C0.B1.A0.SetZero()
	z.C0.B1.A1.SetZero()
	z.C0.B2.A0.SetZero()
	z.C0.B2.A1.SetZero()
	z.C1.B0.A0.SetZero()
	z.C1.B0.A1.SetZero()
	z.C1.B1.A0.SetZero()
	z.C1.B1.A1.SetZero()
	z.C1.B2.A0.SetZero()
	z.C1.B2.A1.SetZero()
	return z
}

// ToMont converts to Mont form
// TODO can this be deleted?
func (z *e12) ToMont() *e12 {
	z.C0.ToMont()
	z.C1.ToMont()
	return z
}

// FromMont converts from Mont form
// TODO can this be deleted?
func (z *e12) FromMont() *e12 {
	z.C0.FromMont()
	z.C1.FromMont()
	return z
}

// Add set z=x+y in e12 and return z
func (z *e12) Add(x, y *e12) *e12 {
	z.C0.Add(&x.C0, &y.C0)
	z.C1.Add(&x.C1, &y.C1)
	return z
}

// Sub set z=x-y in e12 and return z
func (z *e12) Sub(x, y *e12) *e12 {
	z.C0.Sub(&x.C0, &y.C0)
	z.C1.Sub(&x.C1, &y.C1)
	return z
}

// SetRandom used only in tests
// TODO eliminate this method!
func (z *e12) SetRandom() *e12 {
	z.C0.B0.A0.SetRandom()
	z.C0.B0.A1.SetRandom()
	z.C0.B1.A0.SetRandom()
	z.C0.B1.A1.SetRandom()
	z.C0.B2.A0.SetRandom()
	z.C0.B2.A1.SetRandom()
	z.C1.B0.A0.SetRandom()
	z.C1.B0.A1.SetRandom()
	z.C1.B1.A0.SetRandom()
	z.C1.B1.A1.SetRandom()
	z.C1.B2.A0.SetRandom()
	z.C1.B2.A1.SetRandom()
	return z
}

// Mul set z=x*y in e12 and return z
func (z *e12) Mul(x, y *e12) *e12 {
	// Algorithm 20 from https://eprint.iacr.org/2010/354.pdf

	var t0, t1, xSum, ySum e6

	t0.Mul(&x.C0, &y.C0) // step 1
	t1.Mul(&x.C1, &y.C1) // step 2

	// finish processing input in case z==x or y
	xSum.Add(&x.C0, &x.C1)
	ySum.Add(&y.C0, &y.C1)

	// step 3
	{ // begin: inline z.C0.MulByNonResidue(&t1)
		var result e6
		result.B1.Set(&(&t1).B0)
		result.B2.Set(&(&t1).B1)
		{ // begin: inline result.B0.MulByNonResidue(&(&t1).B2)
			var buf e2
			buf.Set(&(&t1).B2)
			result.B0.A1.Add(&buf.A0, &buf.A1)
			{ // begin: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
				(&(result.B0).A0).Neg(&buf.A1)
			} // end: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
			result.B0.A0.AddAssign(&buf.A0)
		} // end: inline result.B0.MulByNonResidue(&(&t1).B2)
		z.C0.Set(&result)
	} // end: inline z.C0.MulByNonResidue(&t1)
	z.C0.Add(&z.C0, &t0)

	// step 4
	z.C1.Mul(&xSum, &ySum).
		Sub(&z.C1, &t0).
		Sub(&z.C1, &t1)

	return z
}

// Square set z=x*x in e12 and return z
func (z *e12) Square(x *e12) *e12 {
	// TODO implement Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	// or the complex method from fp2
	// for now do it the dumb way
	var b0, b1 e6

	b0.Square(&x.C0)
	b1.Square(&x.C1)
	{ // begin: inline b1.MulByNonResidue(&b1)
		var result e6
		result.B1.Set(&(&b1).B0)
		result.B2.Set(&(&b1).B1)
		{ // begin: inline result.B0.MulByNonResidue(&(&b1).B2)
			var buf e2
			buf.Set(&(&b1).B2)
			result.B0.A1.Add(&buf.A0, &buf.A1)
			{ // begin: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
				(&(result.B0).A0).Neg(&buf.A1)
			} // end: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
			result.B0.A0.AddAssign(&buf.A0)
		} // end: inline result.B0.MulByNonResidue(&(&b1).B2)
		b1.Set(&result)
	} // end: inline b1.MulByNonResidue(&b1)
	b1.Add(&b0, &b1)

	z.C1.Mul(&x.C0, &x.C1).Double(&z.C1)
	z.C0 = b1

	return z
}

// Inverse set z to the inverse of x in e12 and return z
func (z *e12) Inverse(x *e12) *e12 {
	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	var t [2]e6

	t[0].Square(&x.C0) // step 1
	t[1].Square(&x.C1) // step 2
	{ // step 3
		var buf e6
		{ // begin: inline buf.MulByNonResidue(&t[1])
			var result e6
			result.B1.Set(&(&t[1]).B0)
			result.B2.Set(&(&t[1]).B1)
			{ // begin: inline result.B0.MulByNonResidue(&(&t[1]).B2)
				var buf e2
				buf.Set(&(&t[1]).B2)
				result.B0.A1.Add(&buf.A0, &buf.A1)
				{ // begin: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
					(&(result.B0).A0).Neg(&buf.A1)
				} // end: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
				result.B0.A0.AddAssign(&buf.A0)
			} // end: inline result.B0.MulByNonResidue(&(&t[1]).B2)
			buf.Set(&result)
		} // end: inline buf.MulByNonResidue(&t[1])
		t[0].Sub(&t[0], &buf)
	}
	t[1].Inverse(&t[0])               // step 4
	z.C0.Mul(&x.C0, &t[1])            // step 5
	z.C1.Mul(&x.C1, &t[1]).Neg(&z.C1) // step 6

	return z
}

// InverseUnitary inverse a unitary element
// TODO deprecate in favour of Conjugate
func (z *e12) InverseUnitary(x *e12) *e12 {
	return z.Conjugate(x)
}

// Conjugate set z to (x.C0, -x.C1) and return z
func (z *e12) Conjugate(x *e12) *e12 {
	z.Set(x)
	z.C1.Neg(&z.C1)
	return z
}

// MulByVW set z to x*(y*v*w) and return z
// here y*v*w means the e12 element with C1.B1=y and all other components 0
func (z *e12) MulByVW(x *e12, y *e2) *e12 {
	var result e12
	var yNR e2

	{ // begin: inline yNR.MulByNonResidue(y)
		var buf e2
		buf.Set(y)
		yNR.A1.Add(&buf.A0, &buf.A1)
		{ // begin: inline MulByNonResidue(&(yNR).A0, &buf.A1)
			(&(yNR).A0).Neg(&buf.A1)
		} // end: inline MulByNonResidue(&(yNR).A0, &buf.A1)
		yNR.A0.AddAssign(&buf.A0)
	} // end: inline yNR.MulByNonResidue(y)
	result.C0.B0.Mul(&x.C1.B1, &yNR)
	result.C0.B1.Mul(&x.C1.B2, &yNR)
	result.C0.B2.Mul(&x.C1.B0, y)
	result.C1.B0.Mul(&x.C0.B2, &yNR)
	result.C1.B1.Mul(&x.C0.B0, y)
	result.C1.B2.Mul(&x.C0.B1, y)
	z.Set(&result)
	return z
}

// MulByV set z to x*(y*v) and return z
// here y*v means the e12 element with C0.B1=y and all other components 0
func (z *e12) MulByV(x *e12, y *e2) *e12 {
	var result e12
	var yNR e2

	{ // begin: inline yNR.MulByNonResidue(y)
		var buf e2
		buf.Set(y)
		yNR.A1.Add(&buf.A0, &buf.A1)
		{ // begin: inline MulByNonResidue(&(yNR).A0, &buf.A1)
			(&(yNR).A0).Neg(&buf.A1)
		} // end: inline MulByNonResidue(&(yNR).A0, &buf.A1)
		yNR.A0.AddAssign(&buf.A0)
	} // end: inline yNR.MulByNonResidue(y)
	result.C0.B0.Mul(&x.C0.B2, &yNR)
	result.C0.B1.Mul(&x.C0.B0, y)
	result.C0.B2.Mul(&x.C0.B1, y)
	result.C1.B0.Mul(&x.C1.B2, &yNR)
	result.C1.B1.Mul(&x.C1.B0, y)
	result.C1.B2.Mul(&x.C1.B1, y)
	z.Set(&result)
	return z
}

// MulByV2W set z to x*(y*v^2*w) and return z
// here y*v^2*w means the e12 element with C1.B2=y and all other components 0
func (z *e12) MulByV2W(x *e12, y *e2) *e12 {
	var result e12
	var yNR e2

	{ // begin: inline yNR.MulByNonResidue(y)
		var buf e2
		buf.Set(y)
		yNR.A1.Add(&buf.A0, &buf.A1)
		{ // begin: inline MulByNonResidue(&(yNR).A0, &buf.A1)
			(&(yNR).A0).Neg(&buf.A1)
		} // end: inline MulByNonResidue(&(yNR).A0, &buf.A1)
		yNR.A0.AddAssign(&buf.A0)
	} // end: inline yNR.MulByNonResidue(y)
	result.C0.B0.Mul(&x.C1.B0, &yNR)
	result.C0.B1.Mul(&x.C1.B1, &yNR)
	result.C0.B2.Mul(&x.C1.B2, &yNR)
	result.C1.B0.Mul(&x.C0.B1, &yNR)
	result.C1.B1.Mul(&x.C0.B2, &yNR)
	result.C1.B2.Mul(&x.C0.B0, y)
	z.Set(&result)
	return z
}

// MulByV2NRInv set z to x*(y*v^2*(1,1)^{-1}) and return z
// here y*v^2 means the e12 element with C0.B2=y and all other components 0
func (z *e12) MulByV2NRInv(x *e12, y *e2) *e12 {
	var result e12
	var yNRInv e2

	{ // begin: inline yNRInv.MulByNonResidueInv(y)
		// (yNRInv).A0 = ((y).A0 + (y).A1)/2
		// (yNRInv).A1 = ((y).A1 - (y).A0)/2
		buf := *(y)
		(yNRInv).A0.Add(&buf.A0, &buf.A1)
		(yNRInv).A1.Sub(&buf.A1, &buf.A0)
		twoInv := fp.Element{
			1730508156817200468,
			9606178027640717313,
			7150789853162776431,
			7936136305760253186,
			15245073033536294050,
			1728177566264616342,
		}
		(yNRInv).A0.MulAssign(&twoInv)
		(yNRInv).A1.MulAssign(&twoInv)
	} // end: inline yNRInv.MulByNonResidueInv(y)

	result.C0.B0.Mul(&x.C0.B1, y)
	result.C0.B1.Mul(&x.C0.B2, y)
	result.C0.B2.Mul(&x.C0.B0, &yNRInv)

	result.C1.B0.Mul(&x.C1.B1, y)
	result.C1.B1.Mul(&x.C1.B2, y)
	result.C1.B2.Mul(&x.C1.B0, &yNRInv)

	z.Set(&result)
	return z
}

// MulByVWNRInv set z to x*(y*v*w*(1,1)^{-1}) and return z
// here y*v*w means the e12 element with C1.B1=y and all other components 0
func (z *e12) MulByVWNRInv(x *e12, y *e2) *e12 {
	var result e12
	var yNRInv e2

	{ // begin: inline yNRInv.MulByNonResidueInv(y)
		// (yNRInv).A0 = ((y).A0 + (y).A1)/2
		// (yNRInv).A1 = ((y).A1 - (y).A0)/2
		buf := *(y)
		(yNRInv).A0.Add(&buf.A0, &buf.A1)
		(yNRInv).A1.Sub(&buf.A1, &buf.A0)
		twoInv := fp.Element{
			1730508156817200468,
			9606178027640717313,
			7150789853162776431,
			7936136305760253186,
			15245073033536294050,
			1728177566264616342,
		}
		(yNRInv).A0.MulAssign(&twoInv)
		(yNRInv).A1.MulAssign(&twoInv)
	} // end: inline yNRInv.MulByNonResidueInv(y)

	result.C0.B0.Mul(&x.C1.B1, y)
	result.C0.B1.Mul(&x.C1.B2, y)
	result.C0.B2.Mul(&x.C1.B0, &yNRInv)

	result.C1.B0.Mul(&x.C0.B2, y)
	result.C1.B1.Mul(&x.C0.B0, &yNRInv)
	result.C1.B2.Mul(&x.C0.B1, &yNRInv)

	z.Set(&result)
	return z
}

// MulByWNRInv set z to x*(y*w*(1,1)^{-1}) and return z
// here y*w means the e12 element with C1.B0=y and all other components 0
func (z *e12) MulByWNRInv(x *e12, y *e2) *e12 {
	var result e12
	var yNRInv e2

	{ // begin: inline yNRInv.MulByNonResidueInv(y)
		// (yNRInv).A0 = ((y).A0 + (y).A1)/2
		// (yNRInv).A1 = ((y).A1 - (y).A0)/2
		buf := *(y)
		(yNRInv).A0.Add(&buf.A0, &buf.A1)
		(yNRInv).A1.Sub(&buf.A1, &buf.A0)
		twoInv := fp.Element{
			1730508156817200468,
			9606178027640717313,
			7150789853162776431,
			7936136305760253186,
			15245073033536294050,
			1728177566264616342,
		}
		(yNRInv).A0.MulAssign(&twoInv)
		(yNRInv).A1.MulAssign(&twoInv)
	} // end: inline yNRInv.MulByNonResidueInv(y)

	result.C0.B0.Mul(&x.C1.B2, y)
	result.C0.B1.Mul(&x.C1.B0, &yNRInv)
	result.C0.B2.Mul(&x.C1.B1, &yNRInv)

	result.C1.B0.Mul(&x.C0.B0, &yNRInv)
	result.C1.B1.Mul(&x.C0.B1, &yNRInv)
	result.C1.B2.Mul(&x.C0.B2, &yNRInv)

	z.Set(&result)
	return z
}

// MulByNonResidue multiplies a e6 by ((0,0),(1,0),(0,0))
func (z *e6) MulByNonResidue(x *e6) *e6 {
	var result e6
	result.B1.Set(&(x).B0)
	result.B2.Set(&(x).B1)
	{ // begin: inline result.B0.MulByNonResidue(&(x).B2)
		var buf e2
		buf.Set(&(x).B2)
		result.B0.A1.Add(&buf.A0, &buf.A1)
		{ // begin: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
			(&(result.B0).A0).Neg(&buf.A1)
		} // end: inline MulByNonResidue(&(result.B0).A0, &buf.A1)
		result.B0.A0.AddAssign(&buf.A0)
	} // end: inline result.B0.MulByNonResidue(&(x).B2)
	z.Set(&result)
	return z
}

// Frobenius set z to Frobenius(x) in e12 and return z
func (z *e12) Frobenius(x *e12) *e12 {
	// Algorithm 28 from https://eprint.iacr.org/2010/354.pdf (beware typos!)
	var t [6]e2

	// Frobenius acts on fp2 by conjugation
	t[0].Conjugate(&x.C0.B0)
	t[1].Conjugate(&x.C0.B1)
	t[2].Conjugate(&x.C0.B2)
	t[3].Conjugate(&x.C1.B0)
	t[4].Conjugate(&x.C1.B1)
	t[5].Conjugate(&x.C1.B2)

	t[1].MulByNonResiduePower2(&t[1])
	t[2].MulByNonResiduePower4(&t[2])
	t[3].MulByNonResiduePower1(&t[3])
	t[4].MulByNonResiduePower3(&t[4])
	t[5].MulByNonResiduePower5(&t[5])

	z.C0.B0 = t[0]
	z.C0.B1 = t[1]
	z.C0.B2 = t[2]
	z.C1.B0 = t[3]
	z.C1.B1 = t[4]
	z.C1.B2 = t[5]

	return z
}

// FrobeniusSquare set z to Frobenius^2(x) in e12 and return z
func (z *e12) FrobeniusSquare(x *e12) *e12 {
	// Algorithm 29 from https://eprint.iacr.org/2010/354.pdf (beware typos!)
	var t [6]e2

	t[1].MulByNonResiduePowerSquare2(&x.C0.B1)
	t[2].MulByNonResiduePowerSquare4(&x.C0.B2)
	t[3].MulByNonResiduePowerSquare1(&x.C1.B0)
	t[4].MulByNonResiduePowerSquare3(&x.C1.B1)
	t[5].MulByNonResiduePowerSquare5(&x.C1.B2)

	z.C0.B0 = x.C0.B0
	z.C0.B1 = t[1]
	z.C0.B2 = t[2]
	z.C1.B0 = t[3]
	z.C1.B1 = t[4]
	z.C1.B2 = t[5]

	return z
}

// FrobeniusCube set z to Frobenius^3(x) in e12 and return z
func (z *e12) FrobeniusCube(x *e12) *e12 {
	// Algorithm 30 from https://eprint.iacr.org/2010/354.pdf (beware typos!)
	var t [6]e2

	// Frobenius^3 acts on fp2 by conjugation
	t[0].Conjugate(&x.C0.B0)
	t[1].Conjugate(&x.C0.B1)
	t[2].Conjugate(&x.C0.B2)
	t[3].Conjugate(&x.C1.B0)
	t[4].Conjugate(&x.C1.B1)
	t[5].Conjugate(&x.C1.B2)

	t[1].MulByNonResiduePowerCube2(&t[1])
	t[2].MulByNonResiduePowerCube4(&t[2])
	t[3].MulByNonResiduePowerCube1(&t[3])
	t[4].MulByNonResiduePowerCube3(&t[4])
	t[5].MulByNonResiduePowerCube5(&t[5])

	z.C0.B0 = t[0]
	z.C0.B1 = t[1]
	z.C0.B2 = t[2]
	z.C1.B0 = t[3]
	z.C1.B1 = t[4]
	z.C1.B2 = t[5]

	return z
}

// MulByNonResiduePower1 set z=x*(1,1)^(1*(p-1)/6) and return z
func (z *e2) MulByNonResiduePower1(x *e2) *e2 {
	// (1,1)^(1*(p-1)/6)
	// 3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760 + u*151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027
	b := e2{
		A0: fp.Element{
			506819140503852133,
			14297063575771579155,
			10946065744702939791,
			11771194236670323182,
			2081670087578406477,
			644615147456521963,
		},
		A1: fp.Element{
			12895611875574011462,
			6359822009455181036,
			14936352902570693524,
			13914887797453940944,
			3330433690892295817,
			1229183470191017903,
		},
	}
	z.Mul(x, &b)
	return z
}

// MulByNonResiduePower2 set z=x*(1,1)^(2*(p-1)/6) and return z
func (z *e2) MulByNonResiduePower2(x *e2) *e2 {
	// (1,1)^(2*(p-1)/6)
	// 0 + u*4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436
	b := e2{
		A0: fp.Element{
			0,
			0,
			0,
			0,
			0,
			0,
		},
		A1: fp.Element{
			14772873186050699377,
			6749526151121446354,
			6372666795664677781,
			10283423008382700446,
			286397964926079186,
			1796971870900422465,
		},
	}
	z.Mul(x, &b)
	return z
}

// MulByNonResiduePower3 set z=x*(1,1)^(3*(p-1)/6) and return z
func (z *e2) MulByNonResiduePower3(x *e2) *e2 {
	// (1,1)^(3*(p-1)/6)
	// 1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257 + u*1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257
	b := e2{
		A0: fp.Element{
			8921533702591418330,
			15859389534032789116,
			3389114680249073393,
			15116930867080254631,
			3288288975085550621,
			1021049300055853010,
		},
		A1: fp.Element{
			8921533702591418330,
			15859389534032789116,
			3389114680249073393,
			15116930867080254631,
			3288288975085550621,
			1021049300055853010,
		},
	}
	z.Mul(x, &b)
	return z
}

// MulByNonResiduePower4 set z=x*(1,1)^(4*(p-1)/6) and return z
func (z *e2) MulByNonResiduePower4(x *e2) *e2 {
	// (1,1)^(4*(p-1)/6)
	// 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437
	b := fp.Element{
		9875771541238924739,
		3094855109658912213,
		5802897354862067244,
		11677019699073781796,
		1505592401347711080,
		1505729768134575418,
	}
	z.A0.Mul(&x.A0, &b)
	z.A1.Mul(&x.A1, &b)
	return z
}

// MulByNonResiduePower5 set z=x*(1,1)^(5*(p-1)/6) and return z
func (z *e2) MulByNonResiduePower5(x *e2) *e2 {
	// (1,1)^(5*(p-1)/6)
	// 877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230 + u*3125332594171059424908108096204648978570118281977575435832422631601824034463382777937621250592425535493320683825557
	b := e2{
		A0: fp.Element{
			9428352843095270463,
			11709709036094816655,
			14335180424952013185,
			8441381030041026197,
			5369959062663957099,
			1665664447512374973,
		},
		A1: fp.Element{
			3974078172982593132,
			8947176549131943536,
			11547238222321620130,
			17244701004083237929,
			42144715806745195,
			208134170135164893,
		},
	}
	z.Mul(x, &b)
	return z
}

// MulByNonResiduePowerSquare1 set z=x*(1,1)^(1*(p^2-1)/6) and return z
func (z *e2) MulByNonResiduePowerSquare1(x *e2) *e2 {
	// (1,1)^(1*(p^2-1)/6)
	// 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620351
	b := fp.Element{
		17076301903736715834,
		13907359434105313836,
		1063007777899403918,
		15402659025741563681,
		5125705813544623108,
		76826746747117401,
	}
	z.A0.Mul(&x.A0, &b)
	z.A1.Mul(&x.A1, &b)
	return z
}

// MulByNonResiduePowerSquare2 set z=x*(1,1)^(2*(p^2-1)/6) and return z
func (z *e2) MulByNonResiduePowerSquare2(x *e2) *e2 {
	// (1,1)^(2*(p^2-1)/6)
	// 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350
	b := fp.Element{
		3526659474838938856,
		17562030475567847978,
		1632777218702014455,
		14009062335050482331,
		3906511377122991214,
		368068849512964448,
	}
	z.A0.Mul(&x.A0, &b)
	z.A1.Mul(&x.A1, &b)
	return z
}

// MulByNonResiduePowerSquare3 set z=x*(1,1)^(3*(p^2-1)/6) and return z
func (z *e2) MulByNonResiduePowerSquare3(x *e2) *e2 {
	// (1,1)^(3*(p^2-1)/6)
	// 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786
	b := fp.Element{
		4897101644811774638,
		3654671041462534141,
		569769440802610537,
		17053147383018470266,
		17227549637287919721,
		291242102765847046,
	}
	z.A0.Mul(&x.A0, &b)
	z.A1.Mul(&x.A1, &b)
	return z
}

// MulByNonResiduePowerSquare4 set z=x*(1,1)^(4*(p^2-1)/6) and return z
func (z *e2) MulByNonResiduePowerSquare4(x *e2) *e2 {
	// (1,1)^(4*(p^2-1)/6)
	// 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436
	b := fp.Element{
		14772873186050699377,
		6749526151121446354,
		6372666795664677781,
		10283423008382700446,
		286397964926079186,
		1796971870900422465,
	}
	z.A0.Mul(&x.A0, &b)
	z.A1.Mul(&x.A1, &b)
	return z
}

// MulByNonResiduePowerSquare5 set z=x*(1,1)^(5*(p^2-1)/6) and return z
func (z *e2) MulByNonResiduePowerSquare5(x *e2) *e2 {
	// (1,1)^(5*(p^2-1)/6)
	// 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437
	b := fp.Element{
		9875771541238924739,
		3094855109658912213,
		5802897354862067244,
		11677019699073781796,
		1505592401347711080,
		1505729768134575418,
	}
	z.A0.Mul(&x.A0, &b)
	z.A1.Mul(&x.A1, &b)
	return z
}

// MulByNonResiduePowerCube1 set z=x*(1,1)^(1*(p^3-1)/6) and return z
func (z *e2) MulByNonResiduePowerCube1(x *e2) *e2 {
	// (1,1)^(1*(p^3-1)/6)
	// 2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530 + u*1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257
	b := e2{
		A0: fp.Element{
			4480897313486445265,
			4797496051193971075,
			4046559893315008306,
			10569151167044009496,
			2123814803385151673,
			852749317591686856,
		},
		A1: fp.Element{
			8921533702591418330,
			15859389534032789116,
			3389114680249073393,
			15116930867080254631,
			3288288975085550621,
			1021049300055853010,
		},
	}
	z.Mul(x, &b)
	return z
}

// MulByNonResiduePowerCube2 set z=x*(1,1)^(2*(p^3-1)/6) and return z
func (z *e2) MulByNonResiduePowerCube2(x *e2) *e2 {
	// (1,1)^(2*(p^3-1)/6)
	// 0 + u*1
	b := e2{
		A0: fp.Element{
			0,
			0,
			0,
			0,
			0,
			0,
		},
		A1: fp.Element{
			8505329371266088957,
			17002214543764226050,
			6865905132761471162,
			8632934651105793861,
			6631298214892334189,
			1582556514881692819,
		},
	}
	z.Mul(x, &b)
	return z
}

// MulByNonResiduePowerCube3 set z=x*(1,1)^(3*(p^3-1)/6) and return z
func (z *e2) MulByNonResiduePowerCube3(x *e2) *e2 {
	// (1,1)^(3*(p^3-1)/6)
	// 2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530 + u*2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530
	b := e2{
		A0: fp.Element{
			4480897313486445265,
			4797496051193971075,
			4046559893315008306,
			10569151167044009496,
			2123814803385151673,
			852749317591686856,
		},
		A1: fp.Element{
			4480897313486445265,
			4797496051193971075,
			4046559893315008306,
			10569151167044009496,
			2123814803385151673,
			852749317591686856,
		},
	}
	z.Mul(x, &b)
	return z
}

// MulByNonResiduePowerCube4 set z=x*(1,1)^(4*(p^3-1)/6) and return z
func (z *e2) MulByNonResiduePowerCube4(x *e2) *e2 {
	// (1,1)^(4*(p^3-1)/6)
	// 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786
	b := fp.Element{
		4897101644811774638,
		3654671041462534141,
		569769440802610537,
		17053147383018470266,
		17227549637287919721,
		291242102765847046,
	}
	z.A0.Mul(&x.A0, &b)
	z.A1.Mul(&x.A1, &b)
	return z
}

// MulByNonResiduePowerCube5 set z=x*(1,1)^(5*(p^3-1)/6) and return z
func (z *e2) MulByNonResiduePowerCube5(x *e2) *e2 {
	// (1,1)^(5*(p^3-1)/6)
	// 1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257 + u*2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530
	b := e2{
		A0: fp.Element{
			8921533702591418330,
			15859389534032789116,
			3389114680249073393,
			15116930867080254631,
			3288288975085550621,
			1021049300055853010,
		},
		A1: fp.Element{
			4480897313486445265,
			4797496051193971075,
			4046559893315008306,
			10569151167044009496,
			2123814803385151673,
			852749317591686856,
		},
	}
	z.Mul(x, &b)
	return z
}

const tAbsVal uint64 = 15132376222941642752 // negative

// Expt set z to x^t in e12 and return z
// TODO make a ExptAssign method that assigns the result to self; then this method can assert fail if z != x
// TODO Expt is the only method that depends on tAbsVal.  The rest of the tower does not depend on this value.  Logically, Expt should be separated from the rest of the tower.
func (z *e12) Expt(x *e12) *e12 {
	// TODO what if x==0?
	// TODO make this match Element.Exp: x is a non-pointer?
	var result e12
	result.Set(x)

	l := bits.Len64(tAbsVal) - 2
	for i := l; i >= 0; i-- {
		result.Square(&result)
		if tAbsVal&(1<<uint(i)) != 0 {
			result.Mul(&result, x)
		}
	}
	result.Conjugate(&result) // because tAbsVal is negative

	z.Set(&result)
	return z
}

// FinalExponentiation computes the final expo x**((p**12 - 1)/r)
func (z *e12) FinalExponentiation(x *e12) *e12 {
	// For BLS curves use Section 3 of https://eprint.iacr.org/2016/130.pdf; "hard part" is Algorithm 1 of https://eprint.iacr.org/2016/130.pdf
	var result e12
	result.Set(x)

	// memalloc
	var t [6]e12

	// buf = x**(p^6-1)
	t[0].FrobeniusCube(&result).
		FrobeniusCube(&t[0])

	result.Inverse(&result)
	t[0].Mul(&t[0], &result)

	// x = (x**(p^6-1)) ^(p^2+1)
	result.FrobeniusSquare(&t[0]).
		Mul(&result, &t[0])

	// hard part (up to permutation)
	// performs the hard part of the final expo
	// Algorithm 1 of https://eprint.iacr.org/2016/130.pdf
	// The result is the same as p**4-p**2+1/r, but up to permutation (it's 3* (p**4 -p**2 +1 /r)), ok since r=1 mod 3)

	t[0].InverseUnitary(&result).Square(&t[0])
	t[5].Expt(&result)
	t[1].Square(&t[5])
	t[3].Mul(&t[0], &t[5])

	t[0].Expt(&t[3])
	t[2].Expt(&t[0])
	t[4].Expt(&t[2])

	t[4].Mul(&t[1], &t[4])
	t[1].Expt(&t[4])
	t[3].InverseUnitary(&t[3])
	t[1].Mul(&t[3], &t[1])
	t[1].Mul(&t[1], &result)

	t[0].Mul(&t[0], &result)
	t[0].FrobeniusCube(&t[0])

	t[3].InverseUnitary(&result)
	t[4].Mul(&t[3], &t[4])
	t[4].Frobenius(&t[4])

	t[5].Mul(&t[2], &t[5])
	t[5].FrobeniusSquare(&t[5])

	t[5].Mul(&t[5], &t[0])
	t[5].Mul(&t[5], &t[4])
	t[5].Mul(&t[5], &t[1])

	result.Set(&t[5])

	z.Set(&result)
	return z
}
