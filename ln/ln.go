package ln

import (
	"math/bits"
	"math/rand"
	"time"

	"github.com/jbarham/primegen"
	"github.com/kavehmz/prime"

	fmp "github.com/sourcekris/goflint"
	mp "github.com/sourcekris/mathparse"
)

const (
	// The number of Miller-Rabin rounds for Golangs ProbablyPrime.
	mrRounds = 20
)

var (
	// BigNOne is the Fmpz representation of -1
	BigNOne = fmp.NewFmpz(-1)
	// BigZero is the Fmpz representation of 0
	BigZero = fmp.NewFmpz(0)
	// BigOne is the Fmpz representation of 1
	BigOne = fmp.NewFmpz(1)
	// BigTwo is the Fmpz representation of 2
	BigTwo = fmp.NewFmpz(2)
	// BigThree is the Fmpz representation of 3
	BigThree = fmp.NewFmpz(3)
	// BigFour is the Fmpz representation of 4
	BigFour = fmp.NewFmpz(4)
	// BigFive is the Fmpz representation of 5
	BigFive = fmp.NewFmpz(5)
	// BigSix is the Fmpz representation of 6
	BigSix = fmp.NewFmpz(6)
	// BigSeven is the Fmpz representation of 7
	BigSeven = fmp.NewFmpz(7)
	// BigEight is the Fmpz representation of 8
	BigEight = fmp.NewFmpz(8)
	// BigNine is the Fmpz representation of 9
	BigNine = fmp.NewFmpz(9)
	// BigEleven is the Fmpz representation of 11
	BigEleven = fmp.NewFmpz(11)
	// BigSixteen is the Fmpz representation of 16
	BigSixteen = fmp.NewFmpz(0xf)
)

// BytesToNumber takes a slice of bytes and returns a Fmpz integer representation.
func BytesToNumber(src []byte) *fmp.Fmpz {
	return new(fmp.Fmpz).SetBytes(src)
}

// NumberToBytes takes an Fmpz integer and returns the byte slice representation.
func NumberToBytes(src *fmp.Fmpz) []byte {
	return src.Bytes()
}

// SolveforD given e, p and q solve for the private exponent d.
func SolveforD(p *fmp.Fmpz, q *fmp.Fmpz, e *fmp.Fmpz) *fmp.Fmpz {
	// invmod(e, (p-1)*(q-1))
	res, _ := mp.Evalf("invmod(%v,((%v-1)*(%v-1)))", e, p, q)
	return res
}

// FindPGivenD finds p and q given d, e, and n - uses an algorithm from pycrypto _slowmath.py [0]
// [0]: https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/_slowmath.py
func FindPGivenD(d *fmp.Fmpz, e *fmp.Fmpz, n *fmp.Fmpz) *fmp.Fmpz {
	m := new(fmp.Fmpz)
	tmp := new(fmp.Fmpz)

	ktot := new(fmp.Fmpz).Set(tmp.Mul(d, e).Sub(tmp, BigOne))
	t := new(fmp.Fmpz).Set(ktot)

	for tmp.Mod(t, BigTwo).Equals(BigZero) {
		t.DivMod(t, BigTwo, m)
	}

	for a := 2; a < 1000; a += 2 {
		k := new(fmp.Fmpz).Set(t)

		cand := new(fmp.Fmpz)
		for k.Cmp(ktot) < 0 {
			cand.Exp(fmp.NewFmpz(int64(a)), k, n)

			if !cand.Equals(BigOne) && !cand.Equals(tmp.Sub(n, BigOne)) && tmp.Exp(cand, BigTwo, n).Equals(BigOne) {
				return FindGcd(tmp.Add(cand, BigOne), n)
			}

			k.Mul(k, BigTwo)
		}
	}

	return BigZero
}

// IsPerfectSquare returns t if n is a perfect square -1 otherwise
func IsPerfectSquare(n *fmp.Fmpz) *fmp.Fmpz {
	h := new(fmp.Fmpz).And(n, BigSixteen)

	if h.Cmp(BigNine) > 1 {
		return BigNOne
	}

	if !h.Equals(BigTwo) && !h.Equals(BigThree) &&
		!h.Equals(BigFive) && !h.Equals(BigSix) &&
		!h.Equals(BigSeven) && !h.Equals(BigEight) {

		t := new(fmp.Fmpz).Sqrt(n)

		if t.Mul(t, t).Equals(n) {
			return t
		}
	}

	return BigNOne
}

// RationalToContfract takes a rational represented by x and y and returns a slice of quotients.
func RationalToContfract(x, y *fmp.Fmpz) []int {
	a := new(fmp.Fmpz).Div(x, y)
	b := new(fmp.Fmpz).Mul(a, y)
	c := new(fmp.Fmpz)

	var pquotients []int

	if b.Equals(x) {
		return []int{int(a.Int64())}
	}
	c.Mul(y, a).Sub(x, c)
	pquotients = RationalToContfract(y, c)
	pquotients = append([]int{int(a.Int64())}, pquotients...)
	return pquotients
}

// ContfractToRational takes a slice of quotients and returns a rational x/y.
func ContfractToRational(frac []int) (*fmp.Fmpz, *fmp.Fmpz) {
	var remainder []int

	switch l := len(frac); l {
	case 0:
		return BigZero, BigOne
	case 1:
		return fmp.NewFmpz(int64(frac[0])), BigOne
	default:
		remainder = frac[1:l]
		num, denom := ContfractToRational(remainder)
		fracZ := fmp.NewFmpz(int64(frac[0]))
		return fracZ.Mul(fracZ, num).Add(fracZ, denom), num
	}
}

// ConvergantsFromContfract takes a slice of quotients and returns the convergants.
func ConvergantsFromContfract(frac []int) [][2]*fmp.Fmpz {
	var convs [][2]*fmp.Fmpz

	for i := range frac {
		a, b := ContfractToRational(frac[0:i])
		convs = append(convs, [2]*fmp.Fmpz{a, b})
	}
	return convs
}

// SieveOfEratosthenes returns primes from begin to n and this implementation comes from:
// https://stackoverflow.com/a/21923233.
func SieveOfEratosthenes(n int) []int {
	var primes []int
	b := make([]bool, n)
	for i := 2; i < n; i++ {
		if b[i] == true {
			continue
		}

		primes = append(primes, i)
		for k := i * i; k < n; k += i {
			b[k] = true
		}
	}
	return primes
}

// SieveOfEratosthenesFmp is a convenience function that simply returns []*fmp.Fmpz instead of
// []int. It does not support finding primes > max_int.
func SieveOfEratosthenesFmp(n int) []*fmp.Fmpz {
	return FmpFromIntSlice(SieveOfEratosthenes(n))
}

// SieveRangeOfAtkin finds primes from begin to the limit n using a SieveOfAtkin from primegen package.
func SieveRangeOfAtkin(begin, n int) []int {
	var primes []int

	pg := primegen.New()
	pg.SkipTo(uint64(begin))
	for i := begin; i < n; i++ {
		primes = append(primes, int(pg.Next()))
	}
	return primes
}

// SieveOfAtkin finds primes from 0 to n using a SieveOfAtkin from primegen package.
func SieveOfAtkin(n int) []int {
	return SieveRangeOfAtkin(2, n)
}

// SieveOfAtkinFmp finds primes from 0 to n using a SieveOfAtkin from primegen package.
func SieveOfAtkinFmp(n int) []*fmp.Fmpz {
	return FmpFromIntSlice(SieveRangeOfAtkin(2, n))
}

// SegmentedSieveFmp is another prime sieve.
func SegmentedSieveFmp(n int) []*fmp.Fmpz {
	return FmpFromUInt64Slice(prime.Primes(uint64(n)))
}

// FmpFromIntSlice returns a slice of Fmpz from a slice of int.
func FmpFromIntSlice(is []int) []*fmp.Fmpz {
	var res []*fmp.Fmpz
	for _, i := range is {
		res = append(res, fmp.NewFmpz(int64(i)))
	}
	return res
}

// FmpFromUInt64Slice returns a slice of Fmpz from a slice of int.
func FmpFromUInt64Slice(is []uint64) []*fmp.Fmpz {
	var res []*fmp.Fmpz
	for _, i := range is {
		res = append(res, new(fmp.Fmpz).SetUint64(i))
	}
	return res
}

// FmpString returns a base 10 fmp.Fmpz integer from a string. It returns BigZero on error.
func FmpString(s string) *fmp.Fmpz {
	res, ok := new(fmp.Fmpz).SetString(s, 10)
	if !ok {
		return BigZero
	}

	return res
}

// MLucas multiplies along a Lucas sequence modulo n.
func MLucas(v, a, n *fmp.Fmpz) *fmp.Fmpz {
	v1 := new(fmp.Fmpz).Set(v)
	v2 := new(fmp.Fmpz).Mul(v, v)
	v2.Sub(v2, BigTwo).Mod(v2, n)

	for i := a.Bits(); i > 1; i-- {
		if a.TstBit(i) == 0 {
			tmpv1 := new(fmp.Fmpz).Set(v1)
			v1.Mul(v1, v1).SubZ(BigTwo).Mod(v1, n)
			v2.Mul(tmpv1, v2).SubZ(v).Mod(v2, n)
		} else {
			v1.Mul(v1, v2).SubZ(v).Mod(v1, n)
			v2.Mul(v2, v2).SubZ(BigTwo).Mod(v2, n)
		}
	}

	return v1
}

// ILog returns the greatest integer l such that b**l <= x.
func ILog(x, b *fmp.Fmpz) *fmp.Fmpz {
	l := fmp.NewFmpz(0)
	for x.Cmp(b) >= 0 {
		x.Div(x, b)
		l.AddZ(BigOne)
	}
	return l
}

// IsPower returns the largest integer that, when squared/cubed/etc, yields n, or 0 if
// no such integer exists.
func IsPower(n *fmp.Fmpz) *fmp.Fmpz {
	p := primegen.New()
	for {
		cursor := p.Next()
		r := new(fmp.Fmpz).Root(n, int32(cursor))
		if r.Equals(BigZero) {
			continue
		}

		rxp := new(fmp.Fmpz).Mul(r, fmp.NewFmpz(int64(cursor)))
		if rxp.Equals(n) {
			return r
		}

		if r.Equals(BigOne) {
			return fmp.NewFmpz(0)
		}
	}
}

// FracPow raises x to the fractional power m/n and returns it.
func FracPow(x *fmp.Fmpz, m, n int) *fmp.Fmpz {
	res := new(fmp.Fmpz)
	return res.ExpXI(x, m).Root(res, int32(n))
}

// FmpzMin returns the min(x,y)
func FmpzMin(x, y *fmp.Fmpz) *fmp.Fmpz {
	if x.Cmp(y) < 0 {
		return x
	}
	return y
}

// GetRand takes a seed from the environment and iterates the state a random
// number of times to get a less deterministic random number from Flint.
func GetRand(state *fmp.FlintRandT, n *fmp.Fmpz) *fmp.Fmpz {
	res := new(fmp.Fmpz)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := 0; i < rand.Intn(65535); i++ {
		res.Randm(state, n)
	}

	return res.Add(res, BigOne)
}

// Combinations returns combinations of n elements for a given Fmpz array.
func Combinations(set []*fmp.Fmpz, n int) (subsets [][]*fmp.Fmpz) {
	length := uint(len(set))

	if n > len(set) {
		n = len(set)
	}

	// Go through all possible combinations of objects
	// from 1 (only first object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		if n > 0 && bits.OnesCount(uint(subsetBits)) != n {
			continue
		}

		var subset []*fmp.Fmpz

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		// add subset to subsets
		subsets = append(subsets, subset)
	}
	return subsets
}

// SolveCRT solves the Chinese Remainder Theorem for sets of residues and moduli.
func SolveCRT(mrs [][]*fmp.Fmpz) *fmp.Fmpz {
	var (
		residues []*fmp.Fmpz
		moduli   []*fmp.Fmpz
		nxs      []*fmp.Fmpz
		ds       []*fmp.Fmpz
		mults    []*fmp.Fmpz
	)

	for _, m := range mrs {
		residues = append(residues, m[0])
		moduli = append(moduli, m[1])
	}

	// Multiply the moduli together.
	bigN := new(fmp.Fmpz).Set(BigOne)
	for _, n := range moduli {
		bigN.MulZ(n)
	}

	// Compute the ratios and the modular inverses.
	for _, n := range moduli {
		nn := new(fmp.Fmpz).Div(bigN, n)
		nxs = append(nxs, nn)
		d := new(fmp.Fmpz).ModInverse(nn, n)
		ds = append(ds, d)
	}

	// Compute the multiples.
	for i := 0; i < len(residues); i++ {
		mults = append(mults, new(fmp.Fmpz).Mul(residues[i], nxs[i]).MulZ(ds[i]))
	}

	// Reduce modulo bigN.
	res := fmp.NewFmpz(0)
	for _, mult := range mults {
		res.AddZ(mult)
	}

	return res.ModZ(bigN)
}
