package ln

import (
	fmp "github.com/sourcekris/goflint"
)

var (
	// BigNOne is the Fmpz representation of -1
	BigNOne = fmp.NewFmpz(-1)
	// BigZero is the Fmpz representation of 0
	BigZero = fmp.NewFmpz(0)
	//  is the Fmpz representation of 1
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
	return new(fmp.Fmpz).ModInverse(e,
		new(fmp.Fmpz).Mul(
			new(fmp.Fmpz).Sub(p, BigOne),
			new(fmp.Fmpz).Sub(q, BigOne),
		),
	)
}

// FindPGivenD finds p and q given d, e, and n - uses an algorithm from pycrypto _slowmath.py [0]
// [0]: https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/_slowmath.py
func FindPGivenD(d *fmp.Fmpz, e *fmp.Fmpz, n *fmp.Fmpz) *fmp.Fmpz {
	m := new(fmp.Fmpz)
	tmp := new(fmp.Fmpz)

	ktot := new(fmp.Fmpz).Set(tmp.Mul(d, e).Sub(tmp, BigOne))
	t := new(fmp.Fmpz).Set(ktot)

	for tmp.Mod(t, BigTwo).Cmp(BigZero) == 0 {
		t.DivMod(t, BigTwo, m)
	}

	for a := 2; a < 1000; a += 2 {
		k := new(fmp.Fmpz).Set(t)

		cand := new(fmp.Fmpz)
		for k.Cmp(ktot) < 0 {
			cand.Exp(fmp.NewFmpz(int64(a)), k, n)

			if cand.Cmp(BigOne) != 0 && cand.Cmp(tmp.Sub(n, BigOne)) != 0 && tmp.Exp(cand, BigTwo, n).Cmp(BigOne) == 0 {
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

	if h.Cmp(fmp.NewFmpz(9)) > 1 {
		return BigNOne
	}

	if h.Cmp(BigTwo) != 0 && h.Cmp(BigThree) != 0 &&
		h.Cmp(BigFive) != 0 && h.Cmp(BigSix) != 0 &&
		h.Cmp(BigSeven) != 0 && h.Cmp(BigEight) != 0 {

		t := new(fmp.Fmpz).Sqrt(n)

		if t.Mul(t, t).Cmp(n) == 0 {
			return t
		} else {
			return BigNOne
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

	if b.Cmp(x) == 0 {
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
		z := [2]*fmp.Fmpz{a, b}
		convs = append(convs, z)
	}
	return convs
}

// SieveRangeOfEratosthenes returns primes from begin to n and this implementation comes from:
// https://stackoverflow.com/a/21923233.
func SieveRangeOfEratosthenes(begin, n int) []int {
	if begin > n {
		return nil
	}

	var primes []int
	b := make([]bool, n)
	for i := begin; i < n; i++ {
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

// SieveOfEratosthenes returns primes less than n
func SieveOfEratosthenes(n int) []int {
	return SieveRangeOfEratosthenes(2, n)
}

// SieveRangeOfEratosthenesFmp is a convenience function that simply returns []*fmp.Fmpz instead of
// []int. It does not support finding primes > max_int.
func SieveRangeOfEratosthenesFmp(begin, n int) []*fmp.Fmpz {
	ps := SieveRangeOfEratosthenes(begin, n)
	var res []*fmp.Fmpz
	for _, p := range ps {
		res = append(res, fmp.NewFmpz(int64(p)))
	}
	return res
}

// SieveOfEratosthenesFmp is a convenience function that simply returns []*fmp.Fmpz instead of
// []int. It does not support finding primes > max_int.
func SieveOfEratosthenesFmp(n int) []*fmp.Fmpz {
	return SieveRangeOfEratosthenesFmp(2, n)
}

// FmpString returns a base 10 fmp.Fmpz integer from a string. It returns BigZero on error.
func FmpString(s string) *fmp.Fmpz {
	res, ok := new(fmp.Fmpz).SetString(s, 10)
	if !ok {
		return BigZero
	}

	return res
}
