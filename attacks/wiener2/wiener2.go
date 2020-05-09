package wiener2

import (
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

func squareAndMultiply(base, exponent, n *fmp.Fmpz) *fmp.Fmpz {
	var be []int
	e := new(fmp.Fmpz).Set(exponent)
	for e.Cmp(ln.BigZero) != 0 {
		be = append(be, new(fmp.Fmpz).Mod(e, ln.BigTwo).GetInt())
		e.Div(e, ln.BigTwo)
	}

	// Reverse be.
	for i := len(be)/2 - 1; i >= 0; i-- {
		opp := len(be) - 1 - i
		be[i], be[opp] = be[opp], be[i]
	}

	result := fmp.NewFmpz(1)
	for _, i := range be {
		if i == 0 {
			result = result.MulZ(result).ModZ(n)
		} else {
			result = result.MulZ(result).MulZ(base).ModZ(n)
		}
	}

	return result
}

// Find the roots of the polynomial x^2 - (N - phi(N) + 1)x + N.
// This does not find p in the example given but may for other examples.
func fullReverse(n, e *fmp.Fmpz, c [2]*fmp.Fmpz) *fmp.Fmpz {
	phi := new(fmp.Fmpz).Set(e).MulZ(c[1]).SubZ(ln.BigOne)
	phi.Div(phi, c[0])

	a := fmp.NewFmpz(1)
	b := new(fmp.Fmpz).Set(n).SubZ(phi).AddZ(ln.BigOne).MulI(-1)
	cee := new(fmp.Fmpz).Set(n)

	delta := new(fmp.Fmpz).Mul(b, b).SubZ(new(fmp.Fmpz).Mul(a, cee).MulI(4))

	if delta.Cmp(ln.BigZero) > 0 {
		x1 := new(fmp.Fmpz).Set(b).MulI(-1).AddZ(new(fmp.Fmpz).Root(delta, 2))
		x1.Div(x1, new(fmp.Fmpz).Mul(a, ln.BigTwo))
		x2 := new(fmp.Fmpz).Set(b).MulI(-1).SubZ(new(fmp.Fmpz).Root(delta, 2))
		x1.Div(x1, new(fmp.Fmpz).Mul(a, ln.BigTwo))

		if x1.MulZ(x2).Cmp(n) == 0 {
			// Recovered p.
			return x2
		}
	}

	return nil
}

// Attack performs a variant of the wiener attack ported from the python version here:
// https://github.com/MxRy/rsa-attacks/blob/master/wiener-attack.py
func Attack(k *keys.RSA) error {
	if k.Key.D != nil {
		return nil
	}

	ts := fmp.NewFmpz(42)
	newc := squareAndMultiply(ts, k.Key.PublicKey.E, k.Key.N)
	convergants := ln.ConvergantsFromContfract(ln.RationalToContfract(k.Key.PublicKey.E, k.Key.N))

	for _, c := range convergants {
		if squareAndMultiply(newc, c[1], k.Key.N).Cmp(ts) == 0 {
			if pp := fullReverse(k.Key.N, k.Key.PublicKey.E, c); pp != nil {
				k.PackGivenP(pp)
				return nil
			}
			k.PackGivenP(ln.FindPGivenD(c[1], k.Key.PublicKey.E, k.Key.N))
			return nil
		}
	}

	return nil
}
