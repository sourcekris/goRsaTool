package ln

import fmp "github.com/sourcekris/goflint"

// FindGcd returns a Fmpz GCD of a and b or 1 if a and b are co-prime.
func FindGcd(a, b *fmp.Fmpz) *fmp.Fmpz {
	return new(fmp.Fmpz).GCD(a, b)
}

// XGCD finds the coefficients of Bézout's identity using the Extended Euclidean
// algorithm.
func XGCD(a, b *fmp.Fmpz) (*fmp.Fmpz, *fmp.Fmpz, *fmp.Fmpz) {
	if a.Equals(BigZero) {
		return b, fmp.NewFmpz(0), fmp.NewFmpz(1)
	}

	gcd, u, v := XGCD(new(fmp.Fmpz).Mod(b, a), a)
	return gcd, new(fmp.Fmpz).Sub(v, new(fmp.Fmpz).Div(b, a).MulZ(u)), u
}
