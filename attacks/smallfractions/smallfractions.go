package smallfractions

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "small fractions"

// depth is the max size of the numerator and denominator to test to.
const depth int64 = 50

// Which fmp initializer to use so we can swap out the constructor
// for debugging.
var (
	fmpz    = fmp.NewFmpz
	poly    = fmp.NewFmpzPoly
	modpoly = fmp.NewFmpzModPoly
	mat     = fmp.NewFmpzMatNF
)

// Attack implements SmallFractions attack.
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	if k.Key.D != nil {
		return nil
	}

	var num, den int64

	n := fmpz(0).Set(k.Key.N)
	ctx := fmp.NewFmpzModCtx(n)
	for den = 2; den < depth+1; den++ {
		for num = 1; num < den; num++ {
			g := fmpz(0).GCD(fmpz(num), fmpz(den))

			if g.Equals(ln.BigOne) {
				phint := fmpz(0).Mul(n, fmpz(den))
				phint.Div(phint, fmpz(num)).Root(phint, 2)

				X := ln.FracPow(n, 3, 16)
				X.Div(X, ln.BigTwo)

				// f = x - phint
				f := modpoly(ctx).SetCoeffUI(1, 1)
				f.Sub(f, modpoly(ctx).SetCoeff(0, phint))

				// Copy f to type FmpzPoly.
				fp := poly()
				fcs := f.GetCoeffs()
				for i, c := range fcs {
					fp.SetCoeff(i, c)
				}

				// x
				x := poly().SetCoeffUI(1, 1)
				//  Construct an array of polys.
				var g []*fmp.FmpzPoly
				for i := 0; i < 4; i++ {
					// np = x * N^(4-i)
					np := poly().MulScalar(x, fmpz(0).ExpXI(k.Key.N, 4-i))
					// np * f^i
					np.Mul(np, poly().Pow(fp, i))
					g = append(g, np)

				}

				//  Extend the array of polys.
				for i := 0; i < 4; i++ {
					// np = x**i * f**4
					np := poly().Pow(x, i)
					np.Mul(np, poly().Pow(fp, 4))
					g = append(g, np)
				}

				// Construct an empty 8*8 matrix and set the values.
				B := mat(8, 8)
				for i := 0; i < 8; i++ {
					for j := 0; j < g[i].Len(); j++ {
						B.SetVal(g[i].GetCoeff(j).MulZ(fmpz(0).ExpXI(X, j)), j, i)
					}
				}

				// Peform lattice reduction.
				B.LLL()
				ff := poly()
				for i := 0; i < 8; i++ {
					a := fmpz(0).Div(B.Entry(i, 0), fmpz(0).ExpXI(X, i))
					b := poly().Pow(x, i)
					b.MulScalar(b, a)
					ff.Add(ff, b)
				}

				// Find the roots of the resulting polynomial via factorization.
				fac := ff.Factor()
				for i := 0; i < fac.Len(); i++ {

					// One of the coefficients of the factors could be related to p.
					p := fac.GetPolyNF(i)
					for j := 0; j < p.Len(); j++ {
						coeff := fmpz(0).Mod(p.GetCoeff(j), k.Key.N)
						if coeff.Equals(ln.BigZero) {
							continue
						}

						// Due to the FLINT LLL implementation I think we often get sign problems in the factors
						// of the polynomials. So try both +/- versions.
						pps := []*fmp.Fmpz{
							fmpz(0).Sub(phint, coeff),
							fmpz(0).Sub(phint, fmpz(0).Mul(coeff, ln.BigNOne)),
						}

						for _, pp := range pps {
							if pp.Equals(ln.BigZero) || pp.Equals(k.Key.N) {
								continue
							}
							if fmpz(0).Mod(k.Key.N, pp).Equals(ln.BigZero) {
								k.PackGivenP(pp)
								return nil
							}
						}
					}
				}
			}
		}
	}

	return fmt.Errorf("%s did not find the factors", name)
}
