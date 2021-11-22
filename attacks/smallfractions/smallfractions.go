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

// Attack implements SmallFractions attack.
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	if k.Key.D != nil {
		return nil
	}

	var num, den int64

	for den = 2; den < depth+1; den++ {
		for num = 1; num < den; num++ {
			g := new(fmp.Fmpz).GCD(fmp.NewFmpz(num), fmp.NewFmpz(den))

			if g.Equals(ln.BigOne) {
				phint := new(fmp.Fmpz).Mul(k.Key.N, fmp.NewFmpz(den))
				phint.Div(phint, fmp.NewFmpz(num)).Root(phint, 2)

				X := ln.FracPow(k.Key.N, 3, 16)
				X.Div(X, ln.BigTwo)

				ctx := fmp.NewFmpzModCtx(k.Key.N)
				// f = x - phint
				f := fmp.NewFmpzModPoly(ctx).SetCoeffUI(1, 1)
				f.Sub(f, fmp.NewFmpzModPoly(ctx).SetCoeff(0, phint))

				// Copy f to type FmpzPoly.
				fp := fmp.NewFmpzPoly()
				fcs := f.GetCoeffs()
				for i, c := range fcs {
					fp.SetCoeff(i, c)
				}

				// x
				x := fmp.NewFmpzPoly().SetCoeffUI(1, 1)
				//  Construct an array of polys.
				var g []*fmp.FmpzPoly
				for i := 0; i < 4; i++ {
					// np = x * N^(4-i)
					np := fmp.NewFmpzPoly().MulScalar(x, new(fmp.Fmpz).ExpXI(k.Key.N, 4-i))
					// np * f^i
					np.Mul(np, fmp.NewFmpzPoly().Pow(fp, i))
					g = append(g, np)

				}

				//  Extend the array of polys.
				for i := 0; i < 4; i++ {
					// np = x**i * f**4
					np := fmp.NewFmpzPoly().Pow(x, i)
					np.Mul(np, fmp.NewFmpzPoly().Pow(fp, 4))
					g = append(g, np)
				}

				// Construct an empty 8*8 matrix and set the values.
				B := fmp.NewFmpzMat(8, 8)
				for i := 0; i < 8; i++ {
					for j := 0; j < g[i].Len(); j++ {
						B.SetVal(g[i].GetCoeff(j).MulZ(new(fmp.Fmpz).ExpXI(X, j)), j, i)
					}
				}

				// Peform lattice reduction.
				B.LLL()

				ff := fmp.NewFmpzPoly()
				for i := 0; i < 8; i++ {
					a := new(fmp.Fmpz).Div(B.Entry(i, 0), new(fmp.Fmpz).ExpXI(X, i))
					b := new(fmp.FmpzPoly).Pow(x, i)
					b.MulScalar(b, a)
					ff.Add(ff, b)
				}

				// Find the roots of the resulting polynomial via factorization.
				fac := ff.Factor()
				for i := 0; i < fac.Len(); i++ {

					// One of the coefficients of the factors could be related to p.
					p := fac.GetPoly(i)
					for j := 0; j < p.Len(); j++ {
						coeff := new(fmp.Fmpz).Mod(p.GetCoeff(j), k.Key.N)
						if coeff.Equals(ln.BigZero) {
							continue
						}

						// Due to the FLINT LLL implementation I think we often get sign problems in the factors
						// of the polynomials. So try both +/- versions.
						pps := []*fmp.Fmpz{
							new(fmp.Fmpz).Sub(phint, coeff),
							new(fmp.Fmpz).Sub(phint, new(fmp.Fmpz).Mul(coeff, ln.BigNOne)),
						}

						for _, pp := range pps {
							if pp.Equals(ln.BigZero) || pp.Equals(k.Key.N) {
								continue
							}
							if new(fmp.Fmpz).Mod(k.Key.N, pp).Equals(ln.BigZero) {
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
