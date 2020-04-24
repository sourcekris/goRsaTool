package wiener

import (
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// Attack attack based on the python implementation of the algorithm by Pablo Celayes:
// https://github.com/pablocelayes/rsa-wiener-attack
func Attack(t *keys.RSA) error {
	if t.Key.D != nil {
		// Key already factored.
		return nil
	}

	frac := ln.RationalToContfract(t.Key.PublicKey.E, t.Key.N)
	convergants := ln.ConvergantsFromContfract(frac)

	z := new(fmp.Fmpz)

	for _, g := range convergants {
		k := g[0]
		d := g[1]

		if k.Cmp(ln.BigZero) != 0 && z.Mul(d, t.Key.PublicKey.E).Sub(z, ln.BigOne).Mod(z, k).Cmp(ln.BigZero) == 0 {
			phi := new(fmp.Fmpz).Set(z.Mul(d, t.Key.PublicKey.E).Sub(z, ln.BigOne).Div(z, k))      // phi = (e*d-1)//k
			s := new(fmp.Fmpz).Set(z.Sub(t.Key.N, phi).Add(z, ln.BigOne))                          // s = n - phi + 1
			discr := new(fmp.Fmpz).Set(z.Mul(s, s).Sub(z, new(fmp.Fmpz).Mul(ln.BigFour, t.Key.N))) // discr = s*s - 4*n
			if discr.Sign() >= 0 {
				ts := ln.IsPerfectSquare(discr)
				if ts.Cmp(ln.BigNOne) != 0 && z.Add(s, ts).Mod(z, ln.BigTwo).Cmp(ln.BigZero) == 0 {
					// We found d, pack the private key.
					t.PackGivenP(ln.FindPGivenD(d, t.Key.PublicKey.E, t.Key.N))
				}
			}
		}
	}

	return nil
}
