package wiener

import (
	"log"

	"github.com/sourcekris/goRsaTool/attacks/wiener2"
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

const name = "wiener"

// Attack implements the Wiener attack on an RSA public key and this implementation is based on the
// python implementation of the algorithm by Pablo Celayes:
// https://github.com/pablocelayes/rsa-wiener-attack
func Attack(ts []*keys.RSA) error {
	t := ts[0]
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

		if !k.Equals(ln.BigZero) && z.Mul(d, t.Key.PublicKey.E).Sub(z, ln.BigOne).Mod(z, k).Equals(ln.BigZero) {
			phi := new(fmp.Fmpz).Set(z.Mul(d, t.Key.PublicKey.E).Sub(z, ln.BigOne).Div(z, k))      // phi = (e*d-1)//k
			s := new(fmp.Fmpz).Set(z.Sub(t.Key.N, phi).Add(z, ln.BigOne))                          // s = n - phi + 1
			discr := new(fmp.Fmpz).Set(z.Mul(s, s).Sub(z, new(fmp.Fmpz).Mul(ln.BigFour, t.Key.N))) // discr = s*s - 4*n
			if discr.Sign() >= 0 {
				ts := ln.IsPerfectSquare(discr)
				if !ts.Equals(ln.BigNOne) && z.Add(s, ts).Mod(z, ln.BigTwo).Equals(ln.BigZero) {
					// We found d, pack the private key.
					t.PackGivenP(ln.FindPGivenD(d, t.Key.PublicKey.E, t.Key.N))
					return nil
				}
			}
		}
	}

	if t.Verbose {
		log.Printf("%s attack failed, trying the the next variant", name)
	}

	// Try the variant approach.
	return wiener2.Attack(ts)
}
