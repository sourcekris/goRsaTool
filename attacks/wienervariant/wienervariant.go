// Package wienervariant implements Andrej Dujella's variant on Wiener's RSA attack.
// See: https://www.math.tugraz.at/~cecc08/abstracts/cecc08_abstract_20.pdf
package wienervariant

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "wiener variant"

// Attack performs a variant of the wiener attack by Andrej Dujella.
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	if k.Key.D != nil {
		return nil
	}

	var (
		q0    = fmp.NewFmpz(1)
		fakeM = fmp.NewFmpz(31337)
		fakeC = new(fmp.Fmpz).Exp(fakeM, k.Key.PublicKey.E, k.Key.N)
	)

	convergants := ln.ConvergantsFromContfract(ln.RationalToContfract(k.Key.PublicKey.E, k.Key.N))

	for _, c := range convergants {
		q1 := c[1]

		for r := 0; r <= 30; r++ {
			for s := 0; s <= 30; s++ {
				d := new(fmp.Fmpz).Set(q1).MulI(r).AddZ(new(fmp.Fmpz).Set(q0).MulI(s))
				mMaybe := new(fmp.Fmpz).Exp(fakeC, d, k.Key.N)
				if mMaybe.Equals(fakeM) {
					k.PackGivenP(ln.FindPGivenD(d, k.Key.PublicKey.E, k.Key.N))
					return nil
				}
			}
		}

		q0.Set(q1)
	}

	return fmt.Errorf("%s attack failed", name)
}
