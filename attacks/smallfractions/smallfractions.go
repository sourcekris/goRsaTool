package smallfractions

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// Attack implements SmallFractions attack.
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	if k.Key.D != nil {
		return nil
	}

	var (
		depth    int64 = 50
		num, den int64
	)

	for den = 2; den < depth+1; den++ {
		for num = 1; num < den; num++ {
			g := new(fmp.Fmpz).GCD(fmp.NewFmpz(num), fmp.NewFmpz(den))

			if g.Cmp(ln.BigOne) == 0 {
				phint := new(fmp.Fmpz).Mul(k.Key.N, fmp.NewFmpz(num))
				phint.Mul(phint, fmp.NewFmpz(den)).Root(phint, 2)
				// fmt.Printf("phint: %s\n", phint)

				// // need to find the small roots of phint
				// //fmt.Printf("phint: %s\n", phint)
				dMaybe := new(fmp.Fmpz).ModInverse(k.Key.PublicKey.E, phint)
				pMaybe := ln.FindPGivenD(dMaybe, k.Key.PublicKey.E, k.Key.N)

				fmt.Printf("pmaybe:%s\n", pMaybe)
				if pMaybe.Cmp(ln.BigZero) > 0 {
					fmt.Printf("p: %s\n", pMaybe)
					return nil
				}
			}
		}
	}

	return nil
}
