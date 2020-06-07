package dixons

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "dixon's factorization"

var (
	base = []*fmp.Fmpz{ln.BigTwo, ln.BigThree, ln.BigFive, ln.BigEleven,
		fmp.NewFmpz(13), fmp.NewFmpz(17), fmp.NewFmpz(19), fmp.NewFmpz(23)}
)

// Attack implements the Dixon's factorization method.
func Attack(ks []*keys.RSA) error {
	var (
		k = ks[0]
		n = k.Key.PublicKey.N
		i = new(fmp.Fmpz).Sqrt(n)
	)

	for i.Cmp(n) < 0 {
		for _, j := range base {
			lhs := new(fmp.Fmpz).ExpXIM(i, 2, n)
			rhs := new(fmp.Fmpz).ExpXIM(j, 2, n)

			if lhs.Equals(rhs) {
				f := new(fmp.Fmpz).GCD(new(fmp.Fmpz).Sub(i, j), n)
				if !f.Equals(ln.BigOne) {
					k.PackGivenP(f)
					return nil
				}
			}
		}

		i.AddI(1)
	}

	return fmt.Errorf("%s failed to find a factor", name)
}
