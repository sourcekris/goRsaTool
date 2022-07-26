package commonfactor

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "common factors"

// Attack implements the common factors method against moduli in multiple keys.
func Attack(ks []*keys.RSA, ch chan error) {
	for _, i := range ks {
		for _, j := range ks {
			if i.Key.N == j.Key.N {
				continue
			}

			g := new(fmp.Fmpz).GCD(i.Key.N, j.Key.N)
			if g.Cmp(ln.BigOne) > 0 {
				i.PackGivenP(g)
				j.PackGivenP(g)

				ch <- nil
				return
			}
		}
	}
	ch <- fmt.Errorf("%s was unable to factor the keys", name)
}
