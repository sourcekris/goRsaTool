package fermat

import (
	"log"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "fermat factorization"

// Attack implements the Fermat Factorization attack.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		// Key already factored.
		ch <- nil
		return
	}

	a := new(fmp.Fmpz).Sqrt(t.Key.N)
	b := new(fmp.Fmpz).Set(a)
	b2 := new(fmp.Fmpz).Mul(a, a)
	b2.Sub(b2, t.Key.N)

	if t.Verbose {
		log.Printf("%s attempt beginning", name)
	}
	c := new(fmp.Fmpz).Mul(b, b)
	for !c.Equals(b2) {
		a.Add(a, ln.BigOne)
		b2.Mul(a, a).Sub(b2, t.Key.N)
		b.Sqrt(b2)
		c.Mul(b, b)
	}

	t.PackGivenP(new(fmp.Fmpz).Add(a, b))
	ch <- nil
}
