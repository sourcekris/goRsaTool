package fermat

import (
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// Attack implements the Fermat Factorization attack.
func Attack(t *keys.RSA) error {
	if t.Key.D != nil {
		// Key already factored.
		return nil
	}

	a := new(fmp.Fmpz).Sqrt(t.Key.N)
	b := new(fmp.Fmpz).Set(a)
	b2 := new(fmp.Fmpz).Mul(a, a)
	b2.Sub(b2, t.Key.N)

	c := new(fmp.Fmpz).Mul(b, b)

	for c.Cmp(b2) != 0 {
		a.Add(a, ln.BigOne)
		b2.Mul(a, a).Sub(b2, t.Key.N)
		b.Sqrt(b2)
		c.Mul(b, b)
	}

	t.PackGivenP(new(fmp.Fmpz).Add(a, b))
	return nil
}
