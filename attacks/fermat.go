package attacks

import (
	"fmt"

	ln "github.com/sourcekris/goRsaTool/libnum"
	fmp "github.com/sourcekris/goflint"
)

// FermatFactorization attack.
func FermatFactorization(t *RSAStuff) error {
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
	fmt.Printf("[+] Factors found with fermat\n")

	return nil
}
