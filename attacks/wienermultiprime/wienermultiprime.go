package wienermultiprime

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

const name = "wiener multiprime"

// Attack implements the Wiener attack on an RSA public key where the modulus is composed of
// more than 2 primes.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		// Key already factored.
		ch <- nil
		return
	}

	// Encrypt something simple to validate our decryption later.
	m := fmp.NewFmpz(12345)
	c := new(fmp.Fmpz).Pow(m, t.Key.PublicKey.E, t.Key.N)

	q0 := fmp.NewFmpz(1)

	frac := ln.RationalToContfract(t.Key.PublicKey.E, t.Key.N)
	convergants := ln.ConvergantsFromContfract(frac)

	var r, s int64
	for _, g := range convergants {
		q1 := g[1] // denominator

		for r = 0; r < 20; r++ {
			for s = 0; s < 20; s++ {
				// d = r*q1 + s*q0
				d := new(fmp.Fmpz).Mul(fmp.NewFmpz(r), q1)
				d = d.Add(d, new(fmp.Fmpz).Mul(fmp.NewFmpz(s), q0))

				// Test decryption with our new d.
				m1 := new(fmp.Fmpz).Pow(c, d, t.Key.N)
				if m1.Cmp(m) == 0 {
					t.PackGivenD(d)
					ch <- nil
					return
				}
			}
			q0 = q0.Set(q1)
		}
	}

	ch <- fmt.Errorf("%s attack failed", name)
}
