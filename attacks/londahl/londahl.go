// Package londahl implements Carl Löndahl's method of factorization for close primes and is based
// on code from RsaCtfTool https://github.com/grocid/CTF and Carl's CTF writeups
// https://github.com/grocid/CTF
package londahl

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// timeout puts a limit on how long we should attempt to find a solution.
var timeout = time.Minute * 5

// name is the name of this attack.
const name = "londahl"

func factorizeNPhi(n, phi *fmp.Fmpz) (*fmp.Fmpz, *fmp.Fmpz) {
	m := new(fmp.Fmpz).Sub(n, phi).AddI(1)
	i := new(fmp.Fmpz).Root(new(fmp.Fmpz).Sub(new(fmp.Fmpz).ExpXI(m, 2), new(fmp.Fmpz).Mul(n, ln.BigFour)), 2)
	rootOne := new(fmp.Fmpz).Sub(m, i).Rsh(1)
	rootTwo := new(fmp.Fmpz).Add(m, i).Rsh(1)

	if new(fmp.Fmpz).Mul(rootOne, rootTwo).Cmp(n) == 0 {
		return rootOne, rootTwo
	}

	return nil, nil
}

func londahl(ch chan bool, n, p *fmp.Fmpz, b int64) {
	var lookup = make(map[string]int64)

	phiApprox := new(fmp.Fmpz).Add(new(fmp.Fmpz).Sub(n, new(fmp.Fmpz).Mul(new(fmp.Fmpz).Root(n, 2), ln.BigTwo)), ln.BigOne)

	// Generate a lookup table, store the integers in string representations so we can use fast hash lookups.
	z := fmp.NewFmpz(1)
	for i := int64(0); i <= b; i++ {
		lookup[z.String()] = i
		z = z.Lsh(1).ModZ(n)
	}

	mu := new(fmp.Fmpz).ModInverse(new(fmp.Fmpz).Pow(ln.BigTwo, phiApprox, n), n)
	fac := new(fmp.Fmpz).ExpXIM(ln.BigTwo, int(b), n)

	for i := int64(0); i <= b; i++ {
		if v, ok := lookup[mu.String()]; ok {
			phi := new(fmp.Fmpz).Add(phiApprox, fmp.NewFmpz(v-(i*b)))
			r1, _ := factorizeNPhi(n, phi)
			if r1 != nil {
				p.Set(r1)
				ch <- true
				return
			}
		}

		mu = mu.Mul(mu, fac).ModZ(n)
	}
}

// Attack implements the Londahl attack.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		return nil
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan bool)

	// Create a pointer where we can store the result.
	p := new(fmp.Fmpz)

	// Boundary for the londahl attack.
	var b int64 = 20000000

	if t.Verbose {
		log.Printf("%s attempt beginning with timeout %v", name, timeout)
	}
	go londahl(ch, t.Key.N, p, b)

	select {
	case <-ch:
		t.PackGivenP(p)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s failed to recover the private key", name)
	}
}
