package pollardsp1

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

const (
	startA = 7
	startB = 65536
)

// primeSieve finds Fmpz type primes less than argument n.
var primeSieve = ln.SieveOfEratosthenesFmp

// Attack implements the Pollards P minus 1 factorization technique. This technique was used in
// BostonKeyParty 2017 challenge "RSA Buffet".
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	// Solution based on https://github.com/HackThisSite/ Python solution.
	// Solution is derived from the work here: https://math.berkeley.edu/~sagrawal/su14_math55/notes_pollard.pdf
	n := k.Key.N

	primes := primeSieve(startB)

	a := fmp.NewFmpz(int64(startA))
	b := fmp.NewFmpz(int64(startB))

	for _, x := range primes {
		tmp := fmp.NewFmpz(int64(1))
		for tmp.Cmp(b) < 0 {
			a.Exp(a, x, n)
			tmp.Mul(tmp, x)
		}
	}
	d := ln.FindGcd(a.Sub(a, ln.BigOne), n)
	if d.Cmp(n) == 0 {
		return fmt.Errorf("unable to factor key with a of: %d (try another a?)", startA)
	}

	if d.Cmp(ln.BigOne) > 0 {
		// Success
		k.PackGivenP(d)
		return nil
	}

	return fmt.Errorf("unable to factor key with b of: %d", startB)
}
