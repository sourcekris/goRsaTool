// Package londahl implements Carl Löndahl's method of factorization for close primes and is based
// on code from RsaCtfTool https://github.com/grocid/CTF and Carl's CTF writeups
// https://github.com/grocid/CTF
package londahl

import (
	"fmt"
	"hash/fnv"
	"log"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

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

func storeInt(z, n *fmp.Fmpz, m map[uint64]int64, i int64) {
	h := fnv.New64()
	h.Write(z.Bytes())
	m[h.Sum64()] = i
}

// Attack implements the Londahl attack.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		ch <- nil
		return
	}
	// Create a pointer where we can store the result.
	p := new(fmp.Fmpz)

	// Boundary for the londahl attack.
	var b int64 = 20000000

	if t.Verbose {
		log.Printf("%s attempt beginning", name)
	}

	var lookup = make(map[uint64]int64)
	phiApprox := new(fmp.Fmpz).Add(new(fmp.Fmpz).Sub(t.Key.N, new(fmp.Fmpz).Mul(new(fmp.Fmpz).Root(t.Key.N, 2), ln.BigTwo)), ln.BigOne)
	// Generate a lookup table, store just the fnv hash of the integer to save memory.
	z := fmp.NewFmpz(1)
	for i := int64(0); i <= b; i++ {
		storeInt(z, t.Key.N, lookup, i)
		z = z.Lsh(1).ModZ(t.Key.N)
	}

	mu := new(fmp.Fmpz).ModInverse(new(fmp.Fmpz).Pow(ln.BigTwo, phiApprox, t.Key.N), t.Key.N)
	fac := new(fmp.Fmpz).ExpXIM(ln.BigTwo, int(b), t.Key.N)

	for i := int64(0); i <= b; i++ {
		h := fnv.New64()
		h.Write(mu.Bytes())
		if v, ok := lookup[h.Sum64()]; ok {
			phi := new(fmp.Fmpz).Add(phiApprox, fmp.NewFmpz(v-(i*b)))
			r1, _ := factorizeNPhi(t.Key.N, phi)
			if r1 != nil {
				p.Set(r1)
				t.PackGivenP(p)
				ch <- nil
				return
			}
		}

		mu = mu.Mul(mu, fac).ModZ(t.Key.N)
	}

	ch <- fmt.Errorf("%s failed to recover the private key", name)
}
