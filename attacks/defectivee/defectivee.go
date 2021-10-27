// Package defectivee implements a common broken rsa implementation where e
// and phi(n) are not coprime by finding the root of unity modulo n.
// Given some n, and e we factor n for p and q.
// We find the totient = (p-1)*(q-1) but it is not coprime to e so RSA is
// defective since one ciphertext can have many correct solutions.
// An example was seen in BuckEye CTF 2021:
// https://github.com/cscosu/buckeyectf-2021/tree/master/crypto/defective_rsa/solve
package defectivee

import (
	"bytes"
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
	mp "github.com/sourcekris/mathparse"
)

const name = "defective e"

var rounds int64 = 500

func rootsOfUnity(e, phi, n *fmp.Fmpz, rounds int64) ([]*fmp.Fmpz, *fmp.Fmpz) {
	var (
		i     int64
		roots []*fmp.Fmpz
	)

	phiCoprime := new(fmp.Fmpz).Set(phi)

	for new(fmp.Fmpz).GCD(phiCoprime, e).Cmp(ln.BigOne) != 0 {
		phiCoprime.Div(phiCoprime, new(fmp.Fmpz).GCD(phiCoprime, e))
	}

OUTER:
	for i = 0; i < rounds; i++ {
		r := new(fmp.Fmpz).Exp(fmp.NewFmpz(i), phiCoprime, n)

		// Don't add duplicate roots.
		for _, root := range roots {
			if r.Cmp(root) == 0 {
				continue OUTER
			}
		}

		roots = append(roots, r)
	}

	return roots, phiCoprime
}

// Attack implements the defectivee method against RSA given at least one prime.
func Attack(ks []*keys.RSA) error {

	var (
		p, q *fmp.Fmpz
		// ms   []*fmp.Fmpz
	)

	k := ks[0]
	if k.Key.Primes == nil {
		return fmt.Errorf("%s attack requires the modulus to already be factored, provide at least one prime with -p flag", name)
	}

	if len(k.Key.Primes) == 1 {
		p = k.Key.Primes[0]
		q = new(fmp.Fmpz).Div(k.Key.N, p)

		if new(fmp.Fmpz).Mul(p, q).Cmp(k.Key.N) != 0 {
			return fmt.Errorf("%s failed. n is not the product of primes p and q", name)
		}
	}

	// TODO: Use a hueristic instead like, "are all of the bytes in m considered printable?"
	if k.KnownPlainText == nil {
		return fmt.Errorf("%s requires a crib, part of the plaintext, so we know when our solution is found (e.g. CTF flag format)", name)
	}

	e := new(fmp.Fmpz).Set(k.Key.PublicKey.E)
	n := new(fmp.Fmpz).Set(k.Key.N)
	c := new(fmp.Fmpz).Set(ln.BytesToNumber(k.CipherText))

	phi, _ := mp.Evalf("(%v-1)*(%v-1))", p, q)
	d := new(fmp.Fmpz).ModInverse(phi, e)

	if d.Cmp(ln.BigZero) != 0 {
		return fmt.Errorf("%s failed: e is probably co-prime to phi(n) since there exists an inverse modulus of e, phi(n): %v", name, d)
	}

	// Find e'th roots of unity modulo n.
	roots, phiCoprime := rootsOfUnity(e, phi, n, rounds)

	// Use phiCoprime to get one possible plaintext for c.
	d = new(fmp.Fmpz).ModInverse(e, phiCoprime)
	m := new(fmp.Fmpz).Exp(c, d, n)

	testC := new(fmp.Fmpz).Exp(m, e, n)
	if testC.Cmp(c) != 0 {
		return fmt.Errorf("%s failed to find a possible plaintext for the given ciphertext and key", name)
	}

	// Maybe the first m is the right one? If so pack the key and return.
	if bytes.HasPrefix(ln.NumberToBytes(m), k.KnownPlainText) {
		k.Key.D = new(fmp.Fmpz).Set(d)
		k.PlainText = ln.NumberToBytes(m)
		k.Key.Primes = append(k.Key.Primes, q)
		return nil
	}

	// Search the roots for a plaintext matching our crib.
	for _, root := range roots {
		mt := new(fmp.Fmpz).Mul(m, root).ModZ(n)
		if bytes.HasPrefix(ln.NumberToBytes(mt), k.KnownPlainText) {
			k.Key.D = new(fmp.Fmpz).Set(d)
			k.PlainText = ln.NumberToBytes(mt)
			k.Key.Primes = append(k.Key.Primes, q)
			return nil
		}
	}

	return nil
}
