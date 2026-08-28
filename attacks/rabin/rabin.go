// Package rabin implements a solver for the Rabin Cryptosystem.
//
// The Rabin cryptosystem is an asymmetric cryptographic technique published in 1979
// by Michael O. Rabin. It is computationally related to RSA with public exponent e = 2.
//
// Cryptosystem overview:
//   - Key generation: Two large distinct primes p and q are chosen, typically Blum primes
//     where p ≡ 3 (mod 4) and q ≡ 3 (mod 4). The public key modulus is n = p * q.
//     The public exponent is fixed at e = 2.
//   - Encryption: Given a message m in {0, ..., n-1}, the ciphertext c is computed as:
//     c = m^2 mod n
//   - Decryption: Decryption requires computing modular square roots of c modulo n.
//     Since factoring n into p and q is equivalent to finding square roots modulo n,
//     decryption requires knowledge of the factors p and q:
//     1. Compute square roots modulo p: m_p = sqrt(c) mod p.
//        For Blum primes (p ≡ 3 mod 4), this has the closed-form solution:
//        m_p = c^((p+1)/4) mod p
//        For other odd primes, the Tonelli-Shanks algorithm is used.
//     2. Compute square roots modulo q: m_q = sqrt(c) mod q.
//        m_q = c^((q+1)/4) mod q
//     3. Use the Extended Euclidean Algorithm (Bézout's identity) to find yp, yq such that:
//        yp * p + yq * q = gcd(p, q) = 1
//     4. Use the Chinese Remainder Theorem (CRT) to combine the solutions (±m_p, ±m_q),
//        yielding 4 candidate square roots modulo n:
//        r1 = (yp * p * m_q + yq * q * m_p) mod n
//        r2 = n - r1
//        r3 = (yp * p * m_q - yq * q * m_p) mod n
//        r4 = n - r3
//     5. The true plaintext is identified from the 4 candidates by matching known cribs
//        (k.KnownPlainText), common CTF flag formats (e.g. "flag{", "FLAG{", "ctf{"),
//        or printable ASCII text heuristics.
package rabin

import (
	"bytes"
	"fmt"
	"log"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "rabin"

// isPrintableASCII returns true if all bytes in b are printable ASCII characters or standard whitespace.
func isPrintableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if (c < 32 || c > 126) && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}

// tonelliShanks computes a square root of n modulo an odd prime p.
func tonelliShanks(n, p *fmp.Fmpz) (*fmp.Fmpz, error) {
	c := new(fmp.Fmpz).Mod(n, p)
	if c.IsZero() {
		return fmp.NewFmpz(0), nil
	}

	if c.Jacobi(p) == -1 {
		return nil, fmt.Errorf("number is not a quadratic residue modulo prime")
	}

	pMinus1 := new(fmp.Fmpz).Sub(p, ln.BigOne)
	q := new(fmp.Fmpz).Set(pMinus1)
	s := 0
	for new(fmp.Fmpz).Mod(q, ln.BigTwo).IsZero() {
		q.Div(q, ln.BigTwo)
		s++
	}

	if s == 1 {
		// p = 3 mod 4: sqrt(c) mod p = c^((p+1)/4) mod p
		exp := new(fmp.Fmpz).Add(p, ln.BigOne)
		exp.Div(exp, ln.BigFour)
		return new(fmp.Fmpz).Exp(c, exp, p), nil
	}

	// Find a quadratic non-residue z modulo p.
	z := fmp.NewFmpz(2)
	for z.Jacobi(p) != -1 {
		z.AddI(1)
	}

	m := s
	cVal := new(fmp.Fmpz).Exp(z, q, p)
	t := new(fmp.Fmpz).Exp(c, q, p)
	rExp := new(fmp.Fmpz).Div(new(fmp.Fmpz).Add(q, ln.BigOne), ln.BigTwo)
	r := new(fmp.Fmpz).Exp(c, rExp, p)

	for {
		if t.IsZero() {
			return fmp.NewFmpz(0), nil
		}
		if t.Equals(ln.BigOne) {
			return r, nil
		}

		// Find least i (0 < i < m) such that t^(2^i) == 1 mod p
		i := 0
		tmp := new(fmp.Fmpz).Set(t)
		for i = 1; i < m; i++ {
			tmp.Mul(tmp, tmp).ModZ(p)
			if tmp.Equals(ln.BigOne) {
				break
			}
		}
		if i == m {
			return nil, fmt.Errorf("tonelli-shanks: no root found")
		}

		// b = cVal^(2^(m - i - 1)) mod p
		bExp := new(fmp.Fmpz).Exp(ln.BigTwo, fmp.NewFmpz(int64(m-i-1)), nil)
		b := new(fmp.Fmpz).Exp(cVal, bExp, p)

		m = i
		cVal.Mul(b, b).ModZ(p)
		t.Mul(t, cVal).ModZ(p)
		r.Mul(r, b).ModZ(p)
	}
}

// modSqrt computes the modular square root of c modulo prime p.
func modSqrt(c, p *fmp.Fmpz) (*fmp.Fmpz, error) {
	cMod := new(fmp.Fmpz).Mod(c, p)
	if cMod.IsZero() {
		return fmp.NewFmpz(0), nil
	}

	if cMod.Jacobi(p) == -1 {
		return nil, fmt.Errorf("ciphertext is not a quadratic residue modulo prime %v", p)
	}

	// Closed form for Blum primes: p ≡ 3 (mod 4)
	pMod4 := new(fmp.Fmpz).Mod(p, ln.BigFour)
	if pMod4.Equals(ln.BigThree) {
		exp := new(fmp.Fmpz).Add(p, ln.BigOne)
		exp.Div(exp, ln.BigFour)
		return new(fmp.Fmpz).Exp(cMod, exp, p), nil
	}

	return tonelliShanks(cMod, p)
}

// selectPlaintext selects the best candidate plaintext matching cribs, flag patterns, or printable ASCII.
func selectPlaintext(candidates []*fmp.Fmpz, knownPrefix []byte) ([]byte, error) {
	var (
		printableCandidates [][]byte
		flagPatterns        = [][]byte{[]byte("flag{"), []byte("FLAG{"), []byte("ctf{"), []byte("CTF{")}
	)

	for _, cand := range candidates {
		pt := ln.NumberToBytes(cand)

		// 1. If known plaintext crib is provided, check if it matches.
		if len(knownPrefix) > 0 && bytes.Contains(pt, knownPrefix) {
			return pt, nil
		}

		// 2. Check for standard CTF flag formats.
		for _, fp := range flagPatterns {
			if bytes.Contains(pt, fp) {
				return pt, nil
			}
		}

		// 3. Collect candidates with printable ASCII characters.
		if isPrintableASCII(pt) {
			printableCandidates = append(printableCandidates, pt)
		}
	}

	if len(printableCandidates) > 0 {
		return printableCandidates[0], nil
	}

	if len(candidates) > 0 {
		return ln.NumberToBytes(candidates[0]), nil
	}

	return nil, fmt.Errorf("no valid plaintext candidate found")
}

// Attack implements the Rabin Cryptosystem attack for public exponent e = 2.
func Attack(ks []*keys.RSA, ch chan error) {
	k := ks[0]

	if k.Key.PublicKey.E == nil || !k.Key.PublicKey.E.Equals(ln.BigTwo) {
		ch <- fmt.Errorf("%s failed: public exponent e must be 2 (got %v)", name, k.Key.PublicKey.E)
		return
	}

	if k.CipherText == nil || len(k.CipherText) == 0 {
		ch <- fmt.Errorf("%s failed: ciphertext needs to be provided for this attack", name)
		return
	}

	if len(k.Key.Primes) == 0 {
		ch <- fmt.Errorf("%s attack requires the modulus to be factored, provide at least one prime with -p flag or in key file", name)
		return
	}

	var p, q *fmp.Fmpz
	if len(k.Key.Primes) == 1 {
		p = k.Key.Primes[0]
		q = new(fmp.Fmpz).Div(k.Key.N, p)

		if new(fmp.Fmpz).Mul(p, q).Cmp(k.Key.N) != 0 || new(fmp.Fmpz).Mod(k.Key.N, p).Cmp(ln.BigZero) != 0 {
			ch <- fmt.Errorf("%s failed: provided prime p is not a factor of n", name)
			return
		}
		k.Key.Primes = append(k.Key.Primes, q)
	} else {
		p = k.Key.Primes[0]
		q = k.Key.Primes[1]

		if new(fmp.Fmpz).Mul(p, q).Cmp(k.Key.N) != 0 {
			ch <- fmt.Errorf("%s failed: product of primes p and q does not equal n", name)
			return
		}
	}

	if p.Cmp(q) == 0 {
		ch <- fmt.Errorf("%s failed: primes p and q cannot be equal", name)
		return
	}

	if k.Verbose {
		log.Printf("%s attack beginning", name)
	}

	c := ln.BytesToNumber(k.CipherText)
	n := k.Key.N

	// 1. Compute modular square roots mp and mq modulo p and q.
	mp, err := modSqrt(c, p)
	if err != nil {
		ch <- fmt.Errorf("%s failed: %w", name, err)
		return
	}

	mq, err := modSqrt(c, q)
	if err != nil {
		ch <- fmt.Errorf("%s failed: %w", name, err)
		return
	}

	// 2. Use Extended Euclidean Algorithm: yp * p + yq * q = 1.
	_, yp, yq := ln.XGCD(p, q)

	// 3. Compute CRT terms:
	// a = yq * q * mp mod n
	// b = yp * p * mq mod n
	a := new(fmp.Fmpz).Mul(mp, yq)
	a.Mul(a, q).ModZ(n)

	b := new(fmp.Fmpz).Mul(mq, yp)
	b.Mul(b, p).ModZ(n)

	// 4. Generate the 4 candidate plaintexts:
	// r1 = (a + b) mod n
	r1 := new(fmp.Fmpz).Add(a, b).ModZ(n)
	if r1.Sign() < 0 {
		r1.Add(r1, n)
	}

	// r2 = (n - r1) mod n
	r2 := new(fmp.Fmpz).Sub(n, r1).ModZ(n)
	if r2.Sign() < 0 {
		r2.Add(r2, n)
	}

	// r3 = (a - b) mod n
	r3 := new(fmp.Fmpz).Sub(a, b).ModZ(n)
	if r3.Sign() < 0 {
		r3.Add(r3, n)
	}

	// r4 = (n - r3) mod n
	r4 := new(fmp.Fmpz).Sub(n, r3).ModZ(n)
	if r4.Sign() < 0 {
		r4.Add(r4, n)
	}

	candidates := []*fmp.Fmpz{r1, r2, r3, r4}

	if k.Verbose {
		for i, cand := range candidates {
			candBytes := ln.NumberToBytes(cand)
			log.Printf("%s candidate %d: int=%s str=%q printable=%v", name, i+1, cand, string(candBytes), isPrintableASCII(candBytes))
		}
	}

	pt, err := selectPlaintext(candidates, k.KnownPlainText)
	if err != nil {
		ch <- fmt.Errorf("%s failed: %w", name, err)
		return
	}

	k.PlainText = pt
	ch <- nil
}
