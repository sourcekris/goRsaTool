package crt

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "crt solver"

// Attack solves for a plaintext given a ciphertext and the CRT components Dp, Dq, p, q.
func Attack(ks []*keys.RSA) error {
	k := ks[0]

	// We need values in the precomputer portion of the key for this attack.
	if k.Key.Precomputed == nil {
		return fmt.Errorf("%s failed - Precomputed values (Dp, Dq, etc) is not in key %s", name, k.KeyFilename)
	}

	// If we only got 1 prime, deduce the 2nd prime from N/p = q
	if len(k.Key.Primes) == 1 && k.Key.N != nil {
		k.Key.Primes = append(k.Key.Primes, new(fmp.Fmpz).Div(k.Key.N, k.Key.Primes[0]))
	}

	if len(k.Key.Primes) < 2 {
		return fmt.Errorf("%s failed - need two primes", name)
	}

	if k.CipherText == nil {
		return fmt.Errorf("%s failed - no ciphertext provided", name)
	}

	pp := new(fmp.Fmpz).Sub(k.Key.Primes[0], ln.BigOne)
	pp.Div(pp, ln.BigFour)

	qq := new(fmp.Fmpz).Sub(k.Key.Primes[1], ln.BigOne)
	qq.Div(qq, ln.BigFour)

	mrs := [][]*fmp.Fmpz{
		{new(fmp.Fmpz).Mod(k.Key.Precomputed.Dp, ln.BigFour), fmp.NewFmpz(4)},
		{new(fmp.Fmpz).Mod(k.Key.Precomputed.Dp, pp), pp},
		{new(fmp.Fmpz).Mod(k.Key.Precomputed.Dq, qq), qq},
	}

	d := ln.SolveCRT(mrs)
	n := new(fmp.Fmpz).Mul(k.Key.Primes[0], k.Key.Primes[1])

	k.PlainText = ln.NumberToBytes(new(fmp.Fmpz).Exp(ln.BytesToNumber(k.CipherText), d, n))

	if len(k.PlainText) > 0 {
		return nil
	}

	return fmt.Errorf("%s failed", name)
}
