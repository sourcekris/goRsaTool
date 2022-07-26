package hastadsbroadcast

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "hastads broadcast"

// Attack implements the hastads broadcast attack against three keys and their ciphertexts.
func Attack(ks []*keys.RSA, ch chan error) {
	// Check key parameters are compatible with the attack.
	if len(ks) < 2 {
		ch <- fmt.Errorf("%s attack requires 2+ public keys, got: %d", name, len(ks))
		return
	}
	for _, k := range ks {
		if k.CipherText == nil {
			ch <- fmt.Errorf("%s failed - supply ciphertext for each key", name)
			return
		}

		// It's possible this works for other small primes though.
		if k.Key.PublicKey.E.Cmp(ln.BigThree) > 0 {
			ch <- fmt.Errorf("%s failed - exponents should be 3 but key exponent is: %v", name, k.Key.PublicKey.E)
			return
		}
	}

	// Collect the ciphertexts and moduli into a slice of slices.
	var rns [][]*fmp.Fmpz
	for _, key := range ks {
		var ctn []*fmp.Fmpz
		ctn = append(ctn, ln.BytesToNumber(key.CipherText))
		ctn = append(ctn, key.Key.N)
		rns = append(rns, ctn)
	}
	k := len(ks)
	crt := ln.SolveCRT(rns)
	solution := new(fmp.Fmpz).Root(crt, int32(k))

	test := new(fmp.Fmpz).ExpXIM(solution, k, ks[0].Key.N)
	if test.Equals(ln.BytesToNumber(ks[0].CipherText)) {
		ks[0].PlainText = ln.NumberToBytes(solution)
		ch <- nil
		return
	}

	ch <- fmt.Errorf("%s attack failed", name)
}
