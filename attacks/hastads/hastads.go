package hastads

import (
	"fmt"
	"log"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "hastads"

// Attack implements the Hastads attack.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil || t.Key.PublicKey.E.Cmp(ln.BigEleven) > 0 {
		ch <- nil
		return
	}

	if t.CipherText == nil {
		ch <- fmt.Errorf("%s failed - ciphertext needs to be provided for this attack", name)
		return
	}

	c := ln.BytesToNumber(t.CipherText)
	pt := new(fmp.Fmpz)

	if t.Verbose {
		log.Printf("%s attempt beginning", name)
	}

	m := new(fmp.Fmpz)
	pow := new(fmp.Fmpz)
	original := new(fmp.Fmpz).Set(c)
	for {
		m.Root(c, int32(t.Key.PublicKey.E.Int64()))
		pow.Exp(m, t.Key.PublicKey.E, t.Key.N)

		if pow.Equals(original) {
			pt.Set(m)
			break
		}
		c.Add(c, t.Key.N)
	}

	t.PlainText = ln.NumberToBytes(pt)
	ch <- nil
}
