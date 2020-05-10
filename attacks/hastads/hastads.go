package hastads

import (
	"errors"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// Attack implements the Hastads attack.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil || t.Key.PublicKey.E.Cmp(ln.BigEleven) > 0 {
		return nil
	}

	if t.CipherText == nil {
		return errors.New("ciphertext needs to be provided for hastads attack")
	}

	c := ln.BytesToNumber(t.CipherText)
	m := new(fmp.Fmpz)
	pow := new(fmp.Fmpz)

	original := new(fmp.Fmpz).Set(c)

	for {
		m.Root(c, int32(t.Key.PublicKey.E.Int64()))
		pow.Exp(m, t.Key.PublicKey.E, t.Key.N)

		if pow.Cmp(original) == 0 {
			t.PlainText = ln.NumberToBytes(m)
			return nil
		}
		c.Add(c, t.Key.N)
	}
}
