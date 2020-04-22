package attacks

import (
	ln "github.com/sourcekris/goRsaTool/libnum"
	fmp "github.com/sourcekris/goflint"
)

// Hastads attack.
func Hastads(t *RSAStuff) error {
	if t.Key.D != nil || t.Key.PublicKey.E.Cmp(ln.BigEleven) > 0 || len(t.CipherText) == 0 {
		return nil
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

	return nil
}
