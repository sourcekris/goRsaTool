package franklinreiter

import (
	"fmt"
	"log"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "franklin reiter related message attack"

// Attack implements the franklin reiter related message attack against two keys.
func Attack(ks []*keys.RSA) error {
	if len(ks) != 2 {
		return fmt.Errorf("%s requires exactly 2 keys to work - got %d", name, len(ks))
	}

	if ks[0].KnownPlainText == nil || ks[1].KnownPlainText == nil {
		return fmt.Errorf("%s requires each key has a corresponding known plaintext component", name)
	}

	if ks[0].CipherText == nil || ks[1].CipherText == nil {
		return fmt.Errorf("%s requires each key has a corresponding ciphertext", name)
	}

	c1 := ln.BytesToNumber(ks[0].CipherText)
	c2 := ln.BytesToNumber(ks[1].CipherText)
	s1 := ln.BytesToNumber(ks[0].KnownPlainText)
	s2 := ln.BytesToNumber(ks[1].KnownPlainText)
	e := ks[0].Key.PublicKey.E.GetInt()
	n := ks[0].Key.N

	// f = (x-s1+s2)^e - c1
	f := fmp.NewFmpzModPoly(n).SetCoeffUI(1, 1)
	f.Sub(f, fmp.NewFmpzModPoly(n).SetCoeff(0, s2)).Add(f, fmp.NewFmpzModPoly(n).SetCoeff(0, s1)).Pow(f, e)
	f.Sub(f, fmp.NewFmpzModPoly(n).SetCoeff(0, c1))

	// g = x^e-c2
	g := fmp.NewFmpzModPoly(n).SetCoeffUI(1, 1)
	g.Pow(g, e).Sub(g, fmp.NewFmpzModPoly(n).SetCoeff(0, c2))

	a := fmp.NewFmpzModPoly(f.GetMod()).Set(f)
	b := fmp.NewFmpzModPoly(g.GetMod()).Set(g)

	zero := fmp.NewFmpzModPoly(n).Zero()
	rp := fmp.NewFmpzModPoly(n)

	if ks[0].Verbose {
		log.Printf("%s beginning, this can sometimes crash, try it again if it does.", name)
	}

	var r *fmp.FmpzModPoly
	for {
		_, r = a.DivRem(b)

		if r.Equal(zero) {
			co0 := rp.GetCoeff(0)
			co1 := rp.GetCoeff(1)

			q, _ := fmp.NewFmpzModPoly(n).SetCoeff(0, ln.BigOne).DivRem(fmp.NewFmpzModPoly(n).SetCoeff(0, co1))
			q.MulScalar(q, ln.BigNOne).MulScalar(q, co0)
			ks[0].PlainText = ln.NumberToBytes(q.GetCoeff(0))
			return nil
		}

		rp.Set(r)
		a.Set(b)
		b.Set(r)
	}
}
