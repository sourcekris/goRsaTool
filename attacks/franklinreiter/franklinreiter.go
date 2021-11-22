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

type sigAttack struct {
	cs []*fmp.Fmpz
	ss []*fmp.Fmpz
	n  *fmp.Fmpz
	e  int
}

// attempt runs the attack attempt itself.
func (s *sigAttack) attempt(v bool) []byte {
	// f = (x-s1+s2)^e - c1
	ctx := fmp.NewFmpzModCtx(s.n)
	f := fmp.NewFmpzModPoly(ctx).SetCoeffUI(1, 1)
	f.Sub(f, fmp.NewFmpzModPoly(ctx).SetCoeff(0, s.ss[1])).Add(f, fmp.NewFmpzModPoly(ctx).SetCoeff(0, s.ss[0])).Pow(f, s.e)
	f.Sub(f, fmp.NewFmpzModPoly(ctx).SetCoeff(0, s.cs[0]))

	// g = x^e-c2
	g := fmp.NewFmpzModPoly(ctx).SetCoeffUI(1, 1)
	g.Pow(g, s.e).Sub(g, fmp.NewFmpzModPoly(ctx).SetCoeff(0, s.cs[1]))

	a := fmp.NewFmpzModPoly(fmp.NewFmpzModCtx(f.GetMod())).Set(f)
	b := fmp.NewFmpzModPoly(fmp.NewFmpzModCtx(g.GetMod())).Set(g)

	zero := fmp.NewFmpzModPoly(ctx).Zero()
	rp := fmp.NewFmpzModPoly(ctx)

	if v {
		log.Printf("%s beginning, this can sometimes crash, try it again if it does.", name)
	}

	var r *fmp.FmpzModPoly
	for {
		_, r = a.DivRem(b)

		if r.Equal(zero) {
			co0 := rp.GetCoeff(0)
			co1 := rp.GetCoeff(1)

			q, _ := fmp.NewFmpzModPoly(ctx).SetCoeff(0, ln.BigOne).DivRem(fmp.NewFmpzModPoly(ctx).SetCoeff(0, co1))
			q.MulScalar(q, ln.BigNOne).MulScalar(q, co0)
			return ln.NumberToBytes(q.GetCoeff(0))
		}

		rp.Set(r)
		a.Set(b)
		b.Set(r)
	}
}

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

	sa := &sigAttack{n: ks[0].Key.N, e: ks[0].Key.PublicKey.E.GetInt()}
	for i := 0; i < 2; i++ {
		sa.ss = append(sa.ss, ln.BytesToNumber(ks[i].KnownPlainText))
		sa.cs = append(sa.cs, ln.BytesToNumber(ks[i].CipherText))
	}

	if res := sa.attempt(ks[0].Verbose); res != nil {
		ks[0].PlainText = res
		return nil
	}

	return fmt.Errorf("%s failed to recover the plaintext", name)
}
