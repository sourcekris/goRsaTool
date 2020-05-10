package pollardrhobrent

import (
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// Attack conducts Pollard's Rho method Richard Brent variant for factoring
// large composites. See: https://maths-people.anu.edu.au/~brent/pd/rpb051i.pdf
func Attack(kks []*keys.RSA) error {
	kk := kks[0]

	var (
		x     = new(fmp.Fmpz)
		ys    = new(fmp.Fmpz)
		g     = new(fmp.Fmpz).Set(kk.Key.N)
		state = new(fmp.FlintRandT)
	)

	for g.Cmp(kk.Key.N) == 0 {
		y := ln.GetRand(state, kk.Key.N)
		c := ln.GetRand(state, kk.Key.N)
		m := ln.GetRand(state, kk.Key.N)
		r := fmp.NewFmpz(1)
		q := fmp.NewFmpz(1)
		g.SetInt64(1)

		for g.Cmp(ln.BigOne) == 0 {
			x.Set(y)
			k := fmp.NewFmpz(0)
			counter := fmp.NewFmpz(0)
			for counter.Cmp(r) < 0 {
				y.Mul(y, y).Add(y, c).Mod(y, kk.Key.N)
				counter.Add(counter, ln.BigOne)
			}
			for k.Cmp(r) < 0 && g.Cmp(ln.BigOne) == 0 {
				ys = new(fmp.Fmpz).Set(y)
				min := ln.FmpzMin(m, new(fmp.Fmpz).Sub(r, k))
				counter.Set(ln.BigZero)
				for counter.Cmp(min) < 0 {
					y.Mul(y, y).Add(y, c).Mod(y, kk.Key.N)
					q.Mul(q, new(fmp.Fmpz).Abs(new(fmp.Fmpz).Sub(x, y))).Mod(q, kk.Key.N)
					counter.Add(counter, ln.BigOne)
				}
				g = ln.FindGcd(q, kk.Key.N)
				k.Add(k, m)
			}
			r.Mul(r, ln.BigTwo)
		}

		if g.Cmp(kk.Key.N) == 0 {
			for {
				ys.Mul(ys, ys).Add(ys, c).Mod(ys, kk.Key.N)
				g = ln.FindGcd(new(fmp.Fmpz).Abs(new(fmp.Fmpz).Sub(x, ys)), kk.Key.N)
				if g.Cmp(ln.BigOne) > 0 {
					break
				}
			}
		}
	}

	kk.PackGivenP(g)
	return nil
}
