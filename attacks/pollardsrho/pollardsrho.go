package pollardsrho

import (
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// Attack uses Pollard's Rho factorization method.
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	var (
		state = new(fmp.FlintRandT)
		x     = ln.GetRand(state, k.Key.N)
		c     = ln.GetRand(state, k.Key.N)
		y     = new(fmp.Fmpz).Set(x)
		g     = fmp.NewFmpz(1)
	)

	for g.Cmp(ln.BigOne) == 0 {
		x.Mul(x, x).Mod(x, k.Key.N).Add(x, c).Mod(x, k.Key.N)
		y.Mul(y, y).Mod(y, k.Key.N).Add(y, c).Mod(y, k.Key.N)
		y.Mul(y, y).Mod(y, k.Key.N).Add(y, c).Mod(y, k.Key.N)
		g = ln.FindGcd(new(fmp.Fmpz).Abs(new(fmp.Fmpz).Sub(x, y)), k.Key.N)
	}

	k.PackGivenP(g)

	return nil
}
