package williamsp1

import (
	"github.com/jbarham/primegen"
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "william's p+1"

// Attack performs williams P+1 factorization.
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	p := primegen.New()
	v := fmp.NewFmpz(0)
	for {
		v.Add(v, ln.BigOne)
		for {
			pcursor := fmp.NewFmpz(int64(p.Next()))
			e := ln.ILog(new(fmp.Fmpz).Set(k.Key.N).Root(k.Key.N, 2), pcursor)
			if e.Equals(ln.BigZero) {
				break
			}
			count := fmp.NewFmpz(0)
			for count.Cmp(e) != 0 {
				v = ln.MLucas(v, pcursor, k.Key.N)
				count.Add(count, ln.BigOne)
			}

			g := ln.FindGcd(new(fmp.Fmpz).Set(v).Sub(v, ln.BigTwo), k.Key.N)
			if g.Cmp(ln.BigOne) > 0 && g.Cmp(k.Key.N) < 0 {
				// Found P.
				k.PackGivenP(g)
				return nil
			}

			if g.Equals(k.Key.N) {
				break
			}
		}
	}
}
