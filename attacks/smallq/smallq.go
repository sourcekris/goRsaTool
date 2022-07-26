package smallq

import (
	"log"

	"github.com/jbarham/primegen"
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "small q"

func chk(p, n *fmp.Fmpz) (bool, *fmp.Fmpz) {
	zz := new(fmp.Fmpz).Set(p)
	if new(fmp.Fmpz).Mod(n, zz).Equals(ln.BigZero) {
		return true, zz
	}
	return false, nil
}

// Attack iterate small primes until we timeout and test them as factors of N.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		ch <- nil
		return
	}

	if t.Verbose {
		log.Printf("%s attempt beginning", name)
	}

	pc := new(fmp.Fmpz)
	pr := primegen.New()
	for {
		pc.SetUint64(pr.Next())
		if res, pp := chk(pc, t.Key.N); res {
			t.PackGivenP(pp)
			ch <- nil
			return
		}
	}
}
