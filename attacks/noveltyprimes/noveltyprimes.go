package noveltyprimes

import (
	"fmt"
	"strings"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

const maxnoveltylen = 25

// name is the name of this attack.
const name = "novelty primes"

// Attack implements the NoveltyPrimes attack.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		return nil
	}

	modp := new(fmp.Fmpz)

	for i := 0; i < (maxnoveltylen - 4); i++ {
		p, _ := new(fmp.Fmpz).SetString("3133"+strings.Repeat("3", i)+"7", 10)
		modp.Mod(t.Key.N, p)

		if modp.Cmp(ln.BigZero) == 0 {
			t.PackGivenP(p)
			return nil
		}
	}

	return fmt.Errorf("%s attack failed", name)
}
