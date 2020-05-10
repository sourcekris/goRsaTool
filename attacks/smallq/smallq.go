package smallq

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "small q"

// go seems so fast making small primes we can probably make this much larger
const maxprimeint = 100000000

// Attack iterate small primes < maxprimeint and test them as factors of N at a memory cost.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		return nil
	}

	primes := ln.SieveOfEratosthenesFmp(maxprimeint)
	modp := new(fmp.Fmpz)

	for _, p := range primes {
		modp = modp.Mod(t.Key.N, p)
		if modp.Cmp(ln.BigZero) == 0 {
			t.PackGivenP(p)
			return nil
		}
	}

	return fmt.Errorf("%s failed - no factors found", name)
}
