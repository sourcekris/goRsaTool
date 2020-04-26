package smallq

import (
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// go seems so fast making small primes we can probably make this much larger
const maxprimeint = 1000000

// Attack iterate small primes < maxprimeint and test them as factors of N at a memory cost.
func Attack(t *keys.RSA) error {
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

	return nil
}
