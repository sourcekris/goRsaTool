package knownprime

import (
	"fmt"
	"log"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "knownprime"

// Attack implements the knownprime attack.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		return nil
	}

	if t.Key.Primes == nil {
		return fmt.Errorf("%s attack failed, no prime provided. Use the -p flag or provide a 'p = ' field in the key", name)
	}

	// Sanity check the prime is actually a factor of n.
	f := new(fmp.Fmpz).Mod(t.Key.N, t.Key.Primes[0])
	if f.Cmp(ln.BigZero) != 0 {
		return fmt.Errorf("provided prime is not a factor of n: p %% n = %v", f)
	}

	if t.Verbose {
		log.Printf("%s attempt beginning", name)
	}

	t.PackGivenP(t.Key.Primes[0])
	return nil
}
