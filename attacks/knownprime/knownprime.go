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
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		ch <- nil
		return
	}

	if t.Key.Primes == nil {
		ch <- fmt.Errorf("%s attack failed, no prime provided. Use the -p flag or provide a 'p = ' field in the key", name)
		return
	}

	// Sanity check the prime is actually a factor of n.
	f := new(fmp.Fmpz).Mod(t.Key.N, t.Key.Primes[0])
	if f.Cmp(ln.BigZero) != 0 {
		ch <- fmt.Errorf("provided prime is not a factor of n: p %% n = %v", f)
		return
	}

	if t.Verbose {
		log.Printf("%s attempt beginning", name)
	}

	t.PackGivenP(t.Key.Primes[0])
	ch <- nil
}
