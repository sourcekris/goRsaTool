package manysmallprimes

import (
	"log"

	"github.com/jbarham/primegen"
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "manysmallprimes"

// Attack iterates small primes until we timeout and test them as factors of N.
func Attack(ts []*keys.RSA, ch chan error) {

	var (
		p         = primegen.New()
		primeList []*fmp.Fmpz
		t         = ts[0]
	)

	if t.Key.D != nil {
		ch <- nil
		return
	}

	if t.Verbose {
		log.Printf("%s attempt beginning", name)
	}

	for {
		pc := new(fmp.Fmpz)
		modp := new(fmp.Fmpz)
		for {
			pc.SetUint64(p.Next())
			if modp.Mod(t.Key.N, pc).Equals(ln.BigZero) {
				primeList = append(primeList, new(fmp.Fmpz).Set(pc))
				if len(primeList) == t.NumPrimes {
					if t.Verbose {
						log.Printf("found these primes %v", primeList)
					}
					if err := t.PackMultiPrime(primeList); err != nil {

						ch <- err
						return
					}
					ch <- nil
					return
				}
			}
		}
	}
}
