package manysmallprimes

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jbarham/primegen"
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// timeout puts a limit on how long we should attempt to find the factors.
var timeout = time.Minute * 3

// name is the name of this attack.
const name = "manysmallprimes"

// Global primegen.
var (
	p         = primegen.New()
	primeList []*fmp.Fmpz
)

func smallq(ch chan bool, n, pc *fmp.Fmpz) {
	modp := new(fmp.Fmpz)
	for {
		pc.SetUint64(p.Next())
		if modp.Mod(n, pc).Equals(ln.BigZero) {
			ch <- true
			return
		}
	}
}

// reset will reset the global state each Attack run.
func reset() {
	p = primegen.New()
	primeList = nil
}

// Attack iterates small primes until we timeout and test them as factors of N.
func Attack(ts []*keys.RSA) error {

	reset()

	t := ts[0]
	if t.Key.D != nil {
		return nil
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan bool)

	if t.Verbose {
		log.Printf("%s attempt beginning with timeout %v", name, timeout)
	}

	for {
		pc := new(fmp.Fmpz)
		go smallq(ch, t.Key.N, pc)

		select {
		case <-ch:
			primeList = append(primeList, new(fmp.Fmpz).Set(pc))
			if t.Verbose {
				log.Printf("found prime %v (%d / %d)", pc, len(primeList), t.NumPrimes)
			}
			if len(primeList) == t.NumPrimes {
				if t.Verbose {
					log.Printf("found these primes %v", primeList)
				}
				if err := t.PackMultiPrime(primeList); err != nil {
					return err
				}
				return nil
			}
		case <-ctx.Done():
			return fmt.Errorf("%s failed - didnt find %d factors - found %d - last prime tried %v", name, t.NumPrimes, len(primeList), pc)
		}
	}
}
