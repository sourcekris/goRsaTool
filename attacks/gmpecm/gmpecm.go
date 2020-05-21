package gmpecm

import (
	"context"
	"fmt"
	"time"

	"github.com/sourcekris/goRsaTool/ln"

	"github.com/sourcekris/goRsaTool/keys"

	fmp "github.com/sourcekris/goflint"
	ecm "github.com/sourcekris/gogmpecm"
)

// timeout puts a limit on how long gmpecm should attempt to find a solution.
var timeout = time.Minute * 5

// name is the name of this attack.
const name = "gmp-ecm elliptic curve factorization"

// Attack implements the common factors method against moduli in multiple keys.
func Attack(ks []*keys.RSA) error {
	var (
		k   = ks[0]
		ch  = make(chan bool)
		ctx = context.Background()
		res = new(ecm.Mpz)
	)

	n, ok := new(ecm.Mpz).SetString(k.Key.N.String(), 10)
	if !ok {
		return fmt.Errorf("%s failed to construct an Mpz from modulus", name)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	p := ecm.NewParams()
	go func() {
		var err error
		res, err = p.Factor(n)
		if err != nil {
			ch <- false
			return
		}

		ch <- true
		return
	}()

	select {
	case <-ch:
		ff, ok := new(fmp.Fmpz).SetString(res.String(), 10)
		if !ok {
			return fmt.Errorf("%s failed to parse the factor: %q", name, res.String())
		}
		if ff.Cmp(ln.BigZero) > 0 {
			k.PackGivenP(ff)
			return nil
		}
	case <-ctx.Done():
		return fmt.Errorf("%s failed - no factors found", name)
	}

	return fmt.Errorf("%s was unable to factor the key", name)
}
