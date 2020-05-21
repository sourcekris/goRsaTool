package gmpecm

import (
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
	k := ks[0]

	n, ok := new(ecm.Mpz).SetString(k.Key.N.String(), 10)
	if !ok {
		return fmt.Errorf("%s failed to construct an Mpz from modulus", name)
	}

	p := ecm.NewParams()
	fac, err := p.Factor(n)
	if err != nil {
		return fmt.Errorf("%s failed to factor the key: %v", name, err)
	}

	ff, ok := new(fmp.Fmpz).SetString(fac.String(), 10)
	if !ok {
		return fmt.Errorf("%s failed to parse the factor: %q", name, fac.String())
	}

	if ff.Cmp(ln.BigZero) > 0 {
		k.PackGivenP(ff)
		return nil
	}

	return fmt.Errorf("%s was unable to factor the key", name)
}
