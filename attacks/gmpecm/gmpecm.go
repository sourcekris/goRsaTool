package gmpecm

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/ln"

	"github.com/sourcekris/goRsaTool/keys"

	fmp "github.com/sourcekris/goflint"
	ecm "github.com/sourcekris/gogmpecm"
)

// name is the name of this attack.
const name = "gmp-ecm elliptic curve factorization"

// Attack implements the elliptic curve factorization attack against public keys.
func Attack(ks []*keys.RSA, ch chan error) {
	var (
		k   = ks[0]
		res = new(ecm.Mpz)
	)

	n, ok := new(ecm.Mpz).SetString(k.Key.N.String(), 10)
	if !ok {
		ch <- fmt.Errorf("%s failed to construct an Mpz from modulus", name)
		return
	}

	p := ecm.NewParams()
	res, err := p.Factor(n)
	if err != nil {
		ch <- err
		return
	}

	ff, ok := new(fmp.Fmpz).SetString(res.String(), 10)
	if !ok {
		ch <- fmt.Errorf("%s failed to parse the factor: %q", name, res.String())
		return
	}
	if ff.Cmp(ln.BigZero) > 0 {
		k.PackGivenP(ff)
		ch <- nil
		return
	}

	ch <- fmt.Errorf("%s was unable to factor the key", name)
}
