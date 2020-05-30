package commonmodulus

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "common modulus"

// Attack implements the common modulus attack against two keys.
func Attack(ks []*keys.RSA) error {
	if len(ks) != 2 {
		return fmt.Errorf("%s attack expects exactly 2 keys - got %d keys", name, len(ks))
	}

	if ks[0].CipherText == nil || ks[1].CipherText == nil {
		return fmt.Errorf("%s attack requires each key be associated with a ciphertext", name)
	}

	if !ks[0].Key.N.Equals(ks[1].Key.N) {
		return fmt.Errorf("%s attack requires that both keys share the same modulus", name)
	}

	c1 := ln.BytesToNumber(ks[0].CipherText)
	c2 := ln.BytesToNumber(ks[1].CipherText)
	n := ks[0].Key.N

	_, u, v := ln.XGCD(ks[0].Key.PublicKey.E, ks[1].Key.PublicKey.E)

	var p1, p2 *fmp.Fmpz
	if u.Cmp(ln.BigZero) >= 0 {
		p1 = new(fmp.Fmpz).Exp(c1, u, n)
	} else {
		p1 = new(fmp.Fmpz).ModInverse(new(fmp.Fmpz).Exp(c1, new(fmp.Fmpz).Mul(u, ln.BigNOne), n), n)
	}

	if v.Cmp(ln.BigZero) >= 0 {
		p2 = new(fmp.Fmpz).Exp(c2, v, n)
	} else {
		p2 = new(fmp.Fmpz).ModInverse(new(fmp.Fmpz).Exp(c2, new(fmp.Fmpz).Mul(v, ln.BigNOne), n), n)
	}

	ks[0].PlainText = ln.NumberToBytes(new(fmp.Fmpz).Mul(p1, p2).ModZ(n))

	return nil
}
