// Package brokenrsa implements a common broken rsa implementation against a ciphertext. In
// this case it is when multiplication is used instead of exponentiation. e.g.
// c = me mod n vs. c=m^e mod n
// An example is in RaRCTF 2021 sRSA challenge: https://ctftime.org/task/16900
package brokenrsa

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

const name = "brokenrsa"

// Attack implements the brokenrsa method against ciphertext in multiple keys.
func Attack(ks []*keys.RSA, ch chan error) {

	k := ks[0]
	if k.CipherText == nil {
		ch <- fmt.Errorf("invalid arguments for attack %s: this attack requires the ciphertext", name)
		return
	}
	d, u, _ := ln.XGCD(k.Key.PublicKey.E, k.Key.N)
	if !d.Equals(ln.BigOne) {
		ch <- fmt.Errorf("n and e were not coprime so %s attack will not work: GCE(e,n) == %v", name, d)
		return
	}

	ct := ln.BytesToNumber(k.CipherText)
	pt := new(fmp.Fmpz).Mul(ct, u)
	k.PlainText = ln.NumberToBytes(pt.Mod(pt, k.Key.N))

	ch <- nil
}
