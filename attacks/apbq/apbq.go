// Package abpq implements an rsa implementation against a ciphertext where we're
// given hints in the form of:
//
//   - hint1 = a * p + b * q
//   - hint2 = c * p + d * q
//
// and
//   - a < x
//   - c < y
//
// where x and y are small and can be brute forced (e.g. 4096)
//
// An example is in DUCTF 2023 apbq-rsa-i challenge: https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/crypto/apbq-rsa-i
package apbq

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

const name = "abpq"

// Attack implements the abpq method against a ciphertext.
func Attack(ks []*keys.RSA, ch chan error) {
	var x, y int64
	k := ks[0]
	if k.Hints == nil || len(k.Hints) < 2 {
		ch <- fmt.Errorf("invalid arguments for attack %s: this attack requires 2 hints", name)
		return
	}

	if k.BruteMax == 0 {
		ch <- fmt.Errorf("invalid arguments for attack %s: this attack requires a maximum value > 0 to brute force for x and y", name)
		return
	}

	for x = 1; x < k.BruteMax; x++ {
		for y = 1; y < k.BruteMax; y++ {
			kq := new(fmp.Fmpz).GCD(fmp.NewFmpz(x).MulZ(k.Hints[0]).SubZ(fmp.NewFmpz(y).MulZ(k.Hints[1])), k.Key.N)
			if kq.Cmp(ln.BigOne) > 0 {
				k.PackGivenP(kq)
				ch <- nil
				return
			}
		}
	}

	ch <- fmt.Errorf("%s was unable to factor the key", name)
}
