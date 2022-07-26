package squaren

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "square n"

// Attack recovers the private key when N is square.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		ch <- nil
		return
	}

	p := new(fmp.Fmpz).Root(t.Key.N, 2)

	if new(fmp.Fmpz).Mul(p, p).Cmp(t.Key.N) != 0 {
		ch <- fmt.Errorf("%s failed - n is not square", name)
		return
	}

	t.Key.Primes = append(t.Key.Primes, p, p)
	phin := new(fmp.Fmpz).Mul(p, new(fmp.Fmpz).Sub(p, ln.BigOne))
	t.PackGivenD(new(fmp.Fmpz).ModInverse(t.Key.PublicKey.E, phin))

	ch <- nil
}
