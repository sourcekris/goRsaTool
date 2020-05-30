package fermat

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// timeout puts a limit on how long fermat should attempt to find a solution.
var timeout = time.Minute * 5

// name is the name of this attack.
const name = "fermat factorization"

func fermat(ch chan bool, a, b, b2, c, n *fmp.Fmpz) {
	for !c.Equals(b2) {
		a.Add(a, ln.BigOne)
		b2.Mul(a, a).Sub(b2, n)
		b.Sqrt(b2)
		c.Mul(b, b)
	}

	ch <- true
}

// Attack implements the Fermat Factorization attack.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		// Key already factored.
		return nil
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan bool)

	a := new(fmp.Fmpz).Sqrt(t.Key.N)
	b := new(fmp.Fmpz).Set(a)
	b2 := new(fmp.Fmpz).Mul(a, a)
	b2.Sub(b2, t.Key.N)

	c := new(fmp.Fmpz).Mul(b, b)

	if t.Verbose {
		log.Printf("%s attempt beginning with timeout %v", name, timeout)
	}

	go fermat(ch, a, b, b2, c, t.Key.N)

	select {
	case <-ch:
		t.PackGivenP(new(fmp.Fmpz).Add(a, b))
	case <-ctx.Done():
		return fmt.Errorf("%s failed to factorize the key in the given time", name)
	}

	return nil
}
