package smallq

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

// timeout puts a limit on how long we should attempt to find a factor.
var timeout = time.Minute * 3

// name is the name of this attack.
const name = "small q"

func smallq(ch chan bool, n, pc *fmp.Fmpz) {

	p := primegen.New()
	modp := new(fmp.Fmpz)
	for {
		pc.SetUint64(p.Next())
		if modp.Mod(n, pc).Cmp(ln.BigZero) == 0 {
			ch <- true
			return
		}
	}
}

// Attack iterate small primes until we timeout and test them as factors of N.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		return nil
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	p := new(fmp.Fmpz)
	ch := make(chan bool)

	if t.Verbose {
		log.Printf("%s attempt beginning with timeout %v", name, timeout)
	}
	go smallq(ch, t.Key.N, p)

	select {
	case <-ch:
		t.PackGivenP(p)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s failed - no factors found - last prime tried %v", name, p)
	}
}
