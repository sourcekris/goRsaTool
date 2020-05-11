package hastads

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// timeout puts a limit on how long we should attempt to find a solution.
var timeout = time.Minute * 5

// name is the name of this attack.
const name = "hastads"

func hastads(ch chan bool, n, e, c, pt *fmp.Fmpz) {
	m := new(fmp.Fmpz)
	pow := new(fmp.Fmpz)
	original := new(fmp.Fmpz).Set(c)

	for {
		m.Root(c, int32(e.Int64()))
		pow.Exp(m, e, n)

		if pow.Cmp(original) == 0 {
			pt.Set(m)
			ch <- true
			return
		}
		c.Add(c, n)
	}
}

// Attack implements the Hastads attack.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil || t.Key.PublicKey.E.Cmp(ln.BigEleven) > 0 {
		return nil
	}

	if t.CipherText == nil {
		return fmt.Errorf("%s failed - ciphertext needs to be provided for this attack", name)
	}

	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan bool)

	c := ln.BytesToNumber(t.CipherText)
	pt := new(fmp.Fmpz)

	if t.Verbose {
		log.Printf("%s attempt beginning with timeout %v", name, timeout)
	}
	go hastads(ch, t.Key.N, t.Key.PublicKey.E, c, pt)

	select {
	case <-ch:
		t.PlainText = ln.NumberToBytes(pt)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s failed to recover the plaintext", name)
	}
}
