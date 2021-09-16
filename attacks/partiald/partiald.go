// Package partiald implements an attack against the private exponent of RSA when >= 50% of the LSB of d are known.
package partiald

import (
	"fmt"
	"log"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "partiald"

// Attack implements the Partial D attack.
func Attack(ts []*keys.RSA) error {

	// Validate all the parameters are sane.
	t := ts[0]
	if t.Key.D != nil {
		return nil
	}

	if t.DLSB == nil {
		return fmt.Errorf("%s failed - supply the LSB of 'd' using the -partiald flag or a 'd0 = ' field in the key", name)
	}

	if t.Verbose {
		log.Printf("%s attempt beginning for e = %v", name, t.Key.PublicKey.E)
	}

	if t.Key.PublicKey.E.Cmp(fmp.NewFmpz(65537)) > 0 {
		log.Printf("%s warning - e > 65537 (%v) this might be a slow attack...", name, t.Key.PublicKey.E)
	}

	d0 := new(fmp.Fmpz).SetBytes(t.DLSB)
	d0bits := d0.BitLen()

	a := new(fmp.Fmpz).Add(t.Key.N, ln.BigOne)
	a = a.Div(a, t.Key.PublicKey.E)
	abits := t.Key.N.BitLen() - a.BitLen()

	// Do the attack...
	for k := fmp.NewFmpz(1); k.Cmp(t.Key.PublicKey.E) <= 0; k.Add(k, ln.BigOne) {
		// Approximate d.
		d := new(fmp.Fmpz).Mul(k, t.Key.N)
		d = d.Add(d, ln.BigOne)
		d = d.Div(d, t.Key.PublicKey.E)

		// Replace the LSB of d by the known value
		d1 := fmp.NewFmpz(1).Lsh(d0bits)
		d1 = d1.Mod(d, d1).Xor(d, d1)
		d = d.Xor(d1, d0)

		// do we have enough bits in our approximation to try?
		for i := 0; fmp.NewFmpz(int64(i)).BitLen() <= abits; i++ {
			// brute force uncertain bits.
			bf := fmp.NewFmpz(int64(i)).Lsh(d0bits)
			d = d.Xor(d, bf)
			// test by encrypting and decrypting the integer 2.
			m := new(fmp.Fmpz).Pow(new(fmp.Fmpz).Pow(ln.BigTwo, t.Key.PublicKey.E, t.Key.N), d, t.Key.N)
			if m.Cmp(ln.BigTwo) == 0 {
				t.PackGivenP(ln.FindPGivenD(d, t.Key.PublicKey.E, t.Key.N))
				return nil
			}
		}
	}

	return fmt.Errorf("%s failed to recover the private key", name)
}
