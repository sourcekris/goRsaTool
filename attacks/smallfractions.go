package attacks

import (
	"fmt"

	ln "github.com/sourcekris/goRsaTool/libnum"
	fmp "github.com/sourcekris/goflint"
)

// SmallFractions attack.
func SmallFractions(t *RSAStuff) error {
	if t.Key.D != nil {
		return nil
	}

	// TODO(sewid): Does this stuff even work?
	depth := 50
	//t := t.Key.N.BitLen()

	r := new(fmp.Fmpz)
	fDen := new(fmp.Fmpz)
	fNum := new(fmp.Fmpz)

	// fmt.Printf("n: %s\nt: %d\ndepth: %d\n", t.Key.N, depth, t)

	for den := 2; den < depth+1; den++ {
		for num := 1; num < den; num++ {
			fDen.SetInt64(int64(den))
			fNum.SetInt64(int64(num))

			g := new(fmp.Fmpz).GCD(fDen, fNum)

			if g.Cmp(ln.BigOne) == 0 {
				phint := r.Mul(fDen, t.Key.N).Div(r, fNum).Sqrt(r)

				// need to find the small roots of phint
				//fmt.Printf("phint: %s\n", phint)
				dMaybe := new(fmp.Fmpz).ModInverse(t.Key.PublicKey.E, phint)
				pMaybe := ln.FindPGivenD(dMaybe, t.Key.PublicKey.E, t.Key.N)

				fmt.Printf("pmaybe:%s\n", pMaybe)
				if pMaybe.Cmp(ln.BigZero) > 0 {
					fmt.Printf("p: %s\n", pMaybe)

					return nil
				}
			}
		}
	}
	//t.PackGivenP(new(fmp.Fmpz).Add(a,b))
	//fmt.Printf("[+] Factors found with fermat\n")
	return nil
}

/*

p = 0

for den in xrange(2, depth+1):
  for num in xrange(1, den):
    if libnum.gcd(num, den) == 1:
      r = den/num
      phint = libnum.nroot(n * r, 2)

      print phint
*/
