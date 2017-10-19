package attacks

import (
  "fmt"
  fmp "github.com/sourcekris/goflint"
  ln "github.com/sourcekris/goRsaTool/libnum"
)

func (targetRSA *RSAStuff) SmallFractions() {
  if targetRSA.Key.D != nil {
    return
  }

  depth := 50
  t := targetRSA.Key.N.BitLen()
  //p := new(fmp.Fmpz)
  r := new(fmp.Fmpz)
  f_den := new(fmp.Fmpz)
  f_num := new(fmp.Fmpz)

  fmt.Printf("depth: %d\nt: %d\n", depth, t)

  for den := 2; den < depth + 1; den++ {
    for num := 1; num < den; num++ {
      f_den.SetInt64(int64(den))
      f_num.SetInt64(int64(num))

      g := new(fmp.Fmpz).GCD(f_den, f_num)

      if g.Cmp(ln.BigOne) == 0 {
        r.Div(f_den, f_num)
        phint := new(fmp.Fmpz).Sqrt(r.Mul(targetRSA.Key.N, r))

        d_maybe := new(fmp.Fmpz).ModInverse(targetRSA.Key.PublicKey.E, phint)
        p_maybe := ln.FindPGivenD(d_maybe, targetRSA.Key.PublicKey.E, targetRSA.Key.N)

        fmt.Printf("pmaybe:%s     %s\n", p_maybe, d_maybe)
        if p_maybe.Cmp(ln.BigZero) > 0 {
          fmt.Printf("p: %s\n", p_maybe)

          return
        }

        fmt.Printf("phint: %s\n", phint)
      }
    }
  }
  //targetRSA.PackGivenP(new(fmp.Fmpz).Add(a,b))
  //fmt.Printf("[+] Factors found with fermat\n")
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