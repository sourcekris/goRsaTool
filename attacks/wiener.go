package attacks

import (
  fmp "github.com/sourcekris/goflint"
  ln "github.com/sourcekris/goRsaTool/libnum"
)

/*
 * conduct wiener's attack [0] based on the python implementation of the algorithm by Pablo Celayes [1]
 * [0]: https://en.wikipedia.org/wiki/Wiener%27s_attack
 * [1]: https://github.com/pablocelayes/rsa-wiener-attack
 */

func (targetRSA *RSAStuff) Wiener() {
  if targetRSA.Key.D != nil {
    return
  }

  frac := ln.RationalToContfract(targetRSA.Key.PublicKey.E, targetRSA.Key.N)
  convergants := ln.ConvergantsFromContfract(frac)

  z := new(fmp.Fmpz)

  for _, g := range convergants {
    k := g[0]
    d := g[1]

    if k.Cmp(ln.BigZero) != 0 && z.Mul(d,targetRSA.Key.PublicKey.E).Sub(z,ln.BigOne).Mod(z,k).Cmp(ln.BigZero) == 0 {
      phi := new(fmp.Fmpz).Set(z.Mul(d,targetRSA.Key.PublicKey.E).Sub(z, ln.BigOne).Div(z,k))      // phi = (e*d-1)//k
      s   := new(fmp.Fmpz).Set(z.Sub(targetRSA.Key.N,phi).Add(z, ln.BigOne))                      // s = n - phi + 1
      discr := new(fmp.Fmpz).Set(z.Mul(s,s).Sub(z,new(fmp.Fmpz).Mul(ln.BigFour, targetRSA.Key.N))) // discr = s*s - 4*n
      if discr.Sign() >= 0 {
        t := ln.IsPerfectSquare(discr)
        if t.Cmp(ln.BigNOne) != 0 && z.Add(s,t).Mod(z,ln.BigTwo).Cmp(ln.BigZero) == 0 {
          // We found d, pack the private key
          targetRSA.PackGivenP(ln.FindPGivenD(d, targetRSA.Key.PublicKey.E, targetRSA.Key.N))
        }
      }
    }
  }
}

