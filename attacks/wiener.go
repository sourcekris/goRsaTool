package attacks

import (
  "fmt"
  "github.com/ncw/gmp"
  "github.com/sourcekris/goRsaTool/libnum"
  "github.com/sourcekris/goRsaTool/utils"
)

func (targetRSA *RSAStuff) Wiener() {
  if targetRSA.Key.D != nil {
    return
  }

  frac := libnum.RationalToContfract(targetRSA.Key.PublicKey.E, targetRSA.Key.N)
  convergants := libnum.ConvergantsFromContfract(frac)

  // define some reusable constant gmp.Ints
  bigNegOne := gmp.NewInt(-1)
  bigZero := gmp.NewInt(0)
  bigOne := gmp.NewInt(1)
  bigTwo := gmp.NewInt(2)
  bigFour := gmp.NewInt(4)

  z := new(gmp.Int)

  for _, g := range convergants {
    k := g[0]
    d := g[1]
    

    if k.Cmp(bigZero) != 0 && z.Mul(d,targetRSA.Key.PublicKey.E).Sub(z,bigOne).Mod(z,k).Cmp(bigZero) == 0 {
      phi := new(gmp.Int).Set(z.Mul(d,targetRSA.Key.PublicKey.E).Sub(z,bigOne).Div(z,k))  // phi = (e*d-1)//k
      s   := new(gmp.Int).Set(z.Sub(targetRSA.Key.N,phi).Add(z, bigOne))  // s = n - phi + 1
      discr := new(gmp.Int).Set(z.Mul(s,s).Sub(z,new(gmp.Int).Mul(bigFour, targetRSA.Key.N))) // discr = s*s - 4*n
      if discr.Sign() >= 0 {
        t := libnum.IsPerfectSquare(discr)
        if t.Cmp(bigNegOne) != 0 && z.Add(s,t).Mod(z,bigTwo).Cmp(bigZero) == 0 {
          p := utils.FindPGivenD(d, targetRSA.Key.PublicKey.E, targetRSA.Key.N)
          targetRSA.PackGivenP(p)
          fmt.Printf("d = %d\np = %d\nq = %d\n", targetRSA.Key.D, targetRSA.Key.Primes[0], targetRSA.Key.Primes[1])
        }
      }
    }
  }
}

