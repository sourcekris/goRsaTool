package attacks

import (
  "fmt"
  "github.com/ncw/gmp"
)

func (targetRSA *RSAStuff) FermatFactorization() {
  if targetRSA.Key.D != nil {
    return
  }

  a  := new(gmp.Int).Sqrt(targetRSA.Key.N)
  b  := new(gmp.Int).Set(a)
  b2 := new(gmp.Int).Mul(a, a)
  b2.Sub(b2, targetRSA.Key.N)

  bigOne := gmp.NewInt(1)

  c := new(gmp.Int).Mul(b,b)

  for c.Cmp(b2) != 0 {
    a.Add(a, bigOne)
    b2.Mul(a,a).Sub(b2, targetRSA.Key.N)
    b.Sqrt(b2)
    c.Mul(b,b)
  }

  targetRSA.PackGivenP(new(gmp.Int).Add(a,b))
  fmt.Printf("[+] Factors found with fermat\n")
}