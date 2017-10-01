package attacks

import (
  "fmt"
  fmp "github.com/sourcekris/goflint"
  ln "github.com/sourcekris/goRsaTool/libnum"
)

func (targetRSA *RSAStuff) FermatFactorization() {
  if targetRSA.Key.D != nil {
    return
  }

  a  := new(fmp.Fmpz).Sqrt(targetRSA.Key.N)
  b  := new(fmp.Fmpz).Set(a)
  b2 := new(fmp.Fmpz).Mul(a, a)
  b2.Sub(b2, targetRSA.Key.N)

  c := new(fmp.Fmpz).Mul(b,b)

  for c.Cmp(b2) != 0 {
    a.Add(a, ln.BigOne)
    b2.Mul(a,a).Sub(b2, targetRSA.Key.N)
    b.Sqrt(b2)
    c.Mul(b,b)
  }

  targetRSA.PackGivenP(new(fmp.Fmpz).Add(a,b))
  fmt.Printf("[+] Factors found with fermat\n")
}