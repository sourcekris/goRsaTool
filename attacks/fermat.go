package attacks

import (
  "fmt"
  "math/big"
)

func (targetRSA *RSAStuff) FermatFactorization() {
  if targetRSA.Key.D != nil {
    return
  }

  a  := new(big.Int).Sqrt(targetRSA.Key.N)
  b  := new(big.Int).Set(a)
  b2 := new(big.Int).Mul(a, a)
  b2.Sub(b2, targetRSA.Key.N)

  bigOne := big.NewInt(1)

  c := new(big.Int).Mul(b,b)

  for c.Cmp(b2) != 0 {
    a.Add(a, bigOne)
    b2.Mul(a,a).Sub(b2, targetRSA.Key.N)
    b.Sqrt(b2)
    c.Mul(b,b)
  }

  targetRSA.PackGivenP(new(big.Int).Add(a,b))
  fmt.Printf("[+] Factors found with fermat\n")
}