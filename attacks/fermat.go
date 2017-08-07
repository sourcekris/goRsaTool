package attacks

import (
  "fmt"
  "math/big"
  "github.com/sourcekris/goRsaTool/utils"
)

func (targetRSA *RSAStuff) FermatFactorization() {
  if targetRSA.Key.D != nil {
    return
  }

  a  := new(big.Int).Sqrt(targetRSA.Key.N)
  b  := new(big.Int).Sqrt(targetRSA.Key.N)
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

  key_p := new(big.Int).Add(a,b)
  key_q := new(big.Int).Sub(a,b)
  targetRSA.Key.Primes = []*big.Int{key_p, key_q}
  targetRSA.Key.D      = utils.SolveforD(key_p, key_q, targetRSA.Key.E)

  fmt.Printf("[+] Factors found with fermat\n")

}