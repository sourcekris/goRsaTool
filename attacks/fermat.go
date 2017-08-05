package attacks

import (
  "fmt"
  "math/big"
  "crypto/rsa"
  "github.com/sourcekris/goRsaTool/utils"
)

func FermatFactorization(pubKey *rsa.PrivateKey) {
  if pubKey.D != nil {
    return
  }

  a  := new(big.Int).Sqrt(pubKey.N)
  b  := new(big.Int).Sqrt(pubKey.N)
  b2 := new(big.Int).Mul(a, a)
  b2.Sub(b2, pubKey.N)

  bigOne := big.NewInt(1)

  c := new(big.Int).Mul(b,b)

  for c.Cmp(b2) != 0 {
    a.Add(a, bigOne)
    b2.Mul(a,a).Sub(b2, pubKey.N)
    b.Sqrt(b2)
    c.Mul(b,b)
  }

  key_p := new(big.Int).Add(a,b)
  key_q := new(big.Int).Sub(a,b)
  pubKey.Primes = []*big.Int{key_p, key_q}
  pubKey.D      = utils.SolveforD(key_p, key_q, pubKey.E)

  fmt.Printf("[+] Factors found with fermat\n")

}