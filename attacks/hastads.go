package attacks

import (
  "crypto/rsa"
  "fmt"
  // "math/big"
  "github.com/sourcekris/goRsaTool/utils"
  "github.com/sourcekris/goRsaTool/libnum"
)

func NthRoot(k int64, n *big.Int) *big.Int {
  k1   := new(big.Int).Sub(big.NewInt(k), big.NewInt(1))
  s    := new(big.Int).Add(n, big.NewInt(1))
  u    := new(big.Int).Set(n)
  bigK := big.NewInt(k)
  a    := new(big.Int)

  for u.Cmp(s) < 0 {
    s.Set(u)

    a.Mul(u, k1)
    u.Exp(u, k1, nil).Div(n, u).Add(a,u).Div(u, bigK)
  }

  return s
}

func Hastads(pubKey *rsa.PrivateKey, cipherFile string) {
  if pubKey.D != nil || pubKey.E > 11  || len(cipherFile) == 0 {
    return
  }

  cipherData, _ := utils.ReadCipherText(cipherFile)
  cipherInt     := libnum.BytesToNumber(cipherData)

  fmt.Printf("m = %d\n", cipherInt)

  // XXX: todo, finish this
  return
}