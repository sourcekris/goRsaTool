package attacks

import (
  "fmt"
  "math/big"
  //"github.com/sourcekris/goRsaTool/utils"
  "github.com/sourcekris/goRsaTool/libnum"
)

func NthRoot(k int64, n *big.Int) *big.Int {
  a    := new(big.Int)
  bigK := big.NewInt(k)
  u    := new(big.Int).Set(n)

  k1   := new(big.Int).Sub(bigK, big.NewInt(1))
  s    := new(big.Int).Add(n, big.NewInt(1))
  
  for u.Cmp(s) < 0 {
    s.Set(u)
    a.Mul(u, k1)
    u.Exp(u, k1, nil).Div(n, u).Add(a,u).Div(u, bigK)
  }

  return s
}

func (targetRSA *RSAStuff) Hastads() {
  if targetRSA.Key.D != nil || targetRSA.Key.E > 11  || len(targetRSA.CipherText) == 0 {
    return
  }

  c := libnum.BytesToNumber(targetRSA.CipherText)
  bigE := big.NewInt(int64(targetRSA.Key.E))
  fmt.Printf("c = %d\n",c)

  m := new(big.Int)
  pow := new(big.Int)

  for {
    m.Set(NthRoot(int64(targetRSA.Key.E), c))
    pow.Exp(m, bigE, targetRSA.Key.N)

    fmt.Printf("pow = %d\n",pow)
    if pow.Cmp(c) == 0 {
      targetRSA.PlainText = libnum.NumberToBytes(m)
      return
    } 

    c.Add(c, targetRSA.Key.N)

  }

  return
}