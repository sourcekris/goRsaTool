package attacks

import (
  "math/big"
  "github.com/sourcekris/goRsaTool/libnum"
)

func (targetRSA *RSAStuff) Hastads() {
  if targetRSA.Key.D != nil || targetRSA.Key.E > 11  || len(targetRSA.CipherText) == 0 {
    return
  }

  c := libnum.BytesToNumber(targetRSA.CipherText)
  bigE := big.NewInt(int64(targetRSA.Key.E))

  m := new(big.Int)
  pow := new(big.Int)

  original := new(big.Int).Set(c)

  for {
    m.Set(libnum.NthRoot(int64(targetRSA.Key.E), c))
    pow.Exp(m, bigE, targetRSA.Key.N)

    if pow.Cmp(original) == 0 {
      targetRSA.PlainText = libnum.NumberToBytes(m)
      return
    } 

    c.Add(c, targetRSA.Key.N)
  }

  return
}