package attacks

import (
  "fmt"
  "github.com/ncw/gmp"
  "github.com/sourcekris/goRsaTool/libnum"
)

func (targetRSA *RSAStuff) Hastads() {
  if targetRSA.Key.D != nil || targetRSA.Key.E > 11  || len(targetRSA.CipherText) == 0 {
    return
  }

  c := libnum.BytesToNumber(targetRSA.CipherText)
  bigE := gmp.NewInt(int64(targetRSA.Key.E))

  m := new(gmp.Int)
  pow := new(gmp.Int)

  original := new(gmp.Int).Set(c)

  count := 0

  for {
    m.Set(libnum.NthRoot(int64(targetRSA.Key.E), c))
    pow.Exp(m, bigE, targetRSA.Key.N)

    if pow.Cmp(original) == 0 {
      targetRSA.PlainText = libnum.NumberToBytes(m)
      return
    } 

    count++

    if count == 1000 {
      fmt.Printf("hit 1000\n")
      return
    }

    c.Add(c, targetRSA.Key.N)
  }

  return
}