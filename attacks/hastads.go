package attacks

import (
  fmp "github.com/sourcekris/goflint"
  ln "github.com/sourcekris/goRsaTool/libnum"
)

func (targetRSA *RSAStuff) Hastads() {
  if targetRSA.Key.D != nil || targetRSA.Key.PublicKey.E.Cmp(ln.BigEleven) > 0  || len(targetRSA.CipherText) == 0 {
    return
  }

  c := ln.BytesToNumber(targetRSA.CipherText)

  m := new(fmp.Fmpz)
  pow := new(fmp.Fmpz)

  original := new(fmp.Fmpz).Set(c)

  for {
    m.Root(c, int32(targetRSA.Key.PublicKey.E.Int64()))
    pow.Exp(m, targetRSA.Key.PublicKey.E, targetRSA.Key.N)

    if pow.Cmp(original) == 0 {
      targetRSA.PlainText = ln.NumberToBytes(m)
      return
    } 
    c.Add(c, targetRSA.Key.N)
  }

  return
}