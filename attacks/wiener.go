package attacks

import (
  "fmt"
  "github.com/sourcekris/goRsaTool/libnum"
  "github.com/ncw/gmp"
)

func (targetRSA *RSAStuff) Wiener() {
  if targetRSA.Key.D != nil {
    return
  }
  e := gmp.NewInt(int64(targetRSA.Key.PublicKey.E))
  frac := libnum.RationalToContfract(e, targetRSA.Key.N)
  fmt.Println(frac)
}
