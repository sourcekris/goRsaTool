package attacks

import (
  "fmt"
  "github.com/sourcekris/goRsaTool/libnum"
)

func (targetRSA *RSAStuff) Wiener() {
  if targetRSA.Key.D != nil {
    return
  }

  frac := libnum.RationalToContfract(targetRSA.Key.PublicKey.E, targetRSA.Key.N)
  fmt.Println(frac)
}
