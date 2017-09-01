package attacks

import (
  "fmt"
  //"github.com/ncw/gmp"
  "github.com/sourcekris/goRsaTool/libnum"
)

func (targetRSA *RSAStuff) Wiener() {
  if targetRSA.Key.D != nil {
    return
  }

  frac := libnum.RationalToContfract(targetRSA.Key.PublicKey.E, targetRSA.Key.N)
  //fmt.Println(frac)
  convergants := libnum.ConvergantsFromContfract(frac)
  //_ = libnum.ConvergantsFromContfract(frac)
  fmt.Println(convergants)

  //for _, g := range convergants {
    //k := g[0]
    //d := g[1]
  //}
}
