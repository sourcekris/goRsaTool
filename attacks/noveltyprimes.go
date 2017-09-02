package attacks

import (
  "fmt"
  "strings"

  "github.com/ncw/gmp"
  ln "github.com/sourcekris/goRsaTool/libnum"
  )

const maxnoveltylen = 25

func (targetRSA *RSAStuff) NoveltyPrimes() {
  if targetRSA.Key.D != nil {
    return
  }
  
  modp := new(gmp.Int)

  for i := 0; i < (maxnoveltylen-4); i++ {
    p, _  := new(gmp.Int).SetString("3133" + strings.Repeat("3", i) + "7",10)
    modp.Mod(targetRSA.Key.N, p)

    if modp.Cmp(ln.BigZero) == 0 {
      targetRSA.PackGivenP(p)
      fmt.Printf("[+] Novelty Factor found.\n")
      return
    }
  }
}