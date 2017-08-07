package attacks

import (
  "fmt"
  "math/big"
  "strings"
  )

const maxnoveltylen = 25

func (targetRSA *RSAStuff) NoveltyPrimes() {
  if targetRSA.Key.D != nil {
    return
  }
  
  modp := new(big.Int)
  bigZero := big.NewInt(0)

  for i := 0; i < (maxnoveltylen-4); i++ {
    p, _  := new(big.Int).SetString("3133" + strings.Repeat("3", i) + "7",10)
    modp.Mod(targetRSA.Key.N, p)

    if modp.Cmp(bigZero) == 0 {
      targetRSA.PackGivenP(p)
      fmt.Printf("[+] Novelty Factor found.\n")
      return
    }
  }
}