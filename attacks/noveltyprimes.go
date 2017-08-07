package attacks

import (
  "fmt"
  "math/big"
  "strings"
  "github.com/sourcekris/goRsaTool/utils"
  )

const maxnoveltylen = 25

func NoveltyPrimes(targetRSA *RSAStuff) {
  if targetRSA.Key.D != nil {
    return
  }
  
  modp := new(big.Int)
  bigZero := big.NewInt(0)

  for i := 0; i < (maxnoveltylen-4); i++ {
    prime := "3133" + strings.Repeat("3", i) + "7"
    p, _  := new(big.Int).SetString(prime,10)
    modp   = modp.Mod(targetRSA.Key.N, p)

    if modp.Cmp(bigZero) == 0 {
      fmt.Printf("[+] Novelty Factor found: %d\n", p)
      key_q := new(big.Int).Div(targetRSA.Key.N, p)
      targetRSA.Key.Primes = []*big.Int{p, key_q}
      targetRSA.Key.D      = utils.SolveforD(p, key_q, targetRSA.Key.E)


      return
    }
  }
}