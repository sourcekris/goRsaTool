package attacks

import (
  "fmt"
  fmp "github.com/sourcekris/goflint"
  "github.com/kavehmz/prime"
  ln "github.com/sourcekris/goRsaTool/libnum"
)

// go seems so fast making small primes we can probably make this much larger
const maxprimeint = 1000000

/* 
 * iterate small primes < maxprimeint and test them as factors of N at a memory cost
 */
func (targetRSA *RSAStuff) SmallQ() {
  if targetRSA.Key.D != nil {
    return
  }

  primes  := prime.Primes(maxprimeint)
  modp    := new(fmp.Fmpz)

  for _, p := range primes {
    modp = modp.Mod(targetRSA.Key.N, fmp.NewFmpz(int64(p)))
    if modp.Cmp(ln.BigZero) == 0 {
      targetRSA.PackGivenP(fmp.NewFmpz(int64(p)))
      fmt.Printf("[+] Small q Factor found\n")
      return
    }
  }
}