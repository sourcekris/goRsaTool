package attacks

import (
  "fmt"
  "github.com/ncw/gmp"
  "github.com/kavehmz/prime"
)

// go seems so fast making small primes we can probably make this much larger
const maxprimeint = 100000

/* 
 * iterate small primes < maxprimeint and test them as factors of N at a memory cost
 */
func (targetRSA *RSAStuff) SmallQ() {
  if targetRSA.Key.D != nil {
    return
  }

  primes  := prime.Primes(maxprimeint)
  modp    := new(gmp.Int)
  bigZero := gmp.NewInt(0)

  for _, p := range primes {
    modp = modp.Mod(targetRSA.Key.N, gmp.NewInt(int64(p)))
    if modp.Cmp(bigZero) == 0 {
      targetRSA.PackGivenP(gmp.NewInt(int64(p)))
      fmt.Printf("[+] Small q Factor found\n")
      return
    }
  }
}