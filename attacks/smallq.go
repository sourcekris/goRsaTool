package attacks

import (
  "fmt"
  "math/big"
  "github.com/kavehmz/prime"
  "github.com/sourcekris/goRsaTool/utils"
)

// go seems so fast making small primes we can probably make this much larger
const maxprimeint = 100000

/* 
 * iterate small primes < maxprimeint and test them as factors of N at a memory cost
 */
func SmallQ(targetRSA *RSAStuff) {
  if targetRSA.Key.D != nil {
    return
  }

  primes  := prime.Primes(maxprimeint)
  modp    := new(big.Int)
  bigZero := big.NewInt(0)

  for _, p := range primes {
    modp = modp.Mod(targetRSA.Key.N, big.NewInt(int64(p)))
    if modp.Cmp(bigZero) == 0 {
      fmt.Printf("[+] Small q Factor found: %d\n", p)
      key_p := big.NewInt(int64(p))
      key_q := new(big.Int)
      key_q  = key_q.Div(targetRSA.Key.N, key_p)
      targetRSA.Key.Primes = []*big.Int{key_p, key_q}
      targetRSA.Key.D      = utils.SolveforD(key_p, key_q, targetRSA.Key.E)

      return
    }
  }
}