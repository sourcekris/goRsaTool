package attacks

import (
	"fmt"
	"math/big"
	"strings"
	"crypto/rsa"
	"github.com/sourcekris/goRsaTool/utils"
	)

const maxnoveltylen = 25

func NoveltyPrimes(pubKey *rsa.PrivateKey) {
	modp := new(big.Int)
	bigZero := big.NewInt(0)

	for i := 0; i < (maxnoveltylen-4); i++ {
		prime := "3133" + strings.Repeat("3", i) + "7"
		p := new(big.Int)
		p,_ = p.SetString(prime,10)
		modp = modp.Mod(pubKey.N, p)

		if modp.Cmp(bigZero) == 0 {
			fmt.Printf("[+] Novelty Factor found: %d\n", p)
			key_q := new(big.Int)
			key_q  = key_q.Div(pubKey.N, p)
			pubKey.Primes = []*big.Int{p, key_q}
			pubKey.D      = utils.SolveforD(p, key_q, pubKey.E)

			return
		}
	}
}