package notableprimes

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "notable primes"

// mersenneExponents lists the 6th to 51st mersenne prime number exponents.
var mersenneExponents = []int{17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253,
	4423, 9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839,
	859433, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951,
	30402457, 32582657, 37156667, 42643801, 43112609, 57885161, 74207281, 77232917, 82589933}

// TODO(kris): Add lucas, phi, GF and other notable primes.
// TODO(kris): Roll noveltyprimes into this module.

// Attack checks the key modulus to see if it factors with any mersenne primes.
func Attack(ks []*keys.RSA) error {
	k := ks[0]

	for _, me := range mersenneExponents {
		// mp = 2^me - 1
		mp := new(fmp.Fmpz).ExpXI(ln.BigTwo, me).SubZ(ln.BigOne)
		if new(fmp.Fmpz).Mod(k.Key.N, mp).Equals(ln.BigZero) {
			k.PackGivenP(mp)
			return nil
		}
	}

	return fmt.Errorf("%s was unable to factor the key", name)
}
