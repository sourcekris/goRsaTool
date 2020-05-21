package mersenne

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "mersenne primes"

// mersenneExponents lists the 6th to 51st mersenne prime number exponents.
var mersenneExponents = []int{82589933, 77232917, 74207281, 57885161, 43112609, 42643801, 37156667,
	32582657, 30402457, 25964951, 24036583, 20996011, 13466917, 6972593, 3021377, 2976221, 1398269,
	1257787, 859433, 756839, 216091, 132049, 110503, 86243, 44497, 23209, 21701, 19937, 11213,
	9941, 9689, 4423, 4253, 3217, 2281, 2203, 1279, 607, 521, 127, 107, 89, 61, 31, 19, 17}

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
