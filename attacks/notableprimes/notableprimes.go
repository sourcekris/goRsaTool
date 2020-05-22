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

// lucasPrimes are Lucas numbers from V(2) to V(1100) which are prime.
var lucasPrimes = []int{2, 4, 5, 7, 8, 11, 13, 16, 17, 19, 31, 37, 41, 47, 53, 61, 71, 79, 113, 313,
	353, 503, 613, 617, 863, 1097}

func lucasNumber(n int) *fmp.Fmpz {
	if n == 0 {
		return fmp.NewFmpz(2)
	}

	if n == 1 {
		return fmp.NewFmpz(1)
	}

	var a, b, c = fmp.NewFmpz(2), fmp.NewFmpz(1), fmp.NewFmpz(0)
	for i := 2; i <= n; i++ {
		c.Add(a, b)
		a.Set(b)
		b.Set(c)
	}

	return b
}

// TODO(kris): Add phi, GF and other notable primes.
// TODO(kris): Roll noveltyprimes into this module.

// Attack checks the key modulus to see if it factors with any mersenne primes.
func Attack(ks []*keys.RSA) error {
	k := ks[0]

	for _, me := range mersenneExponents {
		// mp = 2^me - 1
		mp := new(fmp.Fmpz).ExpXI(ln.BigTwo, me).SubZ(ln.BigOne)
		if mp.Cmp(k.Key.N) > 0 {
			break
		}

		if new(fmp.Fmpz).Mod(k.Key.N, mp).Equals(ln.BigZero) {
			k.PackGivenP(mp)
			return nil
		}
	}

	for _, lp := range lucasPrimes {
		lnum := lucasNumber(lp)
		if lnum.Cmp(k.Key.N) > 0 {
			break
		}

		if new(fmp.Fmpz).Mod(k.Key.N, lnum).Equals(ln.BigZero) {
			k.PackGivenP(lnum)
			return nil
		}
	}

	return fmt.Errorf("%s was unable to factor the key", name)
}
