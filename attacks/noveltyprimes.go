package attacks

import (
	"fmt"
	"strings"

	ln "github.com/sourcekris/goRsaTool/libnum"
	fmp "github.com/sourcekris/goflint"
)

const maxnoveltylen = 25

// NoveltyPrimes attack.
func NoveltyPrimes(t *RSAStuff) error {
	if t.Key.D != nil {
		return nil
	}

	modp := new(fmp.Fmpz)

	for i := 0; i < (maxnoveltylen - 4); i++ {
		p, _ := new(fmp.Fmpz).SetString("3133"+strings.Repeat("3", i)+"7", 10)
		modp.Mod(t.Key.N, p)

		if modp.Cmp(ln.BigZero) == 0 {
			t.PackGivenP(p)
			fmt.Printf("[+] Novelty Factor found.\n")
			return nil
		}
	}

	return nil
}
