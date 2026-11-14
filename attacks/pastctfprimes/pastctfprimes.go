package pastctfprimes

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "past ctf primes"

// Attack implements the PastCTFPrimes attack.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		ch <- nil
		return
	}

	var primes []fmp.Fmpz

	file, err := os.Open(t.PastPrimesFile)
	if err != nil {
		ch <- err
		return
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "#") && len(line) != 0 {
			if tmpP, ok := new(fmp.Fmpz).SetString(line, 10); ok {
				primes = append(primes, *tmpP)
			}
		}
	}

	modp := new(fmp.Fmpz)

	for _, p := range primes {
		modp = modp.Mod(t.Key.N, &p)
		if modp.Equals(ln.BigZero) {
			t.PackGivenP(&p)
			ch <- nil
			return
		}
	}

	ch <- fmt.Errorf("%s attack failed", name)
}
