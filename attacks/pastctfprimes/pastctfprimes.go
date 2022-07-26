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
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") && len(strings.Trim(line, "\n\r")) != 0 {
			tmpP, _ := new(fmp.Fmpz).SetString(line, 10)
			primes = append(primes, *tmpP)
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
