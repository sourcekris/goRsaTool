package attacks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	ln "github.com/sourcekris/goRsaTool/libnum"
	fmp "github.com/sourcekris/goflint"
)

// PastCTFPrimes attack.
func PastCTFPrimes(t *RSAStuff) error {
	if t.Key.D != nil {
		return nil
	}

	var primes []fmp.Fmpz

	file, err := os.Open(t.PastPrimesFile)
	if err != nil {
		return err
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
		if modp.Cmp(ln.BigZero) == 0 {
			t.PackGivenP(&p)

			fmt.Printf("[+] Past CTF prime factor found.\n")
			return nil
		}
	}

	return nil
}
