package attacks

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strings"
	"crypto/rsa"
	"github.com/sourcekris/goRsaTool/utils"
	)

func PastCTFPrimes(pubKey *rsa.PrivateKey, pastctffile string) {
	var primes []big.Int

	file, err := os.Open(pastctffile)
	if err != nil {
		fmt.Printf("[-] Error opening past CTF primes file: %s\n", pastctffile)
		return
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") && len(strings.Trim(line, "\n\r")) != 0 {
			tmp_p, _ := new(big.Int).SetString(line, 10)
			primes = append(primes, *tmp_p)
		}
	}

	modp := new(big.Int)
	bigZero := big.NewInt(0)

	for _, p := range primes {
		modp = modp.Mod(pubKey.N, &p)
		if modp.Cmp(bigZero) == 0 {
			key_p := &p
			key_q := new(big.Int).Div(pubKey.N, key_p)
			pubKey.Primes = []*big.Int{key_p, key_q}
			pubKey.D      = utils.SolveforD(key_p, key_q, pubKey.E)
			
			fmt.Printf("[+] Past CTF prime factor found: %d\n", key_p)
			return
		}
	}
}