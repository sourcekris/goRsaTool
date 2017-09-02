package attacks

import (
  "bufio"
  "fmt"
  "os"
  "strings"

  "github.com/ncw/gmp"
  ln "github.com/sourcekris/goRsaTool/libnum"
  )

func (targetRSA *RSAStuff) PastCTFPrimes() {
  if targetRSA.Key.D != nil {
    return
  }

  var primes []gmp.Int

  file, err := os.Open(targetRSA.PastPrimesFile)
  if err != nil {
    fmt.Printf("[-] Error opening past CTF primes file: %s\n", targetRSA.PastPrimesFile)
    return
  }

  defer file.Close()

  scanner := bufio.NewScanner(file)

  for scanner.Scan() {
    line := scanner.Text()
    if !strings.HasPrefix(line, "#") && len(strings.Trim(line, "\n\r")) != 0 {
      tmp_p, _ := new(gmp.Int).SetString(line, 10)
      primes = append(primes, *tmp_p)
    }
  }

  modp := new(gmp.Int)

  for _, p := range primes {
    modp = modp.Mod(targetRSA.Key.N, &p)
    if modp.Cmp(ln.BigZero) == 0 {
      targetRSA.PackGivenP(&p)
      
      fmt.Printf("[+] Past CTF prime factor found.\n")
      return
    }
  }
}