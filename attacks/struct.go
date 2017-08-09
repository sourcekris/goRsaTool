package attacks

import (
  "crypto/rsa"
  "errors"
  "fmt"
  "math/big"
  "github.com/sourcekris/goRsaTool/libnum"
  "github.com/sourcekris/goRsaTool/utils"
)

/*
 * wrap rsa.PrivateKey and add a field for cipher and plaintexts
 */
type RSAStuff struct {
  Key rsa.PrivateKey
  CipherText []byte
  PlainText []byte
  PastPrimesFile string
}

/*
 * constructor for RSAStuff struct
 */
func NewRSAStuff(key *rsa.PrivateKey, c []byte, m []byte, pf string) (*RSAStuff, error) {
	if key.N == nil {
		return nil, errors.New("Key had no modulus or exponent")
	}

  var pastPrimesFile string
    if len(pf) > 0 {
      pastPrimesFile = pf
  }

  var cipherText []byte
    if len(c) > 0 {
      cipherText = c
  }

	// pack the RSAStuff struct
   return &RSAStuff{
      Key: *key,
      PastPrimesFile: pastPrimesFile,
      CipherText: cipherText,
    }, nil
}

/*
 * Given one prime p, pack the Key member of the RSAStuff struct with the private key values, p, q & d
 */
func (targetRSA *RSAStuff) PackGivenP(p *big.Int) {
  q := new(big.Int).Div(targetRSA.Key.N, p)
  targetRSA.Key.Primes = []*big.Int{p, q}
  targetRSA.Key.D      = utils.SolveforD(p, q, targetRSA.Key.E)
}

func (targetRSA *RSAStuff) DumpKey() {
  fmt.Printf("[*] n = %d\n", targetRSA.Key.N)
  fmt.Printf("[*] e = %d\n", targetRSA.Key.E)

  // XXX: Support RSA multiprime [where len(key.Primes) > 2]
  if targetRSA.Key.D!= nil {
    fmt.Printf("[*] d = %d\n", targetRSA.Key.D)
    fmt.Printf("[*] p = %d\n", targetRSA.Key.Primes[0])
    fmt.Printf("[*] q = %d\n", targetRSA.Key.Primes[1])
  }

  if len(targetRSA.CipherText) > 0 {
    fmt.Printf("[*] c = %d\n", libnum.BytesToNumber(targetRSA.CipherText))
  }
}