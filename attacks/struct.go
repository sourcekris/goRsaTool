package attacks

import (
  "crypto/rsa"
  "errors"
  "math/big"

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

	// pack the RSAStuff struct
   return &RSAStuff{
      Key: *key,
      PastPrimesFile: pastPrimesFile,
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