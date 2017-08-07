package attacks

import (
  "crypto/rsa"
  "errors"
)

// wrap rsa.PrivateKey and add a field for cipher and plaintexts
type RSAStuff struct {
  Key rsa.PrivateKey
  CipherText []byte
  PlainText []byte
  PastPrimesFile string
}

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