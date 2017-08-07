package utils

import (
  "fmt"
  "math/big"
  "io/ioutil"
  "unicode"
)

func ReadCipherText(cipherFile string) ([]byte, error) {
  ct, err := ioutil.ReadFile(cipherFile)
  if err != nil {
    fmt.Printf("[-] Error opening ciphertext file: %s\n", cipherFile)
    return nil, err
  }

  return ct, nil
}

// given e, p and q solve for the private exponent d
func SolveforD(p *big.Int, q *big.Int, e int) *big.Int {
  pm1 := new(big.Int).Sub(p, big.NewInt(1))
  qm1 := new(big.Int).Sub(q, big.NewInt(1))
  phi := new(big.Int).Mul(pm1, qm1)
  return new(big.Int).ModInverse(big.NewInt(int64(e)), phi)
}

func IsInt(s string) bool {
  for _, c := range s {
    if !unicode.IsDigit(c) {
      return false
    }
  }
  return true
}
