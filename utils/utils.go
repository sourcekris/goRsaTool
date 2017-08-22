package utils

import (
  "bytes"
  "fmt"
  "io/ioutil"
  "unicode"

  "github.com/ncw/gmp"
)

func ReadCipherText(cipherFile string) ([]byte, error) {
  ct, err := ioutil.ReadFile(cipherFile)
  if err != nil {
    fmt.Printf("[-] Error opening ciphertext file: %s\n", cipherFile)
    return nil, err
  }

  return bytes.TrimRight(ct, "\n\r"), nil
}

// given e, p and q solve for the private exponent d
func SolveforD(p *gmp.Int, q *gmp.Int, e *gmp.Int) *gmp.Int {
  pm1 := new(gmp.Int).Sub(p, gmp.NewInt(1))
  qm1 := new(gmp.Int).Sub(q, gmp.NewInt(1))
  phi := new(gmp.Int).Mul(pm1, qm1)
  return new(gmp.Int).ModInverse(e, phi)
}

func IsInt(s string) bool {
  for _, c := range s {
    if !unicode.IsDigit(c) {
      return false
    }
  }
  return true
}
