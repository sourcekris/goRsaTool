package utils

import (
  "bytes"
  "fmt"
  "io/ioutil"
  "unicode"
)

func ReadCipherText(cipherFile string) ([]byte, error) {
  ct, err := ioutil.ReadFile(cipherFile)
  if err != nil {
    fmt.Printf("[-] Error opening ciphertext file: %s\n", cipherFile)
    return nil, err
  }

  return bytes.TrimRight(ct, "\n\r"), nil
}

func IsInt(s string) bool {
  for _, c := range s {
    if !unicode.IsDigit(c) {
      return false
    }
  }
  return true
}
