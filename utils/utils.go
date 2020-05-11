package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"unicode"

	fmp "github.com/sourcekris/goflint"
)

// ReadCiphertext imports a ciphertext binary file and returns a slice of bytes of an error.
func ReadCipherText(cipherFile string) ([]byte, error) {
	ct, err := ioutil.ReadFile(cipherFile)
	if err != nil {
		fmt.Printf("[-] Error opening ciphertext file: %s\n", cipherFile)
		return nil, err
	}

	return bytes.TrimRight(ct, "\n\r"), nil
}

// IsInt returns true if the string s contains all unicode digit characters.
func IsInt(s string) bool {
	for _, c := range s {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

// FoundP returns true if prime p exists in slice ps.
func FoundP(p *fmp.Fmpz, ps []*fmp.Fmpz) bool {
	for _, prime := range ps {
		if p.Cmp(prime) == 0 {
			return true
		}
	}
	return false
}
