package utils

import (
	"bytes"
	"io/ioutil"
	"unicode"

	fmp "github.com/sourcekris/goflint"
)

// ReadBinary imports a binary file and returns a slice of bytes of an error.
func ReadBinary(bf string) ([]byte, error) {
	ct, err := ioutil.ReadFile(bf)
	if err != nil {
		return nil, err
	}

	return bytes.TrimRight(ct, "\n\r"), nil
}

// ReadCipherText imports a ciphertext binary file and returns a slice of bytes of an error.
func ReadCipherText(ct string) ([]byte, error) {
	return ReadBinary(ct)
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
