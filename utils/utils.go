package utils

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"unicode"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
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
		if p.Equals(prime) {
			return true
		}
	}
	return false
}

// EncodeAndPrintKey is called when the -createkey flag is provided.
func EncodeAndPrintKey(n, e, d string) error {
	if n != "" && e != "" {
		mod, ok := new(fmp.Fmpz).SetString(n, 10)
		if !ok {
			return fmt.Errorf("failed converting modulus to integer: %q", n)
		}

		exp, ok := new(fmp.Fmpz).SetString(e, 10)
		if !ok {
			return fmt.Errorf("failed converting exponent to integer: %q", e)
		}

		pk := &keys.FMPPublicKey{N: mod, E: exp}
		if d != "" {
			pexp, ok := new(fmp.Fmpz).SetString(d, 10)
			if !ok {
				return fmt.Errorf("failed converting d to integer: %q", d)
			}

			priv, err := keys.NewRSA(keys.PrivateFromPublic(pk), nil, nil, "", false)
			if err != nil {
				return err
			}

			priv.PackGivenP(ln.FindPGivenD(pexp, pk.E, pk.N))
			fmt.Println(keys.EncodeFMPPrivateKey(&priv.Key))
			return nil
		}

		fmt.Println(keys.EncodeFMPPublicKey(pk))
		return nil
	}

	return errors.New("no exponent or modulus specified - use -n and -e")
}

// ReportResults iterates a slice of keys and prints the privatekeys or plaintexts found.
func ReportResults(ks []*keys.RSA) {
	for _, k := range ks {
		if k.Key.D != nil && k.Key.Primes != nil {
			fmt.Println(keys.EncodeFMPPrivateKey(&k.Key))
		}

		if k.Key.D != nil && k.Key.Primes == nil {
			fmt.Printf("recovered d but was unable to recover all the primes\nd = %v\n", k.Key.D)
		}

		if len(k.PlainText) > 0 {
			fmt.Printf("Recovered plaintext as an integer: %s\n", ln.BytesToNumber(k.PlainText))
			fmt.Println("Recovered plaintext: ")
			fmt.Println(string(k.PlainText))
		}
	}
}
