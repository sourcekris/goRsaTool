// Package jwtmodulus implements recoving an RS256 modulus given two JWTs.
package jwtmodulus

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	"github.com/sourcekris/goRsaTool/utils"
	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "jwt modulus recovery"

// Precomputed ASN1 DER structure for SHA256. See crypto/rsa/pkcs1v15.go?l=207
var sha256DigestInfo = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

func pkcs1v15Encode(msg []byte, n int) []byte {
	h := sha256.Sum256(msg)
	t := append(sha256DigestInfo, h[:]...) // Slice array and append each element.

	var pad []byte
	for i := 0; i < (n - len(t) - 3); i++ {
		pad = append(pad, byte(0xff))
	}

	res := append([]byte{0, 1}, pad...)
	res = append(res, byte(0))
	return append(res, t...)
}

func getMagic(jwt []byte, e *fmp.Fmpz) (*fmp.Fmpz, error) {
	var header, payload, sig string

	sj := strings.Split(string(jwt), ".")
	if sj == nil || len(sj) != 3 {
		return nil, errors.New("unable to parse JWT")
	}

	header = sj[0]
	payload = sj[1]
	sig = sj[2] + "=="

	rs, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("failed decoding signature base64 in: %v", err)
	}
	sigNum := ln.BytesToNumber(rs)
	padNum := ln.BytesToNumber(pkcs1v15Encode([]byte(header+"."+payload), len(rs)))
	return new(fmp.Fmpz).ExpXY(sigNum, e).SubZ(padNum), nil
}

// Attack calculates an RSA modulus given two known JWTs. If no public exponent is given then it
// is assumed to be 65537.
func Attack(jwtlist []string, exp string) error {
	var (
		magics []*fmp.Fmpz
	)

	if len(jwtlist) != 2 {
		return fmt.Errorf("JWT mode requires 2 JWTs")
	}

	e, ok := new(fmp.Fmpz).SetString(exp, 10)
	if exp == "" || !ok {
		e = fmp.NewFmpz(65537)
	}

	for _, j := range jwtlist {
		jwt, err := utils.ReadBinary(j)
		if err != nil {
			return fmt.Errorf("error reading JWTs %s: %v", j, err)
		}
		m, err := getMagic(jwt, e)
		if err != nil {
			return fmt.Errorf("error reading JWTs %s: %v", j, err)
		}
		magics = append(magics, m)
	}

	res := new(fmp.Fmpz).GCD(magics[0], magics[1])

	k, err := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: res, E: e}), nil, nil, "", false)
	if err != nil {
		return fmt.Errorf("%s failed to construct rsa key once modulus was recovered", name)
	}

	fmt.Println("Recovered public key:")
	fmt.Println(keys.EncodeFMPPublicKey(k.Key.PublicKey))
	return nil
}
