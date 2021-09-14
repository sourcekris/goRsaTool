package keys

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
	"github.com/sourcekris/x509big"
)

var (
	// lineRE is a regexp that should match interesting integers on lines.
	lineRE = regexp.MustCompile(`(?i)^([necpqdk][pq0]?t?|)\s*[:=]\s*((?:0x)?[0-9a-f]+)`)
	// numRE matches numbers in base 10 or hex.
	numRE = regexp.MustCompile(`[0-9a-f]+`)
	// modRE, expRE, ctRE matches 'n', 'e', 'c' case insensitively.
	modRE = regexp.MustCompile(`(?i)^n`)
	expRE = regexp.MustCompile(`(?i)^e`)
	ctRE  = regexp.MustCompile(`(?i)^c`)

	// kptRE is a known plaintext regexp.
	kptRE = regexp.MustCompile(`(?i)^kpt`)

	// d0RE is the LSB of d regexp.
	d0RE = regexp.MustCompile(`(?i)^d0`)

	// CRT components regexps.
	pRE  = regexp.MustCompile(`(?i)^p`)
	qRE  = regexp.MustCompile(`(?i)^q`)
	dpRE = regexp.MustCompile(`(?i)^dp`)
	dqRE = regexp.MustCompile(`(?i)^dq`)
)

type pkParser func([]byte) (*x509big.BigPublicKey, error)

// parsePublicRsaKey attempts to try parsing the given public key yielding a FMPPublicKey or
// an error using multiple methods.
func parsePublicRsaKey(keyBytes []byte) (*FMPPublicKey, error) {
	var (
		parsers = []pkParser{
			x509big.ParseBigPKCS1PublicKey,
			x509big.ParseBigPKIXPublicKey,
		}
		errs []error
	)

	for _, p := range parsers {
		if key, err := p(keyBytes); err != nil {
			errs = append(errs, err)
		} else {
			return &FMPPublicKey{
				N: new(fmp.Fmpz).SetBytes(key.N.Bytes()),
				E: new(fmp.Fmpz).SetBytes(key.E.Bytes()),
			}, nil
		}
	}

	return nil, fmt.Errorf("parsePublicRsaKey failed: %v", errs)
}

func parseBigPrivateRsaKey(keyBytes []byte) (*FMPPrivateKey, error) {
	key, err := x509big.ParseBigPKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parseBigPrivateRsaKey: failed to parse the DER key after decoding: %v", err)
	}
	k := BigtoFMPPrivateKey(key)
	return &k, nil
}

// PrivateFromPublic takes a Public Key and return a Private Key with the public components packed.
func PrivateFromPublic(key *FMPPublicKey) *FMPPrivateKey {
	return &FMPPrivateKey{
		PublicKey: key,
		N:         key.N,
	}
}

// getBase returns the base of a string and, if its prefixed with 0x then the remainder of the string after the prefix.
func getBase(s string) (string, int) {
	if strings.HasPrefix(s, "0x") {
		return s[2:], 16
	}

	return s, 10
}

// ImportIntegerList attempts to parse the key (and optionally ciphertext) data as if it was a list of integers N, and e and c.
func ImportIntegerList(kb []byte) (*RSA, error) {
	var (
		n, e, c, p, q, dp, dq, d0 string
		ct, kpt                   []byte
		crt                       bool
	)

	s := bufio.NewScanner(bytes.NewReader(kb))
	for s.Scan() {
		if lineRE.MatchString(s.Text()) {
			for _, sm := range lineRE.FindAllStringSubmatch(s.Text(), -1) {
				if len(sm) < 3 {
					continue
				}

				switch {
				case modRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					n = sm[2]
				case expRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					e = sm[2]
				case ctRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					c = sm[2]
				case pRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					p = sm[2]
				case qRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					q = sm[2]
				case dpRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					dp = sm[2]
				case dqRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					dq = sm[2]
				case d0RE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					d0 = sm[2]
				case kptRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					if kn, ok := new(fmp.Fmpz).SetString(getBase(sm[2])); ok {
						kpt = ln.NumberToBytes(kn)
					}
				}
			}
		}
	}

	// Do we have enough for CRT solution?
	if dp != "" && dq != "" {
		switch {
		case n == "" && (p == "" || q == ""):
		case n == "" && p != "" && q != "":
			fP, ok1 := new(fmp.Fmpz).SetString(getBase(p))
			fQ, ok2 := new(fmp.Fmpz).SetString(getBase(q))
			if !ok1 || !ok2 {
				crt = false
				break
			}
			n = new(fmp.Fmpz).Mul(fP, fQ).String()
			crt = true
		case n != "" && p != "":
			fN, ok1 := new(fmp.Fmpz).SetString(getBase(n))
			fP, ok2 := new(fmp.Fmpz).SetString(getBase(p))
			if !ok1 || !ok2 {
				crt = false
				break
			}
			q = new(fmp.Fmpz).Div(fN, fP).String()
			crt = true
		case n != "" && q != "":
			fN, ok1 := new(fmp.Fmpz).SetString(getBase(n))
			fQ, ok2 := new(fmp.Fmpz).SetString(getBase(q))
			if !ok1 || !ok2 {
				crt = false
				break
			}
			p = new(fmp.Fmpz).Div(fN, fQ).String()
			crt = true
		}
	}

	if (n == "" || e == "") && !crt {
		return nil, fmt.Errorf("failed to decode key, missing a modulus or an exponent")
	}

	fN, ok := new(fmp.Fmpz).SetString(getBase(n))
	if !ok {
		return nil, fmt.Errorf("failed decoding modulus from keyfile: %v", n)
	}

	if crt {
		k, err := NewRSA(PrivateFromPublic(&FMPPublicKey{N: fN}), ct, nil, "", false)
		if err != nil {
			fmt.Printf("trying crt n: %v\n", n)
			return nil, err
		}
		fQ, ok1 := new(fmp.Fmpz).SetString(getBase(q))
		fP, ok2 := new(fmp.Fmpz).SetString(getBase(p))
		fdP, ok3 := new(fmp.Fmpz).SetString(getBase(dp))
		fdQ, ok4 := new(fmp.Fmpz).SetString(getBase(dq))
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return nil, errors.New("failed to decode crt components")
		}
		k.Key.Primes = []*fmp.Fmpz{fP, fQ}
		k.Key.Precomputed = &PrecomputedValues{Dp: fdP, Dq: fdQ}

		if c != "" {
			fC, ok := new(fmp.Fmpz).SetString(getBase(c))
			if !ok {
				return nil, errors.New("failed converting ciphertext integer to bytes")
			}

			k.CipherText = ln.NumberToBytes(fC)
		}

		return k, nil
	}

	fE, ok := new(fmp.Fmpz).SetString(getBase(e))
	if !ok {
		return nil, errors.New("failed decoding exponent from keyfile")
	}

	if c != "" {
		fC, ok := new(fmp.Fmpz).SetString(getBase(c))
		if !ok {
			return nil, errors.New("failed converting ciphertext integer to bytes")
		}

		ct = ln.NumberToBytes(fC)
	}

	k, err := NewRSA(PrivateFromPublic(&FMPPublicKey{N: fN, E: fE}), ct, nil, "", false)
	if err != nil {
		return nil, err
	}

	if kpt != nil {
		k.KnownPlainText = kpt
	}

	// Place the LSB of D into the k.DLSB field.
	if d0 != "" {
		fd0, ok := new(fmp.Fmpz).SetString(getBase(d0))
		if !ok {
			return nil, errors.New("failed converting d0 integer to bytes")
		}

		k.DLSB = ln.NumberToBytes(fd0)
	}

	return k, nil
}

// ImportKey imports a PEM key file and returns a FMPPrivateKey object or error.
func ImportKey(kb []byte) (*FMPPrivateKey, error) {
	// Decode the PEM data to extract the DER format key.
	block, _ := pem.Decode(kb)
	if block == nil {
		return nil, errors.New("failed to decode PEM key")
	}

	// Try as a private key first.
	priv, err := parseBigPrivateRsaKey(block.Bytes)
	if err == nil {
		// If there was an error, try to parse it an alternative way below.
		return priv, nil
	}

	// Extract a FMPPublicKey from the DER decoded data and pack a private key struct.
	key, err := parsePublicRsaKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ImportKey: failed to parse the key as either a public or private key: %v", err)
	}

	return PrivateFromPublic(key), nil
}
