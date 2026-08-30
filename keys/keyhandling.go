package keys

import (
	"bufio"
	"bytes"
	"encoding/base64"
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
	lineRE = regexp.MustCompile(`(?i)^([necpqdk][pq02349]?t?|)\s*[:=]\s*((?:0x)?[0-9a-f]+)`)
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

	// dLeakLineRE matches partial d leak bitstrings with '?'.
	dLeakLineRE = regexp.MustCompile(`(?i)^(d_leak|dleak|d-leak)\s*[:=]\s*([01\?]+)`)

	// CRT components regexps.
	pRE  = regexp.MustCompile(`(?i)^p`)
	qRE  = regexp.MustCompile(`(?i)^q`)
	dpRE = regexp.MustCompile(`(?i)^dp`)
	dqRE = regexp.MustCompile(`(?i)^dq`)

	// Oracle Ciphertext regexps.
	e2RE = regexp.MustCompile(`(?i)^e2`)
	e3RE = regexp.MustCompile(`(?i)^e3`)
	e4RE = regexp.MustCompile(`(?i)^e4`)
	e9RE = regexp.MustCompile(`(?i)^e9`)
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

func isOracleCiphertext(s string) bool {
	return e2RE.MatchString(s) || e3RE.MatchString(s) || e4RE.MatchString(s) || e9RE.MatchString(s)
}

func whichOracleCiphertext(s string) int {
	switch {
	case e2RE.MatchString(s):
		return 2
	case e3RE.MatchString(s):
		return 3
	case e4RE.MatchString(s):
		return 4
	}

	return 9
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
		n, e, c, p, q, dp, dq, d0, dLeak string
		ct, kpt                          []byte
		crt                              bool
		os                               map[int]*fmp.Fmpz
	)

	os = make(map[int]*fmp.Fmpz)

	s := bufio.NewScanner(bytes.NewReader(kb))
	for s.Scan() {
		text := s.Text()
		if sm := dLeakLineRE.FindStringSubmatch(text); len(sm) >= 3 {
			dLeak = sm[2]
			continue
		}

		if lineRE.MatchString(text) {
			for _, sm := range lineRE.FindAllStringSubmatch(text, -1) {
				if len(sm) < 3 {
					continue
				}

				switch {
				case modRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					n = sm[2]
				case expRE.MatchString(sm[1]) && numRE.MatchString(sm[2]) && !isOracleCiphertext(sm[1]):
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
				case isOracleCiphertext(sm[1]) && numRE.MatchString(sm[2]):
					if o, ok := new(fmp.Fmpz).SetString(getBase(sm[2])); ok {
						os[whichOracleCiphertext(sm[1])] = new(fmp.Fmpz).Set(o)
					}
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

	if (n == "" || e == "") && !crt && len(os) < 4 {
		return nil, fmt.Errorf("failed to decode key, missing a modulus or an exponent")
	}

	fN, ok := new(fmp.Fmpz).SetString(getBase(n))
	if !ok && len(os) < 4 {
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
	if !ok && len(os) < 4 {
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

	if len(os) == 4 {
		k.OracleCiphertexts = os
	}

	// Place the LSB of D into the k.DLSB field.
	if d0 != "" {
		fd0, ok := new(fmp.Fmpz).SetString(getBase(d0))
		if !ok {
			return nil, errors.New("failed converting d0 integer to bytes")
		}

		k.DLSB = ln.NumberToBytes(fd0)
	}

	// Place the partial bitstring of D into the k.DLeak field.
	if dLeak != "" {
		k.DLeak = dLeak
	}

	// Add the primes if we got any.
	if p != "" {
		fP, ok := new(fmp.Fmpz).SetString(getBase(p))
		if !ok {
			return nil, errors.New("failed decoding prime p from keyfile")
		}
		k.Key.Primes = append(k.Key.Primes, fP)
	}

	if q != "" {
		fQ, ok := new(fmp.Fmpz).SetString(getBase(q))
		if !ok {
			return nil, errors.New("failed decoding prime q from keyfile")
		}
		k.Key.Primes = append(k.Key.Primes, fQ)
	}

	return k, nil
}

// ImportKey imports a PEM key file and returns a RSA object or error.
func ImportKey(kb []byte) (*RSA, error) {
	// Decode the PEM data to extract the DER format key.
	block, _ := pem.Decode(kb)
	if block == nil {
		return nil, errors.New("failed to decode PEM key")
	}

	// Try as a private key first.
	priv, err := parseBigPrivateRsaKey(block.Bytes)
	if err == nil {
		// If there was an error, try to parse it an alternative way below.
		return NewRSA(priv, nil, nil, "", false)
	}

	// Extract a FMPPublicKey from the DER decoded data and pack a private key struct.
	key, err := parsePublicRsaKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ImportKey: failed to parse the key as either a public or private key: %v", err)
	}

	return NewRSA(PrivateFromPublic(key), nil, nil, "", false)
}

// ImportPartialKey attempts to extract whatever RSA key components (N, e, d, p, q, etc.)
// it can from a corrupted or truncated PEM, DER, or integer list file.
func ImportPartialKey(kb []byte) (*RSA, error) {
	// 1. Try partial PEM / DER decoding
	if rsa, err := importPartialPEMorDER(kb); err == nil && rsa != nil {
		return rsa, nil
	}

	// 2. Try partial integer list decoding
	if rsa, err := importPartialIntegerList(kb); err == nil && rsa != nil {
		return rsa, nil
	}

	return nil, errors.New("failed to recover any key components from partial key file")
}

func importPartialPEMorDER(kb []byte) (*RSA, error) {
	der := extractDERFromPEM(kb)
	if len(der) == 0 {
		return nil, errors.New("no DER data extracted")
	}

	ints := extractIntegersFromDER(der)
	if len(ints) == 0 {
		return nil, errors.New("no ASN.1 integers found in DER data")
	}

	var (
		n, e, d, p, q, dp, dq, qinv *fmp.Fmpz
	)

	// Check if integers start with Version (0 or 1) as in RSAPrivateKey
	if ints[0].Cmp(ln.BigOne) <= 0 && len(ints) >= 2 {
		n = ints[1]
		if len(ints) >= 3 {
			e = ints[2]
		}
		if len(ints) >= 4 {
			d = ints[3]
		}
		if len(ints) >= 5 {
			p = ints[4]
		}
		if len(ints) >= 6 {
			q = ints[5]
		}
		if len(ints) >= 7 {
			dp = ints[6]
		}
		if len(ints) >= 8 {
			dq = ints[7]
		}
		if len(ints) >= 9 {
			qinv = ints[8]
		}
	} else {
		n = ints[0]
		if len(ints) >= 2 {
			e = ints[1]
		}
		if len(ints) >= 3 {
			d = ints[2]
		}
		if len(ints) >= 4 {
			p = ints[3]
		}
		if len(ints) >= 5 {
			q = ints[4]
		}
	}

	// Mathematical deductions
	if n != nil && p != nil && q == nil && p.Cmp(ln.BigOne) > 0 {
		rem := new(fmp.Fmpz).Mod(n, p)
		if rem.IsZero() {
			q = new(fmp.Fmpz).Div(n, p)
		}
	} else if n != nil && q != nil && p == nil && q.Cmp(ln.BigOne) > 0 {
		rem := new(fmp.Fmpz).Mod(n, q)
		if rem.IsZero() {
			p = new(fmp.Fmpz).Div(n, q)
		}
	} else if p != nil && q != nil && n == nil {
		n = new(fmp.Fmpz).Mul(p, q)
	}

	if p != nil && q != nil && e != nil && d == nil {
		d = ln.SolveforD(p, q, e)
	}

	var primes []*fmp.Fmpz
	if p != nil {
		primes = append(primes, p)
	}
	if q != nil {
		primes = append(primes, q)
	}

	var precomp *PrecomputedValues
	if dp != nil || dq != nil || qinv != nil {
		precomp = &PrecomputedValues{
			Dp:   dp,
			Dq:   dq,
			Qinv: qinv,
		}
	}

	pubKey := &FMPPublicKey{
		N: n,
		E: e,
	}

	key := &FMPPrivateKey{
		PublicKey:   pubKey,
		N:           n,
		D:           d,
		Primes:      primes,
		Precomputed: precomp,
	}

	return NewRSA(key, nil, nil, "", false)
}

func extractDERFromPEM(kb []byte) []byte {
	block, _ := pem.Decode(kb)
	if block != nil && len(block.Bytes) > 0 {
		return block.Bytes
	}

	lines := strings.Split(string(kb), "\n")
	var b64Buf strings.Builder
	inBlock := false
	hasBegin := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----BEGIN") {
			inBlock = true
			hasBegin = true
			continue
		}
		if strings.HasPrefix(line, "-----END") {
			inBlock = false
			break
		}

		if inBlock || !hasBegin {
			clean := cleanBase64(line)
			if len(clean) == 0 {
				if inBlock && hasBegin {
					break
				}
				continue
			}
			if len(clean) != len(line) && hasBegin {
				b64Buf.WriteString(clean)
				break
			}
			b64Buf.WriteString(clean)
		}
	}

	rawB64 := b64Buf.String()
	if len(rawB64) == 0 {
		if len(kb) > 2 && kb[0] == 0x30 {
			return kb
		}
		return nil
	}

	rem := len(rawB64) % 4
	if rem == 2 {
		rawB64 += "=="
	} else if rem == 3 {
		rawB64 += "="
	} else if rem == 1 {
		rawB64 = rawB64[:len(rawB64)-1]
	}

	der, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		der, _ = base64.RawStdEncoding.DecodeString(strings.TrimRight(rawB64, "="))
	}
	return der
}

func cleanBase64(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func extractIntegersFromDER(der []byte) []*fmp.Fmpz {
	var results []*fmp.Fmpz
	parseDERNode(der, &results)
	return results
}

func parseDERNode(data []byte, results *[]*fmp.Fmpz) {
	offset := 0
	for offset < len(data) {
		if offset >= len(data) {
			break
		}
		tag := data[offset]
		offset++
		if offset >= len(data) {
			break
		}

		length := int(data[offset])
		offset++
		if length&0x80 != 0 {
			numBytes := length & 0x7f
			if numBytes > 4 || offset+numBytes > len(data) {
				break
			}
			length = 0
			for i := 0; i < numBytes; i++ {
				length = (length << 8) | int(data[offset])
				offset++
			}
		}

		if tag == 0x30 || tag == 0xa0 || tag == 0xa1 {
			end := offset + length
			if end > len(data) {
				end = len(data)
			}
			parseDERNode(data[offset:end], results)
			offset = end
		} else if tag == 0x03 {
			end := offset + length
			if end > len(data) {
				end = len(data)
			}
			if offset < end {
				parseDERNode(data[offset+1:end], results)
			}
			offset = end
		} else if tag == 0x04 {
			end := offset + length
			if end > len(data) {
				end = len(data)
			}
			if offset < end && data[offset] == 0x30 {
				parseDERNode(data[offset:end], results)
			}
			offset = end
		} else if tag == 0x02 {
			if offset+length <= len(data) && length > 0 {
				val := new(fmp.Fmpz).SetBytes(data[offset : offset+length])
				*results = append(*results, val)
				offset += length
			} else {
				break
			}
		} else {
			offset += length
			if offset > len(data) {
				offset = len(data)
			}
		}
	}
}

func importPartialIntegerList(kb []byte) (*RSA, error) {
	var (
		nStr, eStr, cStr, pStr, qStr, dStr, dpStr, dqStr, d0Str, dLeakStr string
		ct, kpt                                                            []byte
		osMap                                                              map[int]*fmp.Fmpz
	)

	osMap = make(map[int]*fmp.Fmpz)

	s := bufio.NewScanner(bytes.NewReader(kb))
	for s.Scan() {
		text := s.Text()
		if sm := dLeakLineRE.FindStringSubmatch(text); len(sm) >= 3 {
			dLeakStr = sm[2]
			continue
		}

		if lineRE.MatchString(text) {
			for _, sm := range lineRE.FindAllStringSubmatch(text, -1) {
				if len(sm) < 3 {
					continue
				}

				switch {
				case modRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					nStr = sm[2]
				case expRE.MatchString(sm[1]) && numRE.MatchString(sm[2]) && !isOracleCiphertext(sm[1]):
					eStr = sm[2]
				case ctRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					cStr = sm[2]
				case pRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					pStr = sm[2]
				case qRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					qStr = sm[2]
				case dpRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					dpStr = sm[2]
				case dqRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					dqStr = sm[2]
				case d0RE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					d0Str = sm[2]
				case isOracleCiphertext(sm[1]) && numRE.MatchString(sm[2]):
					if o, ok := new(fmp.Fmpz).SetString(getBase(sm[2])); ok {
						osMap[whichOracleCiphertext(sm[1])] = new(fmp.Fmpz).Set(o)
					}
				case kptRE.MatchString(sm[1]) && numRE.MatchString(sm[2]):
					if kn, ok := new(fmp.Fmpz).SetString(getBase(sm[2])); ok {
						kpt = ln.NumberToBytes(kn)
					}
				}
			}
		}
	}

	var n, e, d, p, q, dp, dq *fmp.Fmpz
	if nStr != "" {
		if val, ok := new(fmp.Fmpz).SetString(getBase(nStr)); ok {
			n = val
		}
	}
	if eStr != "" {
		if val, ok := new(fmp.Fmpz).SetString(getBase(eStr)); ok {
			e = val
		}
	}
	if pStr != "" {
		if val, ok := new(fmp.Fmpz).SetString(getBase(pStr)); ok {
			p = val
		}
	}
	if qStr != "" {
		if val, ok := new(fmp.Fmpz).SetString(getBase(qStr)); ok {
			q = val
		}
	}
	if dStr != "" {
		if val, ok := new(fmp.Fmpz).SetString(getBase(dStr)); ok {
			d = val
		}
	}
	if dpStr != "" {
		if val, ok := new(fmp.Fmpz).SetString(getBase(dpStr)); ok {
			dp = val
		}
	}
	if dqStr != "" {
		if val, ok := new(fmp.Fmpz).SetString(getBase(dqStr)); ok {
			dq = val
		}
	}
	if cStr != "" {
		if fC, ok := new(fmp.Fmpz).SetString(getBase(cStr)); ok {
			ct = ln.NumberToBytes(fC)
		}
	}

	// Mathematical deductions
	if n != nil && p != nil && q == nil && p.Cmp(ln.BigOne) > 0 {
		rem := new(fmp.Fmpz).Mod(n, p)
		if rem.IsZero() {
			q = new(fmp.Fmpz).Div(n, p)
		}
	} else if n != nil && q != nil && p == nil && q.Cmp(ln.BigOne) > 0 {
		rem := new(fmp.Fmpz).Mod(n, q)
		if rem.IsZero() {
			p = new(fmp.Fmpz).Div(n, q)
		}
	} else if p != nil && q != nil && n == nil {
		n = new(fmp.Fmpz).Mul(p, q)
	}

	if p != nil && q != nil && e != nil && d == nil {
		d = ln.SolveforD(p, q, e)
	}

	if n == nil && e == nil && p == nil && q == nil && d == nil && ct == nil && len(osMap) == 0 && d0Str == "" && dLeakStr == "" {
		return nil, errors.New("no integer list key parameters found")
	}

	var primes []*fmp.Fmpz
	if p != nil {
		primes = append(primes, p)
	}
	if q != nil {
		primes = append(primes, q)
	}

	var precomp *PrecomputedValues
	if dp != nil || dq != nil {
		precomp = &PrecomputedValues{
			Dp: dp,
			Dq: dq,
		}
	}

	pubKey := &FMPPublicKey{
		N: n,
		E: e,
	}

	k := &FMPPrivateKey{
		PublicKey:   pubKey,
		N:           n,
		D:           d,
		Primes:      primes,
		Precomputed: precomp,
	}

	rsaKey, err := NewRSA(k, ct, nil, "", false)
	if err != nil {
		return nil, err
	}

	if kpt != nil {
		rsaKey.KnownPlainText = kpt
	}
	if len(osMap) > 0 {
		rsaKey.OracleCiphertexts = osMap
	}
	if d0Str != "" {
		if fd0, ok := new(fmp.Fmpz).SetString(getBase(d0Str)); ok {
			rsaKey.DLSB = ln.NumberToBytes(fd0)
		}
	}
	if dLeakStr != "" {
		rsaKey.DLeak = dLeakStr
	}

	return rsaKey, nil
}
