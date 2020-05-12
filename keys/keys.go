package keys

import (
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/sourcekris/goRsaTool/ln"
	"github.com/sourcekris/x509big"

	fmp "github.com/sourcekris/goflint"
)

// RSA wraps FMPPrivateKey and adds a field for cipher and plaintexts
type RSA struct {
	Key            FMPPrivateKey
	CipherText     []byte
	PlainText      []byte
	KeyFilename    string
	PastPrimesFile string
	Verbose        bool
}

// NewRSA constructs an RSA object or returns an error.
func NewRSA(key *FMPPrivateKey, c []byte, m []byte, pf string, v bool) (*RSA, error) {
	var pastPrimesFile string
	if len(pf) > 0 {
		pastPrimesFile = pf
	}

	var cipherText []byte
	if len(c) > 0 {
		cipherText = c
	}

	// pack the RSA struct
	return &RSA{
		Key:            *key,
		PastPrimesFile: pastPrimesFile,
		CipherText:     cipherText,
		Verbose:        v,
	}, nil
}

// PackGivenP takes one prime p and packs the Key member of the RSA struct with the private
// key values, p, q & d
func (t *RSA) PackGivenP(p *fmp.Fmpz) {
	q := new(fmp.Fmpz).Div(t.Key.N, p)
	t.Key.Primes = []*fmp.Fmpz{p, q}
	t.Key.D = ln.SolveforD(p, q, t.Key.PublicKey.E)
}

// String returns the key components in a string format.
func (t *RSA) String() string {
	var res string
	res = fmt.Sprintf("%s:\nn = %s\n", t.KeyFilename, t.Key.PublicKey.N)
	res = fmt.Sprintf("%se = %s\n", res, t.Key.PublicKey.E)

	// TODO(sewid): Support RSA multiprime [where len(key.Primes) > 2]
	if t.Key.D != nil {
		res = fmt.Sprintf("%sd = %s\n", res, t.Key.D)
		res = fmt.Sprintf("%sp = %s\n", res, t.Key.Primes[0])
		res = fmt.Sprintf("%sq = %s\n", res, t.Key.Primes[1])
	}

	if len(t.CipherText) > 0 {
		res = fmt.Sprintf("%sc = %s\n", res, ln.BytesToNumber(t.CipherText))
	}

	return res
}

// DumpKey prints the key components in a string format.
func (t *RSA) DumpKey() {
	fmt.Print(t.String())
}

// FMPPublicKey represents a RSA public key using FMP data structures.
type FMPPublicKey struct {
	N *fmp.Fmpz
	E *fmp.Fmpz
}

// CRTValue contains the precomputed Chinese remainder theorem values.
type CRTValue struct {
	Exp   *fmp.Fmpz // D mod (prime-1).
	Coeff *fmp.Fmpz // R·Coeff ≡ 1 mod Prime.
	R     *fmp.Fmpz // product of primes prior to this (inc p and q).
}

// PrecomputedValues contains precomputed values that speed up private
// operations, if available.
type PrecomputedValues struct {
	Dp, Dq *fmp.Fmpz // D mod (P-1) (or mod Q-1)
	Qinv   *fmp.Fmpz // Q^-1 mod P

	// CRTValues is used for the 3rd and subsequent primes. Due to a
	// historical accident, the CRT for the first two primes is handled
	// differently in PKCS#1 and interoperability is sufficiently
	// important that we mirror this.
	CRTValues []CRTValue
}

// FMPPrivateKey represents a RSA private key using FMP data structures.
type FMPPrivateKey struct {
	PublicKey *FMPPublicKey
	D         *fmp.Fmpz
	Primes    []*fmp.Fmpz
	N         *fmp.Fmpz

	Precomputed *PrecomputedValues
}

// BigtoFMPPrivateKey takes a x509big.BigPrivateKey and returns a FMPPrivateKey that uses fmp.Fmpz types
func BigtoFMPPrivateKey(key *x509big.BigPrivateKey) FMPPrivateKey {
	fmpPubKey := &FMPPublicKey{
		N: new(fmp.Fmpz).SetBytes(key.PublicKey.N.Bytes()),
		E: new(fmp.Fmpz).SetBytes(key.PublicKey.E.Bytes()),
	}

	var fmpPrivateKey *FMPPrivateKey
	if key.D != nil {
		fmpPrivateKey = &FMPPrivateKey{
			PublicKey: fmpPubKey,
			D:         new(fmp.Fmpz).SetBytes(key.D.Bytes()),
			Primes: []*fmp.Fmpz{
				new(fmp.Fmpz).SetBytes(key.Primes[0].Bytes()),
				new(fmp.Fmpz).SetBytes(key.Primes[1].Bytes()),
			},
		}
	} else {
		fmpPrivateKey = PrivateFromPublic(fmpPubKey)
	}

	return *fmpPrivateKey
}

// FMPtoBigPrivateKey takes a FMPPrivateKey and returns an x509big.PrivateKey using native go
// big Int types.
func FMPtoBigPrivateKey(key *FMPPrivateKey) *x509big.BigPrivateKey {
	pubKey := &x509big.BigPublicKey{
		N: new(big.Int).SetBytes(key.N.Bytes()),
		E: new(big.Int).SetBytes(key.PublicKey.E.Bytes()),
	}

	var privateKey *x509big.BigPrivateKey
	if key.D != nil {
		privateKey = &x509big.BigPrivateKey{
			PublicKey: *pubKey,
			D:         new(big.Int).SetBytes(key.D.Bytes()),
			Primes: []*big.Int{
				new(big.Int).SetBytes(key.Primes[0].Bytes()),
				new(big.Int).SetBytes(key.Primes[1].Bytes()),
			},
		}
	} else {
		privateKey = &x509big.BigPrivateKey{
			PublicKey: *pubKey,
		}
	}

	return privateKey
}

// FMPtoBigPublicKey takes a FMPPublicKey and returns an x509big.PublicKey using native go
// big Int types.
func FMPtoBigPublicKey(key *FMPPublicKey) *x509big.BigPublicKey {
	return &x509big.BigPublicKey{
		N: new(big.Int).SetBytes(key.N.Bytes()),
		E: new(big.Int).SetBytes(key.E.Bytes()),
	}
}

func encodeDerToPem(der []byte, t string) string {
	p := pem.EncodeToMemory(
		&pem.Block{
			Type:  t,
			Bytes: der,
		},
	)

	return string(p)
}

// EncodeFMPPrivateKey marshalls an RSA private key using FMP types into a string.
func EncodeFMPPrivateKey(priv *FMPPrivateKey) string {
	privder := x509big.MarshalPKCS1BigPrivateKey(FMPtoBigPrivateKey(priv))
	return encodeDerToPem(privder, "RSA PRIVATE KEY")
}

// EncodeFMPPublicKey marshalls an RSA public key using FMP types into a string.
func EncodeFMPPublicKey(pub *FMPPublicKey) string {
	privder := x509big.MarshalPKCS1BigPublicKey(FMPtoBigPublicKey(pub))
	return encodeDerToPem(privder, "RSA PUBLIC KEY")
}
