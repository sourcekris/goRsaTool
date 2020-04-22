package attacks

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/sourcekris/goRsaTool/libnum"
	"github.com/sourcekris/x509big"

	fmp "github.com/sourcekris/goflint"
)

// SupportedAttacks stores the list of registered attacks we support.
var SupportedAttacks *Attacks

func init() {
	SupportedAttacks = NewAttacks()
	// TODO(sewid): Move attacks to their own packages and register them in each package init function.
	SupportedAttacks.RegisterAttack("factordb", false, true, FactorDB)
	SupportedAttacks.RegisterAttack("fermat", false, true, FermatFactorization)
	SupportedAttacks.RegisterAttack("hastads", false, true, Hastads)
	SupportedAttacks.RegisterAttack("novelty", false, true, NoveltyPrimes)
	SupportedAttacks.RegisterAttack("pastctf", false, true, PastCTFPrimes)
	SupportedAttacks.RegisterAttack("smallfractions", false, false, SmallFractions)
	SupportedAttacks.RegisterAttack("smallq", false, true, SmallQ)
	SupportedAttacks.RegisterAttack("wiener", false, true, Wiener)
}

// FMPPublicKey represents a RSA public key using FMP data structures.
type FMPPublicKey struct {
	N *fmp.Fmpz
	E *fmp.Fmpz
}

// FMPPrivateKey represents a RSA private key using FMP data structures.
type FMPPrivateKey struct {
	PublicKey *FMPPublicKey
	D         *fmp.Fmpz
	Primes    []*fmp.Fmpz
	N         *fmp.Fmpz
}

type attackFunc func(*RSAStuff) error

// Attack encodes a single attack and what features it supports.
type Attack struct {
	Name          string
	SupportsMulti bool
	Unnatended    bool
	F             attackFunc
}

// Attacks wraps a slice of Attack objects that are supported.
type Attacks struct {
	Supported []*Attack
}

// NewAttacks constructs a new Attacks object.
func NewAttacks() *Attacks {
	return &Attacks{}
}

// RegisterAttack adds a new attack to the receiving Attacks.
func (a *Attacks) RegisterAttack(name string, multi bool, unnatended bool, f attackFunc) {
	if a == nil {
		a = NewAttacks()
	}

	a.Supported = append(a.Supported, &Attack{name, multi, unnatended, f})
}

// IsSupported returns true if name attack is supported.
func (a *Attacks) IsSupported(name string) bool {
	for _, a := range a.Supported {
		if a.Name == name {
			return true
		}
	}

	return false
}

// Execute executes the named attack against t.
func (a *Attacks) Execute(name string, t *RSAStuff) error {
	if SupportedAttacks == nil {
		return errors.New("no attacks registered")
	}

	for _, a := range SupportedAttacks.Supported {
		if a.Name == name {
			return a.F(t)
		}
	}

	return errors.New("attack not found")
}

// RSAStuff wraps FMPPrivateKey and adds a field for cipher and plaintexts
type RSAStuff struct {
	Key            FMPPrivateKey
	CipherText     []byte
	PlainText      []byte
	PastPrimesFile string
}

// NewRSAStuff constructs an RSAStuff object or returns an error.
func NewRSAStuff(key *FMPPrivateKey, c []byte, m []byte, pf string) (*RSAStuff, error) {
	if key.PublicKey.N == nil {
		return nil, errors.New("Key had no modulus or exponent")
	}

	var pastPrimesFile string
	if len(pf) > 0 {
		pastPrimesFile = pf
	}

	var cipherText []byte
	if len(c) > 0 {
		cipherText = c
	}

	// pack the RSAStuff struct
	return &RSAStuff{
		Key:            *key,
		PastPrimesFile: pastPrimesFile,
		CipherText:     cipherText,
	}, nil
}

// PackGivenP takes one prime p and packs the Key member of the RSAStuff struct with the private
// key values, p, q & d
func (t *RSAStuff) PackGivenP(p *fmp.Fmpz) {
	q := new(fmp.Fmpz).Div(t.Key.N, p)
	t.Key.Primes = []*fmp.Fmpz{p, q}
	t.Key.D = libnum.SolveforD(p, q, t.Key.PublicKey.E)
}

// String returns the key components in a string format.
func (t *RSAStuff) String() string {
	var res string
	res = fmt.Sprintf("[*] n = %s\n", t.Key.PublicKey.N)
	res = fmt.Sprintf("%s[*] e = %s\n", res, t.Key.PublicKey.E)

	// TODO(sewid): Support RSA multiprime [where len(key.Primes) > 2]
	if t.Key.D != nil {
		res = fmt.Sprintf("%s[*] d = %s\n", res, t.Key.D)
		res = fmt.Sprintf("%s[*] p = %s\n", res, t.Key.Primes[0])
		res = fmt.Sprintf("%s[*] q = %s\n", res, t.Key.Primes[1])
	}

	if len(t.CipherText) > 0 {
		res = fmt.Sprintf("%s[*] c = %s\n", res, libnum.BytesToNumber(t.CipherText))
	}

	return res
}

// DumpKey prints the key components in a string format.
func (t *RSAStuff) DumpKey() {
	fmt.Print(t.String())
}

// RSAtoFMPPrivateKey takes a rsa.PrivateKey and returns a FMPPrivateKey that uses fmp.Fmpz types
func RSAtoFMPPrivateKey(key *rsa.PrivateKey) FMPPrivateKey {
	fmpPubKey := &FMPPublicKey{
		N: new(fmp.Fmpz).SetBytes(key.N.Bytes()),
		E: fmp.NewFmpz(int64(key.E)),
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

// FMPtoRSAPrivateKey takes a FMPPRivateKey and returns an rsa.PrivateKey if the exponent fits
// within the int type.
func FMPtoRSAPrivateKey(key *FMPPrivateKey) *rsa.PrivateKey {
	if key.PublicKey.E.Cmp(fmp.NewFmpz(math.MaxInt64)) > 0 {
		// TODO(sewid): Deprecate rsa.PrivateKey types
		panic("[-] Exponent is too large for the private key to be converted to type rsa.PrivateKey")

	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(key.N.Bytes()),
		E: int(key.PublicKey.E.Int64()),
	}

	var privateKey *rsa.PrivateKey
	if key.D != nil {
		privateKey = &rsa.PrivateKey{
			PublicKey: *pubKey,
			D:         new(big.Int).SetBytes(key.D.Bytes()),
			Primes: []*big.Int{
				new(big.Int).SetBytes(key.Primes[0].Bytes()),
				new(big.Int).SetBytes(key.Primes[1].Bytes()),
			},
		}
	} else {
		privateKey = &rsa.PrivateKey{
			PublicKey: *pubKey,
		}
	}

	return privateKey
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

func encodeDerToPem(der []byte, t string) string {
	p := pem.EncodeToMemory(
		&pem.Block{
			Type:  t,
			Bytes: der,
		},
	)

	return string(p)
}

// EncodePublicKey marshalls an RSA public key into a string or returns an error.
func EncodePublicKey(pub *rsa.PublicKey) (string, error) {
	pubder, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}

	return encodeDerToPem(pubder, "RSA PUBLIC KEY"), nil
}

// EncodePrivateKey marshalls an RSA private key into a string or returns an error.
func EncodePrivateKey(priv *rsa.PrivateKey) string {
	privder := x509.MarshalPKCS1PrivateKey(priv)
	return encodeDerToPem(privder, "RSA PRIVATE KEY")
}

// EncodeFMPPrivateKey marshalls an RSA private key using FMP types into a string or returns an
// error.
func EncodeFMPPrivateKey(priv *FMPPrivateKey) string {
	privder := x509big.MarshalPKCS1BigPrivateKey(FMPtoBigPrivateKey(priv))
	return encodeDerToPem(privder, "RSA PRIVATE KEY")
}
