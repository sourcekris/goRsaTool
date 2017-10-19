package attacks

import (
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "errors"
  "fmt"
  "math"
  "math/big"
  fmp "github.com/sourcekris/goflint"
  "github.com/sourcekris/goRsaTool/libnum"
  "github.com/sourcekris/x509big"
)

// final internal representation for keys
type FMPPublicKey struct {
  N *fmp.Fmpz
  E *fmp.Fmpz
}

type FMPPrivateKey struct {
  PublicKey *FMPPublicKey
  D *fmp.Fmpz
  Primes []*fmp.Fmpz
  N *fmp.Fmpz
}

/*
 * wrap rsa.PrivateKey and add a field for cipher and plaintexts
 */
type RSAStuff struct {
  Key FMPPrivateKey
  CipherText []byte
  PlainText []byte
  PastPrimesFile string
}

/*
 * constructor for RSAStuff struct
 */
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
      Key: *key,
      PastPrimesFile: pastPrimesFile,
      CipherText: cipherText,
    }, nil
}

/*
 * Given one prime p, pack the Key member of the RSAStuff struct with the private key values, p, q & d
 */
func (targetRSA *RSAStuff) PackGivenP(p *fmp.Fmpz) {
  q := new(fmp.Fmpz).Div(targetRSA.Key.N, p)
  targetRSA.Key.Primes = []*fmp.Fmpz{p, q}
  targetRSA.Key.D      = libnum.SolveforD(p, q, targetRSA.Key.PublicKey.E)
}

func (targetRSA *RSAStuff) DumpKey() {
  fmt.Printf("[*] n = %s\n", targetRSA.Key.PublicKey.N)
  fmt.Printf("[*] e = %s\n", targetRSA.Key.PublicKey.E)

  // XXX: Support RSA multiprime [where len(key.Primes) > 2]
  if targetRSA.Key.D!= nil {
    fmt.Printf("[*] d = %s\n", targetRSA.Key.D)
    fmt.Printf("[*] p = %s\n", targetRSA.Key.Primes[0])
    fmt.Printf("[*] q = %s\n", targetRSA.Key.Primes[1])
  }

  if len(targetRSA.CipherText) > 0 {
    fmt.Printf("[*] c = %s\n", libnum.BytesToNumber(targetRSA.CipherText))
  }
}

/*
 * Takes a rsa.PrivateKey and returns a FMPPrivateKey that uses fmp.Fmpz types
 */
func RSAtoFMPPrivateKey(key *rsa.PrivateKey) FMPPrivateKey {
  fmpPubKey := &FMPPublicKey{
    N: new(fmp.Fmpz).SetBytes(key.N.Bytes()),
    E: fmp.NewFmpz(int64(key.E)),
  }

  var fmpPrivateKey *FMPPrivateKey
  if key.D != nil {
    fmpPrivateKey = &FMPPrivateKey{
      PublicKey: fmpPubKey,
      D: new(fmp.Fmpz).SetBytes(key.D.Bytes()),
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

func FMPtoRSAPrivateKey(key *FMPPrivateKey) *rsa.PrivateKey {
  if key.PublicKey.E.Cmp(fmp.NewFmpz(math.MaxInt64)) > 0 {
    // XXX todo: handle better? phase out rsa.PrivateKey types
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
      D: new(big.Int).SetBytes(key.D.Bytes()),
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

func FMPtoBigPrivateKey(key *FMPPrivateKey) *x509big.BigPrivateKey {
  pubKey := &x509big.BigPublicKey{
    N: new(big.Int).SetBytes(key.N.Bytes()),
    E: new(big.Int).SetBytes(key.PublicKey.E.Bytes()),
  }

  var privateKey *x509big.BigPrivateKey
  if key.D != nil {
    privateKey = &x509big.BigPrivateKey{
      PublicKey: *pubKey,
      D: new(big.Int).SetBytes(key.D.Bytes()),
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
      Type: t, 
      Bytes: der,
      },
    )

  return string(p)
}

func EncodePublicKey(pub *rsa.PublicKey) (string, error) {
  pubder, err := x509.MarshalPKIXPublicKey(pub)
  if err != nil {
    return "", err
  }

  return encodeDerToPem(pubder, "RSA PUBLIC KEY"), nil
}

func EncodePrivateKey(priv *rsa.PrivateKey) string {
  privder := x509.MarshalPKCS1PrivateKey(priv)
  return encodeDerToPem(privder, "RSA PRIVATE KEY")
}

func EncodeFMPPrivateKey(priv *FMPPrivateKey) string {
  privder := x509big.MarshalPKCS1BigPrivateKey(FMPtoBigPrivateKey(priv))
  return encodeDerToPem(privder, "RSA PRIVATE KEY")
}