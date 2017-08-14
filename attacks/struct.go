package attacks

import (
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "errors"
  "fmt"
  "math/big"
  "github.com/ncw/gmp"
  "github.com/sourcekris/goRsaTool/libnum"
  "github.com/sourcekris/goRsaTool/utils"
)


type GMPPublicKey struct {
  N *gmp.Int
  E int
}

type GMPPrivateKey struct {
  PublicKey *GMPPublicKey
  D *gmp.Int
  Primes []*gmp.Int
  N *gmp.Int
  E int
}

/*
 * wrap rsa.PrivateKey and add a field for cipher and plaintexts
 */
type RSAStuff struct {
  Key GMPPrivateKey
  CipherText []byte
  PlainText []byte
  PastPrimesFile string
}

/*
 * constructor for RSAStuff struct
 */
func NewRSAStuff(key *rsa.PrivateKey, c []byte, m []byte, pf string) (*RSAStuff, error) {
	if key.N == nil {
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

  // copy a rsa.PrivateKey to a GMPPrivateKey that uses gmp.Int types
  gmpPrivateKey := RSAtoGMPPrivateKey(key)

	// pack the RSAStuff struct
   return &RSAStuff{
      Key: gmpPrivateKey,
      PastPrimesFile: pastPrimesFile,
      CipherText: cipherText,
    }, nil
}

/*
 * Given one prime p, pack the Key member of the RSAStuff struct with the private key values, p, q & d
 */
func (targetRSA *RSAStuff) PackGivenP(p *gmp.Int) {
  q := new(gmp.Int).Div(targetRSA.Key.N, p)
  targetRSA.Key.Primes = []*gmp.Int{p, q}
  targetRSA.Key.D      = utils.SolveforD(p, q, targetRSA.Key.E)
}

func (targetRSA *RSAStuff) DumpKey() {
  fmt.Printf("[*] n = %d\n", targetRSA.Key.N)
  fmt.Printf("[*] e = %d\n", targetRSA.Key.E)

  // XXX: Support RSA multiprime [where len(key.Primes) > 2]
  if targetRSA.Key.D!= nil {
    fmt.Printf("[*] d = %d\n", targetRSA.Key.D)
    fmt.Printf("[*] p = %d\n", targetRSA.Key.Primes[0])
    fmt.Printf("[*] q = %d\n", targetRSA.Key.Primes[1])
  }

  if len(targetRSA.CipherText) > 0 {
    fmt.Printf("[*] c = %d\n", libnum.BytesToNumber(targetRSA.CipherText))
  }
}

/*
 * Takes a rsa.PrivateKey and returns a GMPPrivateKey that uses gmp.Int types
 */
func RSAtoGMPPrivateKey(key *rsa.PrivateKey) GMPPrivateKey {
  gmpPubKey := &GMPPublicKey{
    N: new(gmp.Int).SetBytes(key.N.Bytes()),
    E: key.E,
  }

  var gmpPrivateKey *GMPPrivateKey
  if key.D != nil {
    gmpPrivateKey = &GMPPrivateKey{
      PublicKey: gmpPubKey,
      D: new(gmp.Int).SetBytes(key.D.Bytes()),
      Primes: []*gmp.Int{
        new(gmp.Int).SetBytes(key.Primes[0].Bytes()), 
        new(gmp.Int).SetBytes(key.Primes[1].Bytes()),
        },
    }
  } else {
    gmpPrivateKey = &GMPPrivateKey{
      PublicKey: gmpPubKey,
      N: new(gmp.Int).SetBytes(key.N.Bytes()),
    }
  }

  return *gmpPrivateKey
}

func GMPtoRSAPrivateKey(key *GMPPrivateKey) *rsa.PrivateKey {
  pubKey := &rsa.PublicKey{
    N: new(big.Int).SetBytes(key.N.Bytes()),
    E: key.E,
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

func EncodeGMPPrivateKey(priv *GMPPrivateKey) string {
  privder := x509.MarshalPKCS1PrivateKey(GMPtoRSAPrivateKey(priv))
  return encodeDerToPem(privder, "RSA PRIVATE KEY")
}