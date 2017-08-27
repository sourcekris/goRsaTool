package attacks

import (
  "bytes"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/asn1"
  "encoding/pem"
  "errors"
  "fmt"
  "io/ioutil"
)

type publicKeyInfo struct {
    Raw       asn1.RawContent
    Algorithm pkix.AlgorithmIdentifier
    PublicKey asn1.BitString
}

type PublicKeyAlgorithm int
  
const (
  UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
  RSA
  DSA
  ECDSA
)

// ParsePKIXPublicKey parses a DER encoded public key. These values are
// typically found in PEM blocks with "BEGIN PUBLIC KEY".
// Taken from the standard library so we can return a gmp PublicKey
func BigParsePKIXPublicKey(derBytes []byte) (pub interface{}, err error) {
  var pki publicKeyInfo
  if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
    return nil, err
  } else if len(rest) != 0 {
    return nil, errors.New("trailing data after ASN.1 of public-key")
  }
  algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
  if algo == UnknownPublicKeyAlgorithm {
    return nil, errors.New("unknown public key algorithm")
  }
  return parsePublicKey(algo, &pki)
}

// Taken from standard library
var (
  oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
  oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
  oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Taken from standard library
func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) PublicKeyAlgorithm {
  switch {
  case oid.Equal(oidPublicKeyRSA):
    return RSA
  case oid.Equal(oidPublicKeyDSA):
    return DSA
  case oid.Equal(oidPublicKeyECDSA):
    return ECDSA
  }
  return UnknownPublicKeyAlgorithm
}

// Taken from standard library, removed DSA, ECDSA support and added big.Int exponent support
func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
  asn1Data := keyData.PublicKey.RightAlign()
  switch algo {
  case RSA:
    // RSA public keys must have a NULL in the parameters
    // (https://tools.ietf.org/html/rfc3279#section-2.3.1).
    if !bytes.Equal(keyData.Algorithm.Parameters.FullBytes, asn1.NullBytes) {
      return nil, errors.New("RSA key missing NULL parameters")
    }

    p := new(BigPublicKey)
    rest, err := asn1.Unmarshal(asn1Data, p)
    if err != nil {
      return nil, err
    }
    if len(rest) != 0 {
      return nil, errors.New("trailing data after RSA public key")
    }

    if p.N.Sign() <= 0 {
      return nil, errors.New("RSA modulus is not a positive number")
    }
    if p.E.Sign() <= 0 {
      return nil, errors.New("RSA public exponent is not a positive number")
    }

    pub := &BigPublicKey{
      E: p.E,
      N: p.N,
    }

    return pub, nil
  case DSA:
    return nil,errors.New("DSA Public Keys not supported")
  case ECDSA:
    return nil,errors.New("ECDSA Public Keys not supported")
  default:
    return nil, nil
  }
}

// Use local variant of the standard x509 library to yield a gmp Public Key
func parsePublicRsaKey(keyBytes []byte) (*BigPublicKey, error) {
  key, err := BigParsePKIXPublicKey(keyBytes)
  if err != nil {
    return nil, errors.New("Failed to parse the DER key after decoding.")
  }

  switch key := key.(type) {
    case *BigPublicKey:
      return key, nil
    default:
      return nil, errors.New("Given key is not an RSA Key")
  }
}

func parsePrivateRsaKey(keyBytes []byte) (*BigPrivateKey, error) {
  key, err := x509.ParsePKCS1PrivateKey(keyBytes)
  if err != nil {
    return nil, errors.New("Failed to parse the DER key after decoding.")
  }
  k := RSAtoBigPrivateKey(key)
  return &k, nil
}

// import a PEM key file and return a rsa.PrivateKey object
func ImportKey(keyFile string) (*BigPrivateKey, error) {
  // read the key from the disk
  keyStr, err := ioutil.ReadFile(keyFile)
  if err != nil {
    fmt.Printf("[-] Failed to open/read file %s\n", keyFile)
    return nil, err
  }

  // decode the PEM data to extract the DER format key
  block, _ := pem.Decode([]byte(keyStr))
  if block == nil {
    return nil, errors.New("Failed to decode PEM key.")
  }
  
  key, err := parsePublicRsaKey(block.Bytes)
  if err == nil {
    priv := BigPrivateKey{PublicKey: key}
    return &priv, err
  } 

  priv, err := parsePrivateRsaKey(block.Bytes)
  if err != nil {
    return nil, errors.New("Failed to parse the key as either a public or private key.")
  }
  return priv, err

}