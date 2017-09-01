package attacks

import (
  "crypto/x509"
  "encoding/pem"
  "errors"
  "fmt"
  "io/ioutil"
  
  "github.com/ncw/gmp"
  "github.com/sourcekris/x509big"
)

// Use local variant of the standard x509 library to yield a gmp Public Key
func parsePublicRsaKey(keyBytes []byte) (*GMPPublicKey, error) {
  key, err := x509big.ParseBigPKIXPublicKey(keyBytes)
  if err != nil {
    return nil, errors.New("Failed to parse the DER key after decoding.")
  }

  switch key := key.(type) {
    case *x509big.BigPublicKey:
      k := &GMPPublicKey{
        N: new(gmp.Int).SetBytes(key.N.Bytes()),
        E: new(gmp.Int).SetBytes(key.E.Bytes()),
      }
      return k, nil
    default:
      return nil, errors.New("Given key is not an RSA Key")
  }
}

func parsePrivateRsaKey(keyBytes []byte) (*GMPPrivateKey, error) {
  key, err := x509.ParsePKCS1PrivateKey(keyBytes)
  if err != nil {
    return nil, errors.New("Failed to parse the DER key after decoding.")
  }
  k := RSAtoGMPPrivateKey(key)
  return &k, nil
}
/*
 * Take a Public Key and return a Private Key with the public components packed
 */
func PrivateFromPublic(key *GMPPublicKey) *GMPPrivateKey {
  return &GMPPrivateKey{
            PublicKey: key,
            N: key.N,
          }
}

// import a PEM key file and return a rsa.PrivateKey object
func ImportKey(keyFile string) (*GMPPrivateKey, error) {
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
  
  // extract a GMPPublicKey from the DER decoded data and pack a private key struct
  key, err := parsePublicRsaKey(block.Bytes)
  if err == nil {
    return PrivateFromPublic(key), err
  } 

  priv, err := parsePrivateRsaKey(block.Bytes)
  if err != nil {
    return nil, errors.New("Failed to parse the key as either a public or private key.")
  }
  return priv, err

}