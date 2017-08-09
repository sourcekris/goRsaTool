package utils

import (
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
  "errors"
  "fmt"
  "io/ioutil"
)

// https://golang.org/pkg/crypto/x509/#ParsePKIXPublicKey
func parsePublicRsaKey(keyBytes []byte) (*rsa.PublicKey, error) {
  key, err := x509.ParsePKIXPublicKey(keyBytes)//.Bytes)
  if err != nil {
    return nil, errors.New("Failed to parse the DER key after decoding.")
  }
  
  switch key := key.(type) {
  case *rsa.PublicKey:
    return key, nil
  default:
    return nil, errors.New("Given key is not an RSA Key")
  }
}

func parsePrivateRsaKey(keyBytes []byte) (*rsa.PrivateKey, error) {
  key, err := x509.ParsePKCS1PrivateKey(keyBytes)
  if err != nil {
    return nil, errors.New("Failed to parse the DER key after decoding.")
  }
  return key, nil
}

// import a PEM key file and return a rsa.PrivateKey object
func ImportKey(keyFile string) (*rsa.PrivateKey, error) {
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
    priv := rsa.PrivateKey{PublicKey: *key}
    return &priv, err
  } 

  priv, err := parsePrivateRsaKey(block.Bytes)
  if err != nil {
    return nil, errors.New("Failed to parse the key as either a public or private key.")
  }
  return priv, err

}