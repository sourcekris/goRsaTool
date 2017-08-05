package utils

import (
  "crypto/rsa"
  "crypto/x509"
  "encoding/pem"
)

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