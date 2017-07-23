package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func EncodePublicKey(pub *rsa.PublicKey) (string, error) {
	pubder, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
        return "", err
    }
    pubpem := pem.EncodeToMemory(
    	&pem.Block{
    		Type: "RSA PUBLIC KEY", 
    		Bytes: pubder,
    	},
    )

    return string(pubpem), nil
}

func EncodePrivateKey(priv *rsa.PrivateKey) (string, error) {
	privder := x509.MarshalPKCS1PrivateKey(priv)

    privpem := pem.EncodeToMemory(
    	&pem.Block{
    		Type: "RSA PRIVATE KEY", 
    		Bytes: privder,
    	},
    )

    return string(privpem), nil
}