package keys

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	fmp "github.com/sourcekris/goflint"
	"github.com/sourcekris/x509big"
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

func parsePrivateRsaKey(keyBytes []byte) (*FMPPrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsePrivateRsaKey: failed to parse the DER key after decoding: %v", err)
	}
	k := RSAtoFMPPrivateKey(key)
	return &k, nil
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

// ImportKey imports a PEM key file and returns a FMPPrivateKey object or error.
func ImportKey(keyFile string) (*FMPPrivateKey, error) {
	// read the key from the disk
	keyStr, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file %q: %v", keyFile, err)
	}

	// decode the PEM data to extract the DER format key
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM key")
	}

	// extract a FMPPublicKey from the DER decoded data and pack a private key struct
	key, err := parsePublicRsaKey(block.Bytes)
	if err == nil {
		return PrivateFromPublic(key), nil
	}
	if err != nil {
		fmt.Printf("failed decoding public key: %v\n\n", err)
	}

	priv, err := parseBigPrivateRsaKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ImportKey: failed to parse the key as either a public or private key: %v", err)
	}
	return priv, nil

}
