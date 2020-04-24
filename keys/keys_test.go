package keys

import (
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

func TestEncodePublicKey(t *testing.T) {
	n, _ := new(big.Int).SetString("8597656297860545107091403497608238810415884857788354623649545462584626186357491015183008751788834205126626170046660764709588721169432974804650110624299531971774114543254422558416305578835040900745856782965785268333750404184841766134544089627917308591465828618442384534122739386366913053748919149466237339278512341", 10)
	e := 65537
	pemKey := `-----BEGIN RSA PUBLIC KEY-----
MIGhMA0GCSqGSIb3DQEBAQUAA4GPADCBiwKBgwC60gz5ftUELfaWzk3z5aZ4z0+z
aT098S3+n9P9jMiquLlVM+QU4/wMN39O5UgnEYsdMFYaPHQb6nx2iZeJtRdD4HYJ
LfnrBdyX6xUFzp6xK1q54Qq/VvkgpY5+AOzwWXfocoNN2FhM9KyHy33FAVm9lix1
y++2xqw6MadOfY8eTBDVAgMBAAE=
-----END RSA PUBLIC KEY-----
`

	testKey := rsa.PublicKey{N: n, E: e}
	encodedKey, err := EncodePublicKey(&testKey)

	if err != nil {
		t.Errorf("Error encoding the key: %s\n", err)
	}

	if pemKey != encodedKey {
		t.Errorf("Didnt encode key correctly:\nWanted:\n%s\nGot:\n%s\n", pemKey, encodedKey)
	}
}

func TestEncodePrivateKey(t *testing.T) {
	p, _ := new(fmp.Fmpz).SetString("158304142767773473275973624083670689370769915077762416888835511454118432478825486829242855992134819928313346652550326171670356302948444602468194484069516892927291240140200374848857608566129161693687407393820501709299228594296583862100570595789385365606706350802643746830710894411204232176703046334374939501731", 10)
	q := fmp.NewFmpz(54311)
	e := fmp.NewFmpz(65537)
	n := new(fmp.Fmpz).Mul(p, q)
	d := ln.SolveforD(p, q, e)
	pemKey := `-----BEGIN RSA PRIVATE KEY-----
MIICpwIBAAKBgwC60gz5ftUELfaWzk3z5aZ4z0+zaT098S3+n9P9jMiquLlVM+QU
4/wMN39O5UgnEYsdMFYaPHQb6nx2iZeJtRdD4HYJLfnrBdyX6xUFzp6xK1q54Qq/
VvkgpY5+AOzwWXfocoNN2FhM9KyHy33FAVm9lix1y++2xqw6MadOfY8eTBDVAgMB
AAECgYJFlcHtNhAA2W3vKuk23oB3M4+IAe+hIy0nl5KjuDx6xtWYbcucckvIX+dG
WRVgvQDlnQ+OZI3zYeWb1Wxmt52woJeq0uo2nUCavzOVlPtxfUqF5waZdYOR9Xjj
Dg2/68dh3KdSOxKYq/OoyzjJRml3fNcwRG6nGhI1HC7WzaXo/4BFAoGBAOFuvbXZ
g3okp9rZULhFhxmiTUDGfGHNnv9HK6aFVPTdfRceok/lNUnHjmDZ/rkSiM2z7E7G
lY/bQUf15FIFjJUVbtFDvRmeI5/9O7TIjD6OR06Cg3WCgEwyp5PktArF1EAitSbw
zNHQjjLgSmKfyiP5l3hq+ncWYGJteYOYxKSjAgMA1CcCgYAuOGNjLpa7a1qTD21y
aqb5hYJrXobQErWfx3rWqI2zqtnj7J8A3JDhcK3rg6arUXaFHne76xFtLlojI/JN
MuARDRTsiQPzha3uNqCQP3IpvUg3e6DybfBaLySWuRSFBOywva0Ar+x+tFEDc2Ms
93AdkiYRRXXXBtp6M9HvPlpLGwICDQUCgYEA1910Fo1Ui3ZH4TbxYjXD77xbW6uF
/lCx4bnkDjpMaTnm8StzfDONy9mGgIk/UgRvxBnCng/M4eLIKpOJv+9/xsl3/ILJ
wf0pPqMIkgH0vvUnBelapUvETfXbtfNtcQUi4xPctU6eaKFOqZ7ffJ6gamCqyZqO
bJMtE+mGE0btphU=
-----END RSA PRIVATE KEY-----
`
	testKey := FMPPrivateKey{
		PublicKey: &FMPPublicKey{
			N: n,
			E: e,
		},
		D: d,
		Primes: []*fmp.Fmpz{
			p,
			q,
		},
		N: n,
	}

	convertedTestKey := FMPtoRSAPrivateKey(&testKey)
	encodedKey := EncodePrivateKey(convertedTestKey)

	if pemKey != encodedKey {
		t.Errorf("Didnt encode key correctly:\nWanted:\n%s\nGot:\n%s\n", pemKey, encodedKey)
	}
}
