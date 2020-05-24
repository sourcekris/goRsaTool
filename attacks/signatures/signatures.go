// Package signatures implements recoving the modulus from signatures and plaintexts.
package signatures

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	"github.com/sourcekris/goRsaTool/utils"
	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "recover n from sigs and plaintexts"

// Note this attack is different to the other attack packages in that it is called directly from
// rsatool.go:main.

// Attack calculates an RSA modulus given two known plaintexts and two signatures generated with
// that modulus. Optionally a exponent may be provided but if e is nil then 65537 will be used.
func Attack(ptlist, siglist []string, exp string) error {
	var (
		sigs []*fmp.Fmpz
		pts  []*fmp.Fmpz
	)

	if len(ptlist) != 2 || len(siglist) != 2 {
		return fmt.Errorf("signature mode requires exactly 2 plaintexts and 2 signatures")
	}

	e, ok := new(fmp.Fmpz).SetString(exp, 10)
	if exp == "" || !ok {
		e = fmp.NewFmpz(65537)
	}

	for _, s := range siglist {
		d, err := utils.ReadBinary(s)
		if err != nil {
			return fmt.Errorf("error reading signature %s: %v", s, err)
		}
		sigs = append(sigs, ln.BytesToNumber(d))
	}

	for _, p := range ptlist {
		d, err := utils.ReadBinary(p)
		if err != nil {
			return fmt.Errorf("error reading plaintext %s: %v", p, err)
		}
		pts = append(pts, ln.BytesToNumber(d))
	}

	res := new(fmp.Fmpz).GCD(
		new(fmp.Fmpz).Exp(sigs[0], e, nil).SubZ(pts[0]),
		new(fmp.Fmpz).Exp(sigs[1], e, nil).SubZ(pts[1]),
	)

	if res.Cmp(sigs[0]) < 0 || res.Cmp(sigs[1]) < 0 {
		return fmt.Errorf("%s failed to recover the modulus, the resulting modulus was smaller than one of the signatures", name)
	}

	k, err := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: res, E: e}), nil, nil, "", false)
	if err != nil {
		return fmt.Errorf("%s failed to construct rsa key once modulus was recovered", name)
	}

	fmt.Println("Recovered public key:")
	fmt.Println(keys.EncodeFMPPublicKey(k.Key.PublicKey))
	return nil
}
