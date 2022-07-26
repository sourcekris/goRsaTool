package smallq

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	"github.com/sourcekris/goRsaTool/utils"

	fmp "github.com/sourcekris/goflint"
)

func TestAttack(t *testing.T) {
	tt := []struct {
		name string
		n    *fmp.Fmpz
		e    *fmp.Fmpz
		want *fmp.Fmpz
	}{
		{
			name: "vulnerable key expected to factor",
			n:    ln.FmpString("8597656297860545107091403497608238810415884857788354623649545462584626186357491015183008751788834205126626170046660764709588721169432974804650110624299531971774114543254422558416305578835040900745856782965785268333750404184841766134544089627917308591465828618442384534122739386366913053748919149466237339278512341"),
			e:    fmp.NewFmpz(65537),
			want: ln.FmpString("54311"),
		},
	}

	for _, tc := range tt {
		k, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}), nil, nil, "", false)
		ch := make(chan error)
		go Attack([]*keys.RSA{k}, ch)
		err := <-ch
		if err != nil {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if k.Key.D == nil {
			t.Errorf("Attack() failed: %s d not found", tc.name)
		}

		if !utils.FoundP(tc.want, k.Key.Primes) {
			t.Errorf("Attack() failed: %s expected primes not found - got %v wanted %v", tc.name, k.Key.Primes, tc.want)
		}
	}
}
