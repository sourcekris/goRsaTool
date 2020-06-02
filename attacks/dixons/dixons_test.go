package dixons

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
			n:    ln.FmpString("23449"),
			e:    ln.FmpString("3"),
			want: ln.FmpString("179"),
		},
	}

	for _, tc := range tt {
		fmpPubKey := &keys.FMPPublicKey{
			N: tc.n,
			E: tc.e,
		}

		k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
		err := Attack([]*keys.RSA{k})
		if err != nil {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if !utils.FoundP(tc.want, k.Key.Primes) {
			t.Errorf("Attack() failed: %s expected primes not found - got %v wanted %v", tc.name, k.Key.Primes, tc.want)
		}
	}
}
