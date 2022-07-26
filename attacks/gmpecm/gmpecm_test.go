package gmpecm

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
		want *fmp.Fmpz
	}{
		{
			name: "vulnerable key expected to factor",
			n:    ln.FmpString("115367564564210182766242534110944507919869313713243756429"),
			want: ln.FmpString("3387679"),
		},
	}

	for _, tc := range tt {
		fmpPubKey := &keys.FMPPublicKey{
			N: tc.n,
			E: fmp.NewFmpz(65537),
		}

		k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
		ch := make(chan error)
		go Attack([]*keys.RSA{k}, ch)
		err := <-ch
		if err != nil {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if !utils.FoundP(tc.want, k.Key.Primes) {
			t.Errorf("Attack() failed: %s expected primes not found - got %v wanted %v", tc.name, k.Key.Primes, tc.want)
		}
	}
}
