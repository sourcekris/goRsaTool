package manysmallprimes

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	"github.com/sourcekris/goRsaTool/utils"

	fmp "github.com/sourcekris/goflint"
)

func TestAttack(t *testing.T) {
	tt := []struct {
		name    string
		n       *fmp.Fmpz
		e       *fmp.Fmpz
		numP    int
		want    []*fmp.Fmpz
		wantErr bool
	}{
		{
			name: "vulnerable key with 2 primes expected to factor",
			n:    ln.FmpString("1839290413"),
			e:    fmp.NewFmpz(65537),
			numP: 2,
			want: []*fmp.Fmpz{
				ln.FmpString("42953"),
				ln.FmpString("42821"),
			},
		},
		{
			name: "vulnerable key with 8 primes expected to factor",
			n:    ln.FmpString("32783767296202020287911964765021565179"),
			e:    fmp.NewFmpz(65537),
			numP: 8,
			want: []*fmp.Fmpz{
				ln.FmpString("42953"),
				ln.FmpString("42821"),
				ln.FmpString("49919"),
				ln.FmpString("62477"),
				ln.FmpString("64231"),
				ln.FmpString("46171"),
				ln.FmpString("43177"),
				ln.FmpString("44633"),
			},
		},
		{
			name:    "vulnerable key with 8 primes but we ask for only 6",
			n:       ln.FmpString("32783767296202020287911964765021565179"),
			e:       fmp.NewFmpz(65537),
			numP:    6,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range tt {
		k, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}), nil, nil, "", false)
		k.NumPrimes = tc.numP

		err := Attack([]*keys.RSA{k})
		if err != nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if tc.wantErr && err == nil {
			t.Errorf("Attack() failed: %s expected error but didnt get one.", tc.name)
		}

		if k.Key.D == nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s d not found", tc.name)
		}

		if len(k.Key.Primes) != tc.numP && !tc.wantErr {
			t.Errorf("Attack() failed: %s returned wrong number of primes, wanted %d got %d", tc.name, tc.numP, len(k.Key.Primes))
		}

		if !tc.wantErr && !utils.FoundP(tc.want[0], k.Key.Primes) {
			t.Errorf("Attack() failed: %s expected primes not found - got %v wanted %v", tc.name, k.Key.Primes, tc.want)
		}
	}
}
