package williamsp1

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

func foundP(p *fmp.Fmpz, ps []*fmp.Fmpz) bool {
	for _, prime := range ps {
		if p.Cmp(prime) == 0 {
			return true
		}
	}
	return false
}

func TestAttack(t *testing.T) {
	tt := []struct {
		name    string
		n       *fmp.Fmpz
		wantP   *fmp.Fmpz
		wantErr bool
	}{
		{
			name:  "vulnerable key expected to factor",
			n:     ln.FmpString("149767527975084886970446073530848114556615616489502613024958495602726912268566044330103850191720149622479290535294679429142532379851252608925587476670908668848275349192719279981470382501117310509432417895412013324758865071052169170753552224766744798369054498758364258656141800253652826603727552918575175830897"),
			wantP: ln.FmpString("11807485231629132025602991324007150366908229752508016230400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"),
		},
	}

	for _, tc := range tt {
		fmpPubKey := &keys.FMPPublicKey{
			N: tc.n,
			E: fmp.NewFmpz(65537),
		}

		k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
		err := Attack([]*keys.RSA{k})
		if err != nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if k.Key.D == nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s d not found", tc.name)
		}

		if !foundP(tc.wantP, k.Key.Primes) {
			t.Errorf("Attack() failed: %s expected primes not found - got %v wanted %v", tc.name, k.Key.Primes, tc.wantP)
		}
	}
}
