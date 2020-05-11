package fermat

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
			n:    ln.FmpString("163325259729739139586456854939342071588766536976661696628405612100543978684304953042431845499808366612030757037530278155957389217094639917994417350499882225626580260012564702898468467277918937337494297292631474713546289580689715170963879872522418640251986734692138838546500522994170062961577034037699354013013"),
			e:    fmp.NewFmpz(65537),
			want: ln.FmpString("12779877140635552275193974526927174906313992988726945426212616053383820179306398832891367199026816638983953765799977121840616466620283861630627224899027521"),
		},
	}

	for _, tc := range tt {
		k, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}), nil, nil, "", false)
		err := Attack([]*keys.RSA{k})
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
