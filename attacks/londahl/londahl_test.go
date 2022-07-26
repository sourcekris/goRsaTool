package londahl

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
			name: "vulnerable key expected to factor (70second runtime)",
			n:    ln.FmpString("2462649746477364143454082050368305440553491900304388646893610847386194301369924385009730987303651345060031438478297733694036327257723431468649220444397635127530301992505638291521092898714917678389314956983918603221732358628680256253537449204312287724750669208856634711056863315465220853759428826555838536733"),
			e:    fmp.NewFmpz(201527),
			want: ln.FmpString("1569283195117237003369661884198411787798228566690474267312882038063657810434869771811957721834374075850363708418225687871888930709588875800968904667752571"),
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
