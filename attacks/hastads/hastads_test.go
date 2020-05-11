package hastads

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

func TestAttack(t *testing.T) {
	tt := []struct {
		name string
		n    *fmp.Fmpz
		e    *fmp.Fmpz
		c    *fmp.Fmpz
		want *fmp.Fmpz
	}{
		{
			name: "vulnerable key expected to decrypt ciphertext",
			n:    ln.FmpString("1953100985460341348696462250270875098931515807146586756296095446519328460202594322688077959911801412881736536007030245814199784734114468379391959242638228445246656155129859794350223734103552981321896683545886584718379382489138858499065228901412805708175575610007278296746952620830529848517741610397035368508736304074009571123132231492002047409382240786830369954266084929667038697671614351425836882238175963587766360974168461069129309445949172255481878016805287109"),
			e:    fmp.NewFmpz(3),
			c:    ln.FmpString("219135993109607778001201845084150602227376141082195657844762662508084481089986056048532133767792600470123444605795683268047281347474499409679660783370627652563144258284648474807381611694138314352087429271128942786445607462311052442015618558352506502586843660097471748372196048269942588597722623967402749279662913442303983480435926749879440167236197705613657631022920490906911790425443191781646744542562221829319509319404420795146532861393334310385517838840775182"),
			want: ln.FmpString("12950973085835763560175702356704747094371821722999497961023063926142573092871510801730909790343717206777660797494675328809965345887934044682722741193527531"),
		},
	}

	for _, tc := range tt {
		k, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}), ln.NumberToBytes(tc.c), nil, "", false)
		err := Attack([]*keys.RSA{k})
		if err != nil {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		got := ln.BytesToNumber(k.PlainText)
		if got.Cmp(tc.want) != 0 {
			t.Errorf("%s failed - got / want mismatched: %v / %v", tc.name, got, tc.want)
		}

	}
}