package knownprime

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

func TestAttack(t *testing.T) {
	tt := []struct {
		name    string
		n       *fmp.Fmpz
		e       *fmp.Fmpz
		p       *fmp.Fmpz
		want    *fmp.Fmpz
		wantErr bool
	}{
		{
			name: "correct p expected to recover d",
			n:    ln.FmpString("8450644104582630021913242817568386538429120040389468339510333421395291191808975476248589106433145451532657547271656922804866789681499743153740737742332951"),
			e:    fmp.NewFmpz(65537),
			p:    ln.FmpString("85413884848837835273799534222229453212517685015009235268389913012627608586153"),
			want: ln.FmpString("2302822116724006127246419632863173706300344153704251263794727323080069356157791792381334590808366391320159938345096496437339325191405775580716524653434897"),
		},
		{
			name:    "wrong p not a factor of n",
			n:       ln.FmpString("8450644104582630021913242817568386538429120040389468339510333421395291191808975476248589106433145451532657547271656922804866789681499743153740737742332951"),
			e:       fmp.NewFmpz(65537),
			p:       ln.FmpString("129837912873918739"),
			wantErr: true,
		},
	}

	for _, tc := range tt {
		k, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}), nil, nil, "", false)
		k.Key.Primes = append(k.Key.Primes, tc.p)

		ch := make(chan error)
		go Attack([]*keys.RSA{k}, ch)
		err := <-ch
		if err != nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if err == nil && tc.wantErr {
			t.Errorf("Attack() failed: %s expected error got no error", tc.name)
		}

		if k.Key.D == nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s did not recover the private key", tc.name)
		}

		if !tc.wantErr {
			got := k.Key.D
			if got.Cmp(tc.want) != 0 {
				t.Errorf("%s failed - got / want mismatched: %v / %v", tc.name, got, tc.want)
			}
		}
	}
}
