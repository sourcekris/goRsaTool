package commonmodulus

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

func TestAttack(t *testing.T) {
	tt := []struct {
		name              string
		n, e1, e2, c1, c2 *fmp.Fmpz
		want              string
	}{
		{
			name: "vulnerable key pair expected to decrypt ciphertext",
			n:    ln.FmpString("103109065902334620226101162008793963504256027939117020091876799039690801944735604259018655534860183205031069083254290258577291605287053538752280231959857465853228851714786887294961873006234153079187216285516823832102424110934062954272346111907571393964363630079343598511602013316604641904852018969178919051627"),
			e1:   fmp.NewFmpz(15),
			e2:   fmp.NewFmpz(13),
			c1:   ln.FmpString("38967886293950546985867681676613352615434882473713119991068626535212734564185912355419456770233949444941309990159162308920790534507784780222115519202945910237562862230081994716883914669123599425624234115903155861365538379461307220740245816973014691900859267636779305799305074874903300596536588584162218944072"),
			c2:   ln.FmpString("9157647088095012062046748255650432863128559227635363601343002558563264824641354745950973451073956019724803522452711780940420352023754867537181517152559773558932493582368026770203019314092960199487326448026403100719420249944863502507256750646664636339722595019148973550504256776135273328419912036360990846157"),
			want: "gorsatool test: https://github.com/sourcekris/goRsaTool",
		},
	}

	for _, tc := range tt {
		k1, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{
			N: tc.n,
			E: tc.e1,
		}), ln.NumberToBytes(tc.c1), nil, "", false)

		k2, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{
			N: tc.n,
			E: tc.e2,
		}), ln.NumberToBytes(tc.c2), nil, "", false)

		ch := make(chan error)
		go Attack([]*keys.RSA{k1, k2}, ch)
		err := <-ch
		if err != nil {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if string(k1.PlainText) != tc.want {
			t.Errorf("Attack() failed: %s expected plaintext %q - got %q", tc.name, tc.want, string(k1.PlainText))
		}
	}
}
