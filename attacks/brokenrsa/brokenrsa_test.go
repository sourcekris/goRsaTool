package brokenrsa

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
		ct      *fmp.Fmpz
		want    string
		wantErr bool
	}{
		{
			name: "valid test case should get ciphertext",
			n:    ln.FmpString("5496273377454199065242669248583423666922734652724977923256519661692097814683426757178129328854814879115976202924927868808744465886633837487140240744798219"),
			e:    ln.FmpString("431136"),
			ct:   ln.FmpString("2390642180797714842071565779994548288162547531430992356948054123172912061708724438750151247823692618495310950448700556438560565499149411218448809600"),
			want: "this is a test this is a test this is a test this is a test",
		},
		{
			name:    "invalid case, e is a factor of n",
			n:       ln.FmpString("145089264118764276482000175726681870278495712"),
			e:       ln.FmpString("431136"),
			ct:      ln.FmpString("123456"),
			wantErr: true,
		},
		{
			name:    "invalid case, ct is not provided",
			n:       ln.FmpString("145089264118764276482000175726681870278495712"),
			e:       ln.FmpString("431136"),
			wantErr: true,
		},
	}

	for _, tc := range tt {
		k, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{
			N: tc.n,
			E: tc.e,
		}), nil, nil, "", false)

		if tc.ct != nil {
			k.CipherText = ln.NumberToBytes(tc.ct)
		}
		ch := make(chan error)
		go Attack([]*keys.RSA{k}, ch)
		err := <-ch
		if err != nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if string(k.PlainText) != tc.want && !tc.wantErr {
			t.Errorf("Attack() failed: %s got/want mismatch %s/%s", tc.name, string(k.PlainText), tc.want)
		}
	}

}
