package franklinreiter

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
		c1   *fmp.Fmpz
		c2   *fmp.Fmpz
		s1   string
		s2   string
		want string
	}{
		{
			name: "vulnerable ciphertext expected to decrypt",
			n:    ln.FmpString("114725527397185618184017233206819193913174443780510744606142335459665478168081417742295326326458510125306461590118257162988125409459000413629137879229803717947627133370343339582895822944017711093729671794212087753322731071609302218014807365556283824229308384059742494244873283137838666434755861643308137132991"),
			e:    fmp.NewFmpz(12289),
			c1:   ln.FmpString("84336407416460843625427593781624730536485596229709440190626674287670777475228406785893387306409434683404100671833436089453052181545719798266630036876236972297529690348240810948785326665763368973591146706639059990203047605841982714927690634660531344624446661412970889441345594013976984854754671754767725695982"),
			c2:   ln.FmpString("108433522906017008278495197987783879471486528773633691777463091220511994338081465794810975023895879791645144373423591708210296929600753248667088855809109388612625629657990865202941156392805298883172220013083950203133508235612777951337805179569637080311969129405357746536070708315303381089318595111429986027843"),
			s1:   "Zzapp",
			s2:   "Crapp",
			want: "gorsatool test: https://github.com/sourcekris/goRsaTool - Crapp",
		},
	}

	for _, tc := range tt {

		k1, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}), ln.NumberToBytes(tc.c1), nil, "", false)
		k2, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}), ln.NumberToBytes(tc.c2), nil, "", false)
		k1.KnownPlainText = []byte(tc.s1)
		k2.KnownPlainText = []byte(tc.s2)

		err := Attack([]*keys.RSA{k1, k2})
		if err != nil {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if string(k1.PlainText) != tc.want {
			t.Errorf("Attack() failed - got / want mismatched: %q / %q", k1.PlainText, tc.want)
		}
	}
}
