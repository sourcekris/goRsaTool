package wiener2

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
		c       *fmp.Fmpz
		wantP   *fmp.Fmpz
		wantErr bool
	}{
		{
			name:  "vulnerable key expected to factor",
			n:     ln.FmpString("744818955050534464823866087257532356968231824820271085207879949998948199709147121321290553099733152323288251591199926821010868081248668951049658913424473469563234265317502534369961636698778949885321284313747952124526309774208636874553139856631170172521493735303157992414728027248540362231668996541750186125327789044965306612074232604373780686285181122911537441192943073310204209086616936360770367059427862743272542535703406418700365566693954029683680217414854103"),
			e:     ln.FmpString("57595780582988797422250554495450258341283036312290233089677435648298040662780680840440367886540630330262961400339569961467848933132138886193931053170732881768402173651699826215256813839287157821765771634896183026173084615451076310999329120859080878365701402596570941770905755711526708704996817430012923885310126572767854017353205940605301573014555030099067727738540219598443066483590687404131524809345134371422575152698769519371943813733026109708642159828957941"),
			c:     ln.FmpString("305357304207903396563769252433798942116307601421155386799392591523875547772911646596463903009990423488430360340024642675941752455429625701977714941340413671092668556558724798890298527900305625979817567613711275466463556061436226589272364057532769439646178423063839292884115912035826709340674104581566501467826782079168130132642114128193813051474106526430253192254354664739229317787919578462780984845602892238745777946945435746719940312122109575086522598667077632"),
			wantP: ln.FmpString("81898667053185657217776861102656224337812263165063130502957777871041348925820804435312177708107239627478947414639335049629424397181546298293830340074237802740682637764618684298355354362034675963346832521254574471891454131242331773263762275959192346932664193366747472828644538068884275721660320961728062212189"),
		},
	}

	for _, tc := range tt {
		fmpPubKey := &keys.FMPPublicKey{
			N: tc.n,
			E: tc.e,
		}

		k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), ln.NumberToBytes(tc.c), nil, "", false)
		err := Attack([]*keys.RSA{k})
		if err != nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if k.Key.D == nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s d not found", tc.name)
		}

		if !utils.FoundP(tc.wantP, k.Key.Primes) {
			t.Errorf("Attack() failed: %s expected primes not found - got %v wanted %v", tc.name, k.Key.Primes, tc.wantP)
		}
	}
}
