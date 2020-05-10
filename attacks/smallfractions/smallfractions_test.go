package smallfractions

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

func TestAttack(t *testing.T) {
	fmpPubKey := &keys.FMPPublicKey{
		N: ln.FmpString("207858268718455276831200912684980984824578588190204197472403531338628406400110488622194176904033713524423232229185097795372252163472504321674334445022911835680389482521223677787948987323108793945203232736942944396527891302324471875508607456094556408391316041194492812742420991377357813167227802828310432509001"),
		E: fmp.NewFmpz(65537),
	}

	k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
	err := Attack([]*keys.RSA{k})
	if err != nil {
		t.Errorf("attack")
	}
}
