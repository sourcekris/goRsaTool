package wiener

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
		e       *fmp.Fmpz
		wantP   *fmp.Fmpz
		wantErr bool
	}{
		{
			name:  "vulnerable key expected to factor",
			n:     ln.FmpString("3334856810184677477844358144018917794041731190055839506761047725196006094980863695382177363193369966486016701249215142483636637554021814543035830546215989929795663440797135714052529156584121356430820344157690550828800881814240591307966102200317439798025514933024378636034699031813537269957366107757164860989844073107586429425720904855051982116041375607063348284181020075517929415641544289763746613008111428479297057733166557625147336147566880214355650641577166264521190299115885380737405565001610566944363859489100969586274685083957891857940299867778179224315829434940724792203814646820239647654928926010057013368458245514278044491268911004184046810260941759997123197041098733517706050844547145597277455472453774614055218254132399751743258899881787475545751497375960922131268299479552529031035888108780949909103896592757431124458704783417755010801978390551651313047542712508524793275560368174745062513752629553237925010211952156417038790055587317248535295143994247940211251656493513423704508343198542105407781884990875230425908547394673929549851133924331163825482577078961944622191862486639441372854700487426887512910454786510827672456213611323195410584868699053780747730586864834422625763265388125692936999503906754918551854172173689"),
			e:     ln.FmpString("2886742484284236738106774553791894046416444145459517541766656102330583532154902136604981835389880876713510845417271964019204206949327057151814809422028064218677671539780756790073245011971779691151399771785594074102959490942011855461922052373256869112586069827237757677531152193793922244290357631084923476294942724769982806739137984440930721076461131445531563983299231761780264950983814074640237982898488917656165224244195387250924608815967348988209556714420639312419361130926877862538413221196848322559474276711620086565581403677553882228263027399722889281656046918967381048807623526364266143600256088104112918099637085367138980880401801929864949191436201487350316442963262388421086044955615708039631976078142986495395413372609466947411695520320289903706466828341807884432581092036782685314853874294858647103670051043525755503755113156275596704174274371810869392692475528911042436194087115337615374222449956292870848959480797114952026583740853480852705976157805343363101525183964560440988129944984991815645605643759337280581457184559678726060653232062032958445566260119329244132071683732161836203152982640205805727156468285180704488652033448482014914282137473931519173301689100603078652134608031181394091081450726382793079353630028427"),
			wantP: ln.FmpString("56214247180961101472418904084010866028721084750603538850912412988629938657856050506199747131481758687951394659255916498984648545468149966951075957118009649410947195509540243734626631437077632294920348877778126106857190799098500548702150792996731448944864546089813716649988246458024209115269339139700713248173765122394228136275663424166384192546495220986511506395231230712368557643028950758002822402061597625771649228811312719338006284781996960825317128843424255164212087586472800077894183144689764968774192993792706953206432004848853187269871408285302806880768934306325931793314083485686465813811090736334222919041553"),
		},
	}

	for _, tc := range tt {
		fmpPubKey := &keys.FMPPublicKey{
			N: tc.n,
			E: tc.e,
		}

		k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
		err := Attack(k)
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