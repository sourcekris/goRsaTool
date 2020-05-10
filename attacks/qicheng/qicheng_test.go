package qicheng

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

func TestBInvariants(t *testing.T) {
	tt := []struct {
		name string
		r    *Integers
		a    *fmp.Fmpz
		b    *fmp.Fmpz
		want []*fmp.Fmpz
	}{
		{
			name: "EllipticCurve([0,b])",
			r:    NewIntegers(ln.FmpString("1444329727510154393553799612747635457542181563961160832013134005088873165794135221")),
			a:    fmp.NewFmpz(0),
			b:    ln.FmpString("1444329727510154393553799612747635457542181563961160832013134005088873165794135221"),
			want: []*fmp.Fmpz{
				fmp.NewFmpz(0),
				fmp.NewFmpz(0),
				ln.FmpString("5777318910040617574215198450990541830168726255844643328052536020355492663176540884"),
				fmp.NewFmpz(0),
			},
		},
		{
			name: "EllipticCurve([a,b])",
			r:    NewIntegers(ln.FmpString("1444329727510154393553799612747635457542181563961160832013134005088873165794135221")),
			a:    ln.FmpString("423496229321039945556116643191389369486358684004734918579520842555585327761882944"),
			b:    ln.FmpString("382525617787456904681858421867064822089293328016745843619955905207597894835108733"),
			want: []*fmp.Fmpz{
				fmp.NewFmpz(0),
				ln.FmpString("846992458642079891112233286382778738972717368009469837159041685111170655523765888"),
				ln.FmpString("85772743639673225173634074720623830814991748105822542466689615741518413546299711"),
				ln.FmpString("906793044352543692179376902702889004066190101319838967096211504388962447377917658"),
			},
		},
	}

	for _, tc := range tt {
		e := NewCurve(tc.a, tc.b, tc.r)

		binvs := []*fmp.Fmpz{e.b2, e.b4, e.b6, e.b8}
		for i := 0; i < len(binvs); i++ {
			if binvs[i].Cmp(tc.want[i]) != 0 {
				t.Errorf("%s: failed b invariant %d: in R.n: %v - got %v want %v", tc.name, i, tc.r.n, binvs[i], tc.want[i])
			}
		}
	}
}

func TestPoly(t *testing.T) {
	R := NewIntegers(ln.FmpString("1444329727510154393553799612747635457542181563961160832013134005088873165794135221"))
	ca := ln.FmpString("423496229321039945556116643191389369486358684004734918579520842555585327761882944")
	cb := ln.FmpString("382525617787456904681858421867064822089293328016745843619955905207597894835108733")
	tt := []struct {
		name string
		n    *fmp.Fmpz
		x    *fmp.Fmpz
		r    *Integers
		want *fmp.Fmpz
	}{
		{
			name: "n == -1",
			n:    fmp.NewFmpz(-1),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: ln.FmpString("797066342484854716822486592500611953049617124683130486688408996760282378618282336"),
		},
		{
			name: "n == -2",
			n:    fmp.NewFmpz(-2),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: ln.FmpString("69140364535387380313038706329371220366207251580710056708200762600622038237082660"),
		},
		{
			name: "n == 1",
			n:    fmp.NewFmpz(1),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: fmp.NewFmpz(1),
		},
		{
			name: "n == 3",
			n:    fmp.NewFmpz(3),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: ln.FmpString("343004173296097680383472878246156896541327696590867571817221171477915635571593966"),
		},
		{
			name: "n == 4",
			n:    fmp.NewFmpz(4),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: ln.FmpString("361597614256408774776158456942084806832538333907310744909942505850596421648953605"),
		},
		{
			name: "n == 6",
			n:    fmp.NewFmpz(6),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: ln.FmpString("182271512142053510894178443118010689246735590419103022297385735818943242549249647"),
		},
		{
			name: "n == 7",
			n:    fmp.NewFmpz(7),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: ln.FmpString("120457715306308923861796226130655192787136202200715009954306346642703080624281570"),
		},
		{
			name: "n == large",
			n:    ln.FmpString("1444329727510154393553799612747635457542181563961160832013134005088873165794135221"),
			x:    ln.FmpString("178256826685687688974245285625068301063592645151608966740111632474351129116442156"),
			r:    R,
			want: ln.FmpString("229373498035692133428495927374842495497658428725426775944323450406719300255517714"),
		},
	}

	for _, tc := range tt {
		c := NewCurve(ca, cb, R)
		got := c.Poly(tc.n, tc.x, tc.r)
		if got.Cmp(tc.want) != 0 {
			t.Errorf("TestPoly(): %s expected %v got %v\n", tc.name, tc.want, got)
		}
	}

}

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
		wantP   *fmp.Fmpz
		wantErr bool
	}{
		{
			name:  "vulnerable key expected to factor",
			n:     ln.FmpString("1444329727510154393553799612747635457542181563961160832013134005088873165794135221"),
			wantP: ln.FmpString("74611921979343086722526424506387128972933"),
		},
	}

	for _, tc := range tt {
		fmpPubKey := &keys.FMPPublicKey{
			N: tc.n,
			E: fmp.NewFmpz(65537),
		}

		k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
		err := Attack([]*keys.RSA{k})
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
