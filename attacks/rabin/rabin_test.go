package rabin

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
		c       *fmp.Fmpz
		p       *fmp.Fmpz
		q       *fmp.Fmpz
		kpt     []byte
		want    string
		wantErr bool
	}{
		{
			name: "challenge example with both primes p and q provided",
			n:    ln.FmpString("39416542393528896469794633372610830269223094917405535270799542860552246020309"),
			e:    fmp.NewFmpz(2),
			c:    ln.FmpString("18535188524492261989297529234678737433412836568353300870238799016955517178121"),
			p:    ln.FmpString("180681734391364529780600935381603868843"),
			q:    ln.FmpString("218154549635609229498293724249121422463"),
			want: "flag{rsa_master}",
		},
		{
			name: "challenge example with only prime p provided (q deduced)",
			n:    ln.FmpString("39416542393528896469794633372610830269223094917405535270799542860552246020309"),
			e:    fmp.NewFmpz(2),
			c:    ln.FmpString("18535188524492261989297529234678737433412836568353300870238799016955517178121"),
			p:    ln.FmpString("180681734391364529780600935381603868843"),
			want: "flag{rsa_master}",
		},
		{
			name: "test with known plaintext prefix",
			n:    ln.FmpString("39416542393528896469794633372610830269223094917405535270799542860552246020309"),
			e:    fmp.NewFmpz(2),
			c:    ln.FmpString("18535188524492261989297529234678737433412836568353300870238799016955517178121"),
			p:    ln.FmpString("180681734391364529780600935381603868843"),
			kpt:  []byte("flag{"),
			want: "flag{rsa_master}",
		},
		{
			name:    "invalid exponent e = 3",
			n:       ln.FmpString("39416542393528896469794633372610830269223094917405535270799542860552246020309"),
			e:       fmp.NewFmpz(3),
			c:       ln.FmpString("18535188524492261989297529234678737433412836568353300870238799016955517178121"),
			p:       ln.FmpString("180681734391364529780600935381603868843"),
			wantErr: true,
		},
		{
			name:    "missing ciphertext",
			n:       ln.FmpString("39416542393528896469794633372610830269223094917405535270799542860552246020309"),
			e:       fmp.NewFmpz(2),
			p:       ln.FmpString("180681734391364529780600935381603868843"),
			wantErr: true,
		},
		{
			name:    "missing primes",
			n:       ln.FmpString("39416542393528896469794633372610830269223094917405535270799542860552246020309"),
			e:       fmp.NewFmpz(2),
			c:       ln.FmpString("18535188524492261989297529234678737433412836568353300870238799016955517178121"),
			wantErr: true,
		},
		{
			name:    "invalid prime p not dividing n",
			n:       ln.FmpString("39416542393528896469794633372610830269223094917405535270799542860552246020309"),
			e:       fmp.NewFmpz(2),
			c:       ln.FmpString("18535188524492261989297529234678737433412836568353300870238799016955517178121"),
			p:       ln.FmpString("180681734391364529780600935381603868847"),
			wantErr: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			k, _ := keys.NewRSA(keys.PrivateFromPublic(&keys.FMPPublicKey{
				N: tc.n,
				E: tc.e,
			}), nil, nil, "", false)

			if tc.c != nil {
				k.CipherText = ln.NumberToBytes(tc.c)
			}
			if tc.p != nil {
				k.Key.Primes = append(k.Key.Primes, tc.p)
			}
			if tc.q != nil {
				k.Key.Primes = append(k.Key.Primes, tc.q)
			}
			if tc.kpt != nil {
				k.KnownPlainText = tc.kpt
			}

			ch := make(chan error)
			go Attack([]*keys.RSA{k}, ch)
			err := <-ch

			if err != nil && !tc.wantErr {
				t.Fatalf("Attack() failed: unexpected error %v", err)
			}

			if err == nil && tc.wantErr {
				t.Fatalf("Attack() failed: expected error but got none")
			}

			if !tc.wantErr && string(k.PlainText) != tc.want {
				t.Errorf("Attack() plaintext mismatch: got %q, want %q", string(k.PlainText), tc.want)
			}
		})
	}
}

func TestTonelliShanks(t *testing.T) {
	// Prime p = 73 is 1 mod 8
	p := fmp.NewFmpz(73)
	for a := int64(1); a < 73; a++ {
		orig := fmp.NewFmpz(a)
		c := new(fmp.Fmpz).Mul(orig, orig).ModZ(p)
		root, err := tonelliShanks(c, p)
		if err != nil {
			t.Fatalf("tonelliShanks failed for a=%d, p=73: %v", a, err)
		}
		sq := new(fmp.Fmpz).Mul(root, root).ModZ(p)
		if !sq.Equals(c) {
			t.Errorf("tonelliShanks incorrect root for a=%d: got %v, sq=%v, c=%v", a, root, sq, c)
		}
	}
}
