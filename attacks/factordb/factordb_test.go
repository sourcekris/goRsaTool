package factordb

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

func TestFactorDB(t *testing.T) {
	n, _ := new(fmp.Fmpz).SetString("833810193564967701912362955539789451139872863794534923259743419423089229206473091408403560311191545764221310666338878019", 10)
	d, _ := new(fmp.Fmpz).SetString("521250646663056391768764366517618655312275374668692430321064634566533568373969990465313092928455546989832961905578375473", 10)

	fmpPubKey := &keys.FMPPublicKey{
		N: n,
		E: fmp.NewFmpz(65537),
	}

	targetRSA, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
	if err := Attack(targetRSA); err != nil {
		t.Fatalf("got unexpected error: %v", err)
	}

	if targetRSA.Key.D.Cmp(d) != 0 {
		t.Errorf("got %v wanted %v for d\n", targetRSA.Key.D, d)
	}
}

func TestSolveForP(t *testing.T) {
	tt := []struct {
		name    string
		eq      string
		want    *fmp.Fmpz
		wantErr bool
	}{
		{
			name: "expected equation format",
			eq:   "2^10-1",
			want: fmp.NewFmpz(1023),
		},
		{
			name:    "partial equation format",
			eq:      "2^10",
			want:    fmp.NewFmpz(-1),
			wantErr: true,
		},
		{
			name:    "unexpected equation format",
			eq:      "2+4-1",
			want:    fmp.NewFmpz(-1),
			wantErr: true,
		},
		{
			name:    "empty equation",
			eq:      "",
			want:    fmp.NewFmpz(-1),
			wantErr: true,
		},
	}

	for _, tc := range tt {
		got := solveforP(tc.eq)
		if tc.want.Cmp(got) != 0 && !tc.wantErr {
			t.Errorf("solveforP: %s failed - got %v want %v", tc.name, got, tc.want)
		}

		if got.Cmp(ln.BigZero) == 0 && !tc.wantErr {
			t.Errorf("solveforP: %s unexpected error", tc.name)
		}

		if got.Cmp(ln.BigZero) != 0 && tc.wantErr {
			t.Errorf("solveforP: %s unexpected result when expected error: %v", tc.name, got)
		}
	}
}
