package dleak

import (
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

func TestDLeakAttack(t *testing.T) {
	testCases := []struct {
		name      string
		n         *fmp.Fmpz
		e         *fmp.Fmpz
		c         *fmp.Fmpz
		dLeak     string
		expectedP *fmp.Fmpz
		expectedQ *fmp.Fmpz
		expectedM string
	}{
		{
			name:      "CTF 255-bit d leak challenge",
			n:         ln.FmpString("65391866461388902676235532835369365681321697811786624365237123709402484427329"),
			e:         fmp.NewFmpz(65537),
			c:         ln.FmpString("38340592239092310543404971837633417838373376016327282627920241671485343857199"),
			dLeak:     "?00011010011011001101??0000000???000101?01011100010000010?00??0??1010111000100??1100011?10100?1101110???0110?00?000110110110?1111000???11000?1100100101??01?0?110?011100?111101010?0000?10100111???111101?010100?001?0?0?00?00010??101?1100?0?011?0??0111010001",
			expectedP: ln.FmpString("220817713421138099294875373508760578749"),
			expectedQ: ln.FmpString("296135058407543361541407768944641726421"),
			expectedM: "flag{goRsaTool_test}",
		},
		{
			name:      "CTF 512-bit d leak challenge (102 unknown bits)",
			n:         ln.FmpString("8541042842778522907285585888837717198079188493799991755117188762401504222003444775116332981802529205420516105771100145712897817963650757489336331851030319"),
			e:         fmp.NewFmpz(65537),
			c:         ln.FmpString("4881384533813894248468533148800785722808818130330345870800731308357163468290941147229800079175344820513877343727382857177907312307434341276816214075513673"),
			dLeak:     "1111?11?111001?1?110?011010?11011100?0100??0??01?011100000?1?101?11000?110?0?000110?110??000111100011001?0101100??001010010?11??011?110?10001?1011?00100101110011?00010110??0111?10011??11?1001101010101001?11??1?1?110?010??010?1000?0100?011101??11011110?11?1001001110111??10011001001000001010?011001101101?11111101011?0?100000011101001??011000000110011?0???000?0???00?01110001100110?0?011?0001?0100?0101111101??1?01??01101?00?1?0001010?10?0?0?0110001000010011???1001?0?1???00000111111??0??000110101101001?01011?0?",
			expectedP: ln.FmpString("77371839319046059857897958063452437723123067157134510188391954309842022481931"),
			expectedQ: ln.FmpString("110389554105844254527099123949154741788337883582942349398028131894175194144749"),
			expectedM: "flag{goRsaTool_test}",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "CTF 512-bit d leak challenge (102 unknown bits)" && testing.Short() {
				t.Skip("skipping 512-bit test in short mode")
			}
			k, err := keys.NewRSA(
				keys.PrivateFromPublic(&keys.FMPPublicKey{N: tc.n, E: tc.e}),
				ln.NumberToBytes(tc.c),
				nil,
				"",
				false,
			)
			if err != nil {
				t.Fatalf("unexpected error creating RSA key: %v", err)
			}

			k.DLeak = tc.dLeak

			ch := make(chan error, 1)
			go Attack([]*keys.RSA{k}, ch)

			err = <-ch
			if err != nil {
				t.Fatalf("Attack failed: %v", err)
			}

			if k.Key.D == nil {
				t.Fatalf("expected private exponent d to be recovered, got nil")
			}

			if len(k.Key.Primes) < 2 {
				t.Fatalf("expected at least 2 primes, got %d", len(k.Key.Primes))
			}

			pFound := k.Key.Primes[0]
			qFound := k.Key.Primes[1]
			if (!pFound.Equals(tc.expectedP) && !pFound.Equals(tc.expectedQ)) ||
				(!qFound.Equals(tc.expectedP) && !qFound.Equals(tc.expectedQ)) {
				t.Errorf("recovered primes (%v, %v) do not match expected (%v, %v)",
					pFound, qFound, tc.expectedP, tc.expectedQ)
			}

			if string(k.PlainText) != tc.expectedM {
				t.Errorf("expected plaintext %q, got %q", tc.expectedM, string(k.PlainText))
			}
		})
	}
}

func TestDLeakMissingLeak(t *testing.T) {
	k, err := keys.NewRSA(
		keys.PrivateFromPublic(&keys.FMPPublicKey{N: fmp.NewFmpz(143), E: fmp.NewFmpz(65537)}),
		nil,
		nil,
		"",
		false,
	)
	if err != nil {
		t.Fatalf("unexpected error creating RSA key: %v", err)
	}

	ch := make(chan error, 1)
	go Attack([]*keys.RSA{k}, ch)

	err = <-ch
	if err == nil {
		t.Errorf("expected error when DLeak is missing, got nil")
	}
}
