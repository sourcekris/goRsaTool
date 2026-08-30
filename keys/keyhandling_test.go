package keys

import (
	"strings"
	"testing"
)

func TestImportPartialPEMKey(t *testing.T) {
	// Sample corrupted/truncated PEM file
	partialPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAJxSLgmubtc2mhWZeOdHCDRTxB+V93Z/DWSjelVPIBwxRlJgJNAP
qG56eUXTfRDXDtXNZxHsxawsbij66nW8vF0CAwEAAQJAVBKCviQ5arfsEPfUpZZ3
XCU9ErvGNs3INzsQ/TasD1y81LOLwL8aGcjJUxBd/CMIzdnckUX756/dvx23p/UC
hQIhANuvpv04bQQXKz9n8e3iZPiDIW5ywFOyeECY05hJmcN/AiEAtikjLVP3e4YO
[... 3 lines corrupted ...]
-----END RSA PRIVATE KEY-----`

	k, err := ImportPartialKey([]byte(partialPEM))
	if err != nil {
		t.Fatalf("expected ImportPartialKey to succeed on partial PEM key, got: %v", err)
	}

	expectedN := "8187195876107996572578139755996580175624529121536102895416285828236829865347369190052578824255966402350178623756856908020353732065415063952323205341690973"
	expectedE := "65537"
	expectedD := "4403224026812007800077234111717220218353567876875398915951871867614683953551311706820786691275220749966127981984372076045570027011173337978882875521827461"
	expectedP := "99366864592773965239947802657858879897214412042060417770159321190554668745599"
	expectedQ := "82393621954972862742731378736767506692926286311987696350693744474296399560227"

	if k.Key.PublicKey == nil || k.Key.PublicKey.N == nil || k.Key.PublicKey.N.String() != expectedN {
		t.Errorf("expected N %s, got %v", expectedN, k.Key.PublicKey.N)
	}
	if k.Key.PublicKey.E == nil || k.Key.PublicKey.E.String() != expectedE {
		t.Errorf("expected E %s, got %v", expectedE, k.Key.PublicKey.E)
	}
	if k.Key.D == nil || k.Key.D.String() != expectedD {
		t.Errorf("expected D %s, got %v", expectedD, k.Key.D)
	}
	if len(k.Key.Primes) != 2 {
		t.Fatalf("expected 2 primes, got %d", len(k.Key.Primes))
	}
	if k.Key.Primes[0].String() != expectedP {
		t.Errorf("expected p %s, got %s", expectedP, k.Key.Primes[0])
	}
	if k.Key.Primes[1].String() != expectedQ {
		t.Errorf("expected q %s, got %s", expectedQ, k.Key.Primes[1])
	}

	dump := k.String()
	if !strings.Contains(dump, expectedN) || !strings.Contains(dump, expectedE) || !strings.Contains(dump, expectedD) || !strings.Contains(dump, expectedP) || !strings.Contains(dump, expectedQ) {
		t.Errorf("dump output missing expected parameters: %s", dump)
	}
}

func TestImportPartialIntegerList(t *testing.T) {
	// Partial integer list with only N and p
	intList := `n = 8187195876107996572578139755996580175624529121536102895416285828236829865347369190052578824255966402350178623756856908020353732065415063952323205341690973
p = 99366864592773965239947802657858879897214412042060417770159321190554668745599`

	k, err := ImportPartialKey([]byte(intList))
	if err != nil {
		t.Fatalf("expected ImportPartialKey to succeed on partial integer list, got: %v", err)
	}

	expectedQ := "82393621954972862742731378736767506692926286311987696350693744474296399560227"
	if len(k.Key.Primes) != 2 || k.Key.Primes[1].String() != expectedQ {
		t.Errorf("expected deduced q %s, got %v", expectedQ, k.Key.Primes)
	}
}

func TestImportPartialWithPrimesOnly(t *testing.T) {
	pVal := "99366864592773965239947802657858879897214412042060417770159321190554668745599"
	qVal := "82393621954972862742731378736767506692926286311987696350693744474296399560227"
	intList := "p = " + pVal + "\nq = " + qVal + "\ne = 65537\n"

	k, err := ImportPartialKey([]byte(intList))
	if err != nil {
		t.Fatalf("expected ImportPartialKey to succeed on primes-only integer list, got: %v", err)
	}

	expectedN := "8187195876107996572578139755996580175624529121536102895416285828236829865347369190052578824255966402350178623756856908020353732065415063952323205341690973"
	if k.Key.PublicKey.N.String() != expectedN {
		t.Errorf("expected computed N %s, got %v", expectedN, k.Key.PublicKey.N)
	}
	if k.Key.D == nil {
		t.Errorf("expected computed D when e, p, q are present, got nil")
	}
}

func TestImportInvalidKey(t *testing.T) {
	invalid := "this is completely invalid gibberish without any numbers"
	_, err := ImportPartialKey([]byte(invalid))
	if err == nil {
		t.Errorf("expected error on completely invalid key, got nil")
	}
}
