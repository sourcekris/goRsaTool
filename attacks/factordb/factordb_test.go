package factordb

import (
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	"github.com/sourcekris/goRsaTool/utils"

	fmp "github.com/sourcekris/goflint"
)

var jsonBlob string

func askertest(hc *http.Client, url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(strings.NewReader(jsonBlob)),
	}, nil
}

func TestFactorDB(t *testing.T) {
	// Mock the http request result.
	asker = askertest

	tt := []struct {
		name    string
		n       *fmp.Fmpz
		jb      string
		want    string
		wantErr bool
	}{
		{
			name: "vulnerable key expected to factor",
			n:    ln.FmpString("833810193564967701912362955539789451139872863794534923259743419423089229206473091408403560311191545764221310666338878019"),
			jb:   `{"id":"1100000000886507194","status":"FF","factors":[["863653476616376575308866344984576466644942572246900013156919",1],["965445304326998194798282228842484732438457170595999523426901",1]]}`,
			want: "863653476616376575308866344984576466644942572246900013156919",
		},
		{
			name:    "non vulnerable key is composite",
			n:       ln.FmpString("8586738020906178596816665408975869027249332195806516889218842326669979457567897544415936583733118068451112024495528372623268891464850844330698707082078341676048316328425781368868164458486632570090121972627446596326046274266659293352906034163997023314644106659615348855576648233885381655772208214809201687506171743157882478565146018301168224250821080109298362928393693620666868337500513217122524859198701942611835138196019213020523307383514277039557237260096859973"),
			jb:      `{"id":"1100000001262333660","status":"C","factors":[["8586738020906178596816665408975869027249332195806516889218842326669979457567897544415936583733118068451112024495528372623268891464850844330698707082078341676048316328425781368868164458486632570090121972627446596326046274266659293352906034163997023314644106659615348855576648233885381655772208214809201687506171743157882478565146018301168224250821080109298362928393693620666868337500513217122524859198701942611835138196019213020523307383514277039557237260096859973",1]]}`,
			wantErr: true,
		},
	}

	for _, tc := range tt {
		fmpPubKey := &keys.FMPPublicKey{
			N: tc.n,
			E: fmp.NewFmpz(65537),
		}

		jsonBlob = tc.jb

		k, _ := keys.NewRSA(keys.PrivateFromPublic(fmpPubKey), nil, nil, "", false)
		err := Attack([]*keys.RSA{k})
		if err != nil && !tc.wantErr {
			t.Errorf("Attack() failed: %s expected no error got error: %v", tc.name, err)
		}

		if err == nil && tc.wantErr {
			t.Errorf("Attack() failed: %s expected error got no error", tc.name)
		}

		if !utils.FoundP(ln.FmpString(tc.want), k.Key.Primes) && !tc.wantErr {
			t.Errorf("Attack() failed: %s expected primes not found - got %v wanted %v", tc.name, k.Key.Primes, tc.want)
		}
	}
}
