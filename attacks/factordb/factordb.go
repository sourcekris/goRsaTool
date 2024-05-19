package factordb

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"time"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "factordb factorization"

var (
	base       = "http://www.factordb.com/api?query="
	query      = "index.php?query="
	linkPrefix = "index.php?id="
	// eqRE is a regex that matches equations in the form x^y-z
	eqRE = regexp.MustCompile(`^(\d+)\^(\d+)\-(\d+)$`)
)

type factorDB struct {
	ID      int          	`json:"id"`
	Status  string          `json:"status"`
	Factors [][]interface{} `json:"factors"`
}

// asker can be replaced with another function returning a mock http.Response.
var asker = askFactorDB

// askFactorDB abstracts out the HTTP get so we can mock factordb in unit tests.
func askFactorDB(hc *http.Client, url string) (*http.Response, error) {
	resp, err := hc.Get(url)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Attack factors an RSA Public Key using FactorDB API.
func Attack(ts []*keys.RSA, ch chan error) {
	t := ts[0]
	if t.Key.D != nil {
		// Key already factored.
		ch <- nil
		return
	}

	hc := &http.Client{
		Timeout: 15 * time.Second,
	}

	r, err := asker(hc, base+t.Key.N.String())
	if err != nil {
		ch <- err
		return
	}
	defer r.Body.Close()

	if r.StatusCode != 200 {
		ch <- fmt.Errorf("%s failed to lookup modulus - unexpected http code: %d", name, r.StatusCode)
		return
	}

	js, err := ioutil.ReadAll(r.Body)
	if err != nil {
		ch <- err
		return
	}

	fdb := factorDB{}
	if err := json.Unmarshal(js, &fdb); err != nil {
		ch <- err
		return
	}

	if fdb.Status == "FF" {
		if len(fdb.Factors) < 1 {
			ch <- fmt.Errorf("%s failed due to an unknown error - modulus status is FF but primes were not found", name)
			return
		}

		var primes []*fmp.Fmpz
		for _, f := range fdb.Factors {
			prime, ok := f[0].(string)
			if !ok {
				ch <- fmt.Errorf("%s failed asserting that the factor is a string: %v", name, f)
				return
			}
			primes = append(primes, ln.FmpString(prime))
		}

		// RSA normally has 2 primes but can have more. Handle the simple case first.
		if len(primes) == 2 {
			t.PackGivenP(primes[0])
			ch <- nil
			return
		}

		if err := t.PackMultiPrime(primes); err != nil {
			ch <- err
			return
		}

		ch <- nil
		return
	}

	ch <- fmt.Errorf("%s failed - the modulus is not fully factored on factordb (status = %s)", name, fdb.Status)
}
