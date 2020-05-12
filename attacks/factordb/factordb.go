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
	ID      string          `json:"id"`
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
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		// Key already factored.
		return nil
	}

	hc := &http.Client{
		Timeout: 15 * time.Second,
	}

	r, err := asker(hc, base+t.Key.N.String())
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if r.StatusCode != 200 {
		return fmt.Errorf("%s failed to lookup modulus - unexpected http code: %d", name, r.StatusCode)
	}

	js, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	fdb := factorDB{}
	if err := json.Unmarshal(js, &fdb); err != nil {
		return err
	}

	if fdb.Status == "FF" {
		if len(fdb.Factors) < 1 {
			return fmt.Errorf("%s failed due to an unknown error - modulus status is FF but primes were not found", name)
		}
		p, ok := fdb.Factors[0][0].(string)
		if !ok {
			return fmt.Errorf("%s failed asserting type of factor to be a string: %v", name, fdb.Factors[0][0])
		}

		t.PackGivenP(ln.FmpString(p))
		return nil
	}

	return fmt.Errorf("%s failed - the modulus is not fully factored on factordb (status = %s)", name, fdb.Status)
}
