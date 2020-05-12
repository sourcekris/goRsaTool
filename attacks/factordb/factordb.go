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

// Attack factors an RSA Public Key using FactorDB API.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		// Key already factored.
		return nil
	}

	var httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Get(base + t.Key.N.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("%s failed to lookup modulus - unexpected http code: %d", name, resp.StatusCode)
	}

	js, err := ioutil.ReadAll(resp.Body)
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
