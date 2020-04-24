package factordb

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	"github.com/sourcekris/goRsaTool/utils"

	fmp "github.com/sourcekris/goflint"
)

var (
	pRE = regexp.MustCompile("index\\.php\\?id\\=([0-9]+)")
	qRE = regexp.MustCompile("value=\"([0-9\\^\\-]+)\"")
)

// solveforP extracts components of an equation we get back from factordb and solve it
func solveforP(equation string) *fmp.Fmpz {
	// sometimes the input is not an equation
	if utils.IsInt(equation) {
		m, _ := new(fmp.Fmpz).SetString(equation, 10)
		return m
	}

	reResult, _ := regexp.MatchString("^\\d+\\^\\d+\\-\\d+$", equation)
	if reResult != false {
		baseExp := strings.Split(equation, "^")
		subMe := strings.Split(baseExp[1], "-")

		f, _ := new(fmp.Fmpz).SetString(string(subMe[0]), 10)
		g, _ := new(fmp.Fmpz).SetString(string(subMe[1]), 10)
		e, _ := new(fmp.Fmpz).SetString(string(baseExp[0]), 10)

		e.Exp(e, f, nil).Sub(e, g)

		return e
	}

	return ln.BigZero
}

// Attack factors an RSA Public Key using FactorDB.
func Attack(t *keys.RSA) error {
	if t.Key.D != nil {
		// Key already factored.
		return nil
	}

	url2 := "http://www.factordb.com/"
	url1 := url2 + "index.php?query="

	var httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Get(url1 + t.Key.N.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to lookup modulus - unexpected http code: %d", resp.StatusCode)
	}

	// read and response into []byte
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Extract the second url from the response using the regex
	id := pRE.FindAll(bodyBytes, -1)

	// Extract the primes from the second url
	r1, err := httpClient.Get(url2 + string(id[1]))
	if err != nil {
		return err
	}
	defer r1.Body.Close()

	r1Bytes, _ := ioutil.ReadAll(r1.Body)
	r1Prime := strings.Split(string(qRE.Find(r1Bytes)), "\"")[1] // XXX: I bet this panics sometimes?

	r2, err := httpClient.Get(url2 + string(id[2]))
	if err != nil {
		return err
	}
	defer r2.Body.Close()

	r2Bytes, _ := ioutil.ReadAll(r2.Body)
	r2Prime := strings.Split(string(qRE.Find(r2Bytes)), "\"")[1]

	// check if the returned values are all digits
	if !utils.IsInt(r1Prime) || !utils.IsInt(r2Prime) {
		// Try solve them as equations of the form x^y-z
		tmpP := solveforP(r1Prime)
		tmpQ := solveforP(r2Prime)

		if tmpP.Cmp(ln.BigZero) == 0 || tmpQ.Cmp(ln.BigZero) == 0 {
			return errors.New("one or more of the primes could not be resolved")
		}

		t.PackGivenP(tmpP)
		return nil
	}

	// convert them to fmpz
	keyP, _ := new(fmp.Fmpz).SetString(r1Prime, 10)
	keyQ, _ := new(fmp.Fmpz).SetString(r2Prime, 10)

	// if p == q then the whole thing failed rather gracefully
	if keyP.Cmp(keyQ) == 0 {
		return errors.New("factorDB didn't know the factors")
	}

	t.PackGivenP(keyP)
	return nil
}
