package factordb

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	"github.com/sourcekris/goRsaTool/utils"
	"golang.org/x/net/html"

	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "factordb factorization"

var (
	base       = "http://www.factordb.com/"
	query      = "index.php?query="
	linkPrefix = "index.php?id="
	// eqRE is a regex that matches equations in the form x^y-z
	eqRE = regexp.MustCompile(`^(\d+)\^(\d+)\-(\d+)$`)
)

// solveforP extracts components of an equation we get back from factordb and solve it
func solveforP(equation string) *fmp.Fmpz {
	eq := eqRE.FindStringSubmatch(equation)
	if len(eq) == 4 {
		x, _ := new(fmp.Fmpz).SetString(eq[1], 10)
		y, _ := new(fmp.Fmpz).SetString(eq[2], 10)
		z, _ := new(fmp.Fmpz).SetString(eq[3], 10)
		x.Exp(x, y, nil).Sub(x, z)
		return x
	}
	return ln.BigZero
}

func getHTMLAttr(r io.Reader, attr, prefix string, match int) (string, error) {
	var count int
	z := html.NewTokenizer(r)
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return "", z.Err()
		case html.StartTagToken:
			for {
				k, v, _ := z.TagAttr()
				if string(k) == attr {
					switch {
					case prefix == "":
						if count == match {
							return string(v), nil
						}
						count++
					case prefix != "" && strings.HasPrefix(string(v), prefix):
						if count == match {
							return string(v), nil
						}
						count++
					}
				}

				if k == nil {
					break
				}
			}
		}
	}
}

// Attack factors an RSA Public Key using FactorDB.
func Attack(ts []*keys.RSA) error {
	t := ts[0]
	if t.Key.D != nil {
		// Key already factored.
		return nil
	}

	var httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Get(base + query + t.Key.N.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to lookup modulus - unexpected http code: %d", resp.StatusCode)
	}

	// Parse the response Body looking for links and the respective attributes.
	id, err := getHTMLAttr(resp.Body, "href", linkPrefix, 0)
	if err != nil {
		return err
	}

	// Extract the primes from the second url
	r1, err := httpClient.Get(base + id)
	if err != nil {
		return err
	}
	defer r1.Body.Close()

	primeID, err := getHTMLAttr(r1.Body, "href", linkPrefix, 1)
	if err != nil {
		return err
	}

	r2, err := httpClient.Get(base + primeID)
	if err != nil {
		return err
	}
	defer r2.Body.Close()

	p, err := getHTMLAttr(r2.Body, "value", "", 0)
	if err != nil {
		return err
	}

	// check if the returned values are all digits
	if !utils.IsInt(p) {
		// Try solve them as equations of the form x^y-z
		tmpP := solveforP(p)
		if tmpP.Cmp(ln.BigZero) == 0 {
			return fmt.Errorf("prime p could not be resolved: %v", p)
		}

		t.PackGivenP(tmpP)
		return nil
	}

	keyP, ok := new(fmp.Fmpz).SetString(p, 10)
	if !ok {
		return err
	}

	if keyP.Cmp(t.Key.N) == 0 {
		return fmt.Errorf("%s failed - factordb does not know the factors for %v", name, t.Key.N)
	}
	t.PackGivenP(keyP)
	return nil
}
