/*
 * check if factordb already has the factors for our modulus 
 */

package attacks

 import (
 	"crypto/rsa"
 	"fmt"
 	"io/ioutil"
 	"math/big"
 	"net/http"
 	"strings"
 	"regexp"
 	"time"
 	"unicode"
 )

// XXX: move to some util package
func isInt(s string) bool {
	for _, c := range s {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}

// given e, p and q solve for the private exponent d
func solveforD(p *big.Int, q *big.Int, e int) *big.Int {
	pm1 := big.NewInt(0).Sub(p, big.NewInt(1))
	qm1 := big.NewInt(0).Sub(q, big.NewInt(1))
	phi := big.NewInt(0).Mul(pm1, qm1)
	return big.NewInt(0).ModInverse(big.NewInt(int64(e)), phi)
}

// XXX: this should update the privatekey 
func Factordb(pubKey *rsa.PrivateKey) {
	url2 := "http://www.factordb.com/"
	url1 := url2 + "index.php?query="
	

	var httpClient = &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Get(url1 + pubKey.N.String())
	if err != nil {
		// return nil, errors.New("Failed to contact url."
		fmt.Printf("[-] FactorDB was unreachable?\n")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		// read and response into []byte
		bodyBytes, _ := ioutil.ReadAll(resp.Body)

		// Extract the second url from the response using the regex
		re, _ := regexp.Compile("index\\.php\\?id\\=([0-9]+)")
		id := re.FindAll(bodyBytes,-1)

		// Extract the primes from the second url
		re2, _     := regexp.Compile("value=\"([0-9\\^\\-]+)\"")

		r1, _      := httpClient.Get(url2 + string(id[1]))
		defer r1.Body.Close()
		r1Bytes, _ := ioutil.ReadAll(r1.Body)
		r1Prime    := strings.Split(string(re2.Find(r1Bytes)), "\"")[1] // XXX: I bet this panics sometimes?

		r2, _	   := httpClient.Get(url2 + string(id[2]))
		defer r2.Body.Close()
		r2Bytes, _ := ioutil.ReadAll(r2.Body)
		r2Prime    := strings.Split(string(re2.Find(r2Bytes)), "\"")[1]

		// check if the returned values are all digits
		if !isInt(r1Prime) || !isInt(r2Prime) {
			// XXX: Handle non integer, but valid, primes here
			// XXX: e.g. https://github.com/sourcekris/RsaCtfTool/blob/master/RsaCtfTool.py#L125
			fmt.Printf("[-] One or more of the primes returned by factordb wasnt an integer.\n")
			return
		}

		// convert them to big Ints
		key_p := new(big.Int)
		key_p.SetString(r1Prime, 10)
		key_q := new(big.Int)
		key_q.SetString(r2Prime, 10)

		// if p == q then the whole thing failed rather gracefully
		if key_p.Cmp(key_q) == 0 {
			fmt.Printf("[-] FactorDB didn't know the factors.\n")
			return
		} else {
			fmt.Printf("[+] Found the factors:\n")
			pubKey.Primes = []*big.Int{key_p, key_q}
			pubKey.D      = solveforD(key_p, key_q, pubKey.E)
		}
	} else {
		fmt.Printf("[-] Unexpected HTTP code (%d) so we failed to lookup modulus.\n", resp.StatusCode)
		return
	}


}
