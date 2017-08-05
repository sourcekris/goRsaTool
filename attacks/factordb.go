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
  "github.com/sourcekris/goRsaTool/utils"
 )

// extract components of an equation we get back from factordb and solve it
func solveforP(equation string) (*big.Int) {
  // sometimes the input is not an equation
  if utils.IsInt(equation) {
    m, _ := new(big.Int).SetString(equation, 10)
    return m
  }

  reResult, _ := regexp.MatchString("^\\d+\\^\\d+\\-\\d+$", equation)
  if reResult != false {
    baseExp := strings.Split(equation, "^")
    subMe   := strings.Split(baseExp[1], "-")[1]

    e, _ := new(big.Int).SetString(string(baseExp[0]), 10)
    f, _ := new(big.Int).SetString(string(baseExp[1]), 10)
    g, _ := new(big.Int).SetString(string(subMe), 10)
    e.Exp(e,f,nil)
    e.Sub(e,g)
    
    return e
   } 
  
  return big.NewInt(0)
}

// XXX: this should return errors not print them
func FactorDB(pubKey *rsa.PrivateKey) {
  if pubKey.D != nil {
    return
  }

  url2 := "http://www.factordb.com/"
  url1 := url2 + "index.php?query="
  
  var httpClient = &http.Client{
    Timeout: 15 * time.Second,
  }

  resp, err := httpClient.Get(url1 + pubKey.N.String())
  if err != nil {
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

    r2, _    := httpClient.Get(url2 + string(id[2]))
    defer r2.Body.Close()
    r2Bytes, _ := ioutil.ReadAll(r2.Body)
    r2Prime    := strings.Split(string(re2.Find(r2Bytes)), "\"")[1]

    // check if the returned values are all digits
    if !utils.IsInt(r1Prime) || !utils.IsInt(r2Prime) {
      // Try solve them as equations of the form x^y-z
      tmp_p := solveforP(r1Prime)
      tmp_q := solveforP(r2Prime)

      if tmp_p.Cmp(big.NewInt(0)) == 0  || tmp_q.Cmp(big.NewInt(0)) == 0 {
        fmt.Printf("[-] One or more of the primes could not be resolved.\n")
        return
      }

      fmt.Printf("[+] Found the factors:\n")
      pubKey.Primes = []*big.Int{tmp_p, tmp_q}
      pubKey.D      = utils.SolveforD(tmp_p, tmp_q, pubKey.E)

      return
    }

    // convert them to big Ints
    key_p, _ := new(big.Int).SetString(r1Prime, 10)
    key_q, _ := new(big.Int).SetString(r2Prime, 10)

    // if p == q then the whole thing failed rather gracefully
    if key_p.Cmp(key_q) == 0 {
      fmt.Printf("[-] FactorDB didn't know the factors.\n")
      return
    } else {
      fmt.Printf("[+] Found the factors:\n")
      pubKey.Primes = []*big.Int{key_p, key_q}
      pubKey.D      = utils.SolveforD(key_p, key_q, pubKey.E)
    }
  } else {
    fmt.Printf("[-] Unexpected HTTP code (%d) so we failed to lookup modulus.\n", resp.StatusCode)
    return
  }
}
