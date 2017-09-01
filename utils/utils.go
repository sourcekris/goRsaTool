package utils

import (
  "bytes"
  "fmt"
  "io/ioutil"
  "unicode"

  "github.com/ncw/gmp"
  "github.com/sourcekris/goRsaTool/libnum"
)

func ReadCipherText(cipherFile string) ([]byte, error) {
  ct, err := ioutil.ReadFile(cipherFile)
  if err != nil {
    fmt.Printf("[-] Error opening ciphertext file: %s\n", cipherFile)
    return nil, err
  }

  return bytes.TrimRight(ct, "\n\r"), nil
}

// given e, p and q solve for the private exponent d
func SolveforD(p *gmp.Int, q *gmp.Int, e *gmp.Int) *gmp.Int {
  pm1 := new(gmp.Int).Sub(p, gmp.NewInt(1))
  qm1 := new(gmp.Int).Sub(q, gmp.NewInt(1))
  phi := new(gmp.Int).Mul(pm1, qm1)
  return new(gmp.Int).ModInverse(e, phi)
}

// given d, e, and n, find p and q
func FindPGivenD(d *gmp.Int, e *gmp.Int, n *gmp.Int) *gmp.Int {
  bigOne := gmp.NewInt(1)
  bigTwo := gmp.NewInt(2)
  m      := new(gmp.Int)
  tmp    := new(gmp.Int)

  ktot   := new(gmp.Int).Set(tmp.Mul(d,e).Sub(tmp,gmp.NewInt(1)))
  t      := new(gmp.Int).Set(ktot)
  p      := gmp.NewInt(0)
  
  for tmp.Mod(t,bigTwo).Cmp(gmp.NewInt(0)) == 0 {
    t.DivMod(t, bigTwo, m)
  }

  for a := 2; a < 1000; a+=2 {
    k := new(gmp.Int).Set(t)

    cand := new(gmp.Int)
    for k.Cmp(ktot) < 0 {
      cand.Exp(gmp.NewInt(int64(a)), k, n)

      if cand.Cmp(bigOne) != 0 && cand.Cmp(tmp.Sub(n,bigOne)) != 0 && tmp.Exp(cand, bigTwo, n).Cmp(bigOne) == 0 {
        p = libnum.FindGcd(tmp.Add(cand, bigOne), n)
        return p
      }

      k.Mul(k,bigTwo)
    }
  }

  return p
}

func IsInt(s string) bool {
  for _, c := range s {
    if !unicode.IsDigit(c) {
      return false
    }
  }
  return true
}
