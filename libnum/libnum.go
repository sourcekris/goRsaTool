package libnum

import (
  "github.com/ncw/gmp"
)

var (
  BigNOne  = gmp.NewInt(-1)
  BigZero  = gmp.NewInt(0)
  BigOne   = gmp.NewInt(1)
  BigTwo   = gmp.NewInt(2)
  BigThree = gmp.NewInt(3)
  BigFour  = gmp.NewInt(4)
  BigFive  = gmp.NewInt(5)
  BigSix   = gmp.NewInt(6)
  BigSeven = gmp.NewInt(7)
  BigEight = gmp.NewInt(8)
  BigNine  = gmp.NewInt(9)
  BigEleven  = gmp.NewInt(11)
  BigSixteen = gmp.NewInt(0xf)
)

func BytesToNumber(src []byte) *gmp.Int {
  return new(gmp.Int).SetBytes(src)
}

func NumberToBytes(src *gmp.Int) []byte {
  return src.Bytes()
}

// given e, p and q solve for the private exponent d
func SolveforD(p *gmp.Int, q *gmp.Int, e *gmp.Int) *gmp.Int {
  return new(gmp.Int).ModInverse(e, 
            new(gmp.Int).Mul(
                new(gmp.Int).Sub(p, BigOne), 
                new(gmp.Int).Sub(q, BigOne)
              )
            )
}

/* 
 * given d, e, and n, find p and q - uses an algorithm from pycrypto _slowmath.py [0]
 * [0]: https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/_slowmath.py
 */
func FindPGivenD(d *gmp.Int, e *gmp.Int, n *gmp.Int) *gmp.Int {
  m       := new(gmp.Int)
  tmp     := new(gmp.Int)

  ktot    := new(gmp.Int).Set(tmp.Mul(d,e).Sub(tmp,BigOne))
  t       := new(gmp.Int).Set(ktot)

  for tmp.Mod(t,BigTwo).Cmp(BigZero) == 0 {
    t.DivMod(t, BigTwo, m)
  }

  for a := 2; a < 1000; a+=2 {
    k := new(gmp.Int).Set(t)

    cand := new(gmp.Int)
    for k.Cmp(ktot) < 0 {
      cand.Exp(gmp.NewInt(int64(a)), k, n)

      if cand.Cmp(BigOne) != 0 && cand.Cmp(tmp.Sub(n,BigOne)) != 0 && tmp.Exp(cand, BigTwo, n).Cmp(BigOne) == 0 {
        return FindGcd(tmp.Add(cand, BigOne), n)
      }

      k.Mul(k,BigTwo)
    }
  }

  return BigZero
}

/*
 * returns t if n is a perfect square -1 otherwise
 */
func IsPerfectSquare(n *gmp.Int) *gmp.Int {
  h := new(gmp.Int).And(n, BigSixteen)

  if h.Cmp(gmp.NewInt(9)) > 1 {
    return BigNOne
  }

  if (h.Cmp(BigTwo) != 0 && h.Cmp(BigThree) != 0 && 
     h.Cmp(BigFive) != 0 && h.Cmp(BigSix) != 0 &&
     h.Cmp(BigSeven) != 0 && h.Cmp(BigEight) != 0) {

    t := new(gmp.Int).Sqrt(n)

    if t.Mul(t,t).Cmp(n) == 0 {
      return t
    } else {
      return BigNOne
    }
  }

  return BigNOne
}

func RationalToContfract(x, y *gmp.Int) []int {
  a := new(gmp.Int).Div(x,y)
  b := new(gmp.Int).Mul(a,y)
  c := new(gmp.Int)

  var pquotients []int

  if b.Cmp(x) == 0 {
    return []int{int(a.Int64())}
  }
  c.Mul(y,a).Sub(x,c)
  pquotients = RationalToContfract(y, c)
  pquotients = append([]int{int(a.Int64())}, pquotients...)
  return pquotients
}

func ContfractToRational(frac []int) (*gmp.Int, *gmp.Int) {
  var remainder []int

  switch l := len(frac); l {
    case 0: 
      return BigZero, BigOne
    case 1: 
      return gmp.NewInt(int64(frac[0])), BigOne
    default: 
      remainder = frac[1:l]
      num, denom := ContfractToRational(remainder)
      fracZ := gmp.NewInt(int64(frac[0]))
      return fracZ.Mul(fracZ, num).Add(fracZ, denom), num
  }
}

func ConvergantsFromContfract(frac []int) [][2]*gmp.Int {
  var convs [][2]*gmp.Int

  for i, _ := range frac {
    a, b := ContfractToRational(frac[0:i])
    z := [2]*gmp.Int{a, b}
    convs = append(convs, z)
  }
  return convs
}