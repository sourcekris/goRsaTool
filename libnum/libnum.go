package libnum

import (
  "github.com/ncw/gmp"
)

func BytesToNumber(src []byte) *gmp.Int {
  return new(gmp.Int).SetBytes(src)
}

func NumberToBytes(src *gmp.Int) []byte {
  return src.Bytes()
}

/*
 * returns true if n is a perfect square false otherwise
 */
func IsPerfectSquare(n *gmp.Int) *gmp.Int {
  h := new(gmp.Int).And(n, gmp.NewInt(0xF))
  bigNegOne := gmp.NewInt(-1)

  if h.Cmp(gmp.NewInt(9)) > 1 {
    return bigNegOne
  }

  if (h.Cmp(gmp.NewInt(2)) != 0 && h.Cmp(gmp.NewInt(3)) != 0 && 
     h.Cmp(gmp.NewInt(5)) != 0 && h.Cmp(gmp.NewInt(6)) != 0 &&
     h.Cmp(gmp.NewInt(7)) != 0 && h.Cmp(gmp.NewInt(8)) != 0) {

    t := new(gmp.Int).Sqrt(n)

    if t.Mul(t,t).Cmp(n) == 0 {
      return t
    } else {
      return bigNegOne
    }
  }

  return bigNegOne
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
      return gmp.NewInt(0), gmp.NewInt(1)
    case 1: 
      return gmp.NewInt(int64(frac[0])), gmp.NewInt(1)
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