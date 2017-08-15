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
func IsPerfectSquare(n *gmp.Int) bool {
  h := new(gmp.Int).And(n, gmp.NewInt(0xF))

  if h.Cmp(gmp.NewInt(9)) > 1 {
    return false
  }

  if (h.Cmp(gmp.NewInt(2)) != 0 && h.Cmp(gmp.NewInt(3)) != 0 && 
     h.Cmp(gmp.NewInt(5)) != 0 && h.Cmp(gmp.NewInt(6)) != 0 &&
     h.Cmp(gmp.NewInt(7)) != 0 && h.Cmp(gmp.NewInt(8)) != 0) {

    t := new(gmp.Int).Sqrt(n)

    if t.Mul(t,t).Cmp(n) == 0 {
      return true
    } else {
      false
    }
  }

  return false
}