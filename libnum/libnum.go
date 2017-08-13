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

func NthRoot(k int64, n *gmp.Int) *gmp.Int {
  a    := new(gmp.Int)
  bigK := gmp.NewInt(k)
  u    := new(gmp.Int).Set(n)

  k1   := new(gmp.Int).Sub(bigK, gmp.NewInt(1))
  s    := new(gmp.Int).Add(n, gmp.NewInt(1))

  for u.Cmp(s) < 0 {
    s.Set(u)
    a.Mul(u, k1)
    u.Exp(u, k1, nil).Div(n, u).Add(a,u)
    // this computation is super duper slow
    u.Div(u, bigK)
  }
  
  return s
}