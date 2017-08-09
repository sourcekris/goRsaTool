package libnum

import (
  "math/big"
)

func BytesToNumber(src []byte) *big.Int {
  return new(big.Int).SetBytes(src)
}

func NumberToBytes(src *big.Int) []byte {
  return src.Bytes()
}

func NthRoot(k int64, n *big.Int) *big.Int {
  a    := new(big.Int)
  bigK := big.NewInt(k)
  u    := new(big.Int).Set(n)

  k1   := new(big.Int).Sub(bigK, big.NewInt(1))
  s    := new(big.Int).Add(n, big.NewInt(1))
  
  for u.Cmp(s) < 0 {
    s.Set(u)
    a.Mul(u, k1)
    u.Exp(u, k1, nil).Div(n, u).Add(a,u).Div(u, bigK)
  }
  
  return s
}