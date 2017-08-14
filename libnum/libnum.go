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