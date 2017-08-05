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