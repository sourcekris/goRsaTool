package libnum

import "math/big"

func FindGcd(a, b *big.Int) *big.Int {
	// x := new(Int)
  	// y := new(Int)
 
  	return new(big.Int).GCD(nil, nil, a, b)
}