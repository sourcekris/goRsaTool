package libnum

import "math/big"

// Returns a big.Int GCD of a and b or 1 if a and b are co-prime
func FindGcd(a, b *big.Int) *big.Int {
  	return new(big.Int).GCD(nil, nil, a, b)
}