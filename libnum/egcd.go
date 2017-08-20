package libnum

import "github.com/ncw/gmp"

// Returns a big.Int GCD of a and b or 1 if a and b are co-prime
func FindGcd(a, b *gmp.Int) *gmp.Int {
  return new(gmp.Int).GCD(nil, nil, a, b)
}