package libnum

import fmp "github.com/sourcekris/goflint"

// Returns a Fmpz GCD of a and b or 1 if a and b are co-prime
func FindGcd(a, b *fmp.Fmpz) *fmp.Fmpz {
  return new(fmp.Fmpz).GCD(a, b)
}