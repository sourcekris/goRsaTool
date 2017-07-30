package utils

import (
	"unicode"
	"math/big"
)

// given e, p and q solve for the private exponent d
func SolveforD(p *big.Int, q *big.Int, e int) *big.Int {
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	qm1 := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pm1, qm1)
	return new(big.Int).ModInverse(big.NewInt(int64(e)), phi)
}

func IsInt(s string) bool {
	for _, c := range s {
		if !unicode.IsDigit(c) {
			return false
		}
	}
	return true
}
