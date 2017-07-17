package libnum

import "math/big"
import "testing"

func TestFindGcd(t *testing.T) {
	a := big.NewInt(121891891892166)
	b := big.NewInt(15874264264299962)
	c := big.NewInt(1231231231234)
	d := new(big.Int).Set(FindGcd(a, b))

	if c.Cmp(d) != 0 {
		t.Errorf("got %d; want %d for a = %d and b = %d", d, c, a, b)
	}
}