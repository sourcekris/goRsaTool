package qicheng

import (
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "qicheng factorization"

var (
	state = new(fmp.FlintRandT)
	nTwo  = fmp.NewFmpz(-2)
)

// Integers is a Ring of integers modulo n.
type Integers struct {
	n *fmp.Fmpz
}

// NewIntegers constructs a new Ring of Integers with modulo n and returns it.
func NewIntegers(n *fmp.Fmpz) *Integers {
	return &Integers{n: n}
}

// RandomElement chooses a random element in the Ring i.
func (i *Integers) RandomElement() *fmp.Fmpz {
	return ln.GetRand(state, i.n)
}

// Curve represents the curve y^2 = x^3 + a.
type Curve struct {
	a1    *fmp.Fmpz // a_invariant a1
	a2    *fmp.Fmpz // a_invariant a2
	a3    *fmp.Fmpz // a_invariant a3
	a4    *fmp.Fmpz // a_invariant a4
	a6    *fmp.Fmpz // a_invariant a6
	b2    *fmp.Fmpz // b_invariant b1
	b4    *fmp.Fmpz // b_invariant b2
	b6    *fmp.Fmpz // b_invariant b3
	b8    *fmp.Fmpz // b_invariant b4
	cache map[string]string
}

// NewCurve creates a curve.
func NewCurve(x, y *fmp.Fmpz, r *Integers) *Curve {
	// Set a_invariants
	c := &Curve{
		a1: fmp.NewFmpz(0),
		a2: fmp.NewFmpz(0),
		a3: fmp.NewFmpz(0),
		a4: new(fmp.Fmpz).Set(x),
		a6: new(fmp.Fmpz).Set(y),
	}
	c.BInvariants(r)
	c.cache = make(map[string]string)
	return c
}

// BInvariants sets the B invariants (b2,4,6 and 8) on curve e in the ring r.
func (e *Curve) BInvariants(r *Integers) {
	// a1*a1 + 4*a2
	b2 := new(fmp.Fmpz).Mul(e.a1, e.a1).AddZ(new(fmp.Fmpz).Mul(ln.BigFour, e.a2))
	e.b2 = new(fmp.Fmpz).Mod(b2, r.n)

	// a1*a3 + 2*a4
	b4 := new(fmp.Fmpz).Mul(e.a1, e.a3).AddZ(new(fmp.Fmpz).Mul(ln.BigTwo, e.a4))
	e.b4 = new(fmp.Fmpz).Set(b4) //.Mod(b4, r.n)

	// a3**2 + 4*a6
	b6 := new(fmp.Fmpz).Mul(e.a3, e.a3).AddZ(new(fmp.Fmpz).Mul(ln.BigFour, e.a6))
	if new(fmp.Fmpz).Mod(b6, r.n).Equals(ln.BigZero) {
		e.b6 = new(fmp.Fmpz).Set(b6)
	} else {
		e.b6 = b6.ModZ(r.n)
	}

	// a1**2 * a6 + 4*a2*a6 - a1*a3*a4 + a2*a3**2 - a4**2
	b8 := new(fmp.Fmpz).Add(
		new(fmp.Fmpz).Mul(e.a1, e.a1).MulZ(e.a6),
		new(fmp.Fmpz).Mul(e.a2, e.a6).MulI(4)).SubZ(
		new(fmp.Fmpz).Mul(e.a1, e.a3).MulZ(e.a4)).AddZ(
		new(fmp.Fmpz).Mul(e.a3, e.a3).MulZ(e.a2)).SubZ(
		new(fmp.Fmpz).Mul(e.a4, e.a4))
	e.b8 = b8.ModZ(r.n)
}

// Poly calculates a set of polynomials in the univariate polynomial ring in x over the ring
// of integers r. Ported from sagemath source.
func (e *Curve) Poly(n, x *fmp.Fmpz, r *Integers) *fmp.Fmpz {
	// These values are deterministic so keep them in a cache.
	if v, ok := e.cache[n.String()]; ok {
		// Use strings since storing pointers was too hard to debug.
		return ln.FmpString(v)
	}

	switch {
	// n == -2
	case n.Equals(nTwo):
		// return poly(-1)**2
		res := new(fmp.Fmpz)
		res.ExpXI(e.Poly(fmp.NewFmpz(-1), x, r), 2).ModZ(r.n)
		e.cache[n.String()] = res.String()
		return res
	// n == -1
	case n.Equals(ln.BigNOne):
		// 4*x**3 + b2*x**2 + 2*b4*x + b6
		res := new(fmp.Fmpz)
		res.ExpXI(x, 3).MulI(4).AddZ(
			new(fmp.Fmpz).ExpXI(x, 2).MulZ(e.b2)).AddZ(
			new(fmp.Fmpz).Mul(e.b4, x).MulI(2)).AddZ(e.b6).ModZ(r.n)
		e.cache[n.String()] = res.String()
		return res
	// n < -2
	case n.Cmp(nTwo) < 0:
		return nil
	// n == 1 || n == 2
	case n.Equals(ln.BigOne) || n.Equals(ln.BigTwo):
		res := fmp.NewFmpz(1)
		e.cache[n.String()] = res.String()
		return res
	// n == 3
	case n.Equals(ln.BigThree):
		// 3*x**4 + b2*x**3 + 3*b4*x**2 + 3*b6*x + b8
		res := new(fmp.Fmpz)
		res.ExpXI(x, 4).MulI(3).AddZ(
			new(fmp.Fmpz).ExpXI(x, 3).MulZ(e.b2)).AddZ(
			new(fmp.Fmpz).ExpXI(x, 2).MulZ(e.b4).MulI(3)).AddZ(
			new(fmp.Fmpz).Mul(e.b6, x).MulI(3)).AddZ(e.b8).ModZ(r.n)
		e.cache[n.String()] = res.String()
		return res
	// n == 4
	case n.Equals(ln.BigFour):
		// -poly(-2) + (6*x**2 + b2*x + b4) * poly(3)
		p1 := e.Poly(nTwo, x, r).MulI(-1)
		p2 := new(fmp.Fmpz).Mul(x, x).MulI(6).AddZ(new(fmp.Fmpz).Mul(e.b2, x)).AddZ(e.b4)
		p3 := e.Poly(ln.BigThree, x, r)
		res := new(fmp.Fmpz).Mul(p2, p3).AddZ(p1).ModZ(r.n)
		e.cache[n.String()] = res.String()
		return res
	// n % 2 == 0
	case new(fmp.Fmpz).Mod(n, ln.BigTwo).Equals(ln.BigZero):
		// m = (n-2) // 2
		m := new(fmp.Fmpz).Sub(n, fmp.NewFmpz(2))
		m.Div(m, ln.BigTwo)
		p1 := e.Poly(new(fmp.Fmpz).Add(m, ln.BigOne), x, r)
		p2 := e.Poly(new(fmp.Fmpz).Add(m, ln.BigThree), x, r)
		p3 := new(fmp.Fmpz).ExpXI(e.Poly(m, x, r), 2)
		p4 := e.Poly(new(fmp.Fmpz).Sub(m, ln.BigOne), x, r)
		p5 := new(fmp.Fmpz).ExpXI(e.Poly(new(fmp.Fmpz).Add(m, ln.BigTwo), x, r), 2)
		res := p1.MulZ(new(fmp.Fmpz).Mul(p2, p3).SubZ(new(fmp.Fmpz).Mul(p4, p5))).ModZ(r.n)
		e.cache[n.String()] = res.String()
		return res
	default:
		// m = (n-1) // 2
		m := new(fmp.Fmpz).Sub(n, fmp.NewFmpz(1))
		m.Div(m, ln.BigTwo)
		// if m % 2 == 0
		if new(fmp.Fmpz).Mod(m, ln.BigTwo).Equals(ln.BigZero) {
			// poly(-2) * poly(m+2) * poly(m)**3 - poly(m-1) * poly(m+1)**3
			p1 := e.Poly(fmp.NewFmpz(-2), x, r)
			p2 := e.Poly(new(fmp.Fmpz).Add(m, ln.BigTwo), x, r)
			p3 := new(fmp.Fmpz).ExpXI(e.Poly(m, x, r), 3)
			p4 := e.Poly(new(fmp.Fmpz).Sub(m, ln.BigOne), x, r)
			p5 := new(fmp.Fmpz).ExpXI(e.Poly(new(fmp.Fmpz).Add(m, ln.BigOne), x, r), 3)
			res := new(fmp.Fmpz).Mul(p1, p2).MulZ(p3).SubZ(new(fmp.Fmpz).Mul(p4, p5)).ModZ(r.n)
			e.cache[n.String()] = res.String()
			return res
		}
		// poly(m+2) * poly(m)**3 - poly(-2) * poly(m-1) * poly(m+1)**3
		p1 := e.Poly(new(fmp.Fmpz).Add(m, ln.BigTwo), x, r)
		p2 := new(fmp.Fmpz).ExpXI(e.Poly(m, x, r), 3)
		p3 := e.Poly(nTwo, x, r)
		p4 := e.Poly(new(fmp.Fmpz).Sub(m, ln.BigOne), x, r)
		p5 := new(fmp.Fmpz).ExpXI(e.Poly(new(fmp.Fmpz).Add(m, ln.BigOne), x, r), 3)
		res := new(fmp.Fmpz).Mul(p1, p2).SubZ(new(fmp.Fmpz).Mul(p3, p4).MulZ(p5)).ModZ(r.n)
		e.cache[n.String()] = res.String()
		return res
	}
}

// Attack implements the Qi Cheng attack.
func Attack(ks []*keys.RSA) error {
	k := ks[0]
	js := []*fmp.Fmpz{
		fmp.NewFmpz(0),
		fmp.NewFmpz(-32768),              // (-2^5)^3
		fmp.NewFmpz(-884736),             // (-2^5*3)^3
		fmp.NewFmpz(-147197952000),       // (-2^5*3*5*11)^3
		fmp.NewFmpz(-262537412640768000), // (-2^6*3*5*23*29)^3
	}

	R := NewIntegers(k.Key.N)
	attempts := 20

	for i := 0; i < attempts; i++ {
		for _, j := range js {
			var E *Curve
			if j.Equals(ln.BigZero) {
				a := R.RandomElement()
				E = NewCurve(fmp.NewFmpz(0), a, R)
			} else {
				a := new(fmp.Fmpz).Set(j)
				p2 := new(fmp.Fmpz).Sub(fmp.NewFmpz(1728), j)
				a.DivR(p2, R.n)
				c := R.RandomElement()
				x := new(fmp.Fmpz).ExpXI(c, 2).MulZ(a).MulI(3) // 3*a*c^2
				y := new(fmp.Fmpz).ExpXI(c, 3).MulZ(a).MulI(2) // 2*a*c^3
				E = NewCurve(x, y, R)
			}
			x := R.RandomElement()
			z := E.Poly(k.Key.N, x, R)
			g := ln.FindGcd(z, k.Key.N)

			if g.Cmp(ln.BigOne) > 0 {
				k.PackGivenP(g)
				return nil
			}
		}
	}

	return fmt.Errorf("%s attack failed - no factors found", name)
}
