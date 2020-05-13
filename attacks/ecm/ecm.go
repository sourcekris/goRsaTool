// Package ecm implements the elliptic curve method of factorization and was originally written
// by Keith Randall and distributed under a Public Domain license from his Github here:
// https://github.com/randall77/factorlib
package ecm

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jbarham/primegen"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"

	fmp "github.com/sourcekris/goflint"
)

// timeout puts a limit on how long ecm should attempt to find a solution.
var timeout = time.Minute * 5

// name is the name of this attack.
const name = "ecm factorization"

// point describes an elliptic curve y^2 = x^3 + ax + 1 for a random a in Z_n.
type point struct {
	x, y *fmp.Fmpz
}

func (p point) String() string {
	return fmt.Sprintf("point{%v, %v}", p.x, p.y)
}

func (p point) Zero() bool {
	// since x==y==0 is never a solution to the elliptic curve, we
	// reserve that bit pattern for encoding infinity.
	return p.x.IsZero() && p.y.IsZero()
}

func (p point) Check(n, a *fmp.Fmpz) bool {
	if p.Zero() {
		return true
	}
	lhs := new(fmp.Fmpz).ExpXI(p.y, 2)
	rhs := new(fmp.Fmpz).ExpXI(p.x, 2).AddZ(a).MulZ(p.x).AddZ(ln.BigOne)
	return new(fmp.Fmpz).Sub(lhs, rhs).ModZ(n).IsZero()
}

func (p point) Equals(q point) bool {
	return p.x.Equals(q.x) && p.y.Equals(q.y)
}

func (p point) Add(ch chan bool, q point, n, a, res *fmp.Fmpz) point {
	if p.Zero() {
		return q
	}
	if q.Zero() {
		return p
	}
	var num, denom *fmp.Fmpz
	if !p.x.Equals(q.x) {
		num = new(fmp.Fmpz).Sub(p.y, q.y)
		denom = new(fmp.Fmpz).Sub(p.x, q.x)
	} else if p.y.Equals(q.y) && !p.y.IsZero() {
		// double point
		num = new(fmp.Fmpz).ExpXI(p.x, 2).MulZ(ln.BigThree).AddZ(a)
		denom = new(fmp.Fmpz).Mul(p.y, ln.BigTwo)
	} else {
		return point{fmp.NewFmpz(0), fmp.NewFmpz(0)}
	}
	denom.ModZ(n)
	f := new(fmp.Fmpz).GCD(denom, n)
	if !f.Equals(ln.BigOne) {
		res.Set(f)
		ch <- true
	}
	s := new(fmp.Fmpz).Mul(num, new(fmp.Fmpz).ModInverse(denom, n)).ModZ(n)
	rx := new(fmp.Fmpz).ExpXI(s, 2).SubZ(p.x).SubZ(q.x).ModZ(n)
	ry := new(fmp.Fmpz).Mul(s, new(fmp.Fmpz).Sub(p.x, rx)).SubZ(p.y).ModZ(n)
	return point{rx, ry}
}

func (p point) Mul(ch chan bool, k uint64, n, a, res *fmp.Fmpz) point {
	// compute q=kp by repeated doubling
	q := point{fmp.NewFmpz(0), fmp.NewFmpz(0)}
	for ; k > 1; k >>= 1 {
		if k&1 != 0 {
			q = q.Add(ch, p, n, a, res)
		}
		p = p.Add(ch, p, n, a, res)
	}

	return q.Add(ch, p, n, a, res)
}

// see http://en.wikipedia.org/wiki/Lenstra_elliptic_curve_factorization

// The elliptic curve factorization method (ECM) uses points on the curve
//    y^2 = x^3 + ax + 1 mod n
// where a is chosen at random.
//
// When n is prime, the points on the curve plus a "point at infinity"
// form a group.  Mod a non-prime, they don't quite.  ECM tries to
// find one of these non-group cases and can extract a factorization
// of n from it.
//
// The group + operation on points on the curve is tricky.
// http://en.wikipedia.org/wiki/Elliptic_curve#The_group_law
// The point at infinity is the 0 for the group (x+0=0+x=x).
//  r = p + q:
//    if px != qx
//      s = (qy - py) / (qx - px)
//      rx = s^2 - px - qx
//      ry = s * (px - rx) - py
//    else
//      if py == -qy
//        r = 0,0
//      else
//        must be the case that p == q
//        s = (3*px^2 + a) / (2*py)
//        rx = s^2 - px - qx
//        ry = s * (px - rx) - py
// Where all computations are done mod n.

// When n is not prime, one of the divide steps might fail.  That
// happens because gcd(n, divisor) > 1, and that gives us a factor of
// n.

// We choose a at random, making sure that the elliptic curve is
// nonsingular by checking that 4a^3+27 mod n is not zero.

// Starting at a point p = (0, 1) on the curve, we compute kp for k's
// with lots of small factors.  If we reach the 0 element, then choose
// a new a and try again.  If the divide fails, we've found a factor
// of n.
func ecm(ch chan bool, n, res *fmp.Fmpz, state *fmp.FlintRandT) {
	pg := primegen.New()

	for {
		a := ln.GetRand(state, n)
		if new(fmp.Fmpz).ExpXI(a, 3).MulI(4).AddI(27).ModZ(n).IsZero() {
			// n divides 4a^3+27 - curve has repeating factors, so skip it.
			continue
		}

		p := point{fmp.NewFmpz(0), fmp.NewFmpz(1)}
		for {
			p = p.Mul(ch, pg.Next(), n, a, res)
			if p.Zero() {
				// this curve didn't work
				break
			}
		}
	}
}

// Attack implements the ECM factorization method.
func Attack(ks []*keys.RSA) error {
	var (
		k     = ks[0]
		res   = new(fmp.Fmpz)
		state = new(fmp.FlintRandT)
		ch    = make(chan bool)
		ctx   = context.Background()
	)

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if k.Verbose {
		log.Printf("%s attempt beginning with timeout %v", name, timeout)
	}

	go ecm(ch, k.Key.N, res, state)
	select {
	case <-ch:
		k.PackGivenP(res)
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s failed - no factors found", name)
	}
}
