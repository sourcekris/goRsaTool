// Package dleak implements a partial private exponent leak attack against RSA.
//
// In side-channel analyses (such as power analysis, electromagnetic emissions, or fault injections),
// an attacker may recover a subset of the bits of the private exponent d with certain unknown bits (denoted by '?').
//
// Mathematical Basis:
// In the RSA cryptosystem, the public exponent e, private exponent d, modulus n, and prime factors p, q satisfy:
//
//	e * d - 1 = k * phi(n) = k * (n - (p + q) + 1)
//
// where 1 <= k < e.
//
// 1. Determining k from Most Significant Bits (MSBs):
//
//	Since p, q ≈ sqrt(n), their sum S = p + q ≈ 2*sqrt(n) is much smaller than n (order of sqrt(n) ≈ 2^(n_bits/2)).
//	Thus:
//	    d ≈ (k*(n + 1) + 1) / e - k*(p + q) / e
//	Because k*(p + q)/e < 2^(n_bits/2), the top n_bits/2 bits of d are completely independent of p and q,
//	and are solely determined by k. By matching the known MSBs of d against candidate values of k in [1, e),
//	the exact value of k is uniquely determined using FLINT arithmetic.
//
// 2. Exact Reconstruction of Sum of Factors S = p + q:
//
//	Once k is known, reducing modulo 2^(n_bits/2) yields:
//	    k * S ≡ 1 + k*(n + 1) - e * d  (mod 2^(n_bits/2))
//	Since k is odd (gcd(k, 2) = 1), k has a modular inverse modulo 2^(n_bits/2):
//	    S ≡ (1 + k*(n + 1) - e * d) * k^(-1)  (mod 2^(n_bits/2))
//	Because 2*sqrt(n) <= S < 4*sqrt(n) < 2^(n_bits/2 + 1), the exact integer value of S = p + q is uniquely
//	determined by the lower n_bits/2 bits of d.
//
// 3. Parallel Quadratic Sieve & Meet-in-the-Middle Factorization:
//
//	For unknown bits in the lower half of d, candidate bitmasks are checked in parallel across CPU cores.
//	For each candidate S, the discriminant Δ = S^2 - 4n = (q - p)^2 must be a perfect integer square.
//	A fast small-prime quadratic residue sieve (testing Δ mod p for small primes p in [3, 61]) prunes >99.999%
//	of candidates in nanoseconds. The surviving candidate yields exact factors:
//	    p = (S - sqrt(Δ)) / 2,   q = (S + sqrt(Δ)) / 2
//	which fully factors n and recovers the private key.
package dleak

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/bits"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	fmp "github.com/sourcekris/goflint"
)

// name is the name of this attack.
const name = "dleak"

type u128 struct {
	lo uint64
	hi uint64
}

func add128(a, b u128) u128 {
	lo, carry := bits.Add64(a.lo, b.lo, 0)
	hi, _ := bits.Add64(a.hi, b.hi, carry)
	return u128{lo: lo, hi: hi}
}

func sub128(a, b u128) u128 {
	lo, borrow := bits.Sub64(a.lo, b.lo, 0)
	hi, _ := bits.Sub64(a.hi, b.hi, borrow)
	return u128{lo: lo, hi: hi}
}

func mul128(a, b u128) u128 {
	hi, lo := bits.Mul64(a.lo, b.lo)
	hi += a.lo*b.hi + a.hi*b.lo
	return u128{lo: lo, hi: hi}
}

func fmpToU128(x *fmp.Fmpz) u128 {
	mod128 := new(fmp.Fmpz).Set(ln.BigOne).Lsh(128)
	xMod := new(fmp.Fmpz).Mod(x, mod128)
	b := xMod.Bytes()
	if len(b) < 16 {
		padded := make([]byte, 16)
		copy(padded[16-len(b):], b)
		b = padded
	} else if len(b) > 16 {
		b = b[len(b)-16:]
	}
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	return u128{lo: lo, hi: hi}
}

type u256 [4]uint64

func add256(a, b u256) (res u256) {
	var c uint64
	for i := 0; i < 4; i++ {
		res[i], c = bits.Add64(a[i], b[i], c)
	}
	return
}

func sub256(a, b u256) (res u256) {
	var c uint64
	for i := 0; i < 4; i++ {
		res[i], c = bits.Sub64(a[i], b[i], c)
	}
	return
}

func fmpToU256(x *fmp.Fmpz) u256 {
	mod256 := new(fmp.Fmpz).Set(ln.BigOne).Lsh(256)
	xMod := new(fmp.Fmpz).Mod(x, mod256)
	if xMod.Sign() < 0 {
		xMod.Add(xMod, mod256)
	}
	b := xMod.Bytes()
	var res u256
	padded := make([]byte, 32)
	if len(b) <= 32 {
		copy(padded[32-len(b):], b)
	} else {
		padded = b[len(b)-32:]
	}
	for i := 0; i < 4; i++ {
		offset := 32 - (i+1)*8
		var w uint64
		for k := 0; k < 8; k++ {
			w = (w << 8) | uint64(padded[offset+k])
		}
		res[i] = w
	}
	return res
}

func u256ToFmp(a u256) *fmp.Fmpz {
	res := new(fmp.Fmpz)
	for i := 3; i >= 0; i-- {
		res.Lsh(64)
		res.Add(res, new(fmp.Fmpz).SetUint64(a[i]))
	}
	return res
}

type primeFilter struct {
	p        uint64
	two64_p  uint64
	two128_p uint64
	fourN_p  uint64
	qrLUT    uint64
}

func newPrimeFilter(p uint64, n *fmp.Fmpz) primeFilter {
	pZ := fmp.NewFmpz(int64(p))
	two64Z := new(fmp.Fmpz).Set(ln.BigOne).Lsh(64)
	two128Z := new(fmp.Fmpz).Set(ln.BigOne).Lsh(128)
	fourNZ := new(fmp.Fmpz).Mul(ln.BigFour, n)

	two64_p := uint64(new(fmp.Fmpz).Mod(two64Z, pZ).GetInt())
	two128_p := uint64(new(fmp.Fmpz).Mod(two128Z, pZ).GetInt())
	fourN_p := uint64(new(fmp.Fmpz).Mod(fourNZ, pZ).GetInt())

	var qrLUT uint64
	for i := uint64(0); i < p; i++ {
		qrLUT |= uint64(1) << ((i * i) % p)
	}

	return primeFilter{
		p:        p,
		two64_p:  two64_p,
		two128_p: two128_p,
		fourN_p:  fourN_p,
		qrLUT:    qrLUT,
	}
}

type primeFilter256 struct {
	p        uint64
	two64_p  uint64
	two128_p uint64
	two192_p uint64
	fourN_p  uint64
	qrLUT    uint64
}

func newPrimeFilter256(p uint64, n *fmp.Fmpz) primeFilter256 {
	pZ := fmp.NewFmpz(int64(p))
	two64Z := new(fmp.Fmpz).Set(ln.BigOne).Lsh(64)
	two128Z := new(fmp.Fmpz).Set(ln.BigOne).Lsh(128)
	two192Z := new(fmp.Fmpz).Set(ln.BigOne).Lsh(192)
	fourNZ := new(fmp.Fmpz).Mul(ln.BigFour, n)

	two64_p := uint64(new(fmp.Fmpz).Mod(two64Z, pZ).GetInt())
	two128_p := uint64(new(fmp.Fmpz).Mod(two128Z, pZ).GetInt())
	two192_p := uint64(new(fmp.Fmpz).Mod(two192Z, pZ).GetInt())
	fourN_p := uint64(new(fmp.Fmpz).Mod(fourNZ, pZ).GetInt())

	var qrLUT uint64
	for i := uint64(0); i < p; i++ {
		qrLUT |= uint64(1) << ((i * i) % p)
	}

	return primeFilter256{
		p:        p,
		two64_p:  two64_p,
		two128_p: two128_p,
		two192_p: two192_p,
		fourN_p:  fourN_p,
		qrLUT:    qrLUT,
	}
}

// SolveDLeak recovers prime factors p, q and private exponent d from a partial bitstring leak of d using FLINT.
func SolveDLeak(n *fmp.Fmpz, e *fmp.Fmpz, dLeak string, numWorkers int) (*fmp.Fmpz, *fmp.Fmpz, *fmp.Fmpz, error) {
	if n == nil || e == nil || len(dLeak) == 0 {
		return nil, nil, nil, errors.New("invalid arguments to SolveDLeak")
	}

	eVal := e.GetInt()
	if eVal <= 0 {
		return nil, nil, nil, errors.New("e must be a positive integer")
	}

	dLen := len(dLeak)
	knownBits := make([]int, dLen)
	for i := 0; i < dLen; i++ {
		c := dLeak[dLen-1-i]
		if c == '0' {
			knownBits[i] = 0
		} else if c == '1' {
			knownBits[i] = 1
		} else {
			knownBits[i] = -1
		}
	}

	// 1. Recover candidate k using FLINT arithmetic
	nPlus1 := new(fmp.Fmpz).Add(n, ln.BigOne)

	dMinStr := ""
	dMaxStr := ""
	for i := 0; i < dLen; i++ {
		if dLeak[i] == '?' {
			dMinStr += "0"
			dMaxStr += "1"
		} else {
			dMinStr += string(dLeak[i])
			dMaxStr += string(dLeak[i])
		}
	}
	dMin, ok1 := new(fmp.Fmpz).SetString(dMinStr, 2)
	dMax, ok2 := new(fmp.Fmpz).SetString(dMaxStr, 2)
	if !ok1 || !ok2 {
		return nil, nil, nil, errors.New("failed to parse d leak bit boundaries")
	}

	edMin := new(fmp.Fmpz).Mul(e, dMin)
	edMax := new(fmp.Fmpz).Mul(e, dMax)
	kMin := new(fmp.Fmpz).Div(edMin, n).GetInt()
	kMax := new(fmp.Fmpz).Div(edMax, n).GetInt() + 2

	// Check top bits matching from bit (halfBits + margin) to dLen-1
	startTopCheck := (n.Bits() / 2) + 8

	var matchingK int = -1
	for kCand := kMin; kCand <= kMax; kCand++ {
		if kCand <= 0 || kCand >= eVal {
			continue
		}
		kZ := fmp.NewFmpz(int64(kCand))
		top := new(fmp.Fmpz).Mul(kZ, nPlus1)
		top.Add(top, ln.BigOne)
		dApprox := new(fmp.Fmpz).Div(top, e)

		match := true
		for bit := startTopCheck; bit < dLen; bit++ {
			if knownBits[bit] != -1 {
				bitVal := dApprox.TstBit(bit)
				if bitVal != knownBits[bit] {
					match = false
					break
				}
			}
		}

		if match {
			matchingK = kCand
			break
		}
	}

	if matchingK == -1 {
		return nil, nil, nil, fmt.Errorf("failed to recover k from top bits of d leak")
	}

	kVal := uint64(matchingK)

	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	// For modulus <= 256 bits, use the 128-bit single stage sieve
	if n.Bits() <= 256 {
		var qPosLow []int
		for bit := 0; bit < 128 && bit < dLen; bit++ {
			if knownBits[bit] == -1 {
				qPosLow = append(qPosLow, bit)
			}
		}
		numQ := len(qPosLow)

		if numQ > 32 {
			return nil, nil, nil, fmt.Errorf("too many unknown bits in lower half of d (%d unknown bits, max 32)", numQ)
		}

		dBaseZ := new(fmp.Fmpz)
		for bit := 0; bit < 128 && bit < dLen; bit++ {
			if knownBits[bit] == 1 {
				dBaseZ.Add(dBaseZ, new(fmp.Fmpz).Set(ln.BigOne).Lsh(bit))
			}
		}

		dBase := fmpToU128(dBaseZ)

		qMasks := make([]u128, numQ)
		for i, pos := range qPosLow {
			qMasks[i] = fmpToU128(new(fmp.Fmpz).Set(ln.BigOne).Lsh(pos))
		}

		mod128 := new(fmp.Fmpz).Set(ln.BigOne).Lsh(128)
		invKZ := new(fmp.Fmpz).ModInverse(fmp.NewFmpz(int64(kVal)), mod128)
		if invKZ == nil {
			return nil, nil, nil, fmt.Errorf("k=%d is not coprime to 2^128", kVal)
		}
		invK := fmpToU128(invKZ)

		e128 := u128{lo: uint64(eVal), hi: 0}

		kZ := fmp.NewFmpz(int64(kVal))
		constPartZ := new(fmp.Fmpz).Mul(kZ, nPlus1)
		constPartZ.Add(constPartZ, ln.BigOne)
		constPart := fmpToU128(constPartZ)

		primes := []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61}
		filters := make([]primeFilter, len(primes))
		for i, p := range primes {
			filters[i] = newPrimeFilter(p, n)
		}

		totalCombinations := uint64(1) << numQ
		chunkSize := totalCombinations / uint64(numWorkers)
		if chunkSize == 0 {
			chunkSize = totalCombinations
			numWorkers = 1
		}

		var (
			found int32
			wg    sync.WaitGroup
			resP  *fmp.Fmpz
			resQ  *fmp.Fmpz
			resD  *fmp.Fmpz
			mu    sync.Mutex
		)

		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			startIdx := uint64(w) * chunkSize
			endIdx := startIdx + chunkSize
			if w == numWorkers-1 {
				endIdx = totalCombinations
			}

			go func(sIdx, eIdx uint64) {
				defer wg.Done()

				for mask := sIdx; mask < eIdx; mask++ {
					if atomic.LoadInt32(&found) == 1 {
						return
					}

					dLow := dBase
					for i := 0; i < numQ; i++ {
						if (mask>>i)&1 == 1 {
							dLow = add128(dLow, qMasks[i])
						}
					}

					ed := mul128(e128, dLow)
					top := sub128(constPart, ed)
					sCalc := mul128(top, invK)

					s0 := sCalc.lo
					s1 := sCalc.hi

					passedPrimes := true
					for _, pf := range filters {
						p := pf.p
						sP := (pf.two128_p + (s1%p)*pf.two64_p + (s0 % p)) % p
						delP := (sP*sP + p - (pf.fourN_p % p)) % p
						if (pf.qrLUT>>delP)&1 == 0 {
							passedPrimes = false
							break
						}
					}

					if !passedPrimes {
						continue
					}

					sBytes := make([]byte, 17)
					sBytes[0] = 1
					binary.BigEndian.PutUint64(sBytes[1:9], s1)
					binary.BigEndian.PutUint64(sBytes[9:17], s0)

					sZ := new(fmp.Fmpz).SetBytes(sBytes)
					s2 := new(fmp.Fmpz).Mul(sZ, sZ)
					fourN := new(fmp.Fmpz).Mul(ln.BigFour, n)
					delZ := new(fmp.Fmpz).Sub(s2, fourN)
					if delZ.Sign() < 0 {
						continue
					}

					sqrtDel := new(fmp.Fmpz).Sqrt(delZ)
					sq := new(fmp.Fmpz).Mul(sqrtDel, sqrtDel)
					if !sq.Equals(delZ) {
						continue
					}

					pZ := new(fmp.Fmpz).Sub(sZ, sqrtDel)
					pZ.Div(pZ, ln.BigTwo)
					qZ := new(fmp.Fmpz).Add(sZ, sqrtDel)
					qZ.Div(qZ, ln.BigTwo)

					if new(fmp.Fmpz).Mul(pZ, qZ).Equals(n) {
						mu.Lock()
						if atomic.LoadInt32(&found) == 0 {
							atomic.StoreInt32(&found, 1)
							phi := new(fmp.Fmpz).Mul(new(fmp.Fmpz).Sub(pZ, ln.BigOne), new(fmp.Fmpz).Sub(qZ, ln.BigOne))
							dZ := new(fmp.Fmpz).ModInverse(e, phi)
							resP, resQ, resD = pZ, qZ, dZ
						}
						mu.Unlock()
						return
					}
				}
			}(startIdx, endIdx)
		}

		wg.Wait()

		if atomic.LoadInt32(&found) == 1 {
			return resP, resQ, resD, nil
		}

		return nil, nil, nil, errors.New("failed to factor modulus with partial d leak")
	}

	// For modulus > 256 bits (e.g. 512-bit RSA), use the 256-bit Meet-in-the-Middle solver
	kZ := fmp.NewFmpz(int64(kVal))
	top := new(fmp.Fmpz).Mul(kZ, nPlus1)
	top.Add(top, ln.BigOne)
	dApprox := new(fmp.Fmpz).Div(top, e)

	R := new(fmp.Fmpz).Mod(top, e)
	invKE := new(fmp.Fmpz).ModInverse(kZ, e)
	sModE := new(fmp.Fmpz).Mod(new(fmp.Fmpz).Mul(R, invKE), e)
	constDelta := new(fmp.Fmpz).Div(new(fmp.Fmpz).Sub(new(fmp.Fmpz).Mul(kZ, sModE), R), e)

	knownBits[0] = 1
	for bit := 256; bit < dLen; bit++ {
		knownBits[bit] = dApprox.TstBit(bit)
	}

	var qPositions []int
	for bit := 1; bit < 256 && bit < dLen; bit++ {
		if knownBits[bit] == -1 {
			qPositions = append(qPositions, bit)
		}
	}
	numQ := len(qPositions)

	mod256 := new(fmp.Fmpz).Set(ln.BigOne).Lsh(256)
	invK256 := new(fmp.Fmpz).ModInverse(kZ, mod256)

	dBaseZ := new(fmp.Fmpz)
	for bit := 0; bit < 256 && bit < dLen; bit++ {
		if knownBits[bit] == 1 {
			dBaseZ.Add(dBaseZ, new(fmp.Fmpz).Set(ln.BigOne).Lsh(bit))
		}
	}

	dTarget := new(fmp.Fmpz).Sub(dApprox, constDelta)
	yBaseZ := new(fmp.Fmpz).Sub(dTarget, dBaseZ)
	yBaseZ.Mul(yBaseZ, invK256)
	yBaseZ.Mod(yBaseZ, mod256)
	if yBaseZ.Sign() < 0 {
		yBaseZ.Add(yBaseZ, mod256)
	}
	yBase := fmpToU256(yBaseZ)

	uList := make([]u256, numQ)
	for j, pos := range qPositions {
		bitZ := new(fmp.Fmpz).Set(ln.BigOne).Lsh(pos)
		uZ := new(fmp.Fmpz).Mul(bitZ, invK256)
		uZ.Mod(uZ, mod256)
		uList[j] = fmpToU256(uZ)
	}

	nLow := 24
	if numQ < 24 {
		nLow = numQ / 2
	}
	nHigh := numQ - nLow

	totalLow := 1 << nLow
	xList := make([]u256, totalLow)

	for mask := 0; mask < totalLow; mask++ {
		var x u256
		for j := 0; j < nLow; j++ {
			if (mask>>j)&1 == 1 {
				x = add256(x, uList[j])
			}
		}
		xList[mask] = x
	}

	sort.Slice(xList, func(i, j int) bool {
		return xList[i][3] < xList[j][3]
	})

	numBuckets := 8192
	bucketStart := make([]int, numBuckets+1)
	curB := 0
	for i := 0; i < totalLow; i++ {
		bIdx := int(xList[i][3] >> 51)
		for curB <= bIdx {
			bucketStart[curB] = i
			curB++
		}
	}
	for curB <= numBuckets {
		bucketStart[curB] = totalLow
		curB++
	}

	primes := []uint64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61}
	filters256 := make([]primeFilter256, len(primes))
	for i, p := range primes {
		filters256[i] = newPrimeFilter256(p, n)
	}

	totalHigh := uint64(1) << nHigh
	chunkSize := totalHigh / uint64(numWorkers)
	if chunkSize == 0 {
		chunkSize = totalHigh
		numWorkers = 1
	}

	fourNZ := new(fmp.Fmpz).Mul(ln.BigFour, n)
	sModEVal := uint64(sModE.GetInt())

	var (
		found int32
		resP  *fmp.Fmpz
		resQ  *fmp.Fmpz
		resD  *fmp.Fmpz
		mu    sync.Mutex
		wg    sync.WaitGroup
	)

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		startMask := uint64(w) * chunkSize
		endMask := startMask + chunkSize
		if w == numWorkers-1 {
			endMask = totalHigh
		}

		go func(sM, eM uint64) {
			defer wg.Done()

			for maskH := sM; maskH < eM; maskH++ {
				if atomic.LoadInt32(&found) == 1 {
					return
				}

				var z u256
				for j := 0; j < nHigh; j++ {
					if (maskH>>j)&1 == 1 {
						z = add256(z, uList[nLow+j])
					}
				}

				targetX := sub256(yBase, z)

				var low1 uint64
				if targetX[3] >= (1 << 51) {
					low1 = targetX[3] - (1 << 51)
				} else {
					low1 = 0
				}
				high1 := targetX[3]

				startB := int(low1 >> 51)
				endB := int(high1 >> 51)
				if endB >= numBuckets {
					endB = numBuckets - 1
				}

				sIdx := bucketStart[startB]
				eIdx := bucketStart[endB+1]

				for i := sIdx; i < eIdx; i++ {
					x := xList[i]
					Y := sub256(targetX, x)

					if (Y[3] >> 51) != 0 {
						continue
					}

					y0, y1, y2, y3 := Y[0], Y[1], Y[2], Y[3]
					passed := true
					for _, pf := range filters256 {
						p := pf.p
						yP := ((y3%p)*pf.two192_p + (y2%p)*pf.two128_p + (y1%p)*pf.two64_p + (y0 % p)) % p
						sP := ((yP*(uint64(eVal)%p))%p + sModEVal) % p
						delP := (sP*sP + p - (pf.fourN_p % p)) % p
						if (pf.qrLUT>>delP)&1 == 0 {
							passed = false
							break
						}
					}
					if !passed {
						continue
					}

					YZ := u256ToFmp(Y)
					SZ := new(fmp.Fmpz).Mul(e, YZ).Add(new(fmp.Fmpz).Mul(e, YZ), sModE)
					delZ := new(fmp.Fmpz).Sub(new(fmp.Fmpz).Mul(SZ, SZ), fourNZ)
					if delZ.Sign() < 0 {
						continue
					}

					sqrtDel := new(fmp.Fmpz).Sqrt(delZ)
					if !new(fmp.Fmpz).Mul(sqrtDel, sqrtDel).Equals(delZ) {
						continue
					}

					pZ := new(fmp.Fmpz).Sub(SZ, sqrtDel)
					pZ.Div(pZ, ln.BigTwo)
					qZ := new(fmp.Fmpz).Add(SZ, sqrtDel)
					qZ.Div(qZ, ln.BigTwo)

					if new(fmp.Fmpz).Mul(pZ, qZ).Equals(n) {
						mu.Lock()
						if atomic.LoadInt32(&found) == 0 {
							atomic.StoreInt32(&found, 1)
							phi := new(fmp.Fmpz).Mul(new(fmp.Fmpz).Sub(pZ, ln.BigOne), new(fmp.Fmpz).Sub(qZ, ln.BigOne))
							dZ := new(fmp.Fmpz).ModInverse(e, phi)
							resP, resQ, resD = pZ, qZ, dZ
						}
						mu.Unlock()
						return
					}
				}
			}
		}(startMask, endMask)
	}

	wg.Wait()

	if atomic.LoadInt32(&found) == 1 {
		return resP, resQ, resD, nil
	}

	return nil, nil, nil, errors.New("failed to factor modulus with partial d leak")
}

// Attack implements the Partial Private Exponent Leak attack.
func Attack(ts []*keys.RSA, ch chan error) {
	if len(ts) == 0 {
		ch <- errors.New("no keys provided")
		return
	}

	t := ts[0]
	if t.Key.D != nil {
		ch <- nil
		return
	}

	if t.Key.N == nil || t.Key.PublicKey.E == nil {
		ch <- fmt.Errorf("%s failed - modulus N and exponent E are required", name)
		return
	}

	if len(t.DLeak) == 0 {
		ch <- fmt.Errorf("%s failed - supply the bit leak of 'd' using the -dleak flag or a 'd_leak = ' field in the key", name)
		return
	}

	if t.Verbose {
		log.Printf("%s attempt beginning for e = %v", name, t.Key.PublicKey.E)
	}

	p, _, _, err := SolveDLeak(t.Key.N, t.Key.PublicKey.E, t.DLeak, 0)
	if err != nil {
		ch <- fmt.Errorf("%s failed: %v", name, err)
		return
	}

	t.PackGivenP(p)
	ch <- nil
}
