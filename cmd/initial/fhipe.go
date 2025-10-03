package main

import (
	"fmt"
	"math"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Params are the public parameters.
type Params struct {
	G1Gen bls12381.G1Affine
	G2Gen bls12381.G2Affine
	// S is the bound for the allowed inner product range: [-S, S]
	// The set S = {z ∈ Z : -S ≤ z ≤ S} is polynomial-sized
	S int
}

// MSK is the master secret key for setup (keep B, Bstar secret).
type MSK struct {
	PP    Params
	B     [][]fr.Element // n x n over Z_q
	Bstar [][]fr.Element // det(B) * (B^{-1})^T mod q
	DetB  fr.Element     // cached determinant of B
}

// SecretKey holds sk = (K1, K2) where
// K1 ∈ G1 and K2 is a vector in G1^n.
type SecretKey struct {
	K1 bls12381.G1Affine
	K2 []bls12381.G1Affine
}

// Ciphertext holds ct = (C1, C2) where
// C1 ∈ G2 and C2 is a length-n vector in G2^n: C1 = g2^β, C2[j] = g2^{β · (y B*)_j}.
type Ciphertext struct {
	C1 bls12381.G2Affine
	C2 []bls12381.G2Affine
}

// ErrDimensionMismatch is returned when vectors have wrong length.
var ErrDimensionMismatch = fmt.Errorf("dimension mismatch")

// Setup implements: sample pairing groups & generators; sample B in GL_n(Z_q);
// compute B* = det(B)*(B^{-1})^T  (all arithmetic mod q).
// S is the bound for the allowed inner product set: {z ∈ Z : -S ≤ z ≤ S}.
func Setup(n int, S int) (Params, MSK, error) {
	if n <= 0 {
		return Params{}, MSK{}, fmt.Errorf("n must be > 0")
	}

	// 1) Curve generators (type-3 pairing groups)
	_, _, g1, g2 := bls12381.Generators()

	pp := Params{G1Gen: g1, G2Gen: g2, S: S}

	// 2) Sample an invertible matrix B over Z_q and compute its inverse & determinant
	B, invB, detB, err := randInvertibleMatrix(n)
	if err != nil {
		return Params{}, MSK{}, err
	}

	// 3) Compute B* = det(B) * (invB)^T   (entrywise mod q)
	Bstar := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		Bstar[i] = make([]fr.Element, n)
		for j := 0; j < n; j++ {
			// (invB)^T at (i,j) is invB[j][i]
			var tmp fr.Element
			tmp.Mul(&detB, &invB[j][i])
			Bstar[i][j] = tmp
		}
	}

	msk := MSK{PP: pp, B: B, Bstar: Bstar, DetB: detB}
	return pp, msk, nil
}

// KeyGen implements:
//
//	choose α←Z_q;  K1 = g1^(α·det(B));  K2[j] = g1^(α·(xB)_j)  for j=0..n-1
//
// x is a length-n vector over Z_q (fr.Element).
func KeyGen(msk MSK, x []fr.Element) (SecretKey, error) {
	n := len(msk.B)
	if len(x) != n {
		return SecretKey{}, ErrDimensionMismatch
	}

	// Sample α ← Z_q
	var alpha fr.Element
	if _, err := alpha.SetRandom(); err != nil {
		return SecretKey{}, err
	}

	// K1 = g1^(α · det(B)) using cached determinant
	var exp1 fr.Element
	exp1.Mul(&alpha, &msk.DetB)
	K1 := g1Exp(msk.PP.G1Gen, exp1)

	y := make([]fr.Element, n)
	K2 := make([]bls12381.G1Affine, n)

	// Parallel threshold (avoid goroutine overhead for small n)
	if n < 32 {
		for j := 0; j < n; j++ {
			var acc fr.Element
			acc.SetZero()
			for i := 0; i < n; i++ {
				var tmp fr.Element
				tmp.Mul(&x[i], &msk.B[i][j])
				acc.Add(&acc, &tmp)
			}
			y[j] = acc
			var e fr.Element
			e.Mul(&alpha, &acc)
			K2[j] = g1Exp(msk.PP.G1Gen, e)
		}
		return SecretKey{K1: K1, K2: K2}, nil
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		start := w * chunk
		end := start + chunk
		if end > n {
			end = n
		}
		go func(s, e int) {
			defer wg.Done()
			for j := s; j < e; j++ {
				var acc fr.Element
				acc.SetZero()
				for i := 0; i < n; i++ {
					var tmp fr.Element
					tmp.Mul(&x[i], &msk.B[i][j])
					acc.Add(&acc, &tmp)
				}
				y[j] = acc
				var eexp fr.Element
				eexp.Mul(&alpha, &acc)
				K2[j] = g1Exp(msk.PP.G1Gen, eexp)
			}
		}(start, end)
	}
	wg.Wait()
	return SecretKey{K1: K1, K2: K2}, nil
}

// Encrypt implements:
// choose β ← Z_q; C1 = g2^β; C2[j] = g2^{β · (y B*)_j} for j=0..n-1.
// y must be length n.
func Encrypt(msk MSK, y []fr.Element) (Ciphertext, error) {
	n := len(msk.Bstar)
	if len(y) != n {
		return Ciphertext{}, ErrDimensionMismatch
	}

	var beta fr.Element
	if _, err := beta.SetRandom(); err != nil {
		return Ciphertext{}, err
	}

	z := make([]fr.Element, n)
	C2 := make([]bls12381.G2Affine, n)

	if n < 32 {
		for j := 0; j < n; j++ {
			var acc fr.Element
			acc.SetZero()
			for i := 0; i < n; i++ {
				var tmp fr.Element
				tmp.Mul(&y[i], &msk.Bstar[i][j])
				acc.Add(&acc, &tmp)
			}
			z[j] = acc
			var e fr.Element
			e.Mul(&beta, &acc)
			C2[j] = g2Exp(msk.PP.G2Gen, e)
		}
		C1 := g2Exp(msk.PP.G2Gen, beta)
		return Ciphertext{C1: C1, C2: C2}, nil
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		start := w * chunk
		end := start + chunk
		if end > n {
			end = n
		}
		go func(s, e int) {
			defer wg.Done()
			for j := s; j < e; j++ {
				var acc fr.Element
				acc.SetZero()
				for i := 0; i < n; i++ {
					var tmp fr.Element
					tmp.Mul(&y[i], &msk.Bstar[i][j])
					acc.Add(&acc, &tmp)
				}
				z[j] = acc
				var exp fr.Element
				exp.Mul(&beta, &acc)
				C2[j] = g2Exp(msk.PP.G2Gen, exp)
			}
		}(start, end)
	}
	wg.Wait()
	C1 := g2Exp(msk.PP.G2Gen, beta)
	return Ciphertext{C1: C1, C2: C2}, nil
}

// Decrypt computes D1 = e(K1, C1) and D2 = ∏_j e(K2[j], C2[j]).
// It returns both GT elements.
func Decrypt(pp Params, sk SecretKey, ct Ciphertext) (D1 bls12381.GT, D2 bls12381.GT, err error) {
	if len(sk.K2) != len(ct.C2) {
		return bls12381.GT{}, bls12381.GT{}, ErrDimensionMismatch
	}

	// D1 = e(K1, C1)
	D1, err = bls12381.Pair([]bls12381.G1Affine{sk.K1}, []bls12381.G2Affine{ct.C1})
	if err != nil {
		return bls12381.GT{}, bls12381.GT{}, err
	}

	// D2 = product over j e(K2[j], C2[j]) -- Pair can batch this directly.
	D2, err = bls12381.Pair(sk.K2, ct.C2)
	if err != nil {
		return bls12381.GT{}, bls12381.GT{}, err
	}
	return D1, D2, nil
}

// RecoverInnerProduct searches for z ∈ S such that (D1)^z = D2.
// S is defined as the set {z ∈ Z : -bound ≤ z ≤ bound} (polynomial-sized).
// Returns (z, true) if found, (0, false) otherwise (⊥).
// RecoverInnerProduct attempts to recover z in [-bound, bound] such that D1^z = D2.
// It uses Baby-Step Giant-Step (BSGS) which runs in O(sqrt(bound)) group ops
// instead of linear brute force. For very small bounds, a simple loop may be
// slightly faster; we still use BSGS unconditionally for simplicity.
func RecoverInnerProduct(D1, D2 bls12381.GT, bound int) (int, bool) {
	if bound < 0 {
		return 0, false
	}
	// For small bounds, sequential BSGS often faster due to overhead.
	if bound <= 256 { // adjustable threshold
		return recoverInnerProductSeq(D1, D2, bound)
	}
	return recoverInnerProductParallel(D1, D2, bound)
}

// Sequential BSGS (original logic) extracted for reuse.
func recoverInnerProductSeq(D1, D2 bls12381.GT, bound int) (int, bool) {
	N := 2*bound + 1
	m := int(math.Ceil(math.Sqrt(float64(N))))

	baby := make(map[string]int, m)
	var cur bls12381.GT
	cur.SetOne()
	for j := 0; j < m; j++ {
		baby[gtKey(&cur)] = j
		cur.Mul(&cur, &D1)
	}
	var stride bls12381.GT
	var mBig big.Int
	mBig.SetInt64(int64(m))
	stride.Exp(D1, &mBig)
	var strideInv bls12381.GT
	strideInv.Inverse(&stride)
	var boundPow bls12381.GT
	var boundBig big.Int
	boundBig.SetInt64(int64(bound))
	boundPow.Exp(D1, &boundBig)
	var target bls12381.GT
	target.Mul(&boundPow, &D2)
	for k := 0; k <= m; k++ {
		if j, ok := baby[gtKey(&target)]; ok {
			idx := k*m + j
			if idx < N {
				return idx - bound, true
			}
		}
		target.Mul(&target, &strideInv)
	}
	return 0, false
}

// Parallel BSGS: splits giant steps across workers.
func recoverInnerProductParallel(D1, D2 bls12381.GT, bound int) (int, bool) {
	N := 2*bound + 1
	m := int(math.Ceil(math.Sqrt(float64(N))))

	// Baby steps
	baby := make(map[string]int, m)
	var cur bls12381.GT
	cur.SetOne()
	for j := 0; j < m; j++ {
		baby[gtKey(&cur)] = j
		cur.Mul(&cur, &D1)
	}

	// Precompute stride and its inverse
	var stride bls12381.GT
	var mBig big.Int
	mBig.SetInt64(int64(m))
	stride.Exp(D1, &mBig)
	var strideInv bls12381.GT
	strideInv.Inverse(&stride)

	// target0 = D1^{bound} * D2
	var boundPow bls12381.GT
	var boundBig big.Int
	boundBig.SetInt64(int64(bound))
	boundPow.Exp(D1, &boundBig)
	var target0 bls12381.GT
	target0.Mul(&boundPow, &D2)

	workers := runtime.GOMAXPROCS(0)
	if workers > m+1 { // no need for more workers than iterations
		workers = m + 1
	}
	if workers < 2 { // fallback sequentially
		return recoverInnerProductSeq(D1, D2, bound)
	}

	// Partition k in [0, m]
	chunk := (m + workers) / workers
	var found int32
	var result int32
	var wg sync.WaitGroup
	wg.Add(workers)

	// Precompute powers of strideInv^chunk for jump starting chunks efficiently.
	// strideChunk = strideInv^{chunk}
	var strideChunk bls12381.GT
	var chunkBig big.Int
	chunkBig.SetInt64(int64(chunk))
	strideChunk.Exp(strideInv, &chunkBig)

	// For each worker compute starting target = target0 * strideInv^{start}
	for w := 0; w < workers; w++ {
		startK := w * chunk
		endK := startK + chunk
		if endK > m+1 {
			endK = m + 1
		}
		if startK >= endK {
			wg.Done()
			continue
		}
		go func(sK, eK int) {
			defer wg.Done()
			// Compute strideInv^{sK} via repeated squaring / fast exp
			var pow bls12381.GT
			var expBig big.Int
			expBig.SetInt64(int64(sK))
			pow.Exp(strideInv, &expBig)
			var target bls12381.GT
			target.Mul(&target0, &pow)
			for k := sK; k < eK && atomic.LoadInt32(&found) == 0; k++ {
				if j, ok := baby[gtKey(&target)]; ok {
					idx := k*m + j
					if idx < N {
						if atomic.CompareAndSwapInt32(&found, 0, 1) {
							atomic.StoreInt32(&result, int32(idx-bound))
						}
						return
					}
				}
				target.Mul(&target, &strideInv)
			}
		}(startK, endK)
	}
	wg.Wait()
	if atomic.LoadInt32(&found) == 1 {
		return int(atomic.LoadInt32(&result)), true
	}
	return 0, false
}

// gtKey creates a map key for a GT element via its compressed bytes. We try
// Marshal first (gnark-crypto elements implement encoding), falling back to
// fmt-based representation if needed.
func gtKey(g *bls12381.GT) string {
	// Marshal() exists on gnark-crypto GT; if not, we fallback.
	if marshaler, ok := interface{}(g).(interface{ Marshal() []byte }); ok {
		return string(marshaler.Marshal())
	}
	return g.String()
}

// IntsToFrElements converts a slice of integers to a slice of fr.Element.
// Each integer is converted to its corresponding field element in Z_q.
func IntsToFrElements(ints []int) []fr.Element {
	result := make([]fr.Element, len(ints))
	for i, val := range ints {
		if val >= 0 {
			result[i].SetUint64(uint64(val))
		} else {
			// Handle negative numbers: set positive value then negate
			var tmp fr.Element
			tmp.SetUint64(uint64(-val))
			result[i].Neg(&tmp)
		}
	}
	return result
}

// ------------------------
// Field / matrix utilities
// ------------------------

// randInvertibleMatrix samples a random B ∈ GL_n(Z_q) and returns B, B^{-1}, det(B).
// It resamples until the matrix is invertible (det != 0).
func randInvertibleMatrix(n int) (B [][]fr.Element, invB [][]fr.Element, det fr.Element, err error) {
	for trial := 0; trial < 128; trial++ {
		B = make([][]fr.Element, n)
		for i := 0; i < n; i++ {
			row := make([]fr.Element, n)
			for j := 0; j < n; j++ {
				if _, e := row[j].SetRandom(); e != nil {
					return nil, nil, fr.Element{}, fmt.Errorf("SetRandom: %w", e)
				}
			}
			B[i] = row
		}
		invB, det, ok := invertAndDet(B)
		if ok {
			return B, invB, det, nil
		}
	}
	return nil, nil, fr.Element{}, fmt.Errorf("failed to sample invertible matrix after many tries")
}

// invertAndDet returns (B^{-1}, det(B), ok) over Z_q using Gauss-Jordan elimination.
// It operates in-place on augmented matrices, all constant-time-ish wrt data flow.
// ok=false indicates singular.
func invertAndDet(B [][]fr.Element) (inv [][]fr.Element, det fr.Element, ok bool) {
	n := len(B)
	// Build [A | I]
	A := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		A[i] = make([]fr.Element, 2*n)
		for j := 0; j < n; j++ {
			A[i][j] = B[i][j]
		}
		for j := 0; j < n; j++ {
			if i == j {
				A[i][n+j].SetOne()
			} else {
				A[i][n+j].SetZero()
			}
		}
	}
	det.SetOne()

	// Gaussian elimination
	for col := 0; col < n; col++ {
		pivot := col
		// find nonzero pivot at or below row 'col'
		for r := col; r < n; r++ {
			if !A[r][col].IsZero() {
				pivot = r
				break
			}
		}
		// if entire column is zero → singular
		if A[pivot][col].IsZero() {
			return nil, fr.Element{}, false
		}
		// swap rows if needed
		if pivot != col {
			A[pivot], A[col] = A[col], A[pivot]
			// det *= -1
			var minusOne fr.Element
			minusOne.SetUint64(1).Neg(&minusOne) // -1 mod q
			det.Mul(&det, &minusOne)
		}
		// det *= pivot
		det.Mul(&det, &A[col][col])

		// scale row so pivot becomes 1
		var invPivot fr.Element
		invPivot.Inverse(&A[col][col])
		for c := col; c < 2*n; c++ {
			A[col][c].Mul(&A[col][c], &invPivot)
		}

		// eliminate other rows
		for r := 0; r < n; r++ {
			if r == col {
				continue
			}
			if A[r][col].IsZero() {
				continue
			}
			f := A[r][col] // factor
			// row_r = row_r - f * row_col
			for c := col; c < 2*n; c++ {
				var tmp fr.Element
				tmp.Mul(&f, &A[col][c])
				A[r][c].Sub(&A[r][c], &tmp)
			}
		}
	}

	// Extract inverse from [I | A^{-1}]
	inv = make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		inv[i] = make([]fr.Element, n)
		copy(inv[i], A[i][n:2*n])
	}
	return inv, det, true
}

// determinant computes det(B) over Z_q via Gaussian elimination on a copy.
func determinant(B [][]fr.Element) (fr.Element, error) {
	n := len(B)
	// Deep-copy B into A
	A := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		A[i] = make([]fr.Element, n)
		for j := 0; j < n; j++ {
			A[i][j] = B[i][j]
		}
	}

	var det fr.Element
	det.SetOne()

	for col := 0; col < n; col++ {
		pivot := -1
		for r := col; r < n; r++ {
			if !A[r][col].IsZero() {
				pivot = r
				break
			}
		}
		if pivot == -1 {
			// singular ⇒ det = 0 (should not happen if B∈GL_n)
			det.SetZero()
			return det, nil
		}
		// Row swap if needed (det *= -1)
		if pivot != col {
			A[pivot], A[col] = A[col], A[pivot]
			var minusOne fr.Element
			minusOne.SetUint64(1).Neg(&minusOne) // -1 mod q
			det.Mul(&det, &minusOne)
		}
		// det *= pivot
		det.Mul(&det, &A[col][col])

		// Normalize pivot row
		var inv fr.Element
		inv.Inverse(&A[col][col])
		for c := col; c < n; c++ {
			A[col][c].Mul(&A[col][c], &inv)
		}

		// Eliminate below
		for r := col + 1; r < n; r++ {
			if A[r][col].IsZero() {
				continue
			}
			f := A[r][col]
			for c := col; c < n; c++ {
				var tmp fr.Element
				tmp.Mul(&f, &A[col][c])
				A[r][c].Sub(&A[r][c], &tmp)
			}
		}
	}
	return det, nil
}

// g1Exp returns g1^{e} as an affine point.
func g1Exp(g bls12381.G1Affine, e fr.Element) bls12381.G1Affine {
	var bi big.Int
	e.BigInt(&bi)
	var out bls12381.G1Affine
	out.ScalarMultiplication(&g, &bi)
	return out
}

// g2Exp returns g2^{e} as an affine point.
func g2Exp(g bls12381.G2Affine, e fr.Element) bls12381.G2Affine {
	var bi big.Int
	e.BigInt(&bi)
	var out bls12381.G2Affine
	out.ScalarMultiplication(&g, &bi)
	return out
}
