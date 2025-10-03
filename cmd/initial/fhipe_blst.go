package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
)

// BlstParams holds blst-based public parameters
type BlstParams struct {
	G1Gen *blst.P1Affine
	G2Gen *blst.P2Affine
	S     int // inner product bound
}

// BlstMSK is the master secret key
type BlstMSK struct {
	PP    BlstParams
	B     [][]*big.Int // n x n matrix over scalars
	Bstar [][]*big.Int // det(B) * (B^{-1})^T
	DetB  *big.Int     // determinant
}

// BlstSecretKey holds functional key
type BlstSecretKey struct {
	K1 *blst.P1Affine
	K2 []*blst.P1Affine
}

// BlstCiphertext holds encryption
type BlstCiphertext struct {
	C1 *blst.P2Affine
	C2 []*blst.P2Affine
}

// Scalar field order for BLS12-381
var blstScalarOrder *big.Int

func init() {
	// BLS12-381 scalar field order (r)
	blstScalarOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
}

// BlstSetup creates parameters and MSK
func BlstSetup(n int, S int) (BlstParams, BlstMSK, error) {
	// Get generators - blst provides them already in projective form
	g1GenProj := blst.P1Generator()
	g2GenProj := blst.P2Generator()
	
	g1Gen := g1GenProj.ToAffine()
	g2Gen := g2GenProj.ToAffine()

	pp := BlstParams{G1Gen: g1Gen, G2Gen: g2Gen, S: S}

	// Sample invertible matrix
	B, invB, detB, err := randInvertibleMatrixBig(n)
	if err != nil {
		return BlstParams{}, BlstMSK{}, err
	}

	// Compute Bstar = det(B) * (invB)^T
	Bstar := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		Bstar[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			Bstar[i][j] = new(big.Int).Mul(detB, invB[j][i])
			Bstar[i][j].Mod(Bstar[i][j], blstScalarOrder)
		}
	}

	msk := BlstMSK{PP: pp, B: B, Bstar: Bstar, DetB: detB}
	return pp, msk, nil
}

// BlstKeyGen generates functional key for vector x
func BlstKeyGen(msk BlstMSK, x []*big.Int) (BlstSecretKey, error) {
	n := len(msk.B)
	if len(x) != n {
		return BlstSecretKey{}, fmt.Errorf("dimension mismatch")
	}

	// Sample alpha
	alpha := randScalar()

	// K1 = g1^(alpha * det(B))
	exp1 := new(big.Int).Mul(alpha, msk.DetB)
	exp1.Mod(exp1, blstScalarOrder)
	K1 := scalarMultG1(msk.PP.G1Gen, exp1)

	// Compute xB
	K2 := make([]*blst.P1Affine, n)
	for j := 0; j < n; j++ {
		acc := big.NewInt(0)
		for i := 0; i < n; i++ {
			tmp := new(big.Int).Mul(x[i], msk.B[i][j])
			acc.Add(acc, tmp)
		}
		acc.Mod(acc, blstScalarOrder)

		exp := new(big.Int).Mul(alpha, acc)
		exp.Mod(exp, blstScalarOrder)
		K2[j] = scalarMultG1(msk.PP.G1Gen, exp)
	}

	return BlstSecretKey{K1: K1, K2: K2}, nil
}

// BlstEncrypt encrypts vector y
func BlstEncrypt(msk BlstMSK, y []*big.Int) (BlstCiphertext, error) {
	n := len(msk.Bstar)
	if len(y) != n {
		return BlstCiphertext{}, fmt.Errorf("dimension mismatch")
	}

	beta := randScalar()

	// C1 = g2^beta
	C1 := scalarMultG2(msk.PP.G2Gen, beta)

	// Compute yB*
	C2 := make([]*blst.P2Affine, n)
	for j := 0; j < n; j++ {
		acc := big.NewInt(0)
		for i := 0; i < n; i++ {
			tmp := new(big.Int).Mul(y[i], msk.Bstar[i][j])
			acc.Add(acc, tmp)
		}
		acc.Mod(acc, blstScalarOrder)

		exp := new(big.Int).Mul(beta, acc)
		exp.Mod(exp, blstScalarOrder)
		C2[j] = scalarMultG2(msk.PP.G2Gen, exp)
	}

	return BlstCiphertext{C1: C1, C2: C2}, nil
}

// BlstDecrypt computes pairings - optimized version using multi-pairing
func BlstDecrypt(sk BlstSecretKey, ct BlstCiphertext) (*blst.Fp12, *blst.Fp12, error) {
	if len(sk.K2) != len(ct.C2) {
		return nil, nil, fmt.Errorf("dimension mismatch")
	}

	// D1 = e(K1, C1) - single pairing
	D1 := blst.Fp12MillerLoop(ct.C1, sk.K1)
	D1.FinalExp()

	// D2 uses multi-pairing (batched Miller loop + single final exp)
	// This is the key optimization
	p2s := make([]blst.P2Affine, len(ct.C2))
	p1s := make([]blst.P1Affine, len(sk.K2))
	for i := 0; i < len(sk.K2); i++ {
		p2s[i] = *ct.C2[i]
		p1s[i] = *sk.K2[i]
	}
	
	// Batched multi-pairing: single Miller loop pass + single final exp
	D2 := blst.Fp12MillerLoopN(p2s, p1s)
	D2.FinalExp()

	return D1, D2, nil
}

// Helper functions

func randScalar() *big.Int {
	for {
		b := make([]byte, 32)
		rand.Read(b)
		s := new(big.Int).SetBytes(b)
		if s.Cmp(blstScalarOrder) < 0 && s.Sign() > 0 {
			return s
		}
	}
}

func scalarMultG1(base *blst.P1Affine, scalar *big.Int) *blst.P1Affine {
	scalarBytes := make([]byte, 32)
	scalar.FillBytes(scalarBytes)
	
	var scalar_blst blst.Scalar
	scalar_blst.FromBEndian(scalarBytes)
	
	var result blst.P1
	result.FromAffine(base)
	result.Mult(&scalar_blst)
	return result.ToAffine()
}

func scalarMultG2(base *blst.P2Affine, scalar *big.Int) *blst.P2Affine {
	scalarBytes := make([]byte, 32)
	scalar.FillBytes(scalarBytes)
	
	var scalar_blst blst.Scalar
	scalar_blst.FromBEndian(scalarBytes)
	
	var result blst.P2
	result.FromAffine(base)
	result.Mult(&scalar_blst)
	return result.ToAffine()
}

func randInvertibleMatrixBig(n int) (B, invB [][]*big.Int, det *big.Int, err error) {
	for trial := 0; trial < 128; trial++ {
		B = make([][]*big.Int, n)
		for i := 0; i < n; i++ {
			B[i] = make([]*big.Int, n)
			for j := 0; j < n; j++ {
				B[i][j] = randScalar()
			}
		}
		invB, det, ok := invertMatrixBig(B)
		if ok {
			return B, invB, det, nil
		}
	}
	return nil, nil, nil, fmt.Errorf("failed to sample invertible matrix")
}

func invertMatrixBig(B [][]*big.Int) (inv [][]*big.Int, det *big.Int, ok bool) {
	n := len(B)
	
	// Build augmented matrix [B | I]
	A := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		A[i] = make([]*big.Int, 2*n)
		for j := 0; j < n; j++ {
			A[i][j] = new(big.Int).Set(B[i][j])
		}
		for j := 0; j < n; j++ {
			if i == j {
				A[i][n+j] = big.NewInt(1)
			} else {
				A[i][n+j] = big.NewInt(0)
			}
		}
	}

	det = big.NewInt(1)

	for col := 0; col < n; col++ {
		// Find pivot
		pivot := col
		for r := col; r < n; r++ {
			if A[r][col].Sign() != 0 {
				pivot = r
				break
			}
		}
		if A[pivot][col].Sign() == 0 {
			return nil, nil, false
		}

		// Swap rows
		if pivot != col {
			A[pivot], A[col] = A[col], A[pivot]
			det.Neg(det)
		}

		det.Mul(det, A[col][col])
		det.Mod(det, blstScalarOrder)

		// Scale row
		invPivot := new(big.Int).ModInverse(A[col][col], blstScalarOrder)
		for c := col; c < 2*n; c++ {
			A[col][c].Mul(A[col][c], invPivot)
			A[col][c].Mod(A[col][c], blstScalarOrder)
		}

		// Eliminate
		for r := 0; r < n; r++ {
			if r == col {
				continue
			}
			if A[r][col].Sign() == 0 {
				continue
			}
			f := new(big.Int).Set(A[r][col])
			for c := col; c < 2*n; c++ {
				tmp := new(big.Int).Mul(f, A[col][c])
				A[r][c].Sub(A[r][c], tmp)
				A[r][c].Mod(A[r][c], blstScalarOrder)
			}
		}
	}

	// Extract inverse
	inv = make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		inv[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			inv[i][j] = new(big.Int).Set(A[i][n+j])
		}
	}

	return inv, det, true
}

func IntsToBlstScalars(ints []int) []*big.Int {
	result := make([]*big.Int, len(ints))
	for i, val := range ints {
		if val >= 0 {
			result[i] = big.NewInt(int64(val))
		} else {
			result[i] = new(big.Int).Sub(blstScalarOrder, big.NewInt(int64(-val)))
		}
	}
	return result
}
