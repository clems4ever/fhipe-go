package main

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

/*
Minimal (non function-hiding) Inner-Product Encryption demo with Structured Hints.
Goal: produce Z = e(g1,g2)^{<x,y>} exactly (no hidden r,s factors) THEN recover <x,y>
using small-prime residue hints h_j = g2^{<x,y> mod p'_j}.

Construction (toy):
- Pick global generators g1,g2.
- For i in [0,n): sample alpha_i in Fr*, set beta_i = alpha_i^{-1} mod r (r = group order).
- Publish A_i = g1^{alpha_i}, B_i = g2^{beta_i}.
Then: e(A_i^{x_i}, B_i^{y_i}) = e(g1,g2)^{alpha_i * beta_i * x_i * y_i} = e(g1,g2)^{x_i y_i}.
Ciphertext: C_i = A_i^{x_i}.
Key: K_i = B_i^{y_i}.
Decrypt: Z = Π e(C_i, K_i) = e(g1,g2)^{Σ x_i y_i}.
Hints: For primes p'_j, h_j = g2^{<x,y> mod p'_j}.

This file also provides a DLP recovery benchmark:
1. Naive baby-step giant-step (BSGS) on interval [0,Bound).
2. Hint-aided BSGS restricted to residues consistent with CRT of recovered small residues.
We simulate large search space by choosing Bound = user param.
*/

type PublicParams struct {
	g1 bn254.G1Affine
	g2 bn254.G2Affine
	A  []bn254.G1Affine // A_i = g1^{alpha_i}
	B  []bn254.G2Affine // B_i = g2^{beta_i}
}

type SecretParams struct {
	alpha []*big.Int
	beta  []*big.Int // beta_i = alpha_i^{-1} mod r
}

type Ciphertext struct {
	C     []bn254.G1Affine
	hints []bn254.G2Affine // g2^{<x,y> mod p'_j}
	// store dimension for convenience
	n int
}

type Key struct {
	K []bn254.G2Affine // K_i = B_i^{y_i}
}

var hintPrimes = []int64{251, 257, 263}

func invertMod(x *big.Int, modulus *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(x, modulus)
	if inv == nil {
		panic("no inverse")
	}
	return inv
}

func Setup(n int) (*PublicParams, *SecretParams) {
	_, _, g1gen, g2gen := bn254.Generators()
	r := fr.Modulus() // group order

	A := make([]bn254.G1Affine, n)
	B := make([]bn254.G2Affine, n)
	alpha := make([]*big.Int, n)
	beta := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		ai, err := rand.Int(rand.Reader, r)
		if err != nil {
			panic(err)
		}
		for ai.Sign() == 0 {
			ai, _ = rand.Int(rand.Reader, r)
		}
		bi := invertMod(ai, r)
		alpha[i] = ai
		beta[i] = bi
		A[i].ScalarMultiplication(&g1gen, ai)
		B[i].ScalarMultiplication(&g2gen, bi)
	}
	pp := &PublicParams{g1: g1gen, g2: g2gen, A: A, B: B}
	sp := &SecretParams{alpha: alpha, beta: beta}
	return pp, sp
}

func Encrypt(pp *PublicParams, x []*big.Int) *Ciphertext {
	n := len(x)
	C := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		C[i].ScalarMultiplication(&pp.A[i], x[i])
	}
	// inner product unknown here; hints built later by caller (needs y)
	return &Ciphertext{C: C, n: n}
}

func KeyGen(pp *PublicParams, y []*big.Int) *Key {
	n := len(y)
	K := make([]bn254.G2Affine, n)
	for i := 0; i < n; i++ {
		K[i].ScalarMultiplication(&pp.B[i], y[i])
	}
	return &Key{K: K}
}

func AttachHints(ct *Ciphertext, pp *PublicParams, x, y []*big.Int) {
	// compute t = <x,y>
	t := big.NewInt(0)
	for i := 0; i < ct.n; i++ {
		prod := new(big.Int).Mul(x[i], y[i])
		t.Add(t, prod)
	}
	t.Mod(t, fr.Modulus())
	hints := make([]bn254.G2Affine, len(hintPrimes))
	for j, p := range hintPrimes {
		pBig := big.NewInt(p)
		res := new(big.Int).Mod(t, pBig)
		hints[j].ScalarMultiplication(&pp.g2, res)
	}
	ct.hints = hints
}

// Recover pairing target Z = e(g1,g2)^{<x,y>}
func PairingAggregate(pp *PublicParams, ct *Ciphertext, key *Key) (bn254.GT, error) {
	var acc bn254.GT
	acc.SetOne()
	for i := 0; i < ct.n; i++ {
		pz, err := bn254.Pair([]bn254.G1Affine{ct.C[i]}, []bn254.G2Affine{key.K[i]})
		if err != nil {
			return acc, err
		}
		acc.Mul(&acc, &pz)
	}
	return acc, nil
}

// Recover residues by solving tiny DLP: h_j = g2^{r_j}
func recoverResidues(pp *PublicParams, hints []bn254.G2Affine) []int64 {
	residues := make([]int64, len(hints))
	for j, h := range hints {
		p := hintPrimes[j]
		for k := int64(0); k < p; k++ {
			var test bn254.G2Affine
			test.ScalarMultiplication(&pp.g2, big.NewInt(k))
			if test.Equal(&h) {
				residues[j] = k
				break
			}
		}
	}
	return residues
}

// Chinese Remainder reconstruction of a unique representative in [0, M)
func crt(residues []int64, primes []int64) *big.Int {
	M := int64(1)
	for _, p := range primes {
		M *= p
	}
	result := big.NewInt(0)
	for i, p := range primes {
		m_i := M / p
		inv := new(big.Int).ModInverse(big.NewInt(m_i), big.NewInt(p))
		term := new(big.Int).Mul(big.NewInt(residues[i]), big.NewInt(m_i))
		term.Mul(term, inv)
		result.Add(result, term)
	}
	return result.Mod(result, big.NewInt(M))
}

// Baby-step giant-step for base^x = target, x < bound
func bsgs(base bn254.GT, target bn254.GT, bound int64) (int64, bool) {
	m := int64(math.Ceil(math.Sqrt(float64(bound))))
	table := make(map[string]int64, m)
	var acc bn254.GT
	acc.SetOne()
	for i := int64(0); i < m; i++ {
		key := acc.String()
		if _, ok := table[key]; !ok {
			table[key] = i
		}
		acc.Mul(&acc, &base) // acc = base^{i+1}
	}
	// compute base^{-m}
	var baseInv, step bn254.GT
	baseInv.Inverse(&base)
	step.Exp(baseInv, big.NewInt(m))
	var gamma bn254.GT
	gamma.Set(&target)
	for j := int64(0); j <= m; j++ {
		if i, ok := table[gamma.String()]; ok {
			x := j*m + i
			if x < bound {
				return x, true
			}
		}
		gamma.Mul(&gamma, &step)
	}
	return 0, false
}

// Restricted BSGS using residue class progression x = x0 + k*M
func restrictedSearch(base bn254.GT, target bn254.GT, bound int64, x0 int64, M int64) (int64, bool) {
	// Let x = x0 + k*M < bound -> k < (bound - x0 + M -1)/M
	maxK := (bound - x0 + M - 1) / M
	var baseM bn254.GT
	baseM.Exp(base, big.NewInt(M))
	// Precompute gamma = base^{x0}
	var gamma bn254.GT
	gamma.Exp(base, big.NewInt(x0))
	var cur bn254.GT
	cur.Set(&gamma)
	for k := int64(0); k < maxK; k++ {
		if cur.Equal(&target) {
			return x0 + k*M, true
		}
		cur.Mul(&cur, &baseM)
	}
	return 0, false
}

func main() {
	fmt.Println("=== Minimal IPE + Structured Hints Demo ===")
	// Parameters
	n := 64
	bound := int64(1_000_000) // synthetic upper bound for <x,y>
	fmt.Printf("Dimension n=%d, synthetic DLP bound=%d\n", n, bound)

	pp, _ := Setup(n)
	fmt.Println("✓ Setup complete")

	// Sample small vectors (to keep true t moderately sized but unpredictable)
	x := make([]*big.Int, n)
	y := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		x[i] = big.NewInt(int64(i%11 + 1))
		y[i] = big.NewInt(int64((7*i)%13 + 1))
	}
	// Compute true t
	trueT := big.NewInt(0)
	for i := 0; i < n; i++ {
		trueT.Add(trueT, new(big.Int).Mul(x[i], y[i]))
	}
	fmt.Printf("True inner product t=%s\n", trueT.String())

	// Encrypt & KeyGen
	ct := Encrypt(pp, x)
	key := KeyGen(pp, y)
	AttachHints(ct, pp, x, y)
	fmt.Println("✓ Ciphertext, key, and hints generated")

	// Pairing aggregate
	Z, err := PairingAggregate(pp, ct, key)
	if err != nil {
		panic(err)
	}
	// Base pairing for discrete log space
	basePair, err := bn254.Pair([]bn254.G1Affine{pp.g1}, []bn254.G2Affine{pp.g2})
	if err != nil {
		panic(err)
	}

	// Recover residues
	residues := recoverResidues(pp, ct.hints)
	fmt.Printf("Residues (mod primes): %v over %v\n", residues, hintPrimes)
	crtRep := crt(residues, hintPrimes) // x ≡ x0 (mod M)
	M := int64(1)
	for _, p := range hintPrimes {
		M *= p
	}
	x0 := crtRep.Int64()
	fmt.Printf("CRT representative x0=%d (mod M=%d)\n", x0, M)

	// Benchmark naive BSGS
	startNaive := time.Now()
	foundNaive, okN := bsgs(basePair, Z, bound)
	naiveDur := time.Since(startNaive)
	if !okN {
		fmt.Println("[WARN] naive BSGS did not find solution within bound (increase bound)")
	}

	// Restricted search along progression x0 + kM
	startRestr := time.Now()
	foundRestr, okR := restrictedSearch(basePair, Z, bound, x0, M)
	restrDur := time.Since(startRestr)
	if !okR {
		fmt.Println("[WARN] restricted search failed; inconsistency? (maybe trueT >= bound)")
	}

	fmt.Println("\n=== RESULTS ===")
	fmt.Printf("Recovered (naive) t=%d in %v\n", foundNaive, naiveDur)
	fmt.Printf("Recovered (hinted) t=%d in %v\n", foundRestr, restrDur)
	fmt.Printf("True t=%s\n", trueT.String())
	fmt.Printf("Speedup factor ≈ %.2f× (naive/restricted)\n", float64(naiveDur)/float64(restrDur))
	fmt.Printf("Ideal pruning factor (M) = %d\n", M)
	fmt.Println("Note: For a fair large-scale test, choose bound >> true t and ensure true t < bound.")
}
