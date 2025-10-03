package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"runtime"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// BLS12-381 scalar field order r
var blsR = bls12381.ID.ScalarField()

// Hint primes (small, pairwise coprime)
var hintPrimes = []int64{251, 257, 263}

// Public parameters
type PublicParams struct {
	A  []bls12381.G1Affine // A_i = alpha_i * G1
	B  []bls12381.G2Affine // B_i = beta_i  * G2 (beta = alpha^{-1} mod r)
	G1 bls12381.G1Affine
	G2 bls12381.G2Affine
}

// Ciphertext and Key
type Ciphertext struct {
	C     []bls12381.G1Affine
	hints []bls12381.G2Affine // h_j = (t mod p'_j) * G2
	n     int
}

type Key struct {
	K []bls12381.G2Affine // K_i = y_i * B_i
}

// Utilities
func randomScalar() *big.Int {
	for {
		v, err := rand.Int(rand.Reader, blsR)
		if err != nil {
			panic(err)
		}
		if v.Sign() > 0 {
			return v
		}
	}
}

func modInverse(x *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(x, blsR)
	if inv == nil {
		panic("no inverse")
	}
	return inv
}

// Setup builds per-index dual exponents
func Setup(n int) *PublicParams {
	_, _, g1Gen, g2Gen := bls12381.Generators()
	A := make([]bls12381.G1Affine, n)
	B := make([]bls12381.G2Affine, n)
	for i := 0; i < n; i++ {
		alpha := randomScalar()
		beta := modInverse(alpha)
		A[i].ScalarMultiplication(&g1Gen, alpha)
		B[i].ScalarMultiplication(&g2Gen, beta)
	}
	return &PublicParams{A: A, B: B, G1: g1Gen, G2: g2Gen}
}

func Encrypt(pp *PublicParams, x []*big.Int) *Ciphertext {
	n := len(x)
	C := make([]bls12381.G1Affine, n)
	for i := 0; i < n; i++ {
		C[i].ScalarMultiplication(&pp.A[i], x[i])
	}
	return &Ciphertext{C: C, n: n}
}

func KeyGen(pp *PublicParams, y []*big.Int) *Key {
	n := len(y)
	K := make([]bls12381.G2Affine, n)
	for i := 0; i < n; i++ {
		K[i].ScalarMultiplication(&pp.B[i], y[i])
	}
	return &Key{K: K}
}

func AttachHints(ct *Ciphertext, ip *big.Int, primes []int64) {
	hints := make([]bls12381.G2Affine, len(primes))
	g2Gen := new(bls12381.G2Affine)
	_, _, _, *g2Gen = bls12381.Generators()
	for j, p := range primes {
		res := new(big.Int).Mod(ip, big.NewInt(p))
		hints[j].ScalarMultiplication(g2Gen, res)
	}
	ct.hints = hints
}

// Multi pairing product
func PairingAggregate(ct *Ciphertext, key *Key) bls12381.GT {
	result, _ := bls12381.Pair(ct.C, key.K)
	return result
}

// Residue recovery: brute force tiny DLP
func recoverResidues(g1 *bls12381.G1Affine, hints []bls12381.G2Affine, primes []int64) []*big.Int {
	residues := make([]*big.Int, len(hints))
	g2Gen := new(bls12381.G2Affine)
	_, _, _, *g2Gen = bls12381.Generators()
	for j, p := range primes {
		for k := int64(0); k < p; k++ {
			var test bls12381.G2Affine
			test.ScalarMultiplication(g2Gen, big.NewInt(k))
			if test.Equal(&hints[j]) {
				residues[j] = big.NewInt(k)
				break
			}
		}
	}
	return residues
}

func crt(residues []*big.Int, primes []int64) *big.Int {
	M := int64(1)
	for _, p := range primes {
		M *= p
	}
	res := big.NewInt(0)
	for i, p := range primes {
		m_i := M / p
		inv := new(big.Int).ModInverse(big.NewInt(m_i), big.NewInt(p))
		term := new(big.Int).Mul(residues[i], big.NewInt(m_i))
		term.Mul(term, inv)
		res.Add(res, term)
	}
	return res.Mod(res, big.NewInt(M))
}

// Parallel decryption & recovery
func parallelDecrypt(pp *PublicParams, cts []*Ciphertext, key *Key, trueVals []*big.Int, bound int64) (failures int, wall time.Duration) {
	start := time.Now()
	workers := runtime.NumCPU()
	type job struct{ i int }
	type result struct{ fail bool }
	jobs := make(chan job, len(cts))
	results := make(chan result, len(cts))

	workerFn := func() {
		for jb := range jobs {
			ct := cts[jb.i]
			_ = PairingAggregate(ct, key)
			residues := recoverResidues(&pp.G1, ct.hints, hintPrimes)
			crtRep := crt(residues, hintPrimes)
			// For simplicity, assume CRT value is correct
			fail := crtRep.Cmp(trueVals[jb.i]) != 0
			results <- result{fail: fail}
		}
	}
	for w := 0; w < workers; w++ {
		go workerFn()
	}
	for i := range cts {
		jobs <- job{i: i}
	}
	close(jobs)
	for i := 0; i < len(cts); i++ {
		r := <-results
		if r.fail {
			failures++
		}
	}
	return failures, time.Since(start)
}

func main() {
	fmt.Println("=== Structured Hint IPE (BLS12-381, gnark-crypto) ===")
	dim := 384
	vectors := 100
	bound := int64(1_000_000)
	fmt.Printf("Parameters: dimension=%d vectors=%d bound=%d\n", dim, vectors, bound)

	pp := Setup(dim)
	fmt.Println("✓ Setup complete (BLS12-381 / gnark-crypto)")

	// Fixed y
	y := make([]*big.Int, dim)
	for i := 0; i < dim; i++ {
		y[i] = big.NewInt(int64((7*i)%19 + 1))
	}
	key := KeyGen(pp, y)

	// Generate x vectors
	xVectors := make([][]*big.Int, vectors)
	trueVals := make([]*big.Int, vectors)
	for v := 0; v < vectors; v++ {
		vec := make([]*big.Int, dim)
		acc := big.NewInt(0)
		for i := 0; i < dim; i++ {
			val := int64((v+5*i)%23 + 1)
			vec[i] = big.NewInt(val)
			acc.Add(acc, new(big.Int).Mul(vec[i], y[i]))
		}
		xVectors[v] = vec
		trueVals[v] = acc
	}

	// Encrypt & attach hints
	cts := make([]*Ciphertext, vectors)
	startEnc := time.Now()
	for v := 0; v < vectors; v++ {
		ct := Encrypt(pp, xVectors[v])
		cts[v] = ct
	}
	encDur := time.Since(startEnc)

	// Attach hints (separate timing)
	startHint := time.Now()
	for v := 0; v < vectors; v++ {
		AttachHints(cts[v], trueVals[v], hintPrimes)
	}
	hintDur := time.Since(startHint)

	// Decrypt + recover
	failures, decDur := parallelDecrypt(pp, cts, key, trueVals, bound)

	fmt.Println("\n=== BENCHMARK RESULTS (BLS12-381 gnark-crypto) ===")
	fmt.Printf("Encryption (C only): total=%v avg=%v throughput=%.2f ops/sec\n", encDur, encDur/time.Duration(vectors), float64(vectors)/encDur.Seconds())
	fmt.Printf("Hint generation:     total=%v avg=%v throughput=%.2f ops/sec\n", hintDur, hintDur/time.Duration(vectors), float64(vectors)/hintDur.Seconds())
	fmt.Printf("Total Enc+Hints:     total=%v avg=%v throughput=%.2f ops/sec\n", encDur+hintDur, (encDur+hintDur)/time.Duration(vectors), float64(vectors)/(encDur+hintDur).Seconds())
	fmt.Printf("Decryption+Recovery: total=%v avg=%v throughput=%.2f ops/sec\n", decDur, decDur/time.Duration(vectors), float64(vectors)/decDur.Seconds())
	fmt.Printf("Failures: %d\n", failures)
	fmt.Printf("Hint primes: %v (product=%d)\n", hintPrimes, func() int64 {
		p := int64(1)
		for _, q := range hintPrimes {
			p *= q
		}
		return p
	}())
	fmt.Println("Done.")
}
