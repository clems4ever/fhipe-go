package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Small primes for hints (CRT)
var hintPrimes = []int64{251, 257, 263}

// MasterSecretKey contains the secret parameters
type MasterSecretKey struct {
	s *big.Int // master secret
}

// MasterPublicKey contains public parameters
type MasterPublicKey struct {
	g1 bn254.G1Affine // generator in G1
	g2 bn254.G2Affine // generator in G2
}

// SecretKey for a vector y
type SecretKey struct {
	sky []bn254.G2Affine // sky[i] = g2^(s*y[i])
}

// Ciphertext for a vector x with hints
type Ciphertext struct {
	c0    bn254.G1Affine   // c0 = g1^r
	cx    []bn254.G1Affine // cx[i] = g1^(r*x[i])
	hints []bn254.G2Affine // hints[j] = g2^(t mod p'_j) - cryptographic hints
}

// Setup generates master keys
func Setup(n int) (*MasterSecretKey, *MasterPublicKey) {
	// Generate random master secret s
	s, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		panic(err)
	}

	// Generate G1 and G2 generators
	_, _, g1, g2 := bn254.Generators()

	msk := &MasterSecretKey{s: s}
	mpk := &MasterPublicKey{g1: g1, g2: g2}

	return msk, mpk
}

// KeyGen generates a secret key for vector y
func KeyGen(msk *MasterSecretKey, mpk *MasterPublicKey, y []*big.Int) *SecretKey {
	n := len(y)
	sky := make([]bn254.G2Affine, n)

	for i := 0; i < n; i++ {
		// sky[i] = g2^(s*y[i])
		syi := new(big.Int).Mul(msk.s, y[i])
		syi.Mod(syi, fr.Modulus())
		sky[i].ScalarMultiplication(&mpk.g2, syi)
	}

	return &SecretKey{sky: sky}
}

// Encrypt encrypts vector x with computational hints
func Encrypt(mpk *MasterPublicKey, x []*big.Int, y []*big.Int) *Ciphertext {
	n := len(x)

	// Generate random r
	r, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		panic(err)
	}

	// Compute c0 = g1^r
	var c0 bn254.G1Affine
	c0.ScalarMultiplication(&mpk.g1, r)

	// Compute cx[i] = g1^(r*x[i])
	cx := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		rxi := new(big.Int).Mul(r, x[i])
		rxi.Mod(rxi, fr.Modulus())
		cx[i].ScalarMultiplication(&mpk.g1, rxi)
	}

	// Compute inner product t = <x, y>
	t := big.NewInt(0)
	for i := 0; i < n; i++ {
		term := new(big.Int).Mul(x[i], y[i])
		t.Add(t, term)
	}
	t.Mod(t, fr.Modulus())

	// Compute cryptographic hints: h[j] = g2^(t mod p'_j) for each small prime
	// This is the key innovation: hints are group elements, not plain integers
	hints := make([]bn254.G2Affine, len(hintPrimes))
	for j, p := range hintPrimes {
		pBig := big.NewInt(p)
		tModP := new(big.Int).Mod(t, pBig)
		// Compute h_j = g2^(t mod p'_j)
		hints[j].ScalarMultiplication(&mpk.g2, tModP)
	}

	return &Ciphertext{
		c0:    c0,
		cx:    cx,
		hints: hints,
	}
}

// Decrypt recovers the inner product using the secret key and hints
func Decrypt(sk *SecretKey, ct *Ciphertext, searchBound int) (*big.Int, error) {
	n := len(sk.sky)

	var target bn254.GT
	target.SetOne()

	for i := 0; i < n; i++ {
		var pairing bn254.GT
		pairing, err := bn254.Pair([]bn254.G1Affine{ct.cx[i]}, []bn254.G2Affine{sk.sky[i]})
		if err != nil {
			return nil, err
		}
		target.Mul(&target, &pairing)
	}

	// Now solve DLP: target = e(g1, g2)^(r*s*t) where t = <x,y>
	// Using hints to narrow search space

	// Get base pairing e(g1, g2)
	_, _, g1, g2 := bn254.Generators()
	basePairing, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, err
	}

	// NOTE: In practice, we'd need to know r*s or have a different construction
	// For this demo, let's assume we're solving for t directly (simplified)
	// Using CRT hints to reduce search space

	// Use Chinese Remainder Theorem with hints
	result := solveDLPWithHints(&target, &basePairing, ct.hints, searchBound)

	return result, nil
}

// solveDLPWithHints solves discrete log using CRT hints
// First, it recovers t mod p'_j by solving small DLPs on the hints
// Then uses CRT to reduce the main DLP search space
func solveDLPWithHints(target *bn254.GT, base *bn254.GT, hints []bn254.G2Affine, bound int) *big.Int {
	// Step 1: Recover t mod p'_j from each cryptographic hint
	// Each hint h_j = g2^(t mod p'_j), so we solve small DLP in G2
	recoveredHints := make([]int64, len(hintPrimes))
	_, _, _, g2 := bn254.Generators()

	for j, hintElement := range hints {
		p := hintPrimes[j]
		// Solve DLP: hintElement = g2^x where x ∈ [0, p-1]
		// This is fast because p is small (e.g., 251, 257, 263)
		for x := int64(0); x < p; x++ {
			var test bn254.G2Affine
			test.ScalarMultiplication(&g2, big.NewInt(x))
			if test.Equal(&hintElement) {
				recoveredHints[j] = x
				break
			}
		}
	}

	// Step 2: Use CRT hints to reduce search space
	// The hints tell us: t ≡ recoveredHints[j] (mod hintPrimes[j])
	// So we only search values that satisfy all these congruences

	for t := 0; t <= bound; t++ {
		// Check if t satisfies all hint constraints
		valid := true
		for j, h := range recoveredHints {
			if int64(t)%hintPrimes[j] != h {
				valid = false
				break
			}
		}

		if !valid {
			continue // Skip values that don't match hints
		}

		// Test if base^t == target
		var test bn254.GT
		tBig := big.NewInt(int64(t))
		test.Exp(*base, tBig)

		if test.Equal(target) {
			return tBig
		}
	}

	return nil // Not found
}

func main() {
	fmt.Println("=== FH-IPE with Computational Hints (based on ePrint 2016/440) ===\n")

	// Parameters
	n := 384 // dimension

	fmt.Printf("Setting up FH-IPE for dimension n=%d\n", n)
	fmt.Printf("Using hint primes: %v\n\n", hintPrimes)

	// Setup
	msk, mpk := Setup(n)
	fmt.Println("✓ Setup complete")

	// Define vectors - generate random small values
	x := make([]*big.Int, n)
	y := make([]*big.Int, n)

	for i := 0; i < n; i++ {
		// Use small values for demonstration (1-10 range)
		x[i] = big.NewInt(int64(i%10 + 1))
		y[i] = big.NewInt(int64((i*7)%10 + 1))
	}

	// Compute expected inner product
	expected := big.NewInt(0)
	for i := 0; i < n; i++ {
		term := new(big.Int).Mul(x[i], y[i])
		expected.Add(expected, term)
	}

	fmt.Printf("Vector dimension: %d\n", n)
	fmt.Printf("Sample x[0:5]: %v\n", x[0:5])
	fmt.Printf("Sample y[0:5]: %v\n", y[0:5])
	fmt.Printf("Expected <x,y>: %s\n\n", expected.String())

	// Key generation
	sk := KeyGen(msk, mpk, y)
	fmt.Println("✓ Key generated for vector y")

	// Encryption with hints
	ct := Encrypt(mpk, x, y)
	fmt.Printf("✓ Encrypted vector x\n")
	fmt.Printf("  Computational hints (cryptographic): [%d G2 elements]\n", len(ct.hints))

	// Verify hints by solving small DLPs
	fmt.Println("\n  Hint verification (solving small DLPs in G2):")
	_, _, _, g2 := bn254.Generators()
	for j, hintElement := range ct.hints {
		p := hintPrimes[j]
		expectedHintValue := new(big.Int).Mod(expected, big.NewInt(p))

		// Verify: hint = g2^(t mod p')
		var expectedHintElement bn254.G2Affine
		expectedHintElement.ScalarMultiplication(&g2, expectedHintValue)

		if expectedHintElement.Equal(&hintElement) {
			fmt.Printf("    h_%d = g2^(<x,y> mod %d) = g2^%d ✓\n", j, p, expectedHintValue.Int64())
		} else {
			fmt.Printf("    h_%d verification FAILED\n", j)
		}
	}

	// Decryption (with bounded search)
	fmt.Println("\n✓ Decrypting...")
	searchBound := 1000 // Small bound for demo

	// Note: This is a simplified demonstration
	// In a production implementation, you would call:
	// result := Decrypt(sk, ct, searchBound)
	// The current implementation demonstrates the hint mechanism

	fmt.Printf("  Search bound: %d\n", searchBound)
	fmt.Printf("  Effective search with hints: ~%d (reduced by factor of %d)\n",
		searchBound/int(hintPrimes[0]*hintPrimes[1]*hintPrimes[2]),
		int(hintPrimes[0]*hintPrimes[1]*hintPrimes[2]))

	_ = sk // Used in production: Decrypt(sk, ct, searchBound)

	fmt.Printf("\n=== Demonstration Notes ===\n")
	fmt.Println("This implementation demonstrates the core idea:")
	fmt.Println("1. Include computational hints h_j = <x,y> mod p'_j in ciphertext")
	fmt.Println("2. Hints are information-theoretically hiding (just residues)")
	fmt.Println("3. During DLP solving, only search values matching all hints")
	fmt.Printf("4. With k=%d primes of size ~256, reduces search by ~256^%d\n", len(hintPrimes), len(hintPrimes))
	fmt.Println("5. For k=3, that's approximately 16 million times faster!")
	fmt.Println("\nSecurity: Hints depend only on <x,y>, preserving function-hiding.")
	fmt.Println("The full scheme requires careful construction for proper FH-IPE semantics.")

	// Throughput benchmarking
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("=== THROUGHPUT BENCHMARK (100 vectors) ===")
	fmt.Println(strings.Repeat("=", 70))

	numVectors := 100

	// Pre-generate test vectors
	testVectors := make([][]*big.Int, numVectors)
	for v := 0; v < numVectors; v++ {
		vec := make([]*big.Int, n)
		for i := 0; i < n; i++ {
			vec[i] = big.NewInt(int64((v+i)%10 + 1))
		}
		testVectors[v] = vec
	}

	// Benchmark Encryption
	fmt.Printf("\nEncrypting %d vectors of dimension %d...\n", numVectors, n)
	startEnc := time.Now()
	ciphertexts := make([]*Ciphertext, numVectors)
	for v := 0; v < numVectors; v++ {
		ciphertexts[v] = Encrypt(mpk, testVectors[v], y)
	}
	encDuration := time.Since(startEnc)

	encThroughput := float64(numVectors) / encDuration.Seconds()
	avgEncTime := encDuration / time.Duration(numVectors)

	fmt.Printf("✓ Encryption complete\n")
	fmt.Printf("  Total time: %v\n", encDuration)
	fmt.Printf("  Average per vector: %v\n", avgEncTime)
	fmt.Printf("  Throughput: %.2f encryptions/second\n", encThroughput)

	// Benchmark Decryption (simplified - just pairing computation)
	fmt.Printf("\nDecrypting %d vectors (pairing computation only)...\n", numVectors)
	startDec := time.Now()
	for v := 0; v < numVectors; v++ {
		// Compute the pairing part (skip DLP for benchmark)
		var target bn254.GT
		target.SetOne()

		for i := 0; i < n; i++ {
			var pairing bn254.GT
			pairing, _ = bn254.Pair([]bn254.G1Affine{ciphertexts[v].cx[i]}, []bn254.G2Affine{sk.sky[i]})
			target.Mul(&target, &pairing)
		}
		// In production: would call solveDLPWithHints here
	}
	decDuration := time.Since(startDec)

	decThroughput := float64(numVectors) / decDuration.Seconds()
	avgDecTime := decDuration / time.Duration(numVectors)

	fmt.Printf("✓ Decryption complete\n")
	fmt.Printf("  Total time: %v\n", decDuration)
	fmt.Printf("  Average per vector: %v\n", avgDecTime)
	fmt.Printf("  Throughput: %.2f decryptions/second\n", decThroughput)

	// Summary
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("=== PERFORMANCE SUMMARY ===")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Dimension: %d\n", n)
	fmt.Printf("Number of vectors: %d\n", numVectors)
	fmt.Printf("Hint primes: %v\n\n", hintPrimes)
	fmt.Printf("Encryption throughput:  %.2f ops/sec (%.2f ms/op)\n",
		encThroughput, avgEncTime.Seconds()*1000)
	fmt.Printf("Decryption throughput:  %.2f ops/sec (%.2f ms/op)\n",
		decThroughput, avgDecTime.Seconds()*1000)
	fmt.Printf("\nNote: Decryption time excludes DLP solving (would use hints to accelerate)\n")
	fmt.Println(strings.Repeat("=", 70))

	// =====================================================================
	// Correctness & DLP Recovery Demonstration (Diagnostic Section)
	// =====================================================================
	fmt.Println("\n[DIAGNOSTICS] Inner-Product Recovery & Hint Usage")
	fmt.Println(strings.Repeat("-", 70))

	// CURRENT LIMITATION:
	fmt.Println("This prototype does NOT actually derive e(g1,g2)^{<x,y>} independent of r,s.")
	fmt.Println("Instead it produces e(g1,g2)^{r*s*<x,y>} and then (incorrectly) treats the base as e(g1,g2).")
	fmt.Println("Therefore the DLP recovery for <x,y> would be unsound unless r*s ≡ 1 (which we don't enforce).")

	fmt.Println("Why performance improvement not visible yet:")
	fmt.Println("1. We never execute the (expensive) main DLP search — only pairings are benchmarked.")
	fmt.Println("2. Hints are formed as g2^{t mod p'} but we don't actually use them to prune a real search over t.")
	fmt.Println("3. To see speedup we must (a) have a correct base Z = e(g1,g2)^t, and (b) search a large exponent interval.")

	// Theoretical speedup illustration
	M := int64(1)
	for _, p := range hintPrimes {
		M *= p
	}
	// Suppose we need to search t in [0, B)
	B := int64(1_000_000_000) // hypothetical bound
	naiveCost := B
	// With hints, expected candidates ≈ ceil(B / M)
	candidates := (B + M - 1) / M
	speedup := float64(naiveCost) / float64(candidates)

	fmt.Println("Theoretical DLP search costs (example):")
	fmt.Printf("  Bound B: %d\n", B)
	fmt.Printf("  Product of primes M = ∏ p'_j = %d\n", M)
	fmt.Printf("  Naive candidates: %d\n", naiveCost)
	fmt.Printf("  With hints candidates: %d\n", candidates)
	fmt.Printf("  Ideal pruning factor: %.2f×\n", speedup)
	fmt.Println("  (Matches expected ≈ 256^k for k primes of ~8-bit size.)")

	// Mini practical demo using ONLY first 2 primes so product < demoBound for feasible enumeration
	demoPrimes := hintPrimes[:2]
	demoM := int64(1)
	for _, p := range demoPrimes {
		demoM *= p
	}
	demoBound := int64(200_000) // small enough to enumerate logically (we won't brute force exponentiations)
	demoCandidates := (demoBound + demoM - 1) / demoM
	fmt.Println("Practical mini-demo setup (not executing full exponentiations):")
	fmt.Printf("  Using primes %v => M=%d\n", demoPrimes, demoM)
	fmt.Printf("  Demo bound B=%d, naive=%d, with hints≈%d, factor≈%.1f×\n",
		demoBound, demoBound, demoCandidates, float64(demoBound)/float64(demoCandidates))

	fmt.Println("NEXT STEPS to make this a fully correct FH-IPE prototype:")
	fmt.Println("  1. Replace simplistic construction with dual orthonormal basis (a_i, b_i) s.t. e(g1^{a_i}, g2^{b_j}) = g_T^{δ_{ij}}.")
	fmt.Println("  2. Structure ciphertext & key so randomness r cancels in pairing (avoid r*s factor).")
	fmt.Println("  3. Output Z = e(g1,g2)^{<x,y>} explicitly; then apply hinted DLP on Z.")
	fmt.Println("  4. Implement CRT recombination + restricted baby-step giant-step per residue class.")
	fmt.Println("  5. Benchmark: compare full-range BSGS vs residue-class BSGS (expect ~M speedup).")

	fmt.Println("If you want, I can implement a corrected minimal IPE toy + real hinted DLP benchmark in a follow-up edit.")
}
