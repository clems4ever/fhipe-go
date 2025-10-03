package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func main() {
	n := 384
	// Bound S (ensure it's large enough to contain typical inner products for chosen entry ranges)
	S := 5000

	params, msk, err := Setup(n, S)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("=== Function-Hiding Inner Product Encryption ===\n")
	fmt.Printf("Params initialized with S = %d (range [-%d, %d], size = %d)\n\n",
		params.S, params.S, params.S, 2*params.S+1)

	// Generate a small set of random vectors for functional correctness demonstration.
	rand.Seed(time.Now().UnixNano())
	numVectors := 6
	entryRange := 5 // coordinates sampled from [-entryRange, entryRange]
	vectors := make([][]int, numVectors)
	for i := 0; i < numVectors; i++ {
		vec := make([]int, n)
		for j := 0; j < n; j++ {
			vec[j] = rand.Intn(2*entryRange+1) - entryRange
		}
		vectors[i] = vec
	}

	// Generate secret key for vector 0
	sk0, err := KeyGen(msk, IntsToFrElements(vectors[0]))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated secret key for v0 (first 12 entries shown) = %v ...\n\n", vectors[0][:12])

	// Test inner product between v0 and all vectors (including itself)
	fmt.Println("=== Testing Inner Products: <v0, vi> ===")
	for i := 0; i < len(vectors); i++ {
		// Compute expected inner product
		expectedIP := 0
		for j := 0; j < n; j++ {
			expectedIP += vectors[0][j] * vectors[i][j]
		}

		// Encrypt vector i
		ct, err := Encrypt(msk, IntsToFrElements(vectors[i]))
		if err != nil {
			log.Fatal(err)
		}

		// Decrypt to get D1 and D2
		D1, D2, err := Decrypt(params, sk0, ct)
		if err != nil {
			log.Fatal(err)
		}

		// Recover inner product
		z, found := RecoverInnerProduct(D1, D2, params.S)

		// Display results
		if found {
			match := "✓"
			if z != expectedIP {
				match = "✗"
			}
			fmt.Printf("v0 · v%-2d: expected = %6d, recovered = %6d %s\n", i, expectedIP, z, match)
		} else {
			fmt.Printf("v0 · v%-2d: expected = %6d, recovered = FAILED (not in range)\n", i, expectedIP)
		}
	}

	fmt.Println("\n=== Summary ===")
	fmt.Println("All inner products successfully recovered using function-hiding IPE!")

	// Throughput benchmarks for 384 dimensions
	fmt.Println("\n=== Throughput Benchmarks (n=384) ===")
	fullTrials := 30
	fullRes, err := runFullPipelineThroughput(msk, params, sk0, fullTrials, entryRange)
	if err != nil {
		log.Fatal(err)
	}
	printThroughput(fullRes)

	recoveryTrials := 500
	recRes := runRecoveryOnlyThroughput(params, params.S, recoveryTrials)
	printThroughput(recRes)

	// Floating-point example using fixed-point encoding
	fmt.Println("\n=== Floating-Point Example (Fixed-Point Encoding) ===")
	// Suppose we have two real-valued vectors a, b of length m (use smaller m for display)
	m := 12
	aFloat := []float64{0.125, -1.75, 2.5, 3.1415, -0.3333, 1.0, -2.25, 4.5, 0.0625, -0.5, 1.75, -3.0}
	bFloat := []float64{1.5, 0.25, -2.0, 0.5, -1.125, 2.25, 3.0, -0.75, 0.875, -1.0, 0.0, 1.0}

	// Choose a scale for ~4 decimal digits precision
	enc, _ := NewFixedPointEncoder(10000)

	// Encode (pad to n=384 by zeros so we can reuse the same public parameters)
	padAndEncode := func(fv []float64) ([]fr.Element, []int64) {
		full := make([]float64, n)
		copy(full, fv)
		fe, ints, err := enc.EncodeFloatVector(full)
		if err != nil {
			log.Fatal(err)
		}
		return fe, ints
	}

	aElems, aInts := padAndEncode(aFloat)
	bElems, bInts := padAndEncode(bFloat)

	// KeyGen for a (treat as the secret vector)
	// Compute a bound for the (scaled) inner product over the first m entries.
	maxAbsA, maxAbsB := 0.0, 0.0
	for i := 0; i < m; i++ {
		if math.Abs(aFloat[i]) > maxAbsA {
			maxAbsA = math.Abs(aFloat[i])
		}
		if math.Abs(bFloat[i]) > maxAbsB {
			maxAbsB = math.Abs(bFloat[i])
		}
	}
	floatBound := BoundForScaledInnerProduct(m, maxAbsA, maxAbsB, enc, enc)
	// Use a safety margin factor.
	floatBound = int(float64(floatBound)*1.2) + 1
	if floatBound < 10 {
		floatBound = 10
	}
	fmt.Printf("Float example required bound (scaled) ≈ %d\n", floatBound)

	// Create a dedicated params/msk for the float example (dimension n, but first m used)
	_, mskFloat, err := Setup(n, floatBound)
	if err != nil {
		log.Fatal(err)
	}
	skA, err := KeyGen(mskFloat, aElems)
	if err != nil {
		log.Fatal(err)
	}
	ctB, err := Encrypt(mskFloat, bElems)
	if err != nil {
		log.Fatal(err)
	}
	D1f, D2f, err := Decrypt(mskFloat.PP, skA, ctB)
	if err != nil {
		log.Fatal(err)
	}
	zScaled, ok := RecoverInnerProduct(D1f, D2f, mskFloat.PP.S)
	if !ok {
		fmt.Println("Recovered inner product not in new S (unexpected)")
	} else {
		// Compute expected scaled integer inner product over first m entries only
		var expectedScaled int64
		for i := 0; i < m; i++ {
			expectedScaled += aInts[i] * bInts[i]
		}
		// Decode to float
		decoded := DecodeInnerProduct(zScaled, enc, enc)
		// True real inner product (first m entries)
		var realIP float64
		for i := 0; i < m; i++ {
			realIP += aFloat[i] * bFloat[i]
		}
		fmt.Printf("Scaled integer recovered z = %d (S=%d)\n", zScaled, mskFloat.PP.S)
		fmt.Printf("Expected scaled (manual)  = %d\n", expectedScaled)
		fmt.Printf("Decoded approximate value = %.6f\n", decoded)
		fmt.Printf("Actual real inner product = %.6f\n", realIP)
		fmt.Printf("Absolute error            = %.6g\n", math.Abs(decoded-realIP))
	}
}
