package main

import (
	"fmt"
	"log"
	"math/rand"
	"time"
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
}
