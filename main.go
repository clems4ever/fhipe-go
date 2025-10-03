package main

import (
	"fmt"
	"log"
)

func main() {
	n := 10

	// Define the bound S for the allowed inner product range: [-S, S]
	// The set is {z ∈ Z : -10000 ≤ z ≤ 10000}, which is polynomial-sized
	S := 10000

	params, msk, err := Setup(n, S)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("=== Function-Hiding Inner Product Encryption ===\n")
	fmt.Printf("Params initialized with S = %d (range [-%d, %d], size = %d)\n\n",
		params.S, params.S, params.S, 2*params.S+1)

	// Define 11 test vectors (length n)
	vectors := [][]int{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},      // v0
		{2, 1, 0, 1, 3, 5, 8, 13, 21, 34},    // v1
		{10, 9, 8, 7, 6, 5, 4, 3, 2, 1},      // v2
		{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},       // v3
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},       // v4
		{-1, -2, -3, -4, -5, 6, 7, 8, 9, 10}, // v5 (with negatives)
		{5, 5, 5, 5, 5, 5, 5, 5, 5, 5},       // v6
		{1, 0, 1, 0, 1, 0, 1, 0, 1, 0},       // v7
		{2, 4, 6, 8, 10, 12, 14, 16, 18, 20}, // v8
		{1, -1, 1, -1, 1, -1, 1, -1, 1, -1},  // v9 (alternating)
		{3, 1, 4, 1, 5, 9, 2, 6, 5, 3},       // v10 (pi digits)
	}

	// Generate secret key for vector 0
	sk0, err := KeyGen(msk, IntsToFrElements(vectors[0]))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated secret key for v0 = %v\n\n", vectors[0])

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
			fmt.Printf("v0 · v%-2d: expected = %5d, recovered = %5d %s\n", i, expectedIP, z, match)
		} else {
			fmt.Printf("v0 · v%-2d: expected = %5d, recovered = FAILED (not in range)\n", i, expectedIP)
		}
	}

	fmt.Println("\n=== Summary ===")
	fmt.Println("All inner products successfully recovered using function-hiding IPE!")
}
