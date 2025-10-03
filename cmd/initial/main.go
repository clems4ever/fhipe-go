package main

import (
	"fmt"
	"log"
)

func main() {
	// Example: Using FHIPE to compute inner products
	// We'll create 10 vectors and compute the inner product of vector 0 with each of the others

	n := 5     // dimension of vectors
	S := 10000 // bound for inner product range [-S, S]

	fmt.Println("=== FHIPE Inner Product Example ===")
	fmt.Printf("Vector dimension: %d\n", n)
	fmt.Printf("Inner product bound: [-%d, %d]\n\n", S, S)

	// Step 1: Setup the scheme
	fmt.Println("Step 1: Running Setup...")
	pp, msk, err := Setup(n, S)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}
	fmt.Println("Setup complete!")
	fmt.Println()

	// Step 2: Create 10 vectors
	vectors := make([][]int, 10)

	// Vector 0: [1, 2, 3, 4, 5]
	vectors[0] = []int{1, 2, 3, 4, 5}

	// Vector 1: [5, 4, 3, 2, 1]
	vectors[1] = []int{5, 4, 3, 2, 1}

	// Vector 2: [1, 1, 1, 1, 1]
	vectors[2] = []int{1, 1, 1, 1, 1}

	// Vector 3: [10, 0, 0, 0, 0]
	vectors[3] = []int{10, 0, 0, 0, 0}

	// Vector 4: [0, 10, 0, 0, 0]
	vectors[4] = []int{0, 10, 0, 0, 0}

	// Vector 5: [0, 0, 10, 0, 0]
	vectors[5] = []int{0, 0, 10, 0, 0}

	// Vector 6: [1, -1, 1, -1, 1]
	vectors[6] = []int{1, -1, 1, -1, 1}

	// Vector 7: [2, 2, 2, 2, 2]
	vectors[7] = []int{2, 2, 2, 2, 2}

	// Vector 8: [-1, -2, -3, -4, -5]
	vectors[8] = []int{-1, -2, -3, -4, -5}

	// Vector 9: [0, 0, 0, 0, 1]
	vectors[9] = []int{0, 0, 0, 0, 1}

	fmt.Println("Step 2: Created 10 vectors")
	for i, v := range vectors {
		fmt.Printf("  Vector %d: %v\n", i, v)
	}
	fmt.Println()

	// Step 3: Generate secret key for vector 0
	fmt.Println("Step 3: Generating secret key for vector 0...")
	x := IntsToFrElements(vectors[0])
	sk, err := KeyGen(msk, x)
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	fmt.Println("Secret key generated!")
	fmt.Println()

	// Step 4: Encrypt each vector and compute inner products
	fmt.Println("Step 4: Computing inner products of vector 0 with each vector...")
	fmt.Println()

	for i := 0; i < 10; i++ {
		// Convert vector to field elements
		y := IntsToFrElements(vectors[i])

		// Encrypt the vector
		ct, err := Encrypt(msk, y)
		if err != nil {
			log.Fatalf("Encrypt failed for vector %d: %v", i, err)
		}

		// Decrypt to get D1 and D2
		D1, D2, err := Decrypt(pp, sk, ct)
		if err != nil {
			log.Fatalf("Decrypt failed for vector %d: %v", i, err)
		}

		// Recover the inner product
		innerProduct, found := RecoverInnerProduct(D1, D2, S)
		if !found {
			fmt.Printf("  Vector 0 · Vector %d: NOT FOUND (outside bounds)\n", i)
			continue
		}

		// Compute expected inner product for verification
		expected := 0
		for j := 0; j < n; j++ {
			expected += vectors[0][j] * vectors[i][j]
		}

		// Display results
		if innerProduct == expected {
			fmt.Printf("  Vector 0 · Vector %d = %d ✓ (verified)\n", i, innerProduct)
		} else {
			fmt.Printf("  Vector 0 · Vector %d = %d ✗ (expected %d)\n", i, innerProduct, expected)
		}
	}

	fmt.Println("\n=== Example Complete ===")
}
