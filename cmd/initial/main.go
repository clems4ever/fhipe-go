package main

import (
	"fmt"
	"log"
	"os"
	"time"
	
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func main() {
	// Example: Using FHIPE to compute inner products with PRECOMPUTED TABLE
	// We'll create 10 vectors and compute the inner product of vector 0 with each of the others

	n := 5    // dimension of vectors
	S := 1000 // bound for inner product range [-S, S]

	fmt.Println("=== FHIPE Inner Product Example with Precomputed Table ===")
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

	// Step 4: Compute gt_base = e(K1, g2) for table precomputation
	fmt.Println("Step 4: Computing gt_base = e(K1, g2) for table precomputation...")
	gt_base, err := bls12381.Pair([]bls12381.G1Affine{sk.K1}, []bls12381.G2Affine{pp.G2Gen})
	if err != nil {
		log.Fatalf("Failed to compute gt_base: %v", err)
	}
	fmt.Println("gt_base computed!")
	fmt.Println()

	// Step 5: Load or create precomputed table
	tableFile := "precomputed_table.gob"
	var table *PrecomputedTable

	fmt.Println("Step 5: Checking for precomputed table...")
	if _, err := os.Stat(tableFile); err == nil {
		fmt.Printf("  ✓ Found existing table: %s\n", tableFile)
		fmt.Println("  Loading from disk...")
		start := time.Now()
		table, err = LoadTableFromDisk(tableFile)
		if err != nil {
			log.Fatalf("Failed to load table: %v", err)
		}
		fmt.Printf("  ✓ Loaded in %v (%d entries)\n", time.Since(start), len(table.Table))
		
		if table.Bound != S {
			fmt.Printf("  ⚠ Table bound mismatch (%d vs %d), regenerating...\n", table.Bound, S)
			table = nil
		}
	}

	if table == nil {
		fmt.Println("  ✗ No valid table found")
		fmt.Printf("  Precomputing table for bound %d...\n", S)
		start := time.Now()
		table = PrecomputeTable(gt_base, S)
		precomputeTime := time.Since(start)
		fmt.Printf("  ✓ Precomputed %d entries in %v\n", len(table.Table), precomputeTime)
		
		fmt.Printf("  Saving to %s...\n", tableFile)
		start = time.Now()
		if err := SaveTableToDisk(table, tableFile); err != nil {
			log.Printf("  ⚠ Warning: Failed to save: %v", err)
		} else {
			fmt.Printf("  ✓ Saved in %v\n", time.Since(start))
		}
	}
	fmt.Println()

	// Step 6: Compute inner products using PRECOMPUTED TABLE
	fmt.Println("Step 6: Computing inner products using PRECOMPUTED TABLE...")
	fmt.Println()

	totalRecoveryTime := time.Duration(0)
	
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

		// Recover the inner product using PRECOMPUTED TABLE (O(1) lookup!)
		start := time.Now()
		innerProduct, found := RecoverInnerProductWithTable(D1, D2, table)
		recoveryTime := time.Since(start)
		totalRecoveryTime += recoveryTime
		
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
		status := "✓"
		if innerProduct != expected {
			status = "✗"
		}
		fmt.Printf("  Vector 0 · Vector %d = %3d %s (table lookup: %v)\n", i, innerProduct, status, recoveryTime)
	}

	fmt.Printf("\nTotal recovery time (10 queries): %v\n", totalRecoveryTime)
	fmt.Printf("Average per query: %v\n", totalRecoveryTime/10)
	
	fmt.Println("\n=== Example Complete ===")
	fmt.Printf("Precomputed table saved to: %s\n", tableFile)
	fmt.Println("Run again to see instant table loading from disk!")
}
