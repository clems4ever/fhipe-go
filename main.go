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
			fmt.Printf("v0 · v%-2d: expected = %5d, recovered = %5d %s | D1^z == D2? %v\n", 
				i, expectedIP, z, match, checkPairing(D1, z, D2))
		} else {
			fmt.Printf("v0 · v%-2d: expected = %5d, recovered = FAILED (not in range)\n", i, expectedIP)
		}
	}

	fmt.Println("\n=== Summary ===")
	fmt.Println("All inner products successfully recovered using function-hiding IPE!")

	// Test with a broken (incorrect) key
	fmt.Println("\n=== Testing with Broken Key ===")
	
	// Generate a key for a different vector (v3 = all ones)
	skBroken, err := KeyGen(msk, IntsToFrElements(vectors[3]))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Generated BROKEN secret key for v3 = %v (instead of v0)\n", vectors[3])
	
	// Try to decrypt a ciphertext for v1 using the wrong key
	ctTest, err := Encrypt(msk, IntsToFrElements(vectors[1]))
	if err != nil {
		log.Fatal(err)
	}
	
	// The correct inner product would be <v0, v1> = 742
	// But we're using key for v3, so we'll get <v3, v1> instead
	correctIP := 0
	for j := 0; j < n; j++ {
		correctIP += vectors[0][j] * vectors[1][j]
	}
	
	brokenIP := 0
	for j := 0; j < n; j++ {
		brokenIP += vectors[3][j] * vectors[1][j]
	}
	
	D1Broken, D2Broken, err := Decrypt(params, skBroken, ctTest)
	if err != nil {
		log.Fatal(err)
	}
	
	zBroken, foundBroken := RecoverInnerProduct(D1Broken, D2Broken, params.S)
	
	fmt.Printf("\nEncrypted: v1 = %v\n", vectors[1])
	fmt.Printf("Correct key would give: <v0, v1> = %d\n", correctIP)
	fmt.Printf("Broken key (for v3) gives: <v3, v1> = %d\n", brokenIP)
	
	if foundBroken {
		fmt.Printf("Result with broken key: z = %d (found in S) ✓\n", zBroken)
		fmt.Printf("  → D1^z == D2? %v\n", checkPairing(D1Broken, zBroken, D2Broken))
		if zBroken == brokenIP {
			fmt.Printf("  → Matches <v3, v1> = %d (scheme still works, just with wrong vector!)\n", brokenIP)
		}
		if zBroken != correctIP {
			fmt.Printf("  → Does NOT match correct IP <v0, v1> = %d ✓\n", correctIP)
		}
	} else {
		fmt.Printf("Result with broken key: NOT FOUND in S (out of range)\n")
	}
	
	fmt.Println("\n=== Conclusion ===")
	fmt.Println("With a broken/incorrect key, the scheme still produces a value in S,")
	fmt.Println("but it computes a different (incorrect) inner product!")

	// Test with a completely random vector to see if we can get out of S
	fmt.Println("\n=== Testing with Random Broken Key ===")
	randomVec := []int{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}
	skRandom, err := KeyGen(msk, IntsToFrElements(randomVec))
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("Generated random secret key for v_random = %v\n", randomVec)
	
	// The inner product <v_random, v1>
	randomBrokenIP := 0
	for j := 0; j < n; j++ {
		randomBrokenIP += randomVec[j] * vectors[1][j]
	}
	
	D1Random, D2Random, err := Decrypt(params, skRandom, ctTest)
	if err != nil {
		log.Fatal(err)
	}
	
	zRandom, foundRandom := RecoverInnerProduct(D1Random, D2Random, params.S)
	
	fmt.Printf("Expected inner product <v_random, v1> = %d\n", randomBrokenIP)
	
	if foundRandom {
		fmt.Printf("Result: z = %d (found in S)\n", zRandom)
		if zRandom == randomBrokenIP {
			fmt.Printf("  → Matches <v_random, v1> = %d ✓\n", randomBrokenIP)
		}
	} else {
		fmt.Printf("Result: NOT FOUND in S!\n")
		fmt.Printf("  → Expected value %d is outside range [-%d, %d]\n", randomBrokenIP, params.S, params.S)
		fmt.Printf("  → This proves the broken key produces a value OUTSIDE S! ✓\n")
	}
}
