package main

import (
	"fmt"
	"log"
	"os"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func main() {
	// Test different dimensions
	BenchmarkDimensions()
	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println()

	// Run parallel scaling benchmark
	BenchmarkParallelScaling()
	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println()

	// Many keys / single ciphertext benchmark
	BenchmarkManyKeysOneCiphertext()
	fmt.Println("============================================================")
	fmt.Println()

	// Original throughput benchmark
	runThroughputBenchmark()
}

func runThroughputBenchmark() {
	n := 384   // dimension of vectors
	S := 80000 // bound for inner product range [-S, S] (384 * 10 * 10 = 38400 max)

	fmt.Println("=== FHIPE Throughput Benchmark ===")
	fmt.Printf("Vector dimension: %d\n", n)
	fmt.Printf("Inner product bound: [-%d, %d]\n\n", S, S)

	fmt.Println("Setup...")
	start := time.Now()
	pp, msk, err := Setup(n, S)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}
	fmt.Printf("Setup: %v\n\n", time.Since(start))

	// Generate random vectors
	numVectors := 100
	vectors := make([][]int, numVectors)
	for i := 0; i < numVectors; i++ {
		vectors[i] = make([]int, n)
		for j := 0; j < n; j++ {
			vectors[i][j] = (i*j+j)%20 - 10 // deterministic pseudo-random
		}
	}

	fmt.Println("KeyGen...")
	start = time.Now()
	x := IntsToFrElements(vectors[0])
	sk, err := KeyGen(msk, x)
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	fmt.Printf("KeyGen: %v\n\n", time.Since(start))

	// Compute gt_base
	gt_base, err := bls12381.Pair([]bls12381.G1Affine{sk.K1}, []bls12381.G2Affine{pp.G2Gen})
	if err != nil {
		log.Fatalf("Failed to compute gt_base: %v", err)
	}

	// Load or create table
	tableFile := "precomputed_table.gob"
	var table *PrecomputedTable

	if _, err := os.Stat(tableFile); err == nil {
		start = time.Now()
		table, err = LoadTableFromDisk(tableFile)
		if err != nil {
			log.Fatalf("Failed to load table: %v", err)
		}
		fmt.Printf("Table loaded from disk: %v (%d entries)\n", time.Since(start), len(table.Table))

		if table.Bound != S {
			fmt.Printf("Table bound mismatch, regenerating...\n")
			table = nil
		}
	}

	if table == nil {
		fmt.Printf("Precomputing table (bound=%d)...\n", S)
		start = time.Now()
		table = PrecomputeTable(gt_base, S)
		fmt.Printf("Precomputation: %v (%d entries)\n", time.Since(start), len(table.Table))

		start = time.Now()
		if err := SaveTableToDisk(table, tableFile); err != nil {
			log.Printf("Warning: Failed to save: %v", err)
		} else {
			fmt.Printf("Saved to disk: %v\n", time.Since(start))
		}
	}
	fmt.Println()

	// Benchmark throughput with 100 vectors
	numVectors = 100
	fmt.Printf("Running throughput benchmark with %d encryptions...\n\n", numVectors) // Pre-encrypt all vectors
	fmt.Println("Pre-encrypting vectors...")
	ciphertexts := make([]Ciphertext, numVectors)
	encryptStart := time.Now()
	for i := 0; i < numVectors; i++ {
		y := IntsToFrElements(vectors[i])
		ct, err := Encrypt(msk, y)
		if err != nil {
			log.Fatalf("Encrypt failed: %v", err)
		}
		ciphertexts[i] = ct
	}
	encryptTime := time.Since(encryptStart)
	fmt.Printf("Encryption: %v total, %v per op\n", encryptTime, encryptTime/time.Duration(numVectors))

	// Batch decrypt and recover
	fmt.Println("\nDecrypting and recovering (BATCH PARALLEL)...")
	decryptStart := time.Now()

	D1s, D2s, err := BatchDecryptParallel(pp, sk, ciphertexts)
	if err != nil {
		log.Fatalf("Batch decrypt failed: %v", err)
	}
	totalDecryptTime := time.Since(decryptStart)

	recoveryStart := time.Now()
	successful := 0
	failed := 0
	outOfBounds := 0

	for i := 0; i < numVectors; i++ {
		result, found := RecoverInnerProductWithTable(D1s[i], D2s[i], table)
		if found {
			successful++

			// Verify correctness on first few
			if i < 10 {
				expected := 0
				for j := 0; j < n; j++ {
					expected += vectors[0][j] * vectors[i][j]
				}
				if result != expected {
					fmt.Printf("MISMATCH at %d: got %d, expected %d\n", i, result, expected)
					failed++
				}
			}
		} else {
			// Check if it's actually out of bounds
			expected := 0
			for j := 0; j < n; j++ {
				expected += vectors[0][j] * vectors[i][j]
			}
			if expected < -S || expected > S {
				outOfBounds++
				if outOfBounds <= 5 {
					fmt.Printf("Out of bounds at %d: inner product = %d (bound = [-%d, %d])\n", i, expected, S, S)
				}
			} else {
				fmt.Printf("RECOVERY FAILED at %d: inner product = %d (should be in bounds!)\n", i, expected)
				failed++
			}
		}
	}
	totalRecoveryTime := time.Since(recoveryStart)

	totalTime := time.Since(decryptStart)

	fmt.Printf("\nTotal time: %v, %v per op\n", totalTime, totalTime/time.Duration(numVectors))
	fmt.Printf("Decryption only: %v total, %v per op\n", totalDecryptTime, totalDecryptTime/time.Duration(numVectors))
	fmt.Printf("Recovery only: %v total, %v per op\n", totalRecoveryTime, totalRecoveryTime/time.Duration(numVectors))
	fmt.Printf("Successful recoveries: %d/%d\n", successful, numVectors)
	fmt.Printf("Out of bounds: %d\n", outOfBounds)
	fmt.Printf("Failed (in bounds): %d\n\n", failed)

	// Throughput calculation
	throughput := float64(numVectors) / totalTime.Seconds()
	decryptThroughput := float64(numVectors) / totalDecryptTime.Seconds()
	recoveryThroughput := float64(numVectors) / totalRecoveryTime.Seconds()

	fmt.Println("=== THROUGHPUT RESULTS ===")
	fmt.Printf("Full operation (decrypt + recover): %.2f ops/sec\n", throughput)
	fmt.Printf("Decryption only: %.2f ops/sec\n", decryptThroughput)
	fmt.Printf("Recovery only: %.2f ops/sec\n", recoveryThroughput)
}
