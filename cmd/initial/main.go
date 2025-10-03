package main

import (
	"fmt"
	"log"
	"os"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func main() {
	// Run parallel scaling benchmark
	BenchmarkParallelScaling()
	fmt.Println("\n============================================================\n")

	// Original throughput benchmark
	runThroughputBenchmark()
}

func runThroughputBenchmark() {
	n := 384   // dimension of vectors
	S := 10000 // bound for inner product range [-S, S]

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
	numVectors := 1000
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

	// Benchmark throughput
	fmt.Printf("Running throughput benchmark with %d encryptions...\n\n", numVectors)

	// Pre-encrypt all vectors
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

	// Decrypt and recover
	fmt.Println("\nDecrypting and recovering (PARALLEL)...")
	decryptStart := time.Now()
	var totalRecoveryTime time.Duration
	var totalDecryptTime time.Duration
	successful := 0

	for i := 0; i < numVectors; i++ {
		dStart := time.Now()
		D1, D2, err := DecryptParallel(pp, sk, ciphertexts[i])
		totalDecryptTime += time.Since(dStart)
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}

		recoveryStart := time.Now()
		_, found := RecoverInnerProductWithTable(D1, D2, table)
		totalRecoveryTime += time.Since(recoveryStart)

		if found {
			successful++
		}
	}
	totalTime := time.Since(decryptStart)

	fmt.Printf("Total time: %v, %v per op\n", totalTime, totalTime/time.Duration(numVectors))
	fmt.Printf("Decryption only: %v total, %v per op\n", totalDecryptTime, totalDecryptTime/time.Duration(numVectors))
	fmt.Printf("Recovery only: %v total, %v per op\n", totalRecoveryTime, totalRecoveryTime/time.Duration(numVectors))
	fmt.Printf("Successful recoveries: %d/%d\n\n", successful, numVectors)

	// Throughput calculation
	throughput := float64(numVectors) / totalTime.Seconds()
	decryptThroughput := float64(numVectors) / totalDecryptTime.Seconds()
	recoveryThroughput := float64(numVectors) / totalRecoveryTime.Seconds()

	fmt.Println("=== THROUGHPUT RESULTS ===")
	fmt.Printf("Full operation (decrypt + recover): %.2f ops/sec\n", throughput)
	fmt.Printf("Decryption only: %.2f ops/sec\n", decryptThroughput)
	fmt.Printf("Recovery only: %.2f ops/sec\n", recoveryThroughput)
}
