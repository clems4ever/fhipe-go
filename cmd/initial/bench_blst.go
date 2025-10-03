package main

import (
	"fmt"
	"log"
	"time"
)

func BenchmarkBlst() {
	fmt.Println("=== BLST Performance Benchmark ===")
	n := 384
	S := 80000
	numTests := 100

	fmt.Printf("Dimension: %d, Bound: %d, Tests: %d\n\n", n, S, numTests)

	// Setup
	start := time.Now()
	_, msk, err := BlstSetup(n, S)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}
	fmt.Printf("Setup: %v\n", time.Since(start))

	// Generate vectors
	vectors := make([][]int, numTests)
	for i := 0; i < numTests; i++ {
		vectors[i] = make([]int, n)
		for j := 0; j < n; j++ {
			vectors[i][j] = (i*j + j) % 20 - 10
		}
	}

	// KeyGen
	start = time.Now()
	x := IntsToBlstScalars(vectors[0])
	sk, err := BlstKeyGen(msk, x)
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}
	fmt.Printf("KeyGen: %v\n", time.Since(start))

	// Encrypt
	start = time.Now()
	ciphertexts := make([]BlstCiphertext, numTests)
	for i := 0; i < numTests; i++ {
		y := IntsToBlstScalars(vectors[i])
		ct, err := BlstEncrypt(msk, y)
		if err != nil {
			log.Fatalf("Encrypt failed: %v", err)
		}
		ciphertexts[i] = ct
	}
	encryptTime := time.Since(start)
	fmt.Printf("Encryption: %v total, %v per op\n", encryptTime, encryptTime/time.Duration(numTests))

	// Decrypt (single-threaded for now)
	start = time.Now()
	for i := 0; i < numTests; i++ {
		_, _, err := BlstDecrypt(sk, ciphertexts[i])
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}
	}
	decryptTime := time.Since(start)
	
	fmt.Printf("\nDecryption: %v total, %v per op\n", decryptTime, decryptTime/time.Duration(numTests))
	throughput := float64(numTests) / decryptTime.Seconds()
	fmt.Printf("Throughput: %.2f ops/sec\n\n", throughput)

	fmt.Println("Comparison with gnark-crypto BLS12-381:")
	fmt.Println("  gnark-crypto: ~200 ops/sec")
	fmt.Printf("  blst:         ~%.0f ops/sec\n", throughput)
	fmt.Printf("  Speedup:      %.2fx\n", throughput/200.0)
}
