package main

import (
	"fmt"
	"log"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func BenchmarkDimensions() {
	fmt.Println("=== Dimension Scaling Benchmark ===")
	fmt.Println()

	dimensions := []int{32, 64, 96, 128, 192, 256, 384}
	numTests := 100
	S := 5000

	for _, n := range dimensions {
		fmt.Printf("Testing dimension %d...\n", n)

		// Setup
		pp, msk, err := Setup(n, S)
		if err != nil {
			log.Fatalf("Setup failed: %v", err)
		}

		// Generate vectors
		vectors := make([][]int, numTests)
		for i := 0; i < numTests; i++ {
			vectors[i] = make([]int, n)
			for j := 0; j < n; j++ {
				vectors[i][j] = (i*j+j)%10 - 5
			}
		}

		// KeyGen
		x := IntsToFrElements(vectors[0])
		sk, err := KeyGen(msk, x)
		if err != nil {
			log.Fatalf("KeyGen failed: %v", err)
		}

		// Compute gt_base and table
		gt_base, _ := bls12381.Pair([]bls12381.G1Affine{sk.K1}, []bls12381.G2Affine{pp.G2Gen})
		table := PrecomputeTable(gt_base, S)

		// Pre-encrypt
		ciphertexts := make([]Ciphertext, numTests)
		for i := 0; i < numTests; i++ {
			y := IntsToFrElements(vectors[i])
			ct, _ := Encrypt(msk, y)
			ciphertexts[i] = ct
		}

		// Benchmark
		start := time.Now()
		D1s, D2s, _ := BatchDecryptParallel(pp, sk, ciphertexts)
		decryptTime := time.Since(start)

		recoveryStart := time.Now()
		successful := 0
		for i := 0; i < numTests; i++ {
			_, found := RecoverInnerProductWithTable(D1s[i], D2s[i], table)
			if found {
				successful++
			}
		}
		recoveryTime := time.Since(recoveryStart)

		totalTime := decryptTime + recoveryTime
		throughput := float64(numTests) / totalTime.Seconds()

		fmt.Printf("  Dimension: %3d | Decrypt: %6.2fms | Recovery: %6.2fms | Total: %6.2fms | Throughput: %7.2f ops/sec\n",
			n,
			decryptTime.Seconds()*1000/float64(numTests),
			recoveryTime.Seconds()*1000/float64(numTests),
			totalTime.Seconds()*1000/float64(numTests),
			throughput)
	}

	fmt.Println()
	fmt.Println("Target: 2500 ops/sec = 0.4ms per operation")
}
