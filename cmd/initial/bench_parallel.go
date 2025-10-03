package main

import (
	"fmt"
	"log"
	"runtime"
	"time"
)

func BenchmarkParallelScaling() {
	n := 384
	S := 10000
	numTests := 100

	fmt.Println("=== Parallel Scaling Benchmark ===")
	fmt.Printf("Vector dimension: %d\n", n)
	fmt.Printf("Number of decrypt operations: %d\n\n", numTests)

	// Setup
	pp, msk, err := Setup(n, S)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}

	// Generate test data
	vectors := make([][]int, numTests)
	for i := 0; i < numTests; i++ {
		vectors[i] = make([]int, n)
		for j := 0; j < n; j++ {
			vectors[i][j] = (i*j+j)%20 - 10
		}
	}

	x := IntsToFrElements(vectors[0])
	sk, err := KeyGen(msk, x)
	if err != nil {
		log.Fatalf("KeyGen failed: %v", err)
	}

	// Pre-encrypt
	ciphertexts := make([]Ciphertext, numTests)
	for i := 0; i < numTests; i++ {
		y := IntsToFrElements(vectors[i])
		ct, err := Encrypt(msk, y)
		if err != nil {
			log.Fatalf("Encrypt failed: %v", err)
		}
		ciphertexts[i] = ct
	}

	maxProcs := runtime.GOMAXPROCS(0)
	fmt.Printf("Max available CPUs: %d\n\n", maxProcs)

	// Test with different CPU counts
	cpuCounts := []int{1, 2, 4, 8, 16, 32}
	results := make(map[int]time.Duration)

	for _, cpus := range cpuCounts {
		if cpus > maxProcs {
			break
		}

		runtime.GOMAXPROCS(cpus)

		// Warmup
		for i := 0; i < 5; i++ {
			DecryptParallel(pp, sk, ciphertexts[i%numTests])
		}

		// Benchmark
		start := time.Now()
		for i := 0; i < numTests; i++ {
			_, _, err := DecryptParallel(pp, sk, ciphertexts[i])
			if err != nil {
				log.Fatalf("Decrypt failed: %v", err)
			}
		}
		elapsed := time.Since(start)
		results[cpus] = elapsed

		avgTime := elapsed / time.Duration(numTests)
		throughput := float64(numTests) / elapsed.Seconds()

		fmt.Printf("CPUs: %2d | Total: %8v | Avg: %8v | Throughput: %7.2f ops/sec\n",
			cpus, elapsed, avgTime, throughput)
	}

	// Reset to max
	runtime.GOMAXPROCS(maxProcs)

	// Calculate speedup
	fmt.Println("\nSpeedup Analysis:")
	baseline := results[1]
	for _, cpus := range cpuCounts {
		if cpus > maxProcs {
			break
		}
		speedup := float64(baseline) / float64(results[cpus])
		efficiency := speedup / float64(cpus) * 100
		fmt.Printf("CPUs: %2d | Speedup: %.2fx | Efficiency: %.1f%%\n",
			cpus, speedup, efficiency)
	}
}
