package main

import (
	"fmt"
	"time"

	bls12381gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blst "github.com/supranational/blst/bindings/go"
)

// Benchmark just the pairing operations (the actual bottleneck)
func main() {
	fmt.Println("=== Pairing Performance: blst vs gnark-crypto ===\n")

	iterations := 1000

	// Test 1: Single pairing
	fmt.Println("Single Pairing (e(g1, g2)):")
	
	// gnark-crypto
	_, _, g1gnark, g2gnark := bls12381gnark.Generators()
	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, _ = bls12381gnark.Pair([]bls12381gnark.G1Affine{g1gnark}, []bls12381gnark.G2Affine{g2gnark})
	}
	gnarkTime := time.Since(start)
	fmt.Printf("  gnark-crypto: %v total, %.3f ms/op\n", gnarkTime, float64(gnarkTime.Microseconds())/float64(iterations)/1000)

	// blst
	g1blst := blst.P1Generator().ToAffine()
	g2blst := blst.P2Generator().ToAffine()
	start = time.Now()
	for i := 0; i < iterations; i++ {
		result := blst.Fp12MillerLoop(g2blst, g1blst)
		result.FinalExp()
	}
	blstTime := time.Since(start)
	fmt.Printf("  blst:         %v total, %.3f ms/op\n", blstTime, float64(blstTime.Microseconds())/float64(iterations)/1000)
	fmt.Printf("  Speedup:      %.2fx\n\n", float64(gnarkTime)/float64(blstTime))

	// Test 2: Multi-pairing (n=384)
	n := 384
	fmt.Printf("Multi-Pairing (n=%d, simulating D2 computation):\n", n)

	// gnark-crypto
	g1sGnark := make([]bls12381gnark.G1Affine, n)
	g2sGnark := make([]bls12381gnark.G2Affine, n)
	for i := 0; i < n; i++ {
		g1sGnark[i] = g1gnark
		g2sGnark[i] = g2gnark
	}

	start = time.Now()
	for i := 0; i < 100; i++ {
		_, _ = bls12381gnark.Pair(g1sGnark, g2sGnark)
	}
	gnarkMultiTime := time.Since(start)
	fmt.Printf("  gnark-crypto: %v total, %.3f ms/op\n", gnarkMultiTime, float64(gnarkMultiTime.Microseconds())/100/1000)

	// blst
	g1sBlst := make([]blst.P1Affine, n)
	g2sBlst := make([]blst.P2Affine, n)
	for i := 0; i < n; i++ {
		g1sBlst[i] = *g1blst
		g2sBlst[i] = *g2blst
	}

	start = time.Now()
	for i := 0; i < 100; i++ {
		result := blst.Fp12MillerLoopN(g2sBlst, g1sBlst)
		result.FinalExp()
	}
	blstMultiTime := time.Since(start)
	fmt.Printf("  blst:         %v total, %.3f ms/op\n", blstMultiTime, float64(blstMultiTime.Microseconds())/100/1000)
	fmt.Printf("  Speedup:      %.2fx\n\n", float64(gnarkMultiTime)/float64(blstMultiTime))

	fmt.Println("=== Summary ===")
	fmt.Printf("blst is %.2fx faster for single pairings\n", float64(gnarkTime)/float64(blstTime))
	fmt.Printf("blst is %.2fx faster for multi-pairings (n=384)\n", float64(gnarkMultiTime)/float64(blstMultiTime))
	
	avgSpeedup := (float64(gnarkTime)/float64(blstTime) + float64(gnarkMultiTime)/float64(blstMultiTime)) / 2
	fmt.Printf("\nEstimated FHIPE throughput improvement: %.2fx\n", avgSpeedup)
	fmt.Printf("  Current: ~200 ops/sec → Estimated with blst: ~%.0f ops/sec\n", 200*avgSpeedup)
}
