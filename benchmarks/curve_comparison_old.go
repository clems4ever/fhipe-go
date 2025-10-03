package main

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Benchmark single pairing operation on BLS12-381
func BenchmarkBLS12381SinglePairing(b *testing.B) {
	_, _, g1, g2 := bls12381.Generators()
	
	var scalar fr.Element
	scalar.SetRandom()
	var scalarBig big.Int
	scalar.BigInt(&scalarBig)
	
	var g1Scaled bls12381.G1Affine
	g1Scaled.ScalarMultiplication(&g1, &scalarBig)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bls12381.Pair([]bls12381.G1Affine{g1Scaled}, []bls12381.G2Affine{g2})
	}
}

// Benchmark single pairing operation on BN254
func BenchmarkBN254SinglePairing(b *testing.B) {
	_, _, g1, g2 := bn254.Generators()
	
	var scalar bn254fr.Element
	scalar.SetRandom()
	var scalarBig big.Int
	scalar.BigInt(&scalarBig)
	
	var g1Scaled bn254.G1Affine
	g1Scaled.ScalarMultiplication(&g1, &scalarBig)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bn254.Pair([]bn254.G1Affine{g1Scaled}, []bn254.G2Affine{g2})
	}
}

// Benchmark multi-pairing on BLS12-381 (simulating D2 computation with n=384)
func BenchmarkBLS12381MultiPairing384(b *testing.B) {
	_, _, g1, g2 := bls12381.Generators()
	n := 384
	
	g1Points := make([]bls12381.G1Affine, n)
	g2Points := make([]bls12381.G2Affine, n)
	
	for i := 0; i < n; i++ {
		var scalar fr.Element
		scalar.SetRandom()
		var scalarBig big.Int
		scalar.BigInt(&scalarBig)
		g1Points[i].ScalarMultiplication(&g1, &scalarBig)
		g2Points[i].ScalarMultiplication(&g2, &scalarBig)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bls12381.Pair(g1Points, g2Points)
	}
}

// Benchmark multi-pairing on BN254 (simulating D2 computation with n=384)
func BenchmarkBN254MultiPairing384(b *testing.B) {
	_, _, g1, g2 := bn254.Generators()
	n := 384
	
	g1Points := make([]bn254.G1Affine, n)
	g2Points := make([]bn254.G2Affine, n)
	
	for i := 0; i < n; i++ {
		var scalar bn254fr.Element
		scalar.SetRandom()
		var scalarBig big.Int
		scalar.BigInt(&scalarBig)
		g1Points[i].ScalarMultiplication(&g1, &scalarBig)
		g2Points[i].ScalarMultiplication(&g2, &scalarBig)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bn254.Pair(g1Points, g2Points)
	}
}

// Benchmark GT exponentiation on BLS12-381 (for BSGS recovery)
func BenchmarkBLS12381GTExp(b *testing.B) {
	_, _, g1, g2 := bls12381.Generators()
	gt, _ := bls12381.Pair([]bls12381.G1Affine{g1}, []bls12381.G2Affine{g2})
	
	var exp big.Int
	exp.SetInt64(12345)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result bls12381.GT
		result.Exp(gt, &exp)
	}
}

// Benchmark GT exponentiation on BN254
func BenchmarkBN254GTExp(b *testing.B) {
	_, _, g1, g2 := bn254.Generators()
	gt, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	
	var exp big.Int
	exp.SetInt64(12345)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var result bn254.GT
		result.Exp(gt, &exp)
	}
}

// Manual benchmark runner with clear output
func main() {
	fmt.Println("=== Elliptic Curve Performance Comparison ===")
	fmt.Println()
	
	// Single pairing benchmarks
	fmt.Println("--- Single Pairing Operation ---")
	
	bls12381Time := benchmarkFunc(func() {
		_, _, g1, g2 := bls12381.Generators()
		var scalar fr.Element
		scalar.SetRandom()
		var scalarBig big.Int
		scalar.BigInt(&scalarBig)
		var g1Scaled bls12381.G1Affine
		g1Scaled.ScalarMultiplication(&g1, &scalarBig)
		_, _ = bls12381.Pair([]bls12381.G1Affine{g1Scaled}, []bls12381.G2Affine{g2})
	}, 100)
	fmt.Printf("BLS12-381: %.3f ms/op\n", bls12381Time)
	
	bn254Time := benchmarkFunc(func() {
		_, _, g1, g2 := bn254.Generators()
		var scalar bn254fr.Element
		scalar.SetRandom()
		var scalarBig big.Int
		scalar.BigInt(&scalarBig)
		var g1Scaled bn254.G1Affine
		g1Scaled.ScalarMultiplication(&g1, &scalarBig)
		_, _ = bn254.Pair([]bn254.G1Affine{g1Scaled}, []bn254.G2Affine{g2})
	}, 100)
	fmt.Printf("BN254:     %.3f ms/op\n", bn254Time)
	fmt.Printf("Speedup:   %.2fx\n", bls12381Time/bn254Time)
	fmt.Println()
	
	// Multi-pairing benchmarks (n=384)
	fmt.Println("--- Multi-Pairing (n=384, simulating D2 computation) ---")
	
	bls12381MultiTime := benchmarkFunc(func() {
		_, _, g1, g2 := bls12381.Generators()
		n := 384
		g1Points := make([]bls12381.G1Affine, n)
		g2Points := make([]bls12381.G2Affine, n)
		for i := 0; i < n; i++ {
			var scalar fr.Element
			scalar.SetRandom()
			var scalarBig big.Int
			scalar.BigInt(&scalarBig)
			g1Points[i].ScalarMultiplication(&g1, &scalarBig)
			g2Points[i].ScalarMultiplication(&g2, &scalarBig)
		}
		_, _ = bls12381.Pair(g1Points, g2Points)
	}, 20)
	fmt.Printf("BLS12-381: %.3f ms/op\n", bls12381MultiTime)
	
	bn254MultiTime := benchmarkFunc(func() {
		_, _, g1, g2 := bn254.Generators()
		n := 384
		g1Points := make([]bn254.G1Affine, n)
		g2Points := make([]bn254.G2Affine, n)
		for i := 0; i < n; i++ {
			var scalar bn254fr.Element
			scalar.SetRandom()
			var scalarBig big.Int
			scalar.BigInt(&scalarBig)
			g1Points[i].ScalarMultiplication(&g1, &scalarBig)
			g2Points[i].ScalarMultiplication(&g2, &scalarBig)
		}
		_, _ = bn254.Pair(g1Points, g2Points)
	}, 20)
	fmt.Printf("BN254:     %.3f ms/op\n", bn254MultiTime)
	fmt.Printf("Speedup:   %.2fx\n", bls12381MultiTime/bn254MultiTime)
	fmt.Println()
	
	// GT exponentiation benchmarks
	fmt.Println("--- GT Exponentiation (for BSGS recovery) ---")
	
	bls12381ExpTime := benchmarkFunc(func() {
		_, _, g1, g2 := bls12381.Generators()
		gt, _ := bls12381.Pair([]bls12381.G1Affine{g1}, []bls12381.G2Affine{g2})
		var exp big.Int
		exp.SetInt64(12345)
		var result bls12381.GT
		result.Exp(gt, &exp)
	}, 1000)
	fmt.Printf("BLS12-381: %.3f μs/op\n", bls12381ExpTime*1000)
	
	bn254ExpTime := benchmarkFunc(func() {
		_, _, g1, g2 := bn254.Generators()
		gt, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
		var exp big.Int
		exp.SetInt64(12345)
		var result bn254.GT
		result.Exp(gt, &exp)
	}, 1000)
	fmt.Printf("BN254:     %.3f μs/op\n", bn254ExpTime*1000)
	fmt.Printf("Speedup:   %.2fx\n", bls12381ExpTime/bn254ExpTime)
	fmt.Println()
	
	// Summary
	fmt.Println("=== Summary ===")
	fmt.Printf("BN254 is %.2fx faster for single pairings\n", bls12381Time/bn254Time)
	fmt.Printf("BN254 is %.2fx faster for multi-pairings (n=384)\n", bls12381MultiTime/bn254MultiTime)
	fmt.Printf("BN254 is %.2fx faster for GT exponentiations\n", bls12381ExpTime/bn254ExpTime)
	fmt.Println()
	fmt.Println("Estimated FHIPE performance improvement with BN254:")
	fmt.Printf("  Current BLS12-381 throughput: ~200 ops/sec\n")
	avgSpeedup := (bls12381Time/bn254Time + bls12381MultiTime/bn254MultiTime) / 2
	fmt.Printf("  Estimated BN254 throughput: ~%.0f ops/sec (%.2fx speedup)\n", 200*avgSpeedup, avgSpeedup)
	fmt.Printf("  Gap to 2500 ops/sec target: %.1fx additional improvement needed\n", 2500/(200*avgSpeedup))
	fmt.Println()
	fmt.Println("Note: BN254 provides ~110-bit security vs BLS12-381's ~128-bit security")
}

func benchmarkFunc(f func(), iterations int) float64 {
	// Warmup
	for i := 0; i < 3; i++ {
		f()
	}
	
	start := time.Now()
	for i := 0; i < iterations; i++ {
		f()
	}
	elapsed := time.Since(start)
	return elapsed.Seconds() * 1000 / float64(iterations) // ms per op
}
