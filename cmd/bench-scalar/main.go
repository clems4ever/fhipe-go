package main

import (
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	blst "github.com/supranational/blst/bindings/go"
)

func main() {
	iterations := 1000

	// BN254 with gnark
	_, _, g1bn, _ := bn254.Generators()
	scalar, _ := new(big.Int).SetString("12345678901234567890123456789", 10)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		var result bn254.G1Affine
		result.ScalarMultiplication(&g1bn, scalar)
	}
	bn254Time := time.Since(start)

	// BLS12-381 with blst - Method 1: FromAffine + Mult pattern
	g1blst := blst.P1Generator().ToAffine()
	scalarBytes := make([]byte, 32)
	scalar.FillBytes(scalarBytes)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		var p1 blst.P1
		p1.FromAffine(g1blst)
		p1.Mult(scalarBytes, 256)
		_ = p1.ToAffine()
	}
	blstTime1 := time.Since(start)

	// BLS12-381 with blst - Method 2: Direct Mult on generator
	g1blstProj := blst.P1Generator()
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = g1blstProj.Mult(scalarBytes, 256).ToAffine()
	}
	blstTime2 := time.Since(start)

	fmt.Printf("Scalar Multiplication Benchmark (%d iterations):\n", iterations)
	fmt.Printf("BN254 (gnark):            %v (%.3f ms/op)\n", bn254Time, float64(bn254Time.Microseconds())/float64(iterations)/1000)
	fmt.Printf("BLS12-381 (blst method1): %v (%.3f ms/op)\n", blstTime1, float64(blstTime1.Microseconds())/float64(iterations)/1000)
	fmt.Printf("BLS12-381 (blst method2): %v (%.3f ms/op)\n", blstTime2, float64(blstTime2.Microseconds())/float64(iterations)/1000)
	fmt.Printf("Ratio (blst1/gnark): %.2fx\n", float64(blstTime1)/float64(bn254Time))
	fmt.Printf("Ratio (blst2/gnark): %.2fx\n", float64(blstTime2)/float64(bn254Time))
}
