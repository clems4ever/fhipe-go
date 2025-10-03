package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// floatPrecisionResult holds metrics for one scale.
type floatPrecisionResult struct {
	Scale          int64
	Trials         int
	S              int
	TotalDuration  time.Duration
	AvgPerOp       time.Duration
	ThroughputOpsS float64
	AvgRecovery    time.Duration
	MaxAbsError    float64
	MeanAbsError   float64
}

// runFloatPrecisionBenchmark benchmarks end-to-end FH-IPE (Encrypt+Decrypt+Recover)
// for random float vectors under different fixed-point scales. It chooses the
// minimal S sufficient for the sampled trials (rather than worst-case) to give
// realistic performance. x is fixed across trials; y varies.
func runFloatPrecisionBenchmark(n int, scales []int64, trials int, valueRange float64, seed int64) ([]floatPrecisionResult, error) {
	if trials <= 0 {
		return nil, fmt.Errorf("trials must be > 0")
	}
	rand.Seed(seed)

	// Sample base vector x
	xFloat := make([]float64, n)
	for i := 0; i < n; i++ {
		xFloat[i] = (rand.Float64()*2 - 1) * valueRange
	}

	// Pre-sample y vectors
	yFloats := make([][]float64, trials)
	for t := 0; t < trials; t++ {
		vf := make([]float64, n)
		for i := 0; i < n; i++ {
			vf[i] = (rand.Float64()*2 - 1) * valueRange
		}
		yFloats[t] = vf
	}

	results := make([]floatPrecisionResult, 0, len(scales))

	for _, scale := range scales {
		enc, err := NewFixedPointEncoder(scale)
		if err != nil {
			return nil, err
		}

		// Encode x once to integer domain to compute exact scaled IP bounds.
		xElems, xInts, err := enc.EncodeFloatVector(xFloat)
		if err != nil {
			return nil, err
		}

		rawIPs := make([]float64, trials)
		maxScaledAbs := int64(0)
		// Pre-encode y vectors and compute scaled integer IP exactly.
		yElemsList := make([][]fr.Element, trials)
		yIntsList := make([][]int64, trials)
		for t := 0; t < trials; t++ {
			yElems, yInts, err := enc.EncodeFloatVector(yFloats[t])
			if err != nil {
				return nil, err
			}
			yElemsList[t] = yElems
			yIntsList[t] = yInts
			// Compute scaled integer IP over n components directly.
			var scaledIP int64
			for i := 0; i < n; i++ {
				scaledIP += xInts[i] * yInts[i]
			}
			if abs64(scaledIP) > maxScaledAbs {
				maxScaledAbs = abs64(scaledIP)
			}
			// Also store true float IP for error measurement.
			var ipFloat float64
			for i := 0; i < n; i++ {
				ipFloat += xFloat[i] * yFloats[t][i]
			}
			rawIPs[t] = ipFloat
		}
		// Add headroom (20%) + small constant
		scaledBound := int(float64(maxScaledAbs)*1.2) + 8
		if scaledBound < 10 {
			scaledBound = 10
		}

		// Setup scheme for this scale with enlarged S.
		_, msk, err := Setup(n, scaledBound)
		if err != nil {
			return nil, fmt.Errorf("setup(scale=%d): %w", scale, err)
		}
		skX, err := KeyGen(msk, xElems)
		if err != nil {
			return nil, err
		}

		var total, totalRecovery time.Duration
		var maxAbsErr, sumAbsErr float64

		for t := 0; t < trials; t++ {
			start := time.Now()
			ct, err := Encrypt(msk, yElemsList[t])
			if err != nil {
				return nil, err
			}
			D1, D2, err := Decrypt(msk.PP, skX, ct)
			if err != nil {
				return nil, err
			}
			recStart := time.Now()
			zScaled, ok := RecoverInnerProduct(D1, D2, msk.PP.S)
			recDur := time.Since(recStart)
			if !ok {
				// Auto-expand S by factor 2 and retry once.
				newS := msk.PP.S * 2
				_, msk2, e2 := Setup(n, newS)
				if e2 != nil {
					return nil, fmt.Errorf("expand setup scale=%d: %w", scale, e2)
				}
				skX2, e2 := KeyGen(msk2, xElems)
				if e2 != nil {
					return nil, e2
				}
				ct2, e2 := Encrypt(msk2, yElemsList[t])
				if e2 != nil {
					return nil, e2
				}
				D1, D2, e2 = Decrypt(msk2.PP, skX2, ct2)
				if e2 != nil {
					return nil, e2
				}
				zScaled, ok = RecoverInnerProduct(D1, D2, msk2.PP.S)
				if !ok {
					return nil, fmt.Errorf("recovery failed even after expanding S (scale=%d)", scale)
				}
				// Replace msk with expanded version for subsequent trials
				msk = msk2
				skX = skX2
			}
			elapsed := time.Since(start)
			total += elapsed
			totalRecovery += recDur
			decoded := DecodeInnerProduct(zScaled, enc, enc)
			errAbs := math.Abs(decoded - rawIPs[t])
			if errAbs > maxAbsErr {
				maxAbsErr = errAbs
			}
			sumAbsErr += errAbs
		}

		avg := total / time.Duration(trials)
		avgRec := totalRecovery / time.Duration(trials)
		thr := float64(trials) / total.Seconds()
		results = append(results, floatPrecisionResult{
			Scale: scale, Trials: trials, S: scaledBound,
			TotalDuration: total, AvgPerOp: avg, ThroughputOpsS: thr,
			AvgRecovery: avgRec, MaxAbsError: maxAbsErr,
			MeanAbsError: sumAbsErr / float64(trials),
		})
	}
	return results, nil
}

// abs64 returns absolute value of int64 without overflow for MinInt64 (not expected here).
func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func printFloatPrecisionResults(res []floatPrecisionResult) {
	fmt.Println("\n=== Float Precision Throughput Benchmark ===")
	fmt.Printf("%-8s %-8s %-12s %-12s %-12s %-12s %-12s %-12s\n",
		"scale", "trials", "S", "ops/s", "avg/op", "avgRec", "maxErr", "meanErr")
	for _, r := range res {
		fmt.Printf("%-8d %-8d %-12d %-12.2f %-12v %-12v %-12.3g %-12.3g\n",
			r.Scale, r.Trials, r.S, r.ThroughputOpsS, r.AvgPerOp, r.AvgRecovery, r.MaxAbsError, r.MeanAbsError)
	}
}
