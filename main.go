package main

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"sort"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// recoveryBenchmarkResult stores timing and error statistics for cosine recovery only.
type recoveryBenchmarkResult struct {
	N                int
	Trials           int
	Scale            int64
	S                int
	Successes        int
	Failures         int
	AvgRecoverMs     float64
	P50RecoverMs     float64
	P90RecoverMs     float64
	P99RecoverMs     float64
	MaxRecoverMs     float64
	ThroughputPerSec float64
	AvgAbsError      float64
	MaxAbsError      float64
	P50AbsError      float64
	P90AbsError      float64
	P99AbsError      float64
}

// runRecoveryBenchmarkCosine pre-computes ciphertext pairs (not timed) and measures only RecoverInnerProduct
// with a reduced S (manual) for cosine similarities. It also collects absolute error statistics.
func runRecoveryBenchmarkCosine(n int, trials int, targetPrecision float64, scaleSafety float64, manualS int, seed int64) (*recoveryBenchmarkResult, error) {
	rng := rand.New(rand.NewSource(seed))
	scale := ChooseScaleForCosine(targetPrecision, scaleSafety)

	// If manualS < scale^2 we risk systematic failures; enforce lower bound.
	minS := int(scale * scale)
	if manualS < minS {
		manualS = minS
	}
	// Build parameters with reduced S directly.
	_, msk, err := Setup(n, manualS)
	if err != nil {
		return nil, err
	}
	pp := msk.PP

	d1s := make([]bls12381.GT, trials)
	d2s := make([]bls12381.GT, trials)
	expCos := make([]float64, trials)

	// Precompute pairs.
	for t := 0; t < trials; t++ {
		a := make([]float64, n)
		b := make([]float64, n)
		for i := 0; i < n; i++ {
			a[i] = 2*rng.Float64() - 1
			b[i] = 2*rng.Float64() - 1
		}
		na, err := NormalizeL2(a)
		if err != nil {
			return nil, err
		}
		nb, err := NormalizeL2(b)
		if err != nil {
			return nil, err
		}
		var trueCos float64
		for i := 0; i < n; i++ {
			trueCos += na[i] * nb[i]
		}
		expCos[t] = trueCos
		aElems, _, err := EncodeNormalizedVector(na, scale)
		if err != nil {
			return nil, err
		}
		bElems, _, err := EncodeNormalizedVector(nb, scale)
		if err != nil {
			return nil, err
		}
		sk, err := KeyGen(msk, aElems)
		if err != nil {
			return nil, err
		}
		ct, err := Encrypt(msk, bElems)
		if err != nil {
			return nil, err
		}
		D1, D2, err := Decrypt(pp, sk, ct)
		if err != nil {
			return nil, err
		}
		d1s[t] = D1
		d2s[t] = D2
	}

	recoverDur := make([]float64, 0, trials)
	absErrors := make([]float64, 0, trials)
	successes := 0
	failures := 0
	var maxRec float64
	var sumErr, maxErr float64

	startAll := time.Now()
	for t := 0; t < trials; t++ {
		start := time.Now()
		z, ok := RecoverInnerProduct(d1s[t], d2s[t], pp.S)
		durMs := float64(time.Since(start).Microseconds()) / 1000.0
		recoverDur = append(recoverDur, durMs)
		if durMs > maxRec {
			maxRec = durMs
		}
		if ok {
			decoded := DecodeCosine(z, scale)
			errAbs := math.Abs(decoded - expCos[t])
			absErrors = append(absErrors, errAbs)
			sumErr += errAbs
			if errAbs > maxErr {
				maxErr = errAbs
			}
			successes++
		} else {
			failures++
		}
	}
	total := time.Since(startAll)

	sort.Float64s(recoverDur)
	sort.Float64s(absErrors)
	p50t := percentile(recoverDur, 50)
	p90t := percentile(recoverDur, 90)
	p99t := percentile(recoverDur, 99)
	avgT := avg(recoverDur)

	p50e := percentile(absErrors, 50)
	p90e := percentile(absErrors, 90)
	p99e := percentile(absErrors, 99)
	avgErr := 0.0
	if successes > 0 {
		avgErr = sumErr / float64(successes)
	}

	throughput := float64(trials) / total.Seconds()

	return &recoveryBenchmarkResult{
		N: n, Trials: trials, Scale: scale, S: pp.S,
		Successes: successes, Failures: failures,
		AvgRecoverMs: avgT, P50RecoverMs: p50t, P90RecoverMs: p90t, P99RecoverMs: p99t, MaxRecoverMs: maxRec,
		ThroughputPerSec: throughput,
		AvgAbsError:      avgErr, MaxAbsError: maxErr, P50AbsError: p50e, P90AbsError: p90e, P99AbsError: p99e,
	}, nil
}

func avg(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := (p / 100.0) * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper {
		return sorted[lower]
	}
	frac := idx - float64(lower)
	return sorted[lower] + (sorted[upper]-sorted[lower])*frac
}

func printRecoveryBenchmark(res *recoveryBenchmarkResult, targetPrecision float64) {
	fmt.Println("=== Cosine Recovery Benchmark (Reduced S) ===")
	fmt.Printf("Dimension (n)          : %d\n", res.N)
	fmt.Printf("Trials                : %d\n", res.Trials)
	fmt.Printf("Target precision (abs): %.2e\n", targetPrecision)
	fmt.Printf("Scale                 : %d (resolution ≈ %.2e)\n", res.Scale, 1/float64(res.Scale*res.Scale))
	fmt.Printf("S (bound)             : %d (range [-%d,%d])\n", res.S, res.S, res.S)
	fmt.Printf("Successes / Failures  : %d / %d\n", res.Successes, res.Failures)
	fmt.Printf("Throughput (rec/s)    : %.2f\n", res.ThroughputPerSec)
	fmt.Printf("Recover avg ms        : %.3f (P50 %.3f / P90 %.3f / P99 %.3f / max %.3f)\n", res.AvgRecoverMs, res.P50RecoverMs, res.P90RecoverMs, res.P99RecoverMs, res.MaxRecoverMs)
	fmt.Printf("Abs error avg         : %.3g (max %.3g)\n", res.AvgAbsError, res.MaxAbsError)
	fmt.Printf("Abs error P50/P90/P99 : %.3g / %.3g / %.3g\n", res.P50AbsError, res.P90AbsError, res.P99AbsError)
	if res.Failures > 0 {
		fmt.Println("WARNING: Some recoveries failed; consider increasing S.")
	}
}

func main() {
	n := 384
	target := 1e-6
	scaleSafety := 1.05 // slightly reduced safety to shrink scale

	// Reduced S: use exactly scale^2 (minimum safe) rather than (1+margin)*scale^2
	// We'll compute scale first to derive manualS.
	tmpScale := ChooseScaleForCosine(target, scaleSafety)
	manualS := int(tmpScale * tmpScale) // minimal bound; may cause failure only if rounding overshoots

	trials := 200
	seed := time.Now().UnixNano()
	res, err := runRecoveryBenchmarkCosine(n, trials, target, scaleSafety, manualS, seed)
	if err != nil {
		log.Fatal(err)
	}
	printRecoveryBenchmark(res, target)
}
