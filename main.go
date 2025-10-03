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

func main() {
	n := 384
	target := 1e-6
	baselineScaleSafety := 1.05
	baselineScale := ChooseScaleForCosine(target, baselineScaleSafety)
	baselineS := int(baselineScale * baselineScale)
	fmt.Printf("Baseline scale=%d S=%d (not exceeded)\n", baselineScale, baselineS)

	// Define scales to test (must satisfy scale^2 <= baselineS)
	candidateScales := []int64{300, 500, 700, 900, baselineScale}
	filtered := make([]int64, 0, len(candidateScales))
	for _, sc := range candidateScales {
		if int(sc*sc) <= baselineS {
			filtered = append(filtered, sc)
		}
	}

	trials := 150
	seedBase := time.Now().UnixNano()
	results := make([]*recoveryBenchmarkResult, 0, len(filtered))
	for i, sc := range filtered {
		res, err := runRecoveryBenchmarkCosineForScale(n, sc, trials, seedBase+int64(i)*1337)
		if err != nil {
			log.Fatal(err)
		}
		results = append(results, res)
	}
	printMultiScale(results)
}

// runRecoveryBenchmarkCosineForScale runs recovery benchmark for a fixed scale (S = scale^2).
func runRecoveryBenchmarkCosineForScale(n int, scale int64, trials int, seed int64) (*recoveryBenchmarkResult, error) {
	manualS := int(scale * scale)
	// Build params
	_, msk, err := Setup(n, manualS)
	if err != nil {
		return nil, err
	}
	pp := msk.PP
	rng := rand.New(rand.NewSource(seed))

	d1s := make([]bls12381.GT, trials)
	d2s := make([]bls12381.GT, trials)
	expCos := make([]float64, trials)

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
	avgErr := 0.0
	if successes > 0 {
		avgErr = sumErr / float64(successes)
	}
	return &recoveryBenchmarkResult{
		N: n, Trials: trials, Scale: scale, S: pp.S,
		Successes: successes, Failures: failures,
		AvgRecoverMs: avg(recoverDur), P50RecoverMs: percentile(recoverDur, 50), P90RecoverMs: percentile(recoverDur, 90), P99RecoverMs: percentile(recoverDur, 99), MaxRecoverMs: maxRec,
		ThroughputPerSec: float64(trials) / total.Seconds(),
		AvgAbsError:      avgErr, MaxAbsError: maxErr,
		P50AbsError: percentile(absErrors, 50), P90AbsError: percentile(absErrors, 90), P99AbsError: percentile(absErrors, 99),
	}, nil
}

func printMultiScale(results []*recoveryBenchmarkResult) {
	fmt.Println("\n=== Multi-Scale Recovery Comparison (S <= baseline) ===")
	fmt.Printf("%-6s %-10s %-8s %-9s %-10s %-10s %-10s %-10s %-10s\n", "Scale", "S", "Succ%", "Thr(rec/s)", "Avg(ms)", "P90(ms)", "AvgErr", "P90Err", "MaxErr")
	for _, r := range results {
		succPct := 100 * float64(r.Successes) / float64(r.Trials)
		fmt.Printf("%-6d %-10d %-8.2f %-9.2f %-10.3f %-10.3f %-10.3g %-10.3g %-10.3g\n",
			r.Scale, r.S, succPct, r.ThroughputPerSec, r.AvgRecoverMs, r.P90RecoverMs, r.AvgAbsError, r.P90AbsError, r.MaxAbsError)
	}
}
