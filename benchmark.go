package main

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// recoveryBenchmarkConfig holds parameters for the benchmark.
type recoveryBenchmarkConfig struct {
	Trials      int // number of inner products to recover
	EntryRange  int // sample each coordinate uniformly from [-EntryRange, EntryRange]
	MaxResample int // max attempts to sample vectors whose IP is within S
}

// recoveryStats aggregates timing results.
type recoveryStats struct {
	Trials         int
	Durations      []time.Duration
	Min, Max, Mean time.Duration
	Median         time.Duration
	P90, P95, P99  time.Duration
	StdDev         time.Duration
}

// runRecoveryBenchmark performs multiple encrypt/decrypt cycles and measures only the
// time spent in RecoverInnerProduct.
func runRecoveryBenchmark(msk MSK, params Params, sk SecretKey, cfg recoveryBenchmarkConfig) (recoveryStats, error) {
	rand.Seed(time.Now().UnixNano())
	n := len(msk.B)
	stats := recoveryStats{Trials: cfg.Trials, Durations: make([]time.Duration, 0, cfg.Trials)}

	for t := 0; t < cfg.Trials; t++ {
		// Sample a random y whose inner product with the sk's underlying x is within [-S, S].
		var y []int
		var ipOK bool
		for attempt := 0; attempt < cfg.MaxResample && !ipOK; attempt++ {
			y = make([]int, n)
			for i := 0; i < n; i++ {
				y[i] = rand.Intn(2*cfg.EntryRange+1) - cfg.EntryRange
			}
			// We don't know x explicitly (hidden inside sk); so we can't pre-check IP here.
			// Instead, we rely on S being large enough. (Alternative: store x during KeyGen.)
			ipOK = true // accept as-is; if recovery fails due to out-of-range, that's informative.
		}

		yElems := IntsToFrElements(y)
		ct, err := Encrypt(msk, yElems)
		if err != nil {
			return stats, fmt.Errorf("encrypt: %w", err)
		}
		D1, D2, err := Decrypt(params, sk, ct)
		if err != nil {
			return stats, fmt.Errorf("decrypt: %w", err)
		}

		start := time.Now()
		_, _ = RecoverInnerProduct(D1, D2, params.S)
		dur := time.Since(start)
		stats.Durations = append(stats.Durations, dur)
	}

	computeRecoveryStats(&stats)
	return stats, nil
}

func computeRecoveryStats(s *recoveryStats) {
	if len(s.Durations) == 0 {
		return
	}
	d := append([]time.Duration(nil), s.Durations...)
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	s.Min = d[0]
	s.Max = d[len(d)-1]
	var sum time.Duration
	for _, v := range d {
		sum += v
	}
	s.Mean = time.Duration(int64(sum) / int64(len(d)))
	s.Median = percentileDuration(d, 50)
	s.P90 = percentileDuration(d, 90)
	s.P95 = percentileDuration(d, 95)
	s.P99 = percentileDuration(d, 99)
	// Std dev
	var variance float64
	meanFloat := float64(s.Mean)
	for _, v := range d {
		diff := float64(v) - meanFloat
		variance += diff * diff
	}
	variance /= float64(len(d))
	s.StdDev = time.Duration(math.Sqrt(variance))
}

func percentileDuration(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	// Nearest-rank method
	idx := (len(sorted)*p + 99) / 100 // ceiling
	if idx <= 0 {
		idx = 1
	}
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1]
}

// printRecoveryStats pretty prints the benchmark statistics.
func printRecoveryStats(s recoveryStats) {
	fmt.Printf("Trials: %d\n", s.Trials)
	fmt.Printf("Min    : %v\n", s.Min)
	fmt.Printf("Median : %v\n", s.Median)
	fmt.Printf("Mean   : %v\n", s.Mean)
	fmt.Printf("P90    : %v\n", s.P90)
	fmt.Printf("P95    : %v\n", s.P95)
	fmt.Printf("P99    : %v\n", s.P99)
	fmt.Printf("Max    : %v\n", s.Max)
	fmt.Printf("StdDev : %v\n", s.StdDev)
}

// ----------------------------
// Throughput (products/second)
// ----------------------------

// throughputResult aggregates total time and throughput.
type throughputResult struct {
	Trials        int
	Total         time.Duration
	Avg           time.Duration
	OpsPerSecond  float64
	ComponentNote string
}

// runFullPipelineThroughput measures end-to-end (Encrypt + Decrypt + Recover) throughput.
// It assumes vector entries are already chosen so that inner product always lies in [-S, S].
func runFullPipelineThroughput(msk MSK, params Params, sk SecretKey, trials int, entryRange int) (throughputResult, error) {
	n := len(msk.B)
	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	for t := 0; t < trials; t++ {
		yInts := make([]int, n)
		for i := 0; i < n; i++ {
			yInts[i] = rand.Intn(2*entryRange+1) - entryRange
		}
		yElems := IntsToFrElements(yInts)
		ct, err := Encrypt(msk, yElems)
		if err != nil {
			return throughputResult{}, err
		}
		D1, D2, err := Decrypt(params, sk, ct)
		if err != nil {
			return throughputResult{}, err
		}
		RecoverInnerProduct(D1, D2, params.S)
	}
	total := time.Since(start)
	avg := time.Duration(int64(total) / int64(trials))
	ops := float64(trials) / total.Seconds()
	return throughputResult{Trials: trials, Total: total, Avg: avg, OpsPerSecond: ops, ComponentNote: "full pipeline (Encrypt+Decrypt+Recover)"}, nil
}

// runRecoveryOnlyThroughput measures only the discrete-log style recovery throughput by
// generating synthetic (D1, D2) pairs. This isolates the cost of RecoverInnerProduct
// independent of dimension n.
func runRecoveryOnlyThroughput(params Params, bound int, trials int) throughputResult {
	rand.Seed(time.Now().UnixNano())
	// Base D1 = e(g1, g2)
	D1, _ := bls12381.Pair([]bls12381.G1Affine{params.G1Gen}, []bls12381.G2Affine{params.G2Gen})
	start := time.Now()
	for t := 0; t < trials; t++ {
		// sample z in [-bound, bound]
		z := rand.Intn(2*bound+1) - bound
		var zBig big.Int
		if z >= 0 {
			zBig.SetInt64(int64(z))
		} else {
			zBig.SetInt64(int64(-z))
		}
		var D2 bls12381.GT
		D2.Exp(D1, &zBig)
		if z < 0 {
			D2.Inverse(&D2)
		}
		RecoverInnerProduct(D1, D2, bound)
	}
	total := time.Since(start)
	avg := time.Duration(int64(total) / int64(trials))
	ops := float64(trials) / total.Seconds()
	return throughputResult{Trials: trials, Total: total, Avg: avg, OpsPerSecond: ops, ComponentNote: "recovery only (BSGS)"}
}

func printThroughput(res throughputResult) {
	fmt.Printf("Trials               : %d\n", res.Trials)
	fmt.Printf("Component            : %s\n", res.ComponentNote)
	fmt.Printf("Total time           : %v\n", res.Total)
	fmt.Printf("Average per trial    : %v\n", res.Avg)
	fmt.Printf("Throughput (ops/sec) : %.2f\n", res.OpsPerSecond)
}
