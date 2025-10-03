package main

import (
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// Unified flag set (namespaced where needed to avoid collisions with Go's default flags).
var (
	// Integer recovery benchmark flags
	benchDim        = flag.Int("rec_dim", 384, "dimension for integer recovery benchmark")
	benchTrials     = flag.Int("rec_trials", 300, "number of recovery trials")
	benchEntryRange = flag.Int("rec_entry", 5, "absolute bound of integer coordinates sampled uniformly in [-rec_entry,rec_entry]")
	benchS          = flag.Int("rec_s", 0, "explicit inner product bound S (if 0, inferred)")
	benchSeed       = flag.Int64("rec_seed", 0, "RNG seed for integer recovery (0 -> time-based)")

	// Fast-float histogram flags
	ffDim    = flag.Int("ff_dim", 256, "dimension for fast-float histogram benchmark")
	ffTrials = flag.Int("ff_trials", 100, "number of trials for fast-float histogram")
	ffK      = flag.Int64("ff_k", 1024, "quantization scale K (S = K^2)")
	ffBins   = flag.Int("ff_bins", 12, "number of histogram bins")
	ffSeed   = flag.Int64("ff_seed", 0, "RNG seed for fast-float benchmark (0 -> time-based)")
)

// TestIPEBenchmarks aggregates multiple benchmarking / analysis subtests so users can run any combination
// via: go test -run TestIPEBenchmarks/RecoveryInteger -v -count=1 -args -rec_dim=384 -rec_trials=500
// or:  go test -run TestIPEBenchmarks/FastFloatHistogram -v -count=1 -args -ff_dim=256 -ff_trials=200 -ff_k=1024 -ff_bins=16
func TestIPEBenchmarks(t *testing.T) {
	if !flag.Parsed() {
		flag.Parse()
	}

	t.Run("RecoveryInteger", func(t *testing.T) { runRecoveryInteger(t) })
	t.Run("FastFloatHistogram", func(t *testing.T) { runFastFloatHistogram(t) })
}

// runRecoveryInteger performs the integer recovery throughput benchmark formerly in TestRecoveryThroughput.
func runRecoveryInteger(t *testing.T) {
	n := *benchDim
	trials := *benchTrials
	entryRange := *benchEntryRange
	S := *benchS
	seed := *benchSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))

	if n <= 0 {
		t.Fatalf("rec_dim must be > 0")
	}
	if trials <= 0 {
		t.Fatalf("rec_trials must be > 0")
	}
	if entryRange <= 0 {
		t.Fatalf("rec_entry must be > 0")
	}

	// If S not provided, infer conservative bound: n * entryRange^2 (worst case inner product magnitude) * 1.1 margin.
	if S == 0 {
		worst := float64(n * entryRange * entryRange)
		S = int(math.Ceil(worst * 1.1))
		if S < 10 {
			S = 10
		}
	}

	pp, msk, err := Setup(n, S)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	xInts := make([]int, n)
	for i := 0; i < n; i++ {
		xInts[i] = rng.Intn(2*entryRange+1) - entryRange
	}
	sk, err := KeyGen(msk, IntsToFrElements(xInts))
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	type trialData struct {
		D1, D2     bls12381.GT
		expectedIP int
	}
	data := make([]trialData, trials)
	for tIdx := 0; tIdx < trials; tIdx++ {
		yInts := make([]int, n)
		for i := 0; i < n; i++ {
			yInts[i] = rng.Intn(2*entryRange+1) - entryRange
		}
		ip := 0
		for i := 0; i < n; i++ {
			ip += xInts[i] * yInts[i]
		}
		if ip > S || ip < -S {
			t.Fatalf("inner product %d outside bound S=%d (increase rec_s)", ip, S)
		}
		ct, err := Encrypt(msk, IntsToFrElements(yInts))
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		D1, D2, err := Decrypt(pp, sk, ct)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		data[tIdx] = trialData{D1: D1, D2: D2, expectedIP: ip}
	}

	durations := make([]float64, 0, trials)
	failures := 0
	wrong := 0
	startAll := time.Now()
	for _, td := range data {
		st := time.Now()
		z, ok := RecoverInnerProduct(td.D1, td.D2, S)
		dt := float64(time.Since(st).Microseconds()) / 1000.0
		durations = append(durations, dt)
		if !ok {
			failures++
			continue
		}
		if z != td.expectedIP {
			wrong++
		}
	}
	totalElapsed := time.Since(startAll)

	sort.Float64s(durations)
	avgLat := avg(durations)
	p50 := percentile(durations, 50)
	p90 := percentile(durations, 90)
	p99 := percentile(durations, 99)
	maxLat := durations[len(durations)-1]
	throughput := float64(trials) / totalElapsed.Seconds()

	fmt.Printf("\n=== Recovery Throughput (Subtest) ===\n")
	fmt.Printf("n=%d trials=%d entryRange=%d S=%d\n", n, trials, entryRange, S)
	fmt.Printf("Failures=%d Mismatches=%d\n", failures, wrong)
	fmt.Printf("Avg(ms)=%.4f P50=%.4f P90=%.4f P99=%.4f Max=%.4f\n", avgLat, p50, p90, p99, maxLat)
	fmt.Printf("Throughput(rec/s)=%.2f\n", throughput)

	if failures > 0 || wrong > 0 {
		t.Fatalf("integrity failed: failures=%d wrong=%d", failures, wrong)
	}
}

// runFastFloatHistogram performs the former TestFastFloatErrorHistogram functionality.
func runFastFloatHistogram(t *testing.T) {
	n := *ffDim
	trials := *ffTrials
	K := *ffK
	bins := *ffBins
	seed := *ffSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))

	if n <= 0 || trials <= 0 || K <= 0 || bins <= 0 {
		t.Fatalf("invalid fast-float parameters")
	}

	pp, msk, err := FastFloatSetup(n, K)
	if err != nil {
		t.Fatalf("FastFloatSetup failed: %v", err)
	}
	_ = pp

	errors := make([]float64, 0, trials)
	failures := 0
	startAll := time.Now()
	totalRecover := time.Duration(0)

	for i := 0; i < trials; i++ {
		x := GenerateRandomFloatVector(n, rng.Int63())
		y := GenerateRandomFloatVector(n, rng.Int63())
		sk, _, normX, err := FastFloatKeyGen(msk, x, K)
		if err != nil {
			t.Fatalf("FastFloatKeyGen: %v", err)
		}
		ct, _, normY, err := FastFloatEncrypt(msk, y, K)
		if err != nil {
			t.Fatalf("FastFloatEncrypt: %v", err)
		}
		recStart := time.Now()
		zPrime, approxDot, ok := FastFloatRecover(msk.PP, sk, ct, normX, normY, K)
		_ = zPrime
		recDur := time.Since(recStart)
		totalRecover += recDur
		if !ok {
			failures++
			continue
		}
		var trueDot float64
		for j := 0; j < n; j++ {
			trueDot += x[j] * y[j]
		}
		errors = append(errors, math.Abs(approxDot-trueDot))
	}
	elapsed := time.Since(startAll)
	if failures > 0 {
		t.Logf("WARNING: %d recoveries failed (K might be too small)", failures)
	}

	if len(errors) == 0 {
		t.Fatalf("no successful recoveries to build histogram")
	}
	sort.Float64s(errors)
	avgErr := avg(errors)
	p50 := percentile(errors, 50)
	p90 := percentile(errors, 90)
	p99 := percentile(errors, 99)
	maxErr := errors[len(errors)-1]
	avgRecoverMs := float64(totalRecover.Microseconds()) / 1000.0 / float64(len(errors))
	throughput := float64(len(errors)) / elapsed.Seconds()

	hist := buildHistogram(errors, bins)

	fmt.Printf("\n=== Fast-Float Error Histogram (Subtest) ===\n")
	fmt.Printf("n=%d K=%d S=%d trials=%d (success=%d fail=%d)\n", n, K, int(K*K), trials, len(errors), failures)
	fmt.Printf("AvgAbsErr=%.3g MaxErr=%.3g P50=%.3g P90=%.3g P99=%.3g\n", avgErr, maxErr, p50, p90, p99)
	fmt.Printf("AvgRecover(ms)=%.3f Throughput(rec/s)=%.2f\n", avgRecoverMs, throughput)
	fmt.Println("Histogram (absolute error):")
	printHistogram(hist)
}

// Shared helpers (avg, percentile) are in main.go already.
// Additional histogram utilities redefined here for cohesion.

type histBin struct {
	Low, High float64
	Count     int
}

func buildHistogram(values []float64, bins int) []histBin {
	if bins < 1 {
		bins = 1
	}
	maxV := values[len(values)-1]
	if maxV == 0 {
		return []histBin{{Low: 0, High: 0, Count: len(values)}}
	}
	width := maxV / float64(bins)
	res := make([]histBin, bins)
	for i := 0; i < bins; i++ {
		res[i].Low = float64(i) * width
		res[i].High = float64(i+1) * width
	}
	for _, v := range values {
		idx := int(v / width)
		if idx >= bins {
			idx = bins - 1
		}
		res[idx].Count++
	}
	return res
}

func printHistogram(bins []histBin) {
	maxCount := 0
	total := 0
	for _, b := range bins {
		if b.Count > maxCount {
			maxCount = b.Count
		}
		total += b.Count
	}
	if maxCount == 0 {
		return
	}
	const barWidth = 40
	for _, b := range bins {
		ratio := float64(b.Count) / float64(maxCount)
		hashes := int(math.Round(ratio * barWidth))
		bar := strings.Repeat("#", hashes)
		pct := 100 * float64(b.Count) / float64(total)
		fmt.Printf("[%8.3g , %8.3g) : %5d (%5.2f%%) %s\n", b.Low, b.High, b.Count, pct, bar)
	}
}

// BenchmarkRecovery preserved (can be run with `go test -bench Recovery`).
func BenchmarkRecovery(b *testing.B) {
	n := 384
	entryRange := 5
	S := 5000
	pp, msk, err := Setup(n, S)
	if err != nil {
		b.Fatalf("setup: %v", err)
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	x := make([]int, n)
	for i := 0; i < n; i++ {
		x[i] = rng.Intn(2*entryRange+1) - entryRange
	}
	sk, err := KeyGen(msk, IntsToFrElements(x))
	if err != nil {
		b.Fatalf("keygen: %v", err)
	}
	type pair struct {
		D1, D2   bls12381.GT
		expected int
	}
	pairs := make([]pair, b.N)
	for i := 0; i < b.N; i++ {
		y := make([]int, n)
		ip := 0
		for j := 0; j < n; j++ {
			val := rng.Intn(2*entryRange+1) - entryRange
			y[j] = val
			ip += x[j] * val
		}
		if ip > S || ip < -S {
			i--
			continue
		}
		ct, err := Encrypt(msk, IntsToFrElements(y))
		if err != nil {
			b.Fatalf("encrypt: %v", err)
		}
		D1, D2, err := Decrypt(pp, sk, ct)
		if err != nil {
			b.Fatalf("decrypt: %v", err)
		}
		pairs[i] = pair{D1: D1, D2: D2, expected: ip}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		z, ok := RecoverInnerProduct(pairs[i].D1, pairs[i].D2, S)
		if !ok || z != pairs[i].expected {
			b.Fatalf("recovery mismatch")
		}
	}
}

func TestMain(m *testing.M) { os.Exit(m.Run()) }
