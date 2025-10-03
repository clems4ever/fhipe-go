package main

import (
    "fmt"
    "log"
    "runtime"
    "sync"
    "sync/atomic"
    "time"
)

// BenchmarkManyKeysOneCiphertext measures throughput when a single ciphertext (for a fixed y)
// is decrypted and its inner product recovered against many secret keys (each for an x_i).
// This models a scenario where one party publishes an encryption of y and many authorized
// consumers (holding functional keys for different x_i) compute y·x_i. We aim to understand
// throughput scaling from inter-key parallelism (parallel over keys) rather than intra-key
// (parallel over vector dimension) work.
func BenchmarkManyKeysOneCiphertext() {
    fmt.Println("=== Many Keys / One Ciphertext Benchmark ===")
    n := 384            // vector dimension
    S := 80000          // inner product bound (must exceed max |y·x|)
    numKeys := 500      // number of distinct functional keys (x vectors)
    valueRange := 20    // values in [-valueRange/2, valueRange/2)

    fmt.Printf("Dimension n=%d, bound S=%d, keys=%d, single ciphertext.\n", n, S, numKeys)

    // 1. Setup (single global MSK / Params shared across all keys & ciphertext)
    start := time.Now()
    pp, msk, err := Setup(n, S)
    if err != nil {
        log.Fatalf("Setup failed: %v", err)
    }
    fmt.Printf("Setup: %v\n", time.Since(start))

    // 2. Generate x_i vectors and derive keys
    xs := make([][]int, numKeys)
    for i := 0; i < numKeys; i++ {
        xs[i] = make([]int, n)
        for j := 0; j < n; j++ {
            // deterministic pseudo-random but bounded pattern
            xs[i][j] = ((i+1)*j + 3*j + i) % valueRange - valueRange/2
        }
    }

    fmt.Println("KeyGen for all keys...")
    sks := make([]SecretKey, numKeys)
    kgStart := time.Now()
    for i := 0; i < numKeys; i++ {
        sk, err := KeyGen(msk, IntsToFrElements(xs[i]))
        if err != nil {
            log.Fatalf("KeyGen failed (i=%d): %v", i, err)
        }
        sks[i] = sk
    }
    kgTime := time.Since(kgStart)
    fmt.Printf("KeyGen total: %v (avg %v)\n", kgTime, kgTime/time.Duration(numKeys))

    // 3. Choose one y vector and encrypt it once
    yVec := make([]int, n)
    for j := 0; j < n; j++ {
        yVec[j] = (7*j + 11) % valueRange - valueRange/2
    }
    encStart := time.Now()
    ct, err := Encrypt(msk, IntsToFrElements(yVec))
    if err != nil {
        log.Fatalf("Encrypt failed: %v", err)
    }
    encTime := time.Since(encStart)
    fmt.Printf("Encryption (single y): %v\n", encTime)

    // 4. Sequential baseline (no parallel over keys, internal library may still multi-pair)
    seqStart := time.Now()
    seqSuccess := 0
    for i := 0; i < numKeys; i++ {
        D1, D2, err := Decrypt(pp, sks[i], ct)
        if err != nil {
            log.Fatalf("Decrypt failed (seq i=%d): %v", i, err)
        }
        if _, ok := RecoverInnerProduct(D1, D2, S); ok {
            seqSuccess++
        }
    }
    seqTime := time.Since(seqStart)
    fmt.Printf("Sequential decrypt+recover: %v total, %v per op, throughput %.2f ops/sec (success %d/%d)\n",
        seqTime, seqTime/time.Duration(numKeys), float64(numKeys)/seqTime.Seconds(), seqSuccess, numKeys)

    // 5. Parallel over keys (each worker processes distinct subset; use Decrypt not DecryptParallel to avoid nested parallelism)
    parStart := time.Now()
    workers := runtime.GOMAXPROCS(0)
    if workers > numKeys { // cap redundant workers
        workers = numKeys
    }
    var wg sync.WaitGroup
    successes := int64(0)
    chunk := (numKeys + workers - 1) / workers
    for w := 0; w < workers; w++ {
        startIdx := w * chunk
        endIdx := startIdx + chunk
        if endIdx > numKeys {
            endIdx = numKeys
        }
        if startIdx >= endIdx { continue }
        wg.Add(1)
        go func(s, e int) {
            defer wg.Done()
            localOK := 0
            for i := s; i < e; i++ {
                D1, D2, err := Decrypt(pp, sks[i], ct)
                if err != nil {
                    log.Printf("Decrypt failed (par i=%d): %v", i, err)
                    return
                }
                if _, ok := RecoverInnerProduct(D1, D2, S); ok {
                    localOK++
                }
            }
            // atomic add without importing sync/atomic again by batching writes through channel or closure; simple approach: use mutex
            // For simplicity of code (and low contention), we use a mutex outside; but to avoid adding a global mutex, accumulate after join.
            // We'll store result using a channel.
            // (Simpler: we capture successes pointer with a small critical section.)
            // To keep dependencies minimal, we cast to *int64 via closure variable.
            // Using a small lock free approach would require atomic; we'll just use atomic here.
            // Adding atomic now for clarity.
            // (Implementation note: we could precompute expected results to verify correctness.)
            // This comment explains design trade-offs.
            addSuccesses(&successes, int64(localOK))
        }(startIdx, endIdx)
    }
    wg.Wait()
    parTime := time.Since(parStart)
    fmt.Printf("Parallel decrypt+recover:   %v total, %v per op, throughput %.2f ops/sec (success %d/%d, workers=%d)\n",
        parTime, parTime/time.Duration(numKeys), float64(numKeys)/parTime.Seconds(), successes, numKeys, workers)

    fmt.Println("Note: Parallel mode uses inter-key parallelism only (no DecryptParallel) to avoid nested thread contention.")
    fmt.Println()
}

// addSuccesses atomically adds v to *p.
func addSuccesses(p *int64, v int64) { atomic.AddInt64(p, v) }
