package main

// This file demonstrates the API usage for precomputed tables

/*

BASIC WORKFLOW WITHOUT PRECOMPUTED TABLE:
==========================================

1. Setup:
   pp, msk, err := Setup(n, S)

2. Generate secret key for vector x:
   x := IntsToFrElements([]int{1, 2, 3, 4, 5})
   sk, err := KeyGen(msk, x)

3. Encrypt vector y:
   y := IntsToFrElements([]int{5, 4, 3, 2, 1})
   ct, err := Encrypt(msk, y)

4. Decrypt to get D1 and D2:
   D1, D2, err := Decrypt(pp, sk, ct)

5. Recover inner product using BSGS:
   innerProduct, found := RecoverInnerProduct(D1, D2, S)
   // O(√N) time complexity



OPTIMIZED WORKFLOW WITH PRECOMPUTED TABLE:
===========================================

1. Setup (same as above):
   pp, msk, err := Setup(n, S)

2. Generate secret key (same as above):
   x := IntsToFrElements([]int{1, 2, 3, 4, 5})
   sk, err := KeyGen(msk, x)

3. Get D1 from ANY encryption with this key:
   y := IntsToFrElements([]int{1, 0, 0, 0, 0})
   ct, err := Encrypt(msk, y)
   D1, _, err := Decrypt(pp, sk, ct)

4a. Precompute table (one-time cost):
    table := PrecomputeTable(D1, S)
    // O(N) time, where N = 2*S + 1

4b. Save table to disk (optional):
    err := SaveTableToDisk(table, "table.gob")

4c. Load table from disk (subsequent runs):
    table, err := LoadTableFromDisk("table.gob")
    // Very fast - just deserialization

5. For each new vector to compute inner product:
   y := IntsToFrElements([]int{5, 4, 3, 2, 1})
   ct, err := Encrypt(msk, y)
   D1, D2, err := Decrypt(pp, sk, ct)
   
   // Fast O(1) lookup instead of O(√N) BSGS
   innerProduct, found := RecoverInnerProductWithTable(D1, D2, table)



WHEN TO USE PRECOMPUTED TABLE:
===============================

✅ Use precomputed table when:
   - You'll compute many inner products with the same secret key
   - You can afford one-time precomputation cost
   - You have disk space to store the table
   - You need predictable O(1) performance

❌ Don't use precomputed table when:
   - You only compute a few inner products
   - Secret key changes frequently
   - Memory/storage is extremely limited
   - Bound S is very large (table size = 2*S + 1)



PERFORMANCE COMPARISON:
=======================

Example: S = 1000 (table size = 2001 entries)

Without table (BSGS):
  - Precomputation: 0ms
  - Per query: ~15ms
  - 10 queries: ~150ms
  - 100 queries: ~1500ms

With table:
  - Precomputation: ~500ms (one-time)
  - Save to disk: ~150ms (one-time)
  - Load from disk: ~50ms (future runs)
  - Per query: ~0.1ms
  - 10 queries: ~1ms + precompute = ~501ms (first run) or ~51ms (loaded)
  - 100 queries: ~10ms + precompute = ~510ms (first run) or ~60ms (loaded)

Break-even point: ~35 queries on first run, ~4 queries with loaded table



CODE EXAMPLE - FULL USAGE:
===========================

func example() {
    // Setup
    n, S := 5, 1000
    pp, msk, _ := Setup(n, S)
    
    // Secret key for x = [1, 2, 3, 4, 5]
    x := IntsToFrElements([]int{1, 2, 3, 4, 5})
    sk, _ := KeyGen(msk, x)
    
    // Try to load existing table
    tablePath := "table.gob"
    var table *PrecomputedTable
    
    if fileExists(tablePath) {
        table, _ = LoadTableFromDisk(tablePath)
    } else {
        // Get D1
        y0 := IntsToFrElements([]int{1, 0, 0, 0, 0})
        ct0, _ := Encrypt(msk, y0)
        D1, _, _ := Decrypt(pp, sk, ct0)
        
        // Precompute and save
        table = PrecomputeTable(D1, S)
        SaveTableToDisk(table, tablePath)
    }
    
    // Now compute many inner products efficiently
    vectors := [][]int{
        {5, 4, 3, 2, 1},
        {1, 1, 1, 1, 1},
        {10, 0, 0, 0, 0},
        // ... more vectors
    }
    
    for _, vec := range vectors {
        y := IntsToFrElements(vec)
        ct, _ := Encrypt(msk, y)
        D1, D2, _ := Decrypt(pp, sk, ct)
        
        // O(1) recovery with table
        result, _ := RecoverInnerProductWithTable(D1, D2, table)
        fmt.Printf("Inner product: %d\n", result)
    }
}

*/
