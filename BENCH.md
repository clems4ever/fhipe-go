[cmichaud@laptop-pro fhipe-go]$ go run .
Baseline scale=1050 S=1102500 (not exceeded)

=== Multi-Scale Recovery Comparison (S <= baseline) ===
Scale  S          Succ%    Thr(rec/s) Avg(ms)    P90(ms)    AvgErr     P90Err     MaxErr    
300    90000      100.00   503.15    1.987      2.312      0.00104    0.00209    0.00514   
500    250000     100.00   313.24    3.192      3.487      0.000664   0.0013     0.00183   
700    490000     100.00   234.74    4.259      4.740      0.00045    0.00094    0.00172   
900    810000     100.00   171.52    5.829      6.418      0.000347   0.000696   0.00134   
1050   1102500    100.00   148.06    6.753      7.450      0.000278   0.000577   0.00106

---

# Fast Float FH-IPE Benchmark Notes

## Rationale

Floating-point inner products force large S if we encode raw magnitudes. By L2-normalizing and scaling by an integer K, we bound the quantized inner product to [-K^2, K^2], independent of dimension n.

## Recipe

1. For real vectors x, y compute norms ||x||, ||y||.
2. Quantize: qx = round(K * x / ||x||), qy = round(K * y / ||y||).
3. Run FH-IPE on integer vectors qx, qy with S = K^2.
4. Decrypt to recover z' ≈ <qx,qy> ∈ [-K^2, K^2].
5. Reconstruct approximate real dot: dot ≈ (z' / K^2) * ||x|| * ||y||.

Cosine similarity is simply z'/K^2 (since q vectors approximate unit scale K).

## Precision

Cosine resolution ≈ 1/K^2. Choose K for target absolute cosine error ε:
	K ≈ ceil(1/√ε).

Examples:
	ε = 1e-6 → K ≈ 1000 (we used 1024 power-of-two)
	ε = 2.5e-7 → K ≈ 2000 (use 2048)

## Implemented Helpers (`fastfloat.go`)

- QuantizeNormalize(v,K)
- FastFloatSetup(n,K) => Params, MSK with S=K^2
- FastFloatKeyGen / FastFloatEncrypt
- FastFloatRecover (returns z' and approximate dot)
- RunFastFloatDemo / RunFastFloatMulti

## Planned Optimizations

| Area | Idea | Benefit |
|------|------|---------|
| Discrete Log | Pollard kangaroo | Lower memory, similar or better time for S up to ~1e8 |
| Matrix Mult | Structured (NTT-friendly) B | Reduce O(n^2) to O(n log n) |
| Scalars | Fixed-base tables (g1,g2) | Faster mass exponentiations |
| Pairings | Batched pairings | Fewer Miller loops |

## Next Steps

- Add Pollard kangaroo implementation with automatic switch when S > threshold.
- Add multi-K benchmark using RunFastFloatMulti for K={512,1024,2048}.
- Export CSV for error vs K vs time.