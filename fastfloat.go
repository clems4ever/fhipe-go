package main

import (
	"errors"
	"math"
	"math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// QuantizeNormalize takes a real vector v and an integer scale K.
// It returns q = round( K * v / ||v||_2 ), the L2 norm of v, and an error if v is zero.
// After quantization, ||q||_2 is approximately K, and each |q_i| <= K.
func QuantizeNormalize(v []float64, K int64) ([]int64, float64, error) {
	var norm2 float64
	for _, x := range v {
		norm2 += x * x
	}
	if norm2 == 0 {
		return nil, 0, errors.New("zero vector: cannot normalize")
	}
	norm := math.Sqrt(norm2)
	scale := float64(K) / norm
	q := make([]int64, len(v))
	for i, x := range v {
		q[i] = int64(math.Round(x * scale))
		if q[i] > K {
			q[i] = K
		} else if q[i] < -K {
			q[i] = -K
		} // clamp (rare with rounding)
	}
	return q, norm, nil
}

// Int64sToFr converts signed int64 slice into field elements in Z_q.
func Int64sToFr(src []int64) []fr.Element {
	out := make([]fr.Element, len(src))
	for i, v := range src {
		if v >= 0 {
			out[i].SetUint64(uint64(v))
		} else {
			var tmp fr.Element
			tmp.SetUint64(uint64(-v))
			out[i].Neg(&tmp)
		}
	}
	return out
}

// FastFloatSetup sets S = K^2 (bound for inner product of quantized unit vectors scaled by K).
func FastFloatSetup(n int, K int64) (Params, MSK, error) {
	S := int(K * K)
	return Setup(n, S)
}

// FastFloatKeyGen performs server-side quantization+normalization for secret vector x and returns the SecretKey.
func FastFloatKeyGen(msk MSK, x []float64, K int64) (SecretKey, []int64, float64, error) {
	qx, normX, err := QuantizeNormalize(x, K)
	if err != nil {
		return SecretKey{}, nil, 0, err
	}
	xElems := Int64sToFr(qx)
	sk, err := KeyGen(msk, xElems)
	if err != nil {
		return SecretKey{}, nil, 0, err
	}
	return sk, qx, normX, nil
}

// FastFloatEncrypt quantizes/normalizes y and produces its ciphertext.
func FastFloatEncrypt(msk MSK, y []float64, K int64) (Ciphertext, []int64, float64, error) {
	qy, normY, err := QuantizeNormalize(y, K)
	if err != nil {
		return Ciphertext{}, nil, 0, err
	}
	yElems := Int64sToFr(qy)
	ct, err := Encrypt(msk, yElems)
	if err != nil {
		return Ciphertext{}, nil, 0, err
	}
	return ct, qy, normY, nil
}

// FastFloatRecover recovers z' (quantized cosine * K^2) and returns an approximate true dot product.
// True dot ≈ z' * (normX * normY) / K^2.
func FastFloatRecover(pp Params, sk SecretKey, ct Ciphertext, normX, normY float64, K int64) (zPrime int, dotApprox float64, ok bool) {
	D1, D2, err := Decrypt(pp, sk, ct)
	if err != nil {
		return 0, 0, false
	}
	z, found := RecoverInnerProduct(D1, D2, pp.S)
	if !found {
		return 0, 0, false
	}
	// dot ≈ (z / K^2) * normX * normY
	denom := float64(K * K)
	dot := (float64(z) / denom) * (normX * normY)
	return z, dot, true
}

// GenerateRandomFloatVector helper (uniform in [-1,1]).
func GenerateRandomFloatVector(n int, seed int64) []float64 {
	rng := rand.New(rand.NewSource(seed))
	v := make([]float64, n)
	for i := 0; i < n; i++ {
		v[i] = 2*rng.Float64() - 1
	}
	return v
}

// FastFloatDemo runs a single end-to-end example and returns stats.
type FastFloatDemoResult struct {
	K         int64
	S         int
	ZPrime    int
	ApproxDot float64
	TrueDot   float64
	AbsError  float64
	NormX     float64
	NormY     float64
}

func RunFastFloatDemo(n int, K int64, seed int64) (*FastFloatDemoResult, error) {
	pp, msk, err := FastFloatSetup(n, K)
	if err != nil {
		return nil, err
	}
	x := GenerateRandomFloatVector(n, seed)
	y := GenerateRandomFloatVector(n, seed+42)
	// KeyGen for x
	sk, qx, normX, err := FastFloatKeyGen(msk, x, K)
	_ = qx
	if err != nil {
		return nil, err
	}
	ct, qy, normY, err := FastFloatEncrypt(msk, y, K)
	_ = qy
	if err != nil {
		return nil, err
	}
	zPrime, dotApprox, ok := FastFloatRecover(pp, sk, ct, normX, normY, K)
	if !ok {
		return nil, errors.New("discrete log recovery failed (increase K)")
	}
	// True dot
	var trueDot float64
	for i := 0; i < n; i++ {
		trueDot += x[i] * y[i]
	}
	return &FastFloatDemoResult{
		K: K, S: pp.S, ZPrime: zPrime, ApproxDot: dotApprox, TrueDot: trueDot,
		AbsError: math.Abs(dotApprox - trueDot), NormX: normX, NormY: normY,
	}, nil
}

// FastFloatMultiExperiment runs multiple trials to gather average absolute error and recovery timing.
type FastFloatMultiStats struct {
	K              int64
	S              int
	Trials         int
	AvgAbsError    float64
	MaxAbsError    float64
	AvgRecoverMs   float64
	ThroughputRecS float64
}

func RunFastFloatMulti(n int, K int64, trials int, seed int64) (*FastFloatMultiStats, error) {
	pp, msk, err := FastFloatSetup(n, K)
	if err != nil {
		return nil, err
	}
	var sumErr, maxErr float64
	startAll := time.Now()
	totalRecover := time.Duration(0)
	rngSeed := seed
	for t := 0; t < trials; t++ {
		x := GenerateRandomFloatVector(n, rngSeed+int64(t))
		y := GenerateRandomFloatVector(n, rngSeed+int64(t)+9999)
		sk, _, normX, err := FastFloatKeyGen(msk, x, K)
		if err != nil {
			return nil, err
		}
		ct, _, normY, err := FastFloatEncrypt(msk, y, K)
		if err != nil {
			return nil, err
		}
		// Time only recovery (KeyGen/Encrypt excluded to isolate DL speed)
		recStart := time.Now()
		z, approx, ok := FastFloatRecover(pp, sk, ct, normX, normY, K)
		_ = z
		recDur := time.Since(recStart)
		totalRecover += recDur
		if !ok {
			return nil, errors.New("recovery failed in multi trial")
		}
		// True dot
		var trueDot float64
		for i := 0; i < n; i++ {
			trueDot += x[i] * y[i]
		}
		errAbs := math.Abs(approx - trueDot)
		sumErr += errAbs
		if errAbs > maxErr {
			maxErr = errAbs
		}
	}
	elapsed := time.Since(startAll)
	avgErr := sumErr / float64(trials)
	avgRecMs := float64(totalRecover.Microseconds()) / 1000.0 / float64(trials)
	throughput := float64(trials) / elapsed.Seconds()
	return &FastFloatMultiStats{K: K, S: pp.S, Trials: trials, AvgAbsError: avgErr, MaxAbsError: maxErr, AvgRecoverMs: avgRecMs, ThroughputRecS: throughput}, nil
}
