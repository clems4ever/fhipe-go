package main

import (
	"errors"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// FixedPointEncoder manages conversion of float64 vectors into field elements
// by uniform scaling-and-rounding:  x -> round(x * Scale). The integer image
// is then mapped into Fr via standard signed embedding (negative values -> q - |v|).
// The recovered inner product (an integer) can be converted back to an
// approximate real value by dividing by (ScaleX * ScaleY) if both operands
// used possibly different encoders (commonly they share the same scale).
type FixedPointEncoder struct {
	Scale int64 // positive scaling factor
}

// NewFixedPointEncoder creates a new encoder with the given positive scale.
// Scale must be >=1.
func NewFixedPointEncoder(scale int64) (FixedPointEncoder, error) {
	if scale <= 0 {
		return FixedPointEncoder{}, errors.New("scale must be > 0")
	}
	return FixedPointEncoder{Scale: scale}, nil
}

// EncodeFloatVector converts a float64 slice into field elements plus the
// underlying signed integers (useful for S / bound sizing). It rounds ties to
// nearest even via math.Round semantics.
func (enc FixedPointEncoder) EncodeFloatVector(vec []float64) ([]fr.Element, []int64, error) {
	out := make([]fr.Element, len(vec))
	ints := make([]int64, len(vec))
	s := float64(enc.Scale)
	for i, v := range vec {
		scaled := math.Round(v * s)
		if math.IsNaN(scaled) || math.IsInf(scaled, 0) {
			return nil, nil, errors.New("invalid float (NaN/Inf) encountered")
		}
		// Range check for int64
		if scaled > math.MaxInt64 || scaled < math.MinInt64 {
			return nil, nil, errors.New("scaled value overflows int64")
		}
		si := int64(scaled)
		ints[i] = si
		if si >= 0 {
			out[i].SetUint64(uint64(si))
		} else {
			var tmp fr.Element
			tmp.SetUint64(uint64(-si))
			out[i].Neg(&tmp)
		}
	}
	return out, ints, nil
}

// DecodeInnerProduct converts a recovered integer inner product (scaled by
// encX.Scale * encY.Scale) back to float64.
func DecodeInnerProduct(ip int, encX, encY FixedPointEncoder) float64 {
	denom := float64(encX.Scale) * float64(encY.Scale)
	return float64(ip) / denom
}

// EstimateScale attempts to pick an integer scale so that the *scaled* inner
// products remain well below the field modulus. It assumes both sides will use
// the same scale (worst-case magnitude bound maxAbs). The heuristic leaves a
// safetyMarginBits headroom (default suggestion: 32).
//
// It returns a scale >=1. If it returns 1, your vectors are already near the
// capacity or have extremely large magnitudes; consider normalizing.
func EstimateScale(n int, maxAbs float64, safetyMarginBits int) int64 {
	if maxAbs <= 0 {
		return 1
	}
	modulus := fr.Modulus() // *big.Int
	// Convert to big.Float for sqrt operations.
	modF := new(big.Float).SetInt(modulus)
	// We need: n * (maxAbs^2) * scale^2 << modulus
	// => scale < sqrt(modulus / (n * maxAbs^2))
	denom := new(big.Float).SetFloat64(float64(n) * maxAbs * maxAbs)
	if denom.Cmp(big.NewFloat(0)) == 0 {
		return 1
	}
	ratio := new(big.Float).Quo(modF, denom)
	// sqrt
	sqrtRatio := new(big.Float).Sqrt(ratio)
	// Apply safety margin: divide by 2^{safetyMarginBits}
	if safetyMarginBits < 0 {
		safetyMarginBits = 0
	}
	twoPow := math.Pow(2, float64(safetyMarginBits))
	sqrtRatio.Quo(sqrtRatio, big.NewFloat(twoPow))
	f, _ := sqrtRatio.Float64()
	if f < 1 { // cannot scale further
		return 1
	}
	// choose floor(f)
	if f > float64(math.MaxInt64) {
		f = float64(math.MaxInt64)
	}
	return int64(f)
}

// BoundForScaledInnerProduct returns the maximum absolute inner product for
// vectors with entries bounded by maxAbsX, maxAbsY after scaling by the two
// encoders (used to set Params.S). Bound = n * maxAbsX * maxAbsY * sX * sY.
func BoundForScaledInnerProduct(n int, maxAbsX, maxAbsY float64, encX, encY FixedPointEncoder) int {
	prod := float64(n) * maxAbsX * maxAbsY * float64(encX.Scale) * float64(encY.Scale)
	if prod > float64(math.MaxInt32) {
		// Still return int, but clamp (if you expect very large bounds, switch to big.Int logic)
		if prod > float64(math.MaxInt) {
			return math.MaxInt
		}
	}
	return int(math.Ceil(prod))
}
