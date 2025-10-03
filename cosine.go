package main

import (
	"errors"
	"math"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ChooseScaleForCosine picks a fixed-point scale s so that 1/s^2 <= targetPrecision.
// safetyFactor (>1) enlarges s to reduce aggregate rounding error.
func ChooseScaleForCosine(targetPrecision float64, safetyFactor float64) int64 {
	if targetPrecision <= 0 {
		targetPrecision = 1e-6
	}
	if safetyFactor < 1 {
		safetyFactor = 1.0
	}
	raw := math.Sqrt(1.0/targetPrecision) * safetyFactor
	if raw < 1 {
		raw = 1
	}
	if raw > float64(math.MaxInt64) {
		raw = float64(math.MaxInt64)
	}
	return int64(math.Ceil(raw))
}

// NormalizeL2 returns a copy normalized to unit L2 norm; if zero vector, returns error.
func NormalizeL2(vec []float64) ([]float64, error) {
	var sumSq float64
	for _, v := range vec {
		sumSq += v * v
	}
	if sumSq == 0 {
		return nil, errors.New("cannot normalize zero vector")
	}
	inv := 1.0 / math.Sqrt(sumSq)
	out := make([]float64, len(vec))
	for i, v := range vec {
		out[i] = v * inv
	}
	return out, nil
}

// EncodeNormalizedVector encodes a unit-normalized vector (entries in [-1,1]) using scale.
// Returns field elements and the underlying int64 integers for optional diagnostics.
func EncodeNormalizedVector(vec []float64, scale int64) ([]fr.Element, []int64, error) {
	if scale <= 0 {
		return nil, nil, errors.New("scale must be > 0")
	}
	out := make([]fr.Element, len(vec))
	ints := make([]int64, len(vec))
	s := float64(scale)
	for i, v := range vec {
		// guard minor FP drift beyond [-1,1]
		if v > 1 {
			v = 1
		} else if v < -1 {
			v = -1
		}
		scaled := math.Round(v * s)
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

// SetupCosineIPE sets Parameters & MSK for cosine similarity with target precision.
// S is selected as ceil(scale^2 * (1+margin)).
func SetupCosineIPE(n int, scale int64, margin float64) (Params, MSK, error) {
	if margin < 0 {
		margin = 0
	}
	S := int(math.Ceil(float64(scale*scale)*(1+margin))) + 8
	return Setup(n, S)
}

// DecodeCosine converts recovered scaled integer z to float via z / scale^2.
func DecodeCosine(z int, scale int64) float64 { return float64(z) / float64(scale*scale) }
