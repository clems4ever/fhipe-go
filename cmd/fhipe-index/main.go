package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"

	"golang.org/x/crypto/bn256"
)

/*
This is a toy, not production code.
Implements:
  - Base IPE from the paper (secret-key, function-hiding style)
  - Packed/multi-slot ciphertext with per-slot masks
  - Authorized key includes a single unmasker for one chosen slot

Notation:
  q: group order (BN256)
  B \in GL_n(Z_q), B* = det(B) * (B^{-1})^T
  Setup: msk = (g1, g2, B, B*)
  KeyGen(x): K1 = g1^{alpha*det(B)}, K2[j] = g1^{alpha*(x·B)[j]}
  EncryptPacked({y_i}): For each slot i:
      C2[i][j] = g2^{beta*(y_i·B*)[j]}
    Also publish C1 = g2^{beta} and U = g2^{beta*r}; masks m_i = PRF_k(nonce||i)
  Authorized key for slot j adds: Vj = g1^{ -alpha*det(B) * m_j * r^{-1} }
  DecryptSlot(j): D1 = e(K1, C1)
                   D2_j = Π_j e(K2[j], C2[j_slot][j])
                   MaskRem = e(Vj, U)
                   M = D2_j * MaskRem = D1^{⟨x,y_j⟩ - m_j}
                   Trial-decode z∈S: check D1^{z - m_j} == M
*/

var (
	// BN256 (a.k.a. BN254) order:
	q, _ = new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
)

// ------------ Utilities (mod q) ------------

func randZq() *big.Int {
	for {
		b, err := rand.Int(rand.Reader, q)
		if err != nil {
			panic(err)
		}
		if b.Sign() != 0 {
			return b
		}
	}
}

func mod(x *big.Int) *big.Int {
	x.Mod(x, q)
	if x.Sign() < 0 {
		x.Add(x, q)
	}
	return x
}

func addMod(a, b *big.Int) *big.Int { return mod(new(big.Int).Add(a, b)) }
func subMod(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b)) }
func mulMod(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }

func invMod(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, q)
}

// ------------ Linear algebra over Z_q ------------

type vec []*big.Int
type mat [][]*big.Int

func randVec(n int) vec {
	v := make(vec, n)
	for i := range v {
		v[i] = randZq()
	}
	return v
}

func randMatGL(n int) (mat, *big.Int) {
	// sample until det != 0
	for {
		M := make(mat, n)
		for i := 0; i < n; i++ {
			M[i] = make([]*big.Int, n)
			for j := 0; j < n; j++ {
				M[i][j] = randZq()
			}
		}
		if det := detMod(M); det.Sign() != 0 {
			return M, det
		}
	}
}

func detMod(M mat) *big.Int {
	n := len(M)
	// make a copy for elimination
	A := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		A[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			A[i][j] = new(big.Int).Set(M[i][j])
		}
	}
	d := big.NewInt(1)
	sign := 1
	for i := 0; i < n; i++ {
		pivot := i
		for r := i; r < n; r++ {
			if A[r][i].Sign() != 0 {
				pivot = r
				break
			}
		}
		if A[pivot][i].Sign() == 0 {
			return big.NewInt(0)
		}
		if pivot != i {
			A[i], A[pivot] = A[pivot], A[i]
			sign *= -1
		}
		d = mulMod(d, A[i][i])
		inv := invMod(A[i][i])
		// eliminate
		for r := i + 1; r < n; r++ {
			if A[r][i].Sign() == 0 {
				continue
			}
			f := mulMod(A[r][i], inv)
			for c := i; c < n; c++ {
				tmp := subMod(A[r][c], mulMod(f, A[i][c]))
				A[r][c] = tmp
			}
		}
	}
	if sign == -1 {
		d = subMod(big.NewInt(0), d)
	}
	return mod(d)
}

func invMatMod(M mat) mat {
	n := len(M)
	// augment with identity and Gaussian eliminate
	A := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		A[i] = make([]*big.Int, 2*n)
		for j := 0; j < n; j++ {
			A[i][j] = new(big.Int).Set(M[i][j])
		}
		for j := 0; j < n; j++ {
			if i == j {
				A[i][n+j] = big.NewInt(1)
			} else {
				A[i][n+j] = big.NewInt(0)
			}
		}
	}
	// forward elim
	for i := 0; i < n; i++ {
		pivot := i
		for r := i; r < n; r++ {
			if A[r][i].Sign() != 0 {
				pivot = r
				break
			}
		}
		if A[pivot][i].Sign() == 0 {
			panic("singular")
		}
		if pivot != i {
			A[i], A[pivot] = A[pivot], A[i]
		}
		inv := invMod(A[i][i])
		for c := 0; c < 2*n; c++ {
			A[i][c] = mulMod(A[i][c], inv)
		}
		for r := 0; r < n; r++ {
			if r == i {
				continue
			}
			f := new(big.Int).Set(A[r][i])
			if f.Sign() == 0 {
				continue
			}
			for c := 0; c < 2*n; c++ {
				A[r][c] = subMod(A[r][c], mulMod(f, A[i][c]))
			}
		}
	}
	// extract right half
	Inv := make(mat, n)
	for i := 0; i < n; i++ {
		Inv[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			Inv[i][j] = A[i][n+j]
		}
	}
	return Inv
}

func transpose(M mat) mat {
	n := len(M)
	T := make(mat, n)
	for i := 0; i < n; i++ {
		T[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			T[i][j] = new(big.Int).Set(M[j][i])
		}
	}
	return T
}

func rowMulMat(x vec, M mat) vec {
	n := len(x)
	out := make(vec, n)
	for j := 0; j < n; j++ {
		sum := big.NewInt(0)
		for k := 0; k < n; k++ {
			sum = addMod(sum, mulMod(x[k], M[k][j]))
		}
		out[j] = sum
	}
	return out
}

// ------------ PRF (HMAC-SHA256 -> Z_q) ------------

func prfZq(key []byte, nonce []byte, idx int) *big.Int {
	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(idx))
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	// reduce to Z_q
	return new(big.Int).Mod(new(big.Int).SetBytes(sum), q)
}

// ------------ Scheme types ------------

type Setup struct {
	B   mat
	Bst mat
	det *big.Int
	g1  *bn256.G1
	g2  *bn256.G2
}

type SecretKey struct {
	K1 *bn256.G1   // g1^{alpha*det}
	K2 []*bn256.G1 // g1^{alpha*(x·B)[j]}
	// optional unmasker for a single slot:
	Vj   *bn256.G1 // g1^{-alpha*det * m_j * r^{-1}}
	Slot int
}

type PackedCiphertext struct {
	C1      *bn256.G2     // g2^{beta}
	U       *bn256.G2     // g2^{beta*r}
	C2      [][]*bn256.G2 // [slot][j] : g2^{beta*(y_i·B*)[j]}
	Nonce   []byte        // for PRF
	MaskKey []byte        // encryptor’s PRF key (shared with KGen authority)
}

// ------------ Base operations ------------

func SetupIPE(n int) *Setup {
	B, det := randMatGL(n)
	Binv := invMatMod(B)
	BinvT := transpose(Binv)
	Bst := make(mat, n)
	for i := 0; i < n; i++ {
		Bst[i] = make([]*big.Int, n)
		for j := 0; j < n; j++ {
			Bst[i][j] = mulMod(det, BinvT[i][j]) // det * (B^{-1})^T
		}
	}
	// generators: use ScalarBaseMult(1)
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	return &Setup{B: B, Bst: Bst, det: det, g1: g1, g2: g2}
}

func KeyGenAuthorizeSlot(st *Setup, x vec, prfKey []byte, nonce []byte, slot int, r *big.Int) *SecretKey {
	alpha := randZq()
	// K1
	exp1 := mulMod(alpha, st.det)
	K1 := new(bn256.G1).ScalarBaseMult(exp1)
	// K2 vector
	xb := rowMulMat(x, st.B) // x·B
	K2 := make([]*bn256.G1, len(x))
	for j := 0; j < len(x); j++ {
		exp := mulMod(alpha, xb[j])
		K2[j] = new(bn256.G1).ScalarBaseMult(exp)
	}
	// Unmasker for the authorized slot:
	mj := prfZq(prfKey, nonce, slot)
	rInv := invMod(r)
	expV := mulMod(st.det, mj)
	expV = mulMod(expV, rInv)
	expV = mulMod(expV, alpha)
	expV = subMod(big.NewInt(0), expV) // negate
	Vj := new(bn256.G1).ScalarBaseMult(expV)

	return &SecretKey{K1: K1, K2: K2, Vj: Vj, Slot: slot}
}

func EncryptPacked(st *Setup, ys []vec, prfKey []byte) (*PackedCiphertext, *big.Int) {
	n := len(ys[0])
	beta := randZq()
	r := randZq()
	// C1, U
	C1 := new(bn256.G2).ScalarBaseMult(beta)
	U := new(bn256.G2).ScalarBaseMult(mulMod(beta, r))
	// each slot
	C2 := make([][]*bn256.G2, len(ys))
	for i := range ys {
		ybst := rowMulMat(ys[i], st.Bst) // y_i · B*
		C2[i] = make([]*bn256.G2, n)
		for j := 0; j < n; j++ {
			exp := mulMod(beta, ybst[j])
			C2[i][j] = new(bn256.G2).ScalarBaseMult(exp)
		}
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return &PackedCiphertext{
		C1: C1, U: U, C2: C2, Nonce: nonce, MaskKey: prfKey,
	}, r
}

// GT helpers

func GTExp(P *bn256.GT, e *big.Int) *bn256.GT {
	// Fallback custom exponentiation via double-and-add using GT group law (Add for multiplication).
	if e.Sign() < 0 {
		// handle negative by computing inverse then positive exponent
		pos := new(big.Int).Neg(e)
		inv := new(bn256.GT).Neg(P) // since group written additively, inverse is Neg
		return GTExp(inv, pos)
	}
	res := bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(0)), new(bn256.G2).ScalarBaseMult(big.NewInt(0))) // identity
	// clone P via marshal/unmarshal to avoid mutating original
	baseBytes := P.Marshal()
	base := new(bn256.GT)
	if ok := base.Unmarshal(baseBytes); !ok {
		panic("failed to unmarshal GT element")
	}
	for i := e; i.Sign() > 0; i.Rsh(i, 1) {
		if new(big.Int).And(i, big.NewInt(1)).Sign() != 0 {
			res = GTMul(res, base)
		}
		base = GTMul(base, base)
	}
	return res
}

func GTMul(a, b *bn256.GT) *bn256.GT {
	return new(bn256.GT).Add(a, b)
}

func GTEqual(a, b *bn256.GT) bool {
	return string(a.Marshal()) == string(b.Marshal())
}

// Decrypt one slot: returns (z, ok, maskedGT)
func DecryptSlot(st *Setup, sk *SecretKey, ct *PackedCiphertext, slot int, S []*big.Int) (*big.Int, bool, *bn256.GT) {
	n := len(sk.K2)
	// D1 = e(K1, C1)
	D1 := bn256.Pair(sk.K1, ct.C1)
	// D2_slot = Π_j e(K2[j], C2[slot][j])
	// Accumulate without needing an explicit GT identity element.
	var D2 *bn256.GT
	for j := 0; j < n; j++ {
		p := bn256.Pair(sk.K2[j], ct.C2[slot][j])
		if D2 == nil {
			D2 = p
		} else {
			D2 = GTMul(D2, p)
		}
	}
	// MaskRem = e(Vj, U)
	MaskRem := bn256.Pair(sk.Vj, ct.U)
	M := GTMul(D2, MaskRem) // = D1^{<x,y_slot> - m_slot}

	// Debug: verify exponent relation by brute force discrete log over small S if possible (only for demo S range)
	// (Infeasible generally, but S is tiny.)
	// We try all candidates t in S' = {z - m_j | z in S} to see if D1^t == M to understand failure.
	mj := prfZq(ct.MaskKey, ct.Nonce, slot)
	if sk.Slot == slot { // only for authorized slot
		matchedInner := big.NewInt(-1)
		for _, cand := range S { // attempt to match D2 == D1^cand
			if GTEqual(GTExp(D1, cand), D2) {
				matchedInner = cand
				break
			}
		}
		if matchedInner.Sign() != -1 {
			fmt.Printf("[debug] Found z such that D2==D1^z: z=%d\n", fromMod(matchedInner))
		} else {
			fmt.Printf("[debug] No z in S gives D2==D1^z\n")
		}
		if matchedInner.Sign() != -1 {
			// Check if M matches D1^{z - mj}
			expTest := subMod(new(big.Int).Set(matchedInner), mj)
			if GTEqual(GTExp(D1, expTest), M) {
				fmt.Printf("[debug] M matches D1^{z-mj} for z=%d\n", fromMod(matchedInner))
			} else {
				fmt.Printf("[debug] M DOES NOT match D1^{z-mj} for z=%d\n", fromMod(matchedInner))
			}
		}
	}
	for _, cand := range S {
		exp := subMod(new(big.Int).Set(cand), mj)
		if GTEqual(GTExp(D1, exp), M) {
			// Found match; normal loop below will also catch; break early.
			break
		}
	}
	// recover m_slot via PRF
	// recover m_slot via PRF (already computed above for debug)

	// trial decode over small S
	for _, z := range S {
		exp := subMod(new(big.Int).Set(z), mj) // z - m_j
		test := GTExp(D1, exp)
		if GTEqual(test, M) {
			return new(big.Int).Set(z), true, M
		}
	}
	return nil, false, M
}

// ------------ Demo ------------

func smallSetS(min, max int) []*big.Int {
	var out []*big.Int
	for v := min; v <= max; v++ {
		out = append(out, mod(big.NewInt(int64(v))))
	}
	return out
}

func main() {
	n := 3                  // vector length
	kSlots := 3             // number of packed slots
	S := smallSetS(-20, 20) // allowed outputs (tiny for demo)

	// Setup
	st := SetupIPE(n)

	// Secret PRF key (shared by encryptor + keygen authority)
	prfKey := make([]byte, 32)
	if _, err := rand.Read(prfKey); err != nil {
		log.Fatal(err)
	}

	// User vector x
	x := vec{big.NewInt(3), big.NewInt(-2), big.NewInt(5)}
	for i := range x {
		x[i] = mod(x[i])
	}

	// Pack 3 candidate y's into one ciphertext
	ys := []vec{
		{big.NewInt(1), big.NewInt(1), big.NewInt(1)},  // <x,y>= 6
		{big.NewInt(2), big.NewInt(0), big.NewInt(-1)}, // <x,y>= 1
		{big.NewInt(-1), big.NewInt(4), big.NewInt(0)}, // <x,y>= -11
	}
	for i := range ys {
		for j := range ys[i] {
			ys[i][j] = mod(ys[i][j])
		}
	}

	// Encrypt all slots
	ct, r := EncryptPacked(st, ys, prfKey)

	// Authorize only slot sel
	sel := 1 // choose index 1 (second y)
	sk := KeyGenAuthorizeSlot(st, x, prfKey, ct.Nonce, sel, r)

	// Decrypt authorized slot
	z, ok, _ := DecryptSlot(st, sk, ct, sel, S)
	fmt.Printf("Authorized slot %d -> success:%v value:%v\n", sel, ok, fromMod(z))

	// Debug algebraic identity for selected slot
	xB := rowMulMat(x, st.B)
	yBst := rowMulMat(ys[sel], st.Bst)
	dot := big.NewInt(0)
	for j := 0; j < n; j++ {
		dot = addMod(dot, mulMod(xB[j], yBst[j]))
	}
	ip := big.NewInt(0)
	for j := 0; j < n; j++ {
		ip = addMod(ip, mulMod(x[j], ys[sel][j]))
	}
	rhs := mulMod(st.det, ip)
	fmt.Printf("[debug] dot(xB,yB*)=%v det*<x,y>=%v equal=%v\n", dot, rhs, dot.Cmp(rhs) == 0)

	// Additional explicit exponent check
	mjCheck := prfZq(prfKey, ct.Nonce, sel)
	expWanted := subMod(new(big.Int).Set(ip), mjCheck) // <x,y> - mj
	D1 := bn256.Pair(sk.K1, ct.C1)
	Mcalc := GTExp(D1, expWanted)
	// Recompute M path directly for comparison
	// Rebuild D2 and MaskRem
	D2re := (*bn256.GT)(nil)
	for j := 0; j < n; j++ {
		p := bn256.Pair(sk.K2[j], ct.C2[sel][j])
		if D2re == nil {
			D2re = p
		} else {
			D2re = GTMul(D2re, p)
		}
	}
	MaskRemRe := bn256.Pair(sk.Vj, ct.U)
	Mreal := GTMul(D2re, MaskRemRe)
	fmt.Printf("[debug] explicit exponent expWanted=%d match=%v (Mcalc vs Mreal)\n", fromMod(expWanted), GTEqual(Mcalc, Mreal))

	// Try to read a different slot with the same key (should fail)
	for i := 0; i < kSlots; i++ {
		if i == sel {
			continue
		}
		z2, ok2, masked := DecryptSlot(st, sk, ct, i, S)
		fmt.Printf("Unauthorized slot %d -> success:%v value:%v (masked GT size=%d bytes)\n",
			i, ok2, z2, len(masked.Marshal()))
	}
}

// fromMod interprets a Z_q representative as signed in a tiny range for printing
func fromMod(x *big.Int) int64 {
	if x == nil {
		return 0
	}
	half := new(big.Int).Rsh(q, 1)
	if x.Cmp(half) == 1 { // if x > q/2, treat as negative
		t := new(big.Int).Sub(x, q)
		return t.Int64()
	}
	return x.Int64()
}
