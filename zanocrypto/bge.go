package zanocrypto

import (
	"errors"
	"io"
	"sync"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// src/crypto/one_out_of_many_proofs.cpp

// Generate_BGE_Proof generates a Background Equivalence (one-out-of-many)
// proof demonstrating that the prover knows the discrete log of one element
// in the ring, without revealing which one.
func Generate_BGE_Proof(rnd io.Reader, contextHash []byte, ring []*edwards25519.Point, secret *edwards25519.Scalar, secretIndex int) (*zanobase.BGEProof, error) {
	res := new(zanobase.BGEProof)
	n := 4 // TODO: @#@# move it out

	ringSize := len(ring)
	if ringSize == 0 {
		return nil, errors.New("Generate_BGE_Proof: empty ring")
	}
	if secretIndex >= ringSize {
		return nil, errors.New("Generate_BGE_Proof: invalid secretIndex")
	}

	// const size_t m = std::max(static_cast<uint64_t>(1), constexpr_ceil_log_n(ring_size, n));
	m := max(1, ceilLogN(ringSize, n))
	// const size_t N = constexpr_pow(m, n);
	N := intPow(n, m) // constexpr_pow() arguments are reversed
	// const size_t mn = m * n;
	mn := m * n

	//log.Printf("m=%d n=%d N=%d mn=%d", m, n, N, mn)

	// create a m x n matrix of scalars
	aMat := make([]*edwards25519.Scalar, mn)
	idx := func(a, b int) int {
		return a*m + b
	}
	lDigits := make([]int, m)
	l := secretIndex
	for j := 0; j < m; j += 1 {
		aMat[idx(j, 0)] = new(edwards25519.Scalar)
		for i := n - 1; i != 0; i -= 1 {
			aMat[idx(j, i)] = RandomScalar(rnd)
			aMat[idx(j, 0)] = aMat[idx(j, 0)].Subtract(aMat[idx(j, 0)], aMat[idx(j, i)])
		}
		digit := l % n // j-th digit of secret_index
		lDigits[j] = digit
		l = l / n
	}

	// coeffs calculation (naive implementation, consider optimization in future)
	coeffs := make([]*edwards25519.Scalar, N*m) // m x N matrix
	for i := range coeffs {
		coeffs[i] = new(edwards25519.Scalar)
	}
	one := ScalarInt(1)
	for i := 0; i < N; i += 1 {
		coeffs[i] = one // first row is (1, ..., 1)
		i_tmp := i
		m_bound := 1
		for j := 0; j < m; j += 1 {
			i_j := i_tmp % n // j-th digit of i
			i_tmp /= n

			if i_j == lDigits[j] {
				carry := new(edwards25519.Scalar)
				for k := 0; k < m_bound; k += 1 {
					old := coeffs[k*N+i]
					coeffs[k*N+i] = new(edwards25519.Scalar).Multiply(coeffs[k*N+i], aMat[idx(j, i_j)])
					coeffs[k*N+i] = coeffs[k*N+i].Add(coeffs[k*N+i], carry)
					carry = old
				}
				if m_bound < m {
					addPScalar(&coeffs[m_bound*N+i], carry)
				}
				m_bound += 1
			} else {
				for k := 0; k < m_bound; k += 1 {
					coeffs[k*N+i] = new(edwards25519.Scalar).Multiply(coeffs[k*N+i], aMat[idx(j, i_j)])
				}
			}
		}
	}

	r_A := RandomScalar(rnd)
	r_B := RandomScalar(rnd)
	ro := make([]*edwards25519.Scalar, m)
	for n := range ro {
		ro[n] = RandomScalar(rnd)
	}

	A := C_point_0
	B := C_point_0

	r, r2 := false, false

	for j := 0; j < m; j += 1 {
		for i := 0; i < n; i += 1 {
			gen_1 := get_BGE_generator((j*n+i)*2+0, &r)
			gen_2 := get_BGE_generator((j*n+i)*2+1, &r2)
			if !(r && r2) {
				return nil, errors.New("failed to run get_BGE_generator")
			}
			a := aMat[idx(j, i)]
			//A += a * gen_1 - a * a * gen_2
			A1 := new(edwards25519.Point).ScalarMult(a, gen_1)                                       // a * gen_1
			A2 := new(edwards25519.Point).ScalarMult(new(edwards25519.Scalar).Multiply(a, a), gen_2) // a * a * gen_2
			A = new(edwards25519.Point).Add(A, new(edwards25519.Point).Subtract(A1, A2))

			if lDigits[j] == i {
				// B += gen_1 - a * gen_2
				B = new(edwards25519.Point).Add(B, new(edwards25519.Point).Subtract(gen_1, new(edwards25519.Point).ScalarMult(a, gen_2)))
			} else {
				// B += a * gen_2
				B = new(edwards25519.Point).Add(B, new(edwards25519.Point).ScalarMult(a, gen_2))
			}
		}

		Pk := C_point_0
		for i := 0; i < ringSize; i += 1 {
			// Pk += coeffs[j * N + i] * ring[i]
			Pk = new(edwards25519.Point).Add(Pk, new(edwards25519.Point).ScalarMult(coeffs[j*N+i], ring[i]))
		}
		for i := ringSize; i < N; i += 1 {
			// Pk += coeffs[j * N + i] * ring[ring_size - 1]
			Pk = new(edwards25519.Point).Add(Pk, new(edwards25519.Point).ScalarMult(coeffs[j*N+i], ring[ringSize-1]))
		}

		// Pk += ro[j] * c_point_X
		Pk = new(edwards25519.Point).Add(Pk, new(edwards25519.Point).ScalarMult(ro[j], C_point_X))
		res.Pk = append(res.Pk, &zanobase.Point{new(edwards25519.Point).ScalarMult(Sc1div8, Pk)})
	}

	// A += r_A * c_point_X
	A = new(edwards25519.Point).Add(A, new(edwards25519.Point).ScalarMult(r_A, C_point_X))
	res.A = &zanobase.Point{new(edwards25519.Point).ScalarMult(Sc1div8, A)}
	// B += r_B * c_point_X
	B = new(edwards25519.Point).Add(B, new(edwards25519.Point).ScalarMult(r_B, C_point_X))
	res.B = &zanobase.Point{new(edwards25519.Point).ScalarMult(Sc1div8, B)}

	hsc := NewHashHelper()
	hsc.AddBytes(contextHash)
	for _, el := range ring {
		hsc.Add(new(edwards25519.Point).ScalarMult(Sc1div8, el))
	}
	hsc.Add(res.A.Point)
	hsc.Add(res.B.Point)
	for _, el := range res.Pk {
		hsc.Add(el.Point)
	}
	x := hsc.CalcHash()
	//log.Printf("x = %x", x.Bytes())
	res.F = make([]*zanobase.Scalar, m*(n-1))

	for j := 0; j < m; j += 1 {
		for i := 1; i < n; i += 1 {
			// result.f[j * (n - 1) + i - 1] = a_mat(j, i)
			res.F[j*(n-1)+i-1] = &zanobase.Scalar{aMat[idx(j, i)]}
			if lDigits[j] == i {
				// result.f[j * (n - 1) + i - 1] += x
				addRefScalar(&res.F[j*(n-1)+i-1], x)
			}
		}
	}

	// result.y = r_A + x * r_B
	rY := new(edwards25519.Scalar).Add(r_A, new(edwards25519.Scalar).Multiply(x, r_B))
	res.Y = &zanobase.Scalar{rY}

	rZ := new(edwards25519.Scalar)
	xPower := ScalarInt(1)
	for k := 0; k < m; k += 1 {
		// result.z -= x_power * ro[k]
		rZ = rZ.Subtract(rZ, new(edwards25519.Scalar).Multiply(xPower, ro[k]))
		xPower = xPower.Multiply(xPower, x)
	}
	res.Z = &zanobase.Scalar{rZ.Add(rZ, new(edwards25519.Scalar).Multiply(secret, xPower))}

	return res, nil
}

var (
	precalculatedGenerators []*edwards25519.Point
	precalcGenOnce          sync.Once
)

func get_BGE_generator(index int, ok *bool) *edwards25519.Point {
	precalcGenOnce.Do(func() {
		precalculatedGenerators = make([]*edwards25519.Point, 32) // mn_max == 16; use mn_max*2
		var buf [64]byte
		copy(buf[:], HashToScalar([]byte("Zano BGE generator")).Bytes())

		for i := range precalculatedGenerators {
			buf[32] = byte(i)
			precalculatedGenerators[i] = Hp(buf[:])
		}
	})
	if index >= len(precalculatedGenerators) {
		*ok = false
		return C_point_0
	}
	*ok = true
	return precalculatedGenerators[index]
}
