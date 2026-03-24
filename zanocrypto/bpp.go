package zanocrypto

import (
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// CT = crypto trait
// typedef bpp_crypto_trait_zano<bpp_ct_generators_UGX, 64,  32> bpp_crypto_trait_ZC_out
// template<typename gen_trait_t, size_t N = 64, size_t values_max = 32>
// src/crypto/range_proof_bpp.h

// BPPGen generates a Bulletproof+ range proof for the given values and masks.
// The commitments_1div8 are the pre-computed Pedersen commitments (pre-multiplied by 1/8).
func (trait *Trait) BPPGen(rnd io.Reader, values, masks []*edwards25519.Scalar, commitments_1div8 []*edwards25519.Point) (*zanobase.BPPSignature, error) {
	// Note: commitments_1div8 are supposed to be already calculated

	c_bpp_log2_m := ceilLog2(len(values))
	c_bpp_m := 1 << c_bpp_log2_m
	c_bpp_mn := c_bpp_m * trait.N

	// s.a. BP+ paper, page 15, eq. 11
	// decompose v into aL and aR:
	//   v = aL o (1, 2, 2^2, ..., 2^n-1),  o - component-wise product aka Hadamard product
	//   aR = aL - (1, 1, ... 1)
	//   aR o aL = 0

	// aLs = (aL_0, aL_1, ..., aL_m-1) -- `bit` matrix of c_bpp_m x trait.N, each element is a scalar
	// scalar_mat_t<CT::c_bpp_n> aLs(c_bpp_mn), aRs(c_bpp_mn)
	aLs := make([]*edwards25519.Scalar, c_bpp_mn)
	aRs := make([]*edwards25519.Scalar, c_bpp_mn)
	for n := range aLs {
		aLs[n] = new(edwards25519.Scalar)
		aRs[n] = new(edwards25519.Scalar)
	}

	for i := range values {
		v := values[i].Bytes()
		for j := 0; j < trait.N; j += 1 {
			// if (v.get_bit(j))
			if (v[j/8] & (1 << (j % 8))) != 0 {
				aLs[trait.at(i, j)] = ScOne // aL = 1, aR = 0
			} else {
				aRs[trait.at(i, j)] = ScM1 // aL = 0, aR = -1
			}
		}
	}
	for i := len(values); i < c_bpp_m; i++ {
		for j := 0; j < trait.N; j += 1 {
			aRs[trait.at(i, j)] = ScM1 // aL = 0, aR = -1
		}
	}

	// using e as Fiat-Shamir transcript
	hsc := NewHashHelper()
	e := TraitInitialTranscript()
	//log.Printf("initial transcript: %x", e.Bytes())

	// CT::update_transcript(hsc, e, commitments_1div8);
	e = TraitUpdateTranscript(hsc, e, commitments_1div8)

	// BP+ paper, page 15: The prover begins with sending A = g^aL h^aR h^alpha (group element)
	// so we calculate A0 = alpha * H + SUM(aL_i * G_i) + SUM(aR_i * H_i)

	alpha := RandomScalar(rnd)
	// const point_t& bpp_ct_generators_HGX::bpp_H   = c_point_G
	A0 := new(edwards25519.Point).ScalarMult(alpha, C_point_G)

	for i := range aLs {
		// A0 += aLs[i] * CT::get_generator(false, i) + aRs[i] * CT::get_generator(true, i);
		l := new(edwards25519.Point).ScalarMult(aLs[i], TraitGetGenerator(false, i))
		r := new(edwards25519.Point).ScalarMult(aRs[i], TraitGetGenerator(true, i))
		A0 = new(edwards25519.Point).Add(A0, l)
		A0 = new(edwards25519.Point).Add(A0, r)
	}

	// pre-multiply all output points by c_scalar_1div8
	// in order to enforce these points to be in the prime-order subgroup (after mul by 8 in bpp_verify())

	A0 = new(edwards25519.Point).ScalarMult(Sc1div8, A0)

	//log.Printf("alpha = %x", alpha.Bytes())
	//log.Printf("A0 = %x", A0.Bytes())

	// calculate scalar challenges y and z
	hsc.Add(e)
	hsc.Add(A0)
	y := hsc.CalcHash()
	z := HashToScalar(y.Bytes())
	e = z // transcript for further steps
	//log.Printf("y = %x", y.Bytes())
	//log.Printf("z = %x", z.Bytes())

	// Computing vector d for aggregated version of the protocol (BP+ paper, page 17)
	// (note: elements are stored column-by-column in memory)
	// d = | 1       * z^(2*1),        1 * z^(2*2),        1 * z^(2*3),      ...,        1 * z^(2*m)  |
	//     | 2       * z^(2*1),        2 * z^(2*2),        2 * z^(2*3),      ...,        2 * z^(2*m)  |
	//     | 4       * z^(2*1),        4 * z^(2*2),        4 * z^(2*3),      ...,        4 * z^(2*m)  |
	//     | .......................................................................................  |
	//     | 2^(n-1) * z^(2*1),  2^(n-1) * z^(2*2),  2^(n-1) * z^(2*3),      ...,  2^(n-1) * z^(2*m)) |
	// Note: sum(d_i) = (2^n - 1) * ((z^2)^1 + (z^2)^2 + ... (z^2)^m)) = (2^n-1) * sum_of_powers(x^2, log(m))

	z_sq := new(edwards25519.Scalar).Multiply(z, z)

	d := make([]*edwards25519.Scalar, c_bpp_mn)
	for n := range d {
		d[n] = new(edwards25519.Scalar)
	}
	d[0] = z_sq
	// first row
	prev := z_sq
	for i := 1; i < c_bpp_m; i += 1 {
		d[trait.at(i, 0)] = new(edwards25519.Scalar).Multiply(prev, z_sq)
	}
	// all rows
	for j := 1; j < trait.N; j += 1 {
		for i := 0; i < c_bpp_m; i += 1 {
			v := d[trait.at(i, j-1)]
			d[trait.at(i, j)] = new(edwards25519.Scalar).Add(v, v)
		}
	}

	// DBG_PRINT("Hs(d): " << d.calc_hs());
	//log.Printf("Hs(d): %x", HsB(bter(d)...).Bytes())

	// calculate extended Vandermonde vector y = (1, y, y^2, ..., y^(mn+1))   (BP+ paper, page 18, Fig. 3)
	// (calculate two more elements (1 and y^(mn+1)) for convenience)
	y_powers := make([]*edwards25519.Scalar, c_bpp_mn+2)
	y_powers[0] = ScalarInt(1)
	for i := 1; i <= c_bpp_mn+1; i += 1 {
		y_powers[i] = new(edwards25519.Scalar).Multiply(y_powers[i-1], y)
	}

	y_mn_p1 := y_powers[c_bpp_mn+1]

	// DBG_PRINT("Hs(y_powers): " << y_powers.calc_hs());
	//log.Printf("Hs(y_powers): %x", HsB(bter(y_powers)...).Bytes())

	// aL_hat = aL - 1*z
	aLs_hat := matSub(aLs, z)
	// aR_hat = aR + d o y^leftarr + 1*z where y^leftarr = (y^n, y^(n-1), ..., y)  (BP+ paper, page 18, Fig. 3)
	aRs_hat := matAdd(aRs, z)

	for i := range aRs_hat {
		// aRs_hat[i] += d[i] * y_powers[c_bpp_mn - i]
		aRs_hat[i] = aRs_hat[i].Add(aRs_hat[i], new(edwards25519.Scalar).Multiply(d[i], y_powers[c_bpp_mn-i]))
	}

	//log.Printf("Hs(aLs_hat): %x", HsB(bter(aLs_hat)...).Bytes())
	//log.Printf("Hs(aRs_hat): %x", HsB(bter(aRs_hat)...).Bytes())

	// calculate alpha_hat
	// alpha_hat = alpha + SUM(z^(2j) * gamma_j * y^(mn+1)) for j = 1..m
	// i.e. \hat{\alpha} = \alpha + y^{m n+1} \sum_{j = 1}^{m} z^{2j} \gamma_j
	alpha_hat := new(edwards25519.Scalar)
	for i := range masks {
		alpha_hat = alpha_hat.Add(alpha_hat, new(edwards25519.Scalar).Multiply(d[trait.at(i, 0)], masks[i]))
	}
	// alpha_hat = alpha + y_mn_p1 * alpha_hat
	alpha_hat = new(edwards25519.Scalar).Add(alpha, new(edwards25519.Scalar).Multiply(y_mn_p1, alpha_hat))

	//log.Printf("alpha_hat: %x", alpha_hat.Bytes())

	// calculate 1, y^-1, y^-2, ...
	y_inverse := new(edwards25519.Scalar).Invert(y)
	y_inverse_powers := make([]*edwards25519.Scalar, c_bpp_mn/2+1)
	y_inverse_powers[0] = ScalarInt(1)
	for i := 1; i < len(y_inverse_powers); i += 1 {
		y_inverse_powers[i] = new(edwards25519.Scalar).Multiply(y_inverse_powers[i-1], y_inverse)
	}

	// prepare generator's vector
	g := make([]*edwards25519.Point, c_bpp_mn)
	h := make([]*edwards25519.Point, c_bpp_mn)
	for i := range g {
		g[i] = TraitGetGenerator(false, i)
		h[i] = TraitGetGenerator(true, i)
	}

	// WIP zk-argument called with zk-WIP(g, h, G, H, A_hat, aL_hat, aR_hat, alpha_hat)
	a := aLs_hat
	b := aRs_hat

	res := new(zanobase.BPPSignature)
	res.A0 = &zanobase.Point{A0}

	// zk-WIP reduction rounds (s.a. the preprint page 13 Fig. 1)
	for n, ni := c_bpp_mn/2, 0; n >= 1; n, ni = n/2, ni+1 {
		//log.Printf("#%d (n=%d)", ni, n)
		// zk-WIP(g, h, G, H, P, a, b, alpha)
		dL := RandomScalar(rnd)
		dR := RandomScalar(rnd)
		//log.Printf("dL = %x", dL.Bytes())
		//log.Printf("dR = %x", dR.Bytes())

		// a = (a1, a2),  b = (b1, b2)                      -- vectors of scalars
		// cL = <a1, ((y, y^2, ...) o b2)>                  -- scalar
		cL := ScalarInt(0)
		for i := 0; i < n; i += 1 {
			// cL += a[i] * y_powers[i + 1] * b[n + i]
			tmp := new(edwards25519.Scalar).Multiply(new(edwards25519.Scalar).Multiply(a[i], y_powers[i+1]), b[n+i])
			cL = cL.Add(cL, tmp)
		}
		//log.Printf("cL = %x", cL.Bytes())

		// cR = <a2, ((y, y^2, ...) o b1)> * y^n            -- scalar
		cR := ScalarInt(0)
		for i := 0; i < n; i += 1 {
			// cR += a[n + i] * y_powers[i + 1] * b[i]
			tmp := new(edwards25519.Scalar).Multiply(new(edwards25519.Scalar).Multiply(a[n+i], y_powers[i+1]), b[i])
			cR = cR.Add(cR, tmp)
		}
		cR = cR.Multiply(cR, y_powers[n])
		//log.Printf("cR = %x", cR.Bytes())

		// L = y^-n * a1 * g2 + b2 * h1 + cL * G + dL * H   -- point
		sum := new(edwards25519.Point).Set(C_point_0)
		for i := 0; i < n; i += 1 {
			// sum += a[i] * g[n + i]
			sum = sum.Add(sum, new(edwards25519.Point).ScalarMult(a[i], g[n+i]))
		}
		//L := ct_calc_pedersen_commitment(cL, dL, L)
		L := trait.CalcPedersenCommitment(cL, dL)
		for i := 0; i < n; i += 1 {
			L = L.Add(L, new(edwards25519.Point).ScalarMult(b[n+i], h[i]))
		}
		L = L.Add(L, new(edwards25519.Point).ScalarMult(y_inverse_powers[n], sum))
		L = L.ScalarMult(Sc1div8, L)
		//log.Printf("L = %x", L.Bytes())

		// R = y^n  * a2 * g1 + b1 * h2 + cR * G + dR * H   -- point
		sum = sum.Set(C_point_0)
		for i := 0; i < n; i += 1 {
			// sum += a[n + i] * g[i]
			sum = sum.Add(sum, new(edwards25519.Point).ScalarMult(a[n+i], g[i]))
		}
		R := trait.CalcPedersenCommitment(cR, dR)
		for i := 0; i < n; i += 1 {
			// R += b[i] * h[n + i]
			R = R.Add(R, new(edwards25519.Point).ScalarMult(b[i], h[n+i]))
		}
		R = R.Add(R, new(edwards25519.Point).ScalarMult(y_powers[n], sum))
		R = R.ScalarMult(Sc1div8, R)
		//log.Printf("R = %x", R.Bytes())

		// put L, R to the sig
		res.Lv = append(res.Lv, &zanobase.Point{L})
		res.Rv = append(res.Rv, &zanobase.Point{R})

		// update the transcript
		hsc.Add(e)
		hsc.Add(L, R)
		e = hsc.CalcHash()
		//log.Printf("e = %x", e.Bytes())

		// recalculate arguments for the next round
		e_squared := new(edwards25519.Scalar).Multiply(e, e)
		e_inverse := new(edwards25519.Scalar).Invert(e)
		e_inverse_squared := new(edwards25519.Scalar).Multiply(e_inverse, e_inverse)
		e_y_inv_n := new(edwards25519.Scalar).Multiply(e, y_inverse_powers[n])
		e_inv_y_n := new(edwards25519.Scalar).Multiply(e_inverse, y_powers[n])

		// g_hat = e^-1 * g1 + (e * y^-n) * g2              -- vector of points
		for i := 0; i < n; i += 1 {
			// g[i] = e_inverse * g[i] + e_y_inv_n * g[n + i]
			tmp1 := new(edwards25519.Point).ScalarMult(e_inverse, g[i])
			tmp2 := new(edwards25519.Point).ScalarMult(e_y_inv_n, g[n+i])
			g[i] = new(edwards25519.Point).Add(tmp1, tmp2)
		}

		// h_hat = e * h1 + e^-1 * h2                       -- vector of points
		for i := 0; i < n; i += 1 {
			// h[i] = e * h[i] + e_inverse * h[n + i]
			tmp1 := new(edwards25519.Point).ScalarMult(e, h[i])
			tmp2 := new(edwards25519.Point).ScalarMult(e_inverse, h[n+i])
			h[i] = new(edwards25519.Point).Add(tmp1, tmp2)
		}

		// P_hat = e^2 * L + P + e^-2 * R                   -- point
		// (nothing)

		// a_hat = e * a1 + e^-1 * y^n * a2                 -- vector of scalars
		for i := 0; i < n; i += 1 {
			// a[i] = e * a[i] + e_inv_y_n * a[n + i]
			tmp1 := new(edwards25519.Scalar).Multiply(e, a[i])
			tmp2 := new(edwards25519.Scalar).Multiply(e_inv_y_n, a[n+i])
			a[i] = new(edwards25519.Scalar).Add(tmp1, tmp2)
		}

		// b_hat = e^-1 * b1 + e * b2                       -- vector of scalars
		for i := 0; i < n; i += 1 {
			// b[i] = e_inverse * b[i] + e * b[n + i]
			tmp1 := new(edwards25519.Scalar).Multiply(e_inverse, b[i])
			tmp2 := new(edwards25519.Scalar).Multiply(e, b[n+i])
			b[i] = new(edwards25519.Scalar).Add(tmp1, tmp2)
		}

		// alpha_hat = e^2 * dL + alpha + e^-2 * dR         -- scalar
		// alpha_hat += e_squared * dL + e_inverse_squared * dR
		tmpL := new(edwards25519.Scalar).Multiply(e_squared, dL)
		tmpR := new(edwards25519.Scalar).Multiply(e_inverse_squared, dR)
		alpha_hat = alpha_hat.Add(alpha_hat, new(edwards25519.Scalar).Add(tmpL, tmpR))

		// run next iteraton zk-WIP(g_hat, h_hat, G, H, P_hat, a_hat, b_hat, alpha_hat)
	}

	//log.Printf("#<last>")
	// zk-WIP last round

	r := RandomScalar(rnd)
	s := RandomScalar(rnd)
	delta := RandomScalar(rnd)
	eta := RandomScalar(rnd)
	//log.Printf("r = %x", r.Bytes())
	//log.Printf("s = %x", s.Bytes())
	//log.Printf("delta = %x", delta.Bytes())
	//log.Printf("eta = %x", eta.Bytes())

	// A = r * g + s * h + (r y b + s y a) * G + delta * H -- point
	// CT::calc_pedersen_commitment(y * (r * b[0] + s * a[0]), delta, A)
	tmp := new(edwards25519.Scalar).Add(new(edwards25519.Scalar).Multiply(r, b[0]), new(edwards25519.Scalar).Multiply(s, a[0]))
	A := trait.CalcPedersenCommitment(new(edwards25519.Scalar).Multiply(y, tmp), delta)
	// A += r * g[0] + s * h[0]
	A = A.Add(A, new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(r, g[0]), new(edwards25519.Point).ScalarMult(s, h[0])))
	// A *= c_scalar_1div8
	A = A.ScalarMult(Sc1div8, A)
	//log.Printf("A = %x", A.Bytes())
	res.A = &zanobase.Point{A}

	// B = (r * y * s) * G + eta * H
	// CT::calc_pedersen_commitment(r * y * s, eta, B)
	B := trait.CalcPedersenCommitment(new(edwards25519.Scalar).Multiply(new(edwards25519.Scalar).Multiply(r, y), s), eta)
	// B *= c_scalar_1div8
	B = B.ScalarMult(Sc1div8, B)
	//log.Printf("B = %x", B.Bytes())
	res.B = &zanobase.Point{B}

	// update the transcript
	hsc.Add(e, A, B)
	e = hsc.CalcHash()

	// finalize the signature
	// sig.r = r + e * a[0]
	res.R = &zanobase.Scalar{new(edwards25519.Scalar).Add(r, new(edwards25519.Scalar).Multiply(e, a[0]))}
	// sig.s = s + e * b[0]
	res.S = &zanobase.Scalar{new(edwards25519.Scalar).Add(s, new(edwards25519.Scalar).Multiply(e, b[0]))}
	// sig.delta = eta + e * delta + e * e * alpha_hat
	tmp1 := new(edwards25519.Scalar).Multiply(e, delta)
	tmp2 := new(edwards25519.Scalar).Multiply(new(edwards25519.Scalar).Multiply(e, e), alpha_hat)
	res.Delta = &zanobase.Scalar{new(edwards25519.Scalar).Add(new(edwards25519.Scalar).Add(eta, tmp1), tmp2)}

	return res, nil
}
