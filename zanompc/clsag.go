package zanompc

import (
	"errors"
	"io"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// ClsagParty is one signer in a threshold CLSAG-GGX signature. It holds only the
// Lagrange-weighted additive share w (sum over the committee == the group spend
// secret x) and a fresh per-signature nonce alphaG. No party ever sees x or any
// other party's share.
type ClsagParty struct {
	w      *edwards25519.Scalar
	alphaG *edwards25519.Scalar
}

// NewClsagParty builds a signer from a FROST key share for the committee
// identified by shareIDs (this party at index i). If alphaG is nil a fresh nonce
// is sampled from rnd; tests may inject it.
func NewClsagParty(key *frosttss.Key, shareIDs []*big.Int, i int, alphaG *edwards25519.Scalar, rnd io.Reader) (*ClsagParty, error) {
	w, err := AdditiveShare(key, shareIDs, i)
	if err != nil {
		return nil, err
	}
	if alphaG == nil {
		alphaG = zanocrypto.RandomScalar(rnd)
	}
	return &ClsagParty{w: w, alphaG: alphaG}, nil
}

// Round1 returns this party's partial key image (w*kiBase) and its nonce
// commitments (alphaG*G, alphaG*kiBase).
func (p *ClsagParty) Round1(kiBase *edwards25519.Point) (partialKI, commitG, commitK *edwards25519.Point) {
	partialKI = new(edwards25519.Point).ScalarMult(p.w, kiBase)
	commitG = new(edwards25519.Point).ScalarBaseMult(p.alphaG)
	commitK = new(edwards25519.Point).ScalarMult(p.alphaG, kiBase)
	return
}

// Round2 returns this party's partial layer-0 response: alphaG - cPrev*aggCoeff0*w.
func (p *ClsagParty) Round2(cPrev, aggCoeff0 *edwards25519.Scalar) *edwards25519.Scalar {
	t := new(edwards25519.Scalar).Multiply(cPrev, aggCoeff0)
	t.Multiply(t, p.w)
	return new(edwards25519.Scalar).Subtract(p.alphaG, t)
}

// ClsagCoordinator drives the threshold CLSAG-GGX signature for one input. It
// knows everything public (the ring, key-image base, the per-tx blinding masks
// secret1F/secret2T, and the public per-output scalar hi where the effective
// spend secret is secret0Xp = hi + x). It never learns x.
type ClsagCoordinator struct {
	rnd                       io.Reader
	m                         []byte
	ring                      []zanocrypto.CLSAG_GGXInputRef
	pseudoOutAmountCommitment *edwards25519.Point
	pseudoOutBlindedAssetID   *edwards25519.Point
	secret1F, secret2T        *edwards25519.Scalar
	hi                        *edwards25519.Scalar // public: secret0Xp = hi + x
	spendPub                  *edwards25519.Point  // x*G (group key), for the stealth-consistency check
	secretIndex               uint64

	// state between phases
	kiBase    *edwards25519.Point
	ki        *edwards25519.Point
	inputHash []byte
	aggCoeff0 *edwards25519.Scalar
	aggCoeff1 *edwards25519.Scalar
	cPrev     *edwards25519.Scalar
	sig       *zanobase.CLSAG_Sig
}

// NewClsagCoordinator creates a coordinator. hi is the public per-output scalar
// (Hs(8*v*R, output_index) in Zano); for a standalone signature set hi to the
// zero scalar so secret0Xp == x.
func NewClsagCoordinator(rnd io.Reader, m []byte, ring []zanocrypto.CLSAG_GGXInputRef,
	pseudoOutAmountCommitment, pseudoOutBlindedAssetID *edwards25519.Point,
	secret1F, secret2T, hi *edwards25519.Scalar, spendPub *edwards25519.Point, secretIndex uint64) *ClsagCoordinator {
	return &ClsagCoordinator{
		rnd: rnd, m: m, ring: ring,
		pseudoOutAmountCommitment: pseudoOutAmountCommitment,
		pseudoOutBlindedAssetID:   pseudoOutBlindedAssetID,
		secret1F:                  secret1F, secret2T: secret2T, hi: hi, spendPub: spendPub,
		secretIndex: secretIndex,
	}
}

// KiBase returns Hp(real stealth address); parties need it for Round1.
func (c *ClsagCoordinator) KiBase() *edwards25519.Point {
	if c.kiBase == nil {
		c.kiBase = zanocrypto.Hp(c.ring[c.secretIndex].StealthAddress.Bytes())
	}
	return c.kiBase
}

// Phase1 consumes the parties' Round1 outputs, assembles the key image, runs the
// public ring of challenges, and returns (cPrev, aggCoeff0) for Round2.
func (c *ClsagCoordinator) Phase1(partialKIs, commitGs, commitKs []*edwards25519.Point) (cPrev, aggCoeff0 *edwards25519.Scalar, err error) {
	rs := len(c.ring)
	if c.secretIndex >= uint64(rs) {
		return nil, nil, errors.New("secretIndex out of range")
	}
	kiBase := c.KiBase()

	// key image: ki = hi*kiBase + sum(w_j*kiBase) = (hi+x)*kiBase
	ki := new(edwards25519.Point).ScalarMult(c.hi, kiBase)
	ki.Add(ki, CombinePoints(partialKIs))
	c.ki = ki

	// stealth consistency: ring[real].stealth must equal (hi+x)*G = hi*G + spendPub
	expStealth := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(c.hi), c.spendPub)
	if expStealth.Equal(c.ring[c.secretIndex].StealthAddress) != 1 {
		return nil, nil, errors.New("real stealth address does not match hi*G + spendPub")
	}

	// nonce commitments AG = alphaG*G, AK = alphaG*kiBase
	AG := CombinePoints(commitGs)
	AK := CombinePoints(commitKs)

	// K1, K2 from the per-tx masks (no spend key)
	K1div8 := new(edwards25519.Point).ScalarMult(new(edwards25519.Scalar).Multiply(zanocrypto.Sc1div8, c.secret1F), kiBase)
	K2div8 := new(edwards25519.Point).ScalarMult(new(edwards25519.Scalar).Multiply(zanocrypto.Sc1div8, c.secret2T), kiBase)
	K1 := new(edwards25519.Point).ScalarMult(zanocrypto.ScalarInt(8), K1div8)
	K2 := new(edwards25519.Point).ScalarMult(zanocrypto.ScalarInt(8), K2div8)

	sig := new(zanobase.CLSAG_Sig)
	sig.K1 = &zanobase.Point{Point: K1div8}
	sig.K2 = &zanobase.Point{Point: K2div8}

	// input_hash
	hsc := zanocrypto.NewHashHelper()
	hsc.AddBytesModL(c.m)
	for i := 0; i < rs; i++ {
		hsc.Add(c.ring[i].StealthAddress)
		hsc.Add(c.ring[i].AmountCommitment)
		hsc.Add(c.ring[i].BlindedAssetID)
	}
	hsc.Add(new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, c.pseudoOutAmountCommitment))
	hsc.Add(new(edwards25519.Point).ScalarMult(zanocrypto.Sc1div8, c.pseudoOutBlindedAssetID))
	hsc.Add(ki)
	hsc.Add(sig.K1.Point)
	hsc.Add(sig.K2.Point)
	c.inputHash = hsc.CalcRawHash()

	hsc.AddBytes(zanocrypto.CRYPTO_HDS_CLSAG_GGX_LAYER_0)
	hsc.AddBytes(c.inputHash)
	c.aggCoeff0 = hsc.CalcHash()
	hsc.AddBytes(zanocrypto.CRYPTO_HDS_CLSAG_GGX_LAYER_1)
	hsc.AddBytes(c.inputHash)
	c.aggCoeff1 = hsc.CalcHash()
	hsc.AddBytes(zanocrypto.CRYPTO_HDS_CLSAG_GGX_LAYER_2)
	hsc.AddBytes(c.inputHash)
	aggCoeff2 := hsc.CalcHash()

	WpubG := make([]*edwards25519.Point, rs)
	WpubX := make([]*edwards25519.Point, rs)
	for i := 0; i < rs; i++ {
		Ai := new(edwards25519.Point).ScalarMult(zanocrypto.ScalarInt(8), c.ring[i].AmountCommitment)
		Qi := new(edwards25519.Point).ScalarMult(zanocrypto.ScalarInt(8), c.ring[i].BlindedAssetID)
		t1 := new(edwards25519.Point).ScalarMult(c.aggCoeff0, c.ring[i].StealthAddress)
		t2 := new(edwards25519.Point).ScalarMult(c.aggCoeff1, new(edwards25519.Point).Subtract(Ai, c.pseudoOutAmountCommitment))
		WpubG[i] = new(edwards25519.Point).Add(t1, t2)
		WpubX[i] = new(edwards25519.Point).ScalarMult(aggCoeff2, new(edwards25519.Point).Subtract(Qi, c.pseudoOutBlindedAssetID))
	}
	WkeyImageG := new(edwards25519.Point).Add(
		new(edwards25519.Point).ScalarMult(c.aggCoeff0, ki),
		new(edwards25519.Point).ScalarMult(c.aggCoeff1, K1))
	WkeyImageX := new(edwards25519.Point).ScalarMult(aggCoeff2, K2)

	// X-layer nonce (not spend-key related) and first challenge
	alphaX := zanocrypto.RandomScalar(c.rnd)
	hsc.AddBytes(zanocrypto.CRYPTO_HDS_CLSAG_GGX_CHALLENGE)
	hsc.AddBytes(c.inputHash)
	hsc.Add(AG)
	hsc.Add(AK)
	hsc.Add(new(edwards25519.Point).ScalarMult(alphaX, zanocrypto.C_point_X))
	hsc.Add(new(edwards25519.Point).ScalarMult(alphaX, kiBase))
	cPrev = hsc.CalcHash()

	// decoy responses
	sig.Rg = make([]*zanobase.Scalar, rs)
	sig.Rx = make([]*zanobase.Scalar, rs)
	for i := 0; i < rs; i++ {
		sig.Rg[i] = &zanobase.Scalar{Scalar: zanocrypto.RandomScalar(c.rnd)}
		sig.Rx[i] = &zanobase.Scalar{Scalar: zanocrypto.RandomScalar(c.rnd)}
	}

	// ring loop (public), exactly as the single-key signer
	i := (int(c.secretIndex) + 1) % rs
	for j := 0; j < rs-1; j++ {
		if i == 0 {
			sig.C = &zanobase.Scalar{Scalar: new(edwards25519.Scalar).Set(cPrev)}
		}
		h := zanocrypto.NewHashHelper()
		h.AddBytes(zanocrypto.CRYPTO_HDS_CLSAG_GGX_CHALLENGE)
		h.AddBytes(c.inputHash)
		hpI := zanocrypto.Hp(c.ring[i].StealthAddress.Bytes())
		h.Add(new(edwards25519.Point).Add(
			new(edwards25519.Point).ScalarMult(sig.Rg[i].Scalar, zanocrypto.C_point_G),
			new(edwards25519.Point).ScalarMult(cPrev, WpubG[i])))
		h.Add(new(edwards25519.Point).Add(
			new(edwards25519.Point).ScalarMult(sig.Rg[i].Scalar, hpI),
			new(edwards25519.Point).ScalarMult(cPrev, WkeyImageG)))
		h.Add(new(edwards25519.Point).Add(
			new(edwards25519.Point).ScalarMult(sig.Rx[i].Scalar, zanocrypto.C_point_X),
			new(edwards25519.Point).ScalarMult(cPrev, WpubX[i])))
		h.Add(new(edwards25519.Point).Add(
			new(edwards25519.Point).ScalarMult(sig.Rx[i].Scalar, hpI),
			new(edwards25519.Point).ScalarMult(cPrev, WkeyImageX)))
		cPrev = h.CalcHash()
		i = (i + 1) % rs
	}
	if c.secretIndex == 0 {
		sig.C = &zanobase.Scalar{Scalar: new(edwards25519.Scalar).Set(cPrev)}
	}

	// X-layer real response (no spend key): rx[real] = alphaX - cPrev*aggCoeff2*secret2T
	wSecKeyX := new(edwards25519.Scalar).Multiply(aggCoeff2, c.secret2T)
	sig.Rx[c.secretIndex] = &zanobase.Scalar{Scalar: new(edwards25519.Scalar).Subtract(alphaX, new(edwards25519.Scalar).Multiply(cPrev, wSecKeyX))}

	c.cPrev = cPrev
	c.sig = sig
	return cPrev, c.aggCoeff0, nil
}

// Phase2 consumes the parties' Round2 partial responses and finalizes the
// signature. Returns the signature and the assembled key image.
func (c *ClsagCoordinator) Phase2(partialResponses []*edwards25519.Scalar) (*zanobase.CLSAG_Sig, *edwards25519.Point, error) {
	if c.sig == nil {
		return nil, nil, errors.New("Phase1 must run before Phase2")
	}
	// sum(partials) = alphaG - cPrev*aggCoeff0*x
	sum := new(edwards25519.Scalar)
	for _, r := range partialResponses {
		sum.Add(sum, r)
	}
	// subtract the public part: cPrev*(aggCoeff0*hi + aggCoeff1*secret1F)
	pub := new(edwards25519.Scalar).Multiply(c.aggCoeff0, c.hi)
	pub.Add(pub, new(edwards25519.Scalar).Multiply(c.aggCoeff1, c.secret1F))
	pub.Multiply(pub, c.cPrev)
	rgReal := new(edwards25519.Scalar).Subtract(sum, pub)
	c.sig.Rg[c.secretIndex] = &zanobase.Scalar{Scalar: rgReal}
	return c.sig, c.ki, nil
}
