package zanolib

import (
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// InputSigner produces the two spend-key-dependent values for one ZC input: the
// key image and the CLSAG-GGX ring signature. The effective per-input secret is
// secret0Xp = hi + x, where hi is the public per-output scalar
// (Hs(8*v*R, output_index)) and x is the wallet spend secret. A local signer
// holds x directly; a threshold signer (see the zanompc package) holds it as
// shares and never reconstructs it.
//
// Sign calls KeyImage for every input first (key images are part of the tx
// prefix), then — once the prefix hash is known — SignCLSAG for each input.
type InputSigner interface {
	// KeyImage returns the key image for an input whose real output has the
	// given stealth address inEPub and public per-output scalar hi.
	KeyImage(hi *edwards25519.Scalar, inEPub *edwards25519.Point) (*edwards25519.Point, error)

	// SignCLSAG produces the CLSAG-GGX signature for an input. keyImage is the
	// value previously returned by KeyImage; secret1F/secret2T are the per-tx
	// blinding-mask secrets (not the spend key); ring/pseudo-outs/secretIndex
	// describe the input.
	SignCLSAG(rnd io.Reader, hi *edwards25519.Scalar, msg []byte, ring []zanocrypto.CLSAG_GGXInputRef,
		keyImage, pseudoOutAmountCommitment, pseudoOutBlindedAssetID *edwards25519.Point,
		secret1F, secret2T *edwards25519.Scalar, secretIndex uint64) (*zanobase.CLSAG_Sig, error)
}

// localInputSigner signs with the spend secret held in-process (the default,
// non-MPC path). It reproduces the original signing behavior exactly.
type localInputSigner struct {
	spendSecret *edwards25519.Scalar
}

// LocalInputSigner returns an InputSigner backed by an in-process spend secret.
func LocalInputSigner(spendSecret *edwards25519.Scalar) InputSigner {
	return &localInputSigner{spendSecret: spendSecret}
}

func (l *localInputSigner) inESec(hi *edwards25519.Scalar) *edwards25519.Scalar {
	// in_e_sec = Hs(8*v*R, i) + spend_secret = hi + x
	return new(edwards25519.Scalar).Add(hi, l.spendSecret)
}

func (l *localInputSigner) KeyImage(hi *edwards25519.Scalar, inEPub *edwards25519.Point) (*edwards25519.Point, error) {
	return zanocrypto.ComputeKeyImage(l.inESec(hi), inEPub)
}

func (l *localInputSigner) SignCLSAG(rnd io.Reader, hi *edwards25519.Scalar, msg []byte, ring []zanocrypto.CLSAG_GGXInputRef,
	keyImage, pseudoOutAmountCommitment, pseudoOutBlindedAssetID *edwards25519.Point,
	secret1F, secret2T *edwards25519.Scalar, secretIndex uint64) (*zanobase.CLSAG_Sig, error) {
	return zanocrypto.GenerateCLSAG_GGX(rnd, msg, ring, keyImage, pseudoOutAmountCommitment, pseudoOutBlindedAssetID,
		l.inESec(hi), secret1F, secret2T, secretIndex)
}
