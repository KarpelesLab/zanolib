package zanompc

import (
	"context"
	"fmt"
	"sync"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"golang.org/x/crypto/sha3"
)

// ClsagContext is the public signing context for one Zano ZC input, identical
// across every signer. secret0Xp = Hi + x, where Hi is the public per-output
// scalar (Hs(8*v*R, output_index)) and x is the threshold spend secret.
type ClsagContext struct {
	Message                   []byte // 32-byte tx hash for signature
	Ring                      []zanocrypto.CLSAG_GGXInputRef
	PseudoOutAmountCommitment *edwards25519.Point
	PseudoOutBlindedAssetID   *edwards25519.Point
	Secret1F, Secret2T        *edwards25519.Scalar // per-tx blinding masks (not the spend key)
	Hi                        *edwards25519.Scalar // public per-output scalar
	SpendPub                  *edwards25519.Point  // group spend public key (x*G)
	SecretIndex               uint64
}

type clsagRound1msg struct {
	KI      []byte `json:"ki"`       // w_i * kiBase
	CommitG []byte `json:"commit_g"` // alphaG_i * G
	CommitK []byte `json:"commit_k"` // alphaG_i * kiBase
}

type clsagRound2msg struct {
	Resp []byte `json:"resp"` // alphaG_i - cPrev*aggCoeff0*w_i
}

// ClsagResult is the output of a threshold CLSAG signing session.
type ClsagResult struct {
	Sig      *zanobase.CLSAG_Sig
	KeyImage *edwards25519.Point
}

// ClsagSigning runs a threshold CLSAG-GGX signature for one input over tss-lib's
// transport (the same MessageBroker used by frosttss). It is a non-coordinator,
// two-round protocol: every party broadcasts its partial key image + nonce
// commitments (round 1) then its partial response (round 2), and each party
// independently assembles the identical final signature, delivered on Done.
//
// The non-secret per-signature randomness (the X-layer nonce and decoy
// responses) is derived deterministically from the round-1 transcript so all
// parties agree without a coordinator.
type ClsagSigning struct {
	ctx    context.Context
	params *tss.Parameters
	sctx   *ClsagContext
	party  *ClsagParty
	kiBase *edwards25519.Point
	myR1   *clsagRound1msg
	coord  *ClsagCoordinator
	cPrev  *edwards25519.Scalar
	agg0   *edwards25519.Scalar
	myResp *edwards25519.Scalar

	Done chan *ClsagResult
	Err  chan error

	doneOnce, errOnce sync.Once
}

func sendOnce[T any](once *sync.Once, ch chan T, v T) {
	once.Do(func() { ch <- v })
}

// NewClsagSigning starts a threshold CLSAG signing session. The signing
// committee is params.Parties(); the committee size must be at least
// threshold+1. key is this party's FROST key share.
func NewClsagSigning(ctx context.Context, params *tss.Parameters, key *frosttss.Key, sctx *ClsagContext) (*ClsagSigning, error) {
	if params.PartyCount() < params.Threshold()+1 {
		return nil, fmt.Errorf("zanompc: committee size %d < threshold+1 (%d)", params.PartyCount(), params.Threshold()+1)
	}
	if int(sctx.SecretIndex) >= len(sctx.Ring) {
		return nil, fmt.Errorf("zanompc: secret index out of range")
	}
	// Reindex the key share for this signing committee. The committee party IDs
	// must carry the keygen ShareIDs as their Key (so SubsetForParties matches);
	// the committee's Lagrange basis is subset.Ks.
	subset, err := key.SubsetForParties(params.Parties().IDs())
	if err != nil {
		return nil, err
	}
	myIdx := params.PartyID().Index
	party, err := NewClsagParty(subset, subset.Ks, myIdx, nil, params.Rand())
	if err != nil {
		return nil, err
	}
	s := &ClsagSigning{
		ctx:    ctx,
		params: params,
		sctx:   sctx,
		party:  party,
		kiBase: zanocrypto.Hp(sctx.Ring[sctx.SecretIndex].StealthAddress.Bytes()),
		Done:   make(chan *ClsagResult, 1),
		Err:    make(chan error, 1),
	}
	if err := s.round1(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ClsagSigning) otherIDs() []*tss.PartyID {
	var others []*tss.PartyID
	me := s.params.PartyID().Index
	for n, p := range s.params.Parties().IDs() {
		if n == me {
			continue
		}
		others = append(others, p)
	}
	return others
}

func (s *ClsagSigning) round1() error {
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	ki, cg, ck := s.party.Round1(s.kiBase)
	s.myR1 = &clsagRound1msg{KI: ki.Bytes(), CommitG: cg.Bytes(), CommitK: ck.Bytes()}

	others := s.otherIDs()
	s.params.Broker().Receive(tss.JsonWrap("zano:clsag:round1", s.myR1, s.params.PartyID(), nil))
	rcv := tss.NewJsonExpect[clsagRound1msg]("zano:clsag:round1", others, s.round2)
	s.params.Broker().Connect("zano:clsag:round1", rcv)
	return nil
}

func (s *ClsagSigning) round2(ids []*tss.PartyID, msgs []*clsagRound1msg) {
	if s.ctx.Err() != nil {
		sendOnce(&s.errOnce, s.Err, s.ctx.Err())
		return
	}
	n := s.params.PartyCount()
	r1 := make([]*clsagRound1msg, n)
	r1[s.params.PartyID().Index] = s.myR1
	for k, id := range ids {
		r1[id.Index] = msgs[k]
	}

	partialKIs := make([]*edwards25519.Point, n)
	commitGs := make([]*edwards25519.Point, n)
	commitKs := make([]*edwards25519.Point, n)
	for i, m := range r1 {
		if m == nil {
			sendOnce(&s.errOnce, s.Err, fmt.Errorf("missing round1 message for committee index %d", i))
			return
		}
		var err error
		if partialKIs[i], err = pt(m.KI); err != nil {
			sendOnce(&s.errOnce, s.Err, err)
			return
		}
		if commitGs[i], err = pt(m.CommitG); err != nil {
			sendOnce(&s.errOnce, s.Err, err)
			return
		}
		if commitKs[i], err = pt(m.CommitK); err != nil {
			sendOnce(&s.errOnce, s.Err, err)
			return
		}
	}

	// Deterministic per-signature randomness (X-layer nonce + decoys) from the
	// round-1 transcript: identical for every party, so no coordinator is needed.
	rnd := newTranscriptReader(s.sctx.Message, s.sctx.Ring, r1)
	s.coord = NewClsagCoordinator(rnd, s.sctx.Message, s.sctx.Ring,
		s.sctx.PseudoOutAmountCommitment, s.sctx.PseudoOutBlindedAssetID,
		s.sctx.Secret1F, s.sctx.Secret2T, s.sctx.Hi, s.sctx.SpendPub, s.sctx.SecretIndex)

	cPrev, agg0, err := s.coord.Phase1(partialKIs, commitGs, commitKs)
	if err != nil {
		sendOnce(&s.errOnce, s.Err, err)
		return
	}
	s.cPrev, s.agg0 = cPrev, agg0
	s.myResp = s.party.Round2(cPrev, agg0)

	others := s.otherIDs()
	r2 := &clsagRound2msg{Resp: s.myResp.Bytes()}
	s.params.Broker().Receive(tss.JsonWrap("zano:clsag:round2", r2, s.params.PartyID(), nil))
	rcv := tss.NewJsonExpect[clsagRound2msg]("zano:clsag:round2", others, s.finalize)
	s.params.Broker().Connect("zano:clsag:round2", rcv)
}

func (s *ClsagSigning) finalize(ids []*tss.PartyID, msgs []*clsagRound2msg) {
	if s.ctx.Err() != nil {
		sendOnce(&s.errOnce, s.Err, s.ctx.Err())
		return
	}
	resps := make([]*edwards25519.Scalar, 0, s.params.PartyCount())
	resps = append(resps, s.myResp)
	for _, m := range msgs {
		r, err := sc(m.Resp)
		if err != nil {
			sendOnce(&s.errOnce, s.Err, err)
			return
		}
		resps = append(resps, r)
	}
	sig, ki, err := s.coord.Phase2(resps)
	if err != nil {
		sendOnce(&s.errOnce, s.Err, err)
		return
	}
	// Local validity check before declaring success.
	ok, err := zanocrypto.VerifyCLSAG_GGX(s.sctx.Message, s.sctx.Ring, ki, s.sctx.PseudoOutAmountCommitment, s.sctx.PseudoOutBlindedAssetID, sig)
	if err != nil || !ok {
		sendOnce(&s.errOnce, s.Err, fmt.Errorf("threshold CLSAG failed local verification (ok=%v err=%v)", ok, err))
		return
	}
	sendOnce(&s.doneOnce, s.Done, &ClsagResult{Sig: sig, KeyImage: ki})
}

// newTranscriptReader returns a deterministic byte stream seeded by the message,
// ring, and round-1 transcript — used for the non-secret per-signature
// randomness (X-layer nonce + decoy responses) so all parties agree.
func newTranscriptReader(msg []byte, ring []zanocrypto.CLSAG_GGXInputRef, r1 []*clsagRound1msg) sha3.ShakeHash {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("ZANO_THRESHOLD_CLSAG_DETRAND\x00"))
	h.Write(msg)
	for _, r := range ring {
		h.Write(r.StealthAddress.Bytes())
		h.Write(r.AmountCommitment.Bytes())
		h.Write(r.BlindedAssetID.Bytes())
	}
	for _, m := range r1 {
		h.Write(m.KI)
		h.Write(m.CommitG)
		h.Write(m.CommitK)
	}
	seed := h.Sum(nil)
	xof := sha3.NewShake256()
	xof.Write(seed)
	return xof
}

func pt(b []byte) (*edwards25519.Point, error) {
	return new(edwards25519.Point).SetBytes(b)
}

func sc(b []byte) (*edwards25519.Scalar, error) {
	return new(edwards25519.Scalar).SetCanonicalBytes(b)
}
