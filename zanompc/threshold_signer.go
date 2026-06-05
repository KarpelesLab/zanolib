package zanompc

import (
	"context"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/tss-lib/v2/frosttss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// ThresholdInputSigner implements zanolib.InputSigner using a FROST-ed25519 key
// share over tss-lib's transport. The spend secret exists only as shares; this
// signer contributes its partials and, together with the other committee
// members, produces the key image (KeyImage) and CLSAG signature (SignCLSAG)
// without anyone reconstructing the secret. Every committee member runs an
// identical ThresholdInputSigner; they exchange round messages over the broker.
//
// KeyImage and SignCLSAG are called by zanolib.Wallet.SignWith once per input,
// in source order (all KeyImage calls happen before the prefix hash is known,
// then all SignCLSAG calls); this signer pairs them by call order.
type ThresholdInputSigner struct {
	ctx      context.Context
	params   *tss.Parameters
	subset   *frosttss.Key
	spendPub *edwards25519.Point

	inputs []*thresholdInput // per-input state, appended by KeyImage
	signN  int               // SignCLSAG consumption index
}

type thresholdInput struct {
	idx        int
	party      *ClsagParty
	kiBase     *edwards25519.Point
	r1         []*clsagRound1msg
	partialKIs []*edwards25519.Point
	commitGs   []*edwards25519.Point
	commitKs   []*edwards25519.Point
}

// NewThresholdInputSigner builds a signer for this party's key share over the
// signing committee params.Parties() (whose PartyID.Key must be the keygen
// ShareIDs, as produced by tss.NewPartyID(_, _, key.ShareID)).
func NewThresholdInputSigner(ctx context.Context, params *tss.Parameters, key *frosttss.Key) (*ThresholdInputSigner, error) {
	subset, err := key.SubsetForParties(params.Parties().IDs())
	if err != nil {
		return nil, err
	}
	spendPub, err := SpendPublicKey(subset.GroupPublicKey)
	if err != nil {
		return nil, err
	}
	return &ThresholdInputSigner{ctx: ctx, params: params, subset: subset, spendPub: spendPub}, nil
}

func (s *ThresholdInputSigner) otherIDs() []*tss.PartyID {
	var others []*tss.PartyID
	me := s.params.PartyID().Index
	for n, p := range s.params.Parties().IDs() {
		if n != me {
			others = append(others, p)
		}
	}
	return others
}

// KeyImage runs round 1 (partial key image + nonce commitments) over the broker
// and returns the combined key image hi*kiBase + sum_j(w_j*kiBase) = (hi+x)*Hp(inEPub).
func (s *ThresholdInputSigner) KeyImage(hi *edwards25519.Scalar, inEPub *edwards25519.Point) (*edwards25519.Point, error) {
	idx := len(s.inputs)
	party, err := NewClsagParty(s.subset, s.subset.Ks, s.params.PartyID().Index, nil, s.params.Rand())
	if err != nil {
		return nil, err
	}
	kiBase := zanocrypto.Hp(inEPub.Bytes())
	myKI, myCG, myCK := party.Round1(kiBase)
	mine := &clsagRound1msg{KI: myKI.Bytes(), CommitG: myCG.Bytes(), CommitK: myCK.Bytes()}

	collected, err := exchange(s.ctx, s.params, fmt.Sprintf("zano:clsag:ki:%d", idx), mine)
	if err != nil {
		return nil, err
	}

	n := s.params.PartyCount()
	in := &thresholdInput{idx: idx, party: party, kiBase: kiBase,
		r1: collected, partialKIs: make([]*edwards25519.Point, n),
		commitGs: make([]*edwards25519.Point, n), commitKs: make([]*edwards25519.Point, n)}
	for i, m := range collected {
		if in.partialKIs[i], err = pt(m.KI); err != nil {
			return nil, err
		}
		if in.commitGs[i], err = pt(m.CommitG); err != nil {
			return nil, err
		}
		if in.commitKs[i], err = pt(m.CommitK); err != nil {
			return nil, err
		}
	}
	s.inputs = append(s.inputs, in)

	ki := new(edwards25519.Point).ScalarMult(hi, kiBase)
	ki.Add(ki, CombinePoints(in.partialKIs))
	return ki, nil
}

// SignCLSAG runs the challenge + response round over the broker and assembles
// the CLSAG-GGX signature. Per-signature non-secret randomness is derived
// deterministically from the round-1 transcript, so all parties agree.
func (s *ThresholdInputSigner) SignCLSAG(_ io.Reader, hi *edwards25519.Scalar, msg []byte, ring []zanocrypto.CLSAG_GGXInputRef,
	keyImage, pseudoOutAmountCommitment, pseudoOutBlindedAssetID *edwards25519.Point,
	secret1F, secret2T *edwards25519.Scalar, secretIndex uint64) (*zanobase.CLSAG_Sig, error) {
	if s.signN >= len(s.inputs) {
		return nil, fmt.Errorf("zanompc: SignCLSAG called more times than KeyImage")
	}
	in := s.inputs[s.signN]
	s.signN++

	rnd := newTranscriptReader(msg, ring, in.r1)
	coord := NewClsagCoordinator(rnd, msg, ring, pseudoOutAmountCommitment, pseudoOutBlindedAssetID,
		secret1F, secret2T, hi, s.spendPub, secretIndex)
	cPrev, agg0, err := coord.Phase1(in.partialKIs, in.commitGs, in.commitKs)
	if err != nil {
		return nil, err
	}
	myResp := in.party.Round2(cPrev, agg0)

	collected, err := exchange(s.ctx, s.params, fmt.Sprintf("zano:clsag:resp:%d", in.idx), &clsagRound2msg{Resp: myResp.Bytes()})
	if err != nil {
		return nil, err
	}
	resps := make([]*edwards25519.Scalar, len(collected))
	for i, m := range collected {
		if resps[i], err = sc(m.Resp); err != nil {
			return nil, err
		}
	}
	sig, _, err := coord.Phase2(resps)
	return sig, err
}

// exchange broadcasts mine and blocks until messages from all other parties
// arrive, returning the full set indexed by PartyID.Index.
func exchange[T any](ctx context.Context, params *tss.Parameters, typ string, mine *T) ([]*T, error) {
	n := params.PartyCount()
	out := make([]*T, n)
	out[params.PartyID().Index] = mine

	var others []*tss.PartyID
	me := params.PartyID().Index
	for k, p := range params.Parties().IDs() {
		if k != me {
			others = append(others, p)
		}
	}

	done := make(chan struct{})
	params.Broker().Connect(typ, tss.NewJsonExpect[T](typ, others, func(ids []*tss.PartyID, msgs []*T) {
		for k, id := range ids {
			out[id.Index] = msgs[k]
		}
		close(done)
	}))
	params.Broker().Receive(tss.JsonWrap(typ, mine, params.PartyID(), nil))

	if len(others) == 0 {
		return out, nil
	}
	select {
	case <-done:
		return out, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
