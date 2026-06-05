package zanolib

import (
	"fmt"
	"io"
	"sort"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// v256ToPoint decodes a Value256 into an edwards25519 point (nil if invalid).
func v256ToPoint(v zanobase.Value256) *edwards25519.Point {
	return v.ToPoint()
}

// RingMember is one output in an input's decoy ring (the real output plus
// decoys), identified by its chain-wide global index. The point fields are the
// on-chain (1/8-premultiplied) values, exactly as returned by the daemon.
type RingMember struct {
	GlobalIndex      uint64
	StealthAddress   zanobase.Value256
	ConcealingPoint  zanobase.Value256
	AmountCommitment zanobase.Value256
	BlindedAssetId   zanobase.Value256
}

// TransferInput describes one output to spend: the data recovered by ScanTx
// (amount, asset id, blinding masks, the depositing tx public key and output
// index) plus a ring of decoys (which must include the real output, located by
// RealGlobalIndex).
type TransferInput struct {
	Amount              uint64
	AssetId             zanobase.Value256 // unblinded asset id (native = native coin asset id)
	AmountBlindingMask  *zanobase.Scalar
	AssetIdBlindingMask *zanobase.Scalar
	RealOutTxKey        zanobase.Value256 // tx public key of the depositing tx
	RealOutIndex        uint64            // output index within the depositing tx
	RealGlobalIndex     uint64            // chain-wide global index of the real output
	Ring                []RingMember      // decoys + the real output
}

// TransferDest is an output to create: send Amount of AssetId to Address.
type TransferDest struct {
	Address *Address
	AssetId zanobase.Value256
	Amount  uint64
}

// BuildTransfer assembles a FinalizeTxParam from spendable inputs and
// destinations and signs it, producing a ready-to-broadcast transaction. The
// fee is implicit: it is the native-asset surplus (sum of native inputs minus
// native outputs), so the caller controls it by choosing destination amounts.
// Every non-native asset must balance (inputs == outputs).
func (w *Wallet) BuildTransfer(rnd io.Reader, inputs []*TransferInput, dests []*TransferDest, version, hardforkID uint64) (*FinalizedTx, error) {
	if w.IsViewOnly() {
		return nil, fmt.Errorf("cannot build a transfer with a view-only wallet")
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs")
	}

	ftp := &FinalizeTxParam{
		SpendPubKey:  &zanobase.Point{Point: w.SpendPubKey},
		TxVersion:    version,
		TxHardforkId: hardforkID,
	}

	for _, in := range inputs {
		src, err := in.toSource()
		if err != nil {
			return nil, err
		}
		ftp.Sources = append(ftp.Sources, src)
	}

	for _, d := range dests {
		if d.Address == nil {
			return nil, fmt.Errorf("destination with nil address")
		}
		assetPt := v256ToPoint(d.AssetId)
		if assetPt == nil {
			return nil, fmt.Errorf("destination has invalid asset id")
		}
		acc := &zanobase.AccountPublicAddr{Flags: d.Address.Flags}
		copy(acc.SpendKey[:], d.Address.SpendKey)
		copy(acc.ViewKey[:], d.Address.ViewKey)
		ftp.PreparedDestinations = append(ftp.PreparedDestinations, &TxDest{
			Amount:  d.Amount,
			Addr:    []*zanobase.AccountPublicAddr{acc},
			AssetId: &zanobase.Point{Point: assetPt},
		})
	}

	return w.Sign(rnd, ftp, nil)
}

// toSource converts a TransferInput into a TxSource, sorting the ring by global
// index and locating the real output within it.
func (in *TransferInput) toSource() (*TxSource, error) {
	if len(in.Ring) == 0 {
		return nil, fmt.Errorf("input has empty ring")
	}
	ring := make([]RingMember, len(in.Ring))
	copy(ring, in.Ring)
	sort.Slice(ring, func(i, j int) bool { return ring[i].GlobalIndex < ring[j].GlobalIndex })

	realIndex := -1
	outs := make([]*TxSourceOutputEntry, len(ring))
	for i, m := range ring {
		if i > 0 && ring[i-1].GlobalIndex == m.GlobalIndex {
			return nil, fmt.Errorf("duplicate ring member global index %d", m.GlobalIndex)
		}
		stealth := v256ToPoint(m.StealthAddress)
		concealing := v256ToPoint(m.ConcealingPoint)
		commitment := v256ToPoint(m.AmountCommitment)
		blinded := v256ToPoint(m.BlindedAssetId)
		if stealth == nil || concealing == nil || commitment == nil || blinded == nil {
			return nil, fmt.Errorf("ring member %d (gindex %d) has an invalid point", i, m.GlobalIndex)
		}
		outs[i] = &TxSourceOutputEntry{
			OutReference:     zanobase.VariantFor(m.GlobalIndex),
			StealthAddress:   &zanobase.Point{Point: stealth},
			ConcealingPoint:  &zanobase.Point{Point: concealing},
			AmountCommitment: &zanobase.Point{Point: commitment},
			BlindedAssetID:   &zanobase.Point{Point: blinded},
		}
		if m.GlobalIndex == in.RealGlobalIndex {
			realIndex = i
		}
	}
	if realIndex < 0 {
		return nil, fmt.Errorf("real output (gindex %d) not found in ring", in.RealGlobalIndex)
	}

	txKey := v256ToPoint(in.RealOutTxKey)
	if txKey == nil {
		return nil, fmt.Errorf("invalid real_out_tx_key")
	}
	assetPt := v256ToPoint(in.AssetId)
	if assetPt == nil {
		return nil, fmt.Errorf("invalid source asset id")
	}

	return &TxSource{
		Outputs:                    outs,
		RealOutput:                 uint64(realIndex),
		RealOutTxKey:               &zanobase.Point{Point: txKey},
		RealOutAmountBlindingMask:  in.AmountBlindingMask,
		RealOutAssetIdBlindingMask: in.AssetIdBlindingMask,
		RealOutInTxIndex:           in.RealOutIndex,
		Amount:                     in.Amount,
		assetId:                    &zanobase.Point{Point: assetPt},
		isZCInput:                  true,
	}, nil
}

// NativeCoinAssetId returns the native coin asset id (Value256), useful when
// constructing native-coin TransferInputs/TransferDests.
func NativeCoinAssetId() zanobase.Value256 {
	var v zanobase.Value256
	copy(v[:], zanocrypto.NativeCoinAssetIdPt.Bytes())
	return v
}
