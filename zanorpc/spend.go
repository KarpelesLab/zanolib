package zanorpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"

	"github.com/KarpelesLab/zanolib"
	"github.com/KarpelesLab/zanolib/zanobase"
)

// RingSize is the total ring size for ZC inputs on mainnet
// (CURRENCY_HF4_MANDATORY_DECOY_SET_SIZE = 15 decoys + 1 real).
const RingSize = 16

// txHardforkID is the hardfork id carried by current (post-HF5) mainnet
// transactions; observed as 5 on all current v3 txs.
const txHardforkID = 5

// SweepTo builds, signs and (optionally) broadcasts a transaction that sends all
// of the given deposits back to recipient, deducting `fee` (native atomic units)
// from the native amount. Confidential-asset deposits are forwarded in full.
// Decoy rings are fetched per input via getrandom_outs3.
//
// It returns the signed transaction, its raw serialized bytes, and (if
// broadcast) the daemon status. The wallet must hold the spend secret.
func (c *Client) SweepTo(ctx context.Context, wallet *zanolib.Wallet, deposits []*Deposit, recipient string, fee uint64, broadcast bool) (*zanolib.FinalizedTx, []byte, string, error) {
	if len(deposits) == 0 {
		return nil, nil, "", fmt.Errorf("no deposits to sweep")
	}
	addr, err := zanolib.ParseAddress(recipient)
	if err != nil {
		return nil, nil, "", fmt.Errorf("recipient address: %w", err)
	}

	native := zanolib.NativeCoinAssetId()

	// Build inputs (fetch a decoy ring for each) and tally per-asset totals.
	var inputs []*zanolib.TransferInput
	totals := map[string]uint64{} // asset key -> total amount
	assetOrder := []string{}      // preserve first-seen order
	assetBytes := map[string]zanobase.Value256{}
	for _, d := range deposits {
		ring, err := c.GetRingForOutput(ctx, d.GlobalIndex, RingSize)
		if err != nil {
			return nil, nil, "", fmt.Errorf("decoys for gindex %d: %w", d.GlobalIndex, err)
		}
		members := make([]zanolib.RingMember, len(ring))
		for i, o := range ring {
			members[i] = zanolib.RingMember{
				GlobalIndex:      o.GlobalIndex,
				StealthAddress:   o.StealthAddress,
				ConcealingPoint:  o.ConcealingPoint,
				AmountCommitment: o.AmountCommitment,
				BlindedAssetId:   o.BlindedAssetId,
			}
		}
		inputs = append(inputs, &zanolib.TransferInput{
			Amount:              d.Out.Amount,
			AssetId:             d.Out.AssetId,
			AmountBlindingMask:  d.Out.AmountBlindingMask,
			AssetIdBlindingMask: d.Out.AssetIdBlindingMask,
			RealOutTxKey:        d.TxPubKey,
			RealOutIndex:        uint64(d.Out.OutputIndex),
			RealGlobalIndex:     d.GlobalIndex,
			Ring:                members,
		})
		k := string(d.Out.AssetId[:])
		if _, ok := totals[k]; !ok {
			assetOrder = append(assetOrder, k)
			assetBytes[k] = d.Out.AssetId
		}
		totals[k] += d.Out.Amount
	}

	// One destination per asset, all to the recipient; fee comes off native.
	var dests []*zanolib.TransferDest
	for _, k := range assetOrder {
		amount := totals[k]
		if k == string(native[:]) {
			if amount < fee {
				return nil, nil, "", fmt.Errorf("native total %d is less than fee %d", amount, fee)
			}
			amount -= fee
		}
		if amount == 0 {
			continue
		}
		dests = append(dests, &zanolib.TransferDest{
			Address: addr,
			AssetId: assetBytes[k],
			Amount:  amount,
		})
	}

	signed, err := wallet.BuildTransfer(rand.Reader, inputs, dests, zanobase.TransactionVersionPostHF5, txHardforkID)
	if err != nil {
		return nil, nil, "", fmt.Errorf("build transfer: %w", err)
	}

	var buf bytes.Buffer
	if err := zanobase.Serialize(&buf, signed.Tx); err != nil {
		return signed, nil, "", fmt.Errorf("serialize tx: %w", err)
	}
	raw := buf.Bytes()

	if !broadcast {
		return signed, raw, "", nil
	}
	status, err := c.SendRawTx(ctx, raw)
	if err != nil {
		return signed, raw, "", err
	}
	return signed, raw, status, nil
}
