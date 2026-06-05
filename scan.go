package zanolib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
)

// Domain separators for output decoding (must match zano's CRYPTO_HDS_OUT_*).
// CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK is declared in signature.go.
var (
	cryptoHdsOutAmountMask      = []byte("ZANO_HDS_OUT_AMOUNT_MASK_______\x00")
	cryptoHdsOutConcealingPoint = []byte("ZANO_HDS_OUT_CONCEALING_POINT__\x00")
	cryptoHdsOutAssetBlindMask  = []byte("ZANO_HDS_OUT_ASSET_BLIND_MASK__\x00")
)

// ReceivedOutput is a transaction output detected as belonging to the wallet.
// AmountBlindingMask and AssetIdBlindingMask are retained so the output can
// later be turned into a spendable tx_source_entry.
type ReceivedOutput struct {
	OutputIndex         int               `json:"output_index"`
	Amount              uint64            `json:"amount"`
	AssetId             zanobase.Value256 `json:"asset_id"`
	IsNative            bool              `json:"is_native"`
	StealthAddress      zanobase.Value256 `json:"stealth_address"`
	AmountBlindingMask  *zanobase.Scalar  `json:"amount_blinding_mask"`
	AssetIdBlindingMask *zanobase.Scalar  `json:"asset_id_blinding_mask"`
}

// ScanResult holds the outputs of a transaction that belong to the wallet,
// along with the recovered integrated-address payment ID (if any).
type ScanResult struct {
	TxPubKey  zanobase.Value256 `json:"tx_pub_key"`
	Outputs   []*ReceivedOutput `json:"outputs"`
	PaymentId []byte            `json:"payment_id,omitempty"`
}

// Found reports whether any output of the scanned transaction belongs to the wallet.
func (r *ScanResult) Found() bool { return r != nil && len(r.Outputs) > 0 }

// ScanTx inspects a transaction and returns the outputs that belong to this
// wallet (decoding amount and asset id for each), plus the decrypted payment ID
// if the transaction carries one. It is the receive-side inverse of Sign and
// mirrors currency::lookup_acc_outs / is_out_to_acc / decode_output_amount_and_asset_id.
//
// Only the wallet's view secret key is required, so this works for view-only
// wallets. A transaction with no tx public key, or none of whose outputs belong
// to the wallet, yields a ScanResult with an empty Outputs slice (not an error).
func (w *Wallet) ScanTx(tx *zanobase.Transaction) (*ScanResult, error) {
	res := &ScanResult{}

	txPub, ok := getTxPubKey(tx)
	if !ok {
		return res, nil // no tx pub key => nothing addressed to us
	}
	res.TxPubKey = txPub
	txPubPt := txPub.ToPoint()
	if txPubPt == nil {
		return res, errors.New("scan: invalid tx public key in extra")
	}

	// recv_derivation = 8 * view_secret * tx_pub_key
	derivation, err := zanocrypto.GenerateKeyDerivation(txPubPt, w.ViewPrivKey)
	if err != nil {
		return nil, err
	}
	derivationBytes := derivation.Bytes()

	for i, v := range tx.Vout {
		if v.Tag != zanobase.TagTxOutZarcanum {
			continue // only Zarcanum (HF4+) outputs are supported
		}
		zo := zanobase.VariantAs[*zanobase.TxOutZarcanium](v)

		// h = Hs(8 * r * V, i)
		h := zanocrypto.HashToScalar(slices.Concat(derivationBytes, zanobase.Varint(i).Bytes()))

		// P' = h*G + spend_public_key =? stealth_address  (definitive ownership test)
		expStealth := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarBaseMult(h), w.SpendPubKey)
		if !bytes.Equal(expStealth.Bytes(), zo.StealthAddress[:]) {
			continue
		}

		out, err := w.decodeOutput(i, zo, h)
		if err != nil {
			return nil, err
		}
		res.Outputs = append(res.Outputs, out)
	}

	if pid, ok := w.recoverPaymentId(tx, derivationBytes); ok {
		res.PaymentId = pid
	}

	return res, nil
}

// decodeOutput decodes a Zarcanum output already confirmed to be ours (its
// stealth address matched), recovering amount + asset id and validating the
// amount commitment and concealing point. Mirrors decode_output_amount_and_asset_id.
func (w *Wallet) decodeOutput(i int, zo *zanobase.TxOutZarcanium, h *edwards25519.Scalar) (*ReceivedOutput, error) {
	hb := h.Bytes()

	// amount = encrypted_amount XOR Hs(AMOUNT_MASK, h)[:8]
	amountMask := zanocrypto.HashToScalar(slices.Concat(cryptoHdsOutAmountMask, hb))
	amount := zo.EncryptedAmount ^ binary.LittleEndian.Uint64(amountMask.Bytes()[:8])

	amountBlindingMask := zanocrypto.HashToScalar(slices.Concat(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, hb))

	blindedAssetIdPt := zo.BlindedAssetId.ToPoint()
	if blindedAssetIdPt == nil {
		return nil, errors.New("scan: invalid blinded_asset_id")
	}
	blindedAssetFull := zanocrypto.Mul8(blindedAssetIdPt) // 8 * stored

	// Validate amount: A' = amount*blinded_asset_id_full + amount_blinding_mask*G =? 8*amount_commitment
	aPrime := new(edwards25519.Point).Add(
		new(edwards25519.Point).ScalarMult(zanocrypto.ScalarInt(amount), blindedAssetFull),
		new(edwards25519.Point).ScalarMult(amountBlindingMask, zanocrypto.C_point_G),
	)
	amountCommitmentPt := zo.AmountCommitment.ToPoint()
	if amountCommitmentPt == nil {
		return nil, errors.New("scan: invalid amount_commitment")
	}
	if aPrime.Equal(zanocrypto.Mul8(amountCommitmentPt)) != 1 {
		return nil, errors.New("scan: amount commitment mismatch for owned output (malformed tx?)")
	}

	// Validate concealing point: Hs(CONCEALING, h) * view_public_key =? concealing_point
	hQ := zanocrypto.HashToScalar(slices.Concat(cryptoHdsOutConcealingPoint, hb))
	qPrime := new(edwards25519.Point).ScalarMult(hQ, w.ViewPubKey)
	if !bytes.Equal(qPrime.Bytes(), zo.ConcealingPoint[:]) {
		return nil, errors.New("scan: concealing point mismatch for owned output (malformed tx?)")
	}

	out := &ReceivedOutput{
		OutputIndex:        i,
		Amount:             amount,
		StealthAddress:     zo.StealthAddress,
		AmountBlindingMask: &zanobase.Scalar{Scalar: amountBlindingMask},
	}

	// Asset id: H = blinded_asset_id - asset_id_blinding_mask * X.
	if blindedAssetFull.Equal(zanocrypto.NativeCoinAssetIdPt) == 1 {
		// unblinded native coin
		out.IsNative = true
		out.AssetIdBlindingMask = &zanobase.Scalar{Scalar: zanocrypto.ScalarInt(0)}
		copy(out.AssetId[:], zanocrypto.NativeCoinAssetIdPt.Bytes())
	} else {
		assetBlindingMask := zanocrypto.HashToScalar(slices.Concat(cryptoHdsOutAssetBlindMask, hb))
		assetPt := new(edwards25519.Point).Subtract(blindedAssetFull, new(edwards25519.Point).ScalarMult(assetBlindingMask, zanocrypto.C_point_X))
		out.AssetIdBlindingMask = &zanobase.Scalar{Scalar: assetBlindingMask}
		out.IsNative = assetPt.Equal(zanocrypto.NativeCoinAssetIdPt) == 1
		copy(out.AssetId[:], assetPt.Bytes())
	}

	return out, nil
}

// getTxPubKey extracts the single transaction public key (TagPubKey) from the
// transaction extra, returning false if absent.
func getTxPubKey(tx *zanobase.Transaction) (zanobase.Value256, bool) {
	for _, e := range tx.Extra {
		if e.Tag == zanobase.TagPubKey {
			return zanobase.VariantAs[zanobase.Value256](e), true
		}
	}
	return zanobase.Value256{}, false
}

// recoverPaymentId finds the integrated-address payment ID service attachment
// (service_id == "P") in the transaction extra/attachments and decrypts its body
// with the income key derivation (the same 8*v*R used for output detection).
func (w *Wallet) recoverPaymentId(tx *zanobase.Transaction, derivationBytes []byte) ([]byte, bool) {
	find := func(items []*zanobase.Variant) (*zanobase.TxServiceAttachment, bool) {
		for _, e := range items {
			if e.Tag != zanobase.TagServiceAttachment {
				continue
			}
			sa := zanobase.VariantAs[*zanobase.TxServiceAttachment](e)
			if sa.ServiceId == zanobase.PaymentIdServiceId {
				return sa, true
			}
		}
		return nil, false
	}

	sa, ok := find(tx.Extra)
	if !ok {
		sa, ok = find(tx.Attachment)
	}
	if !ok {
		return nil, false
	}

	body := slices.Clone(sa.Body)
	if sa.Flags&zanobase.TxServiceAttachmentEncryptBody != 0 {
		// chacha_crypt(body, derivation): keystream is keyed by the derivation.
		code, err := zanocrypto.ChaCha8GenerateKey(derivationBytes)
		if err != nil {
			return nil, false
		}
		dec, err := zanocrypto.ChaCha8(code, make([]byte, 8), body)
		if err != nil {
			return nil, false
		}
		body = dec
	}
	return body, true
}
