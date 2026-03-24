package zanolib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"

	"filippo.io/edwards25519"
	"github.com/KarpelesLab/zanolib/zanobase"
	"github.com/KarpelesLab/zanolib/zanocrypto"
	"github.com/KarpelesLab/zanolib/zanoproof"
)

var (
	CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK = []byte("ZANO_HDS_OUT_AMOUNT_BLIND_MASK_\x00")
)

// Sign constructs and signs a Zano transaction from the given finalization
// parameters. If oneTimeKey is nil, a random key is generated. The method
// builds the transaction structure, generates CLSAG-GGX ring signatures for
// each input, and produces balance, range, and asset surjection proofs.
func (w *Wallet) Sign(rnd io.Reader, ftp *FinalizeTxParam, oneTimeKey *edwards25519.Scalar) (*FinalizedTx, error) {
	if !bytes.Equal(ftp.SpendPubKey.Bytes(), w.SpendPubKey.Bytes()) {
		return nil, errors.New("spend key does not match")
	}

	if ftp.TxVersion != 2 {
		// TODO add support for TransactionV3 with HardforkId
		return nil, fmt.Errorf("unsupported tx version = %d", ftp.TxVersion)
	}
	tx := &zanobase.Transaction{Version: 2}
	res := &FinalizedTx{
		Tx:  tx,
		FTP: new(FinalizeTxParam),
	}
	// make sure res.FTP unaffected by sources reordering locally
	*res.FTP = *ftp
	res.FTP.Sources = slices.Clone(res.FTP.Sources)

	ogc := &zanobase.GenContext{
		AoAmountBlindingMask: &zanobase.Scalar{zanocrypto.ScalarInt(0)},
	}

	// void wallet2::sign_transfer(const std::string& tx_sources_blob, std::string& signed_tx_blob, currency::transaction& tx)
	// @ src/wallet/wallet2.cpp 4299

	// finalize_transaction(ft.ftp, ft.tx, ft.one_time_key, false);
	// @ src/wallet/wallet2.cpp 7954

	// currency::construct_tx(m_account.get_keys(), ftp, result);
	// @ src/currency_core/currency_format_utils.cpp 2372

	// construct tx uses some method to get an intial value?
	if oneTimeKey == nil {
		oneTimeKey = zanocrypto.GenerateKeyScalar()
	}

	priv := oneTimeKey
	pub := zanocrypto.PubFromPriv(priv)

	res.OneTimeKey = &zanobase.Scalar{priv}
	ogc.TxPubKeyP = &zanobase.Point{pub}
	ogc.TxKey = &zanobase.KeyPair{Sec: &zanobase.Scalar{priv}, Pub: &zanobase.Point{pub}}
	var pubV zanobase.Value256
	copy(pubV[:], pub.Bytes())
	//slices.Reverse(oneTimeKey)
	//priv, pub, err := edwards25519.PrivKeyFromScalar(oneTimeKey)

	tx.Extra = append(tx.Extra, &zanobase.Variant{Tag: zanobase.TagPubKey, Value: pubV})
	tx.Extra = append(tx.Extra, &zanobase.Variant{Tag: zanobase.TagEtcTxFlags16, Value: uint16(0)}) // Flags

	// use ftp.Sources
	for _, src := range ftp.Sources {
		vin := &zanobase.TxInZcInput{}
		realOut := src.Outputs[src.RealOutput]

		var prev uint64
		for _, out := range src.Outputs {
			// generate_key_image_helper(sender_account_keys, src_entr.real_out_tx_key, src_entr.real_output_in_tx_index, in_context.in_ephemeral, img))
			// → derive_ephemeral_key_helper(ack, tx_public_key, real_output_index, in_ephemeral)
			//   → crypto::generate_key_derivation(tx_public_key, ack.view_secret_key, recv_derivation)
			// → crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, ki)
			val := zanobase.VariantAs[uint64](out.OutReference)
			cur := val - prev
			prev = val
			vin.KeyOffsets = append(vin.KeyOffsets, zanobase.VariantFor(cur))
		}

		// Derive ephemeral
		realOutTxKey := new(edwards25519.Point).Set(src.RealOutTxKey.Point)

		// generate_key_image_helper(sender_account_keys, src_entr.real_out_tx_key,
		derivation, err := zanocrypto.GenerateKeyDerivation(realOutTxKey, w.ViewPrivKey)
		if err != nil {
			return nil, err
		}
		in_e_pub, err := zanocrypto.DerivePublicKey(derivation.Bytes(), src.RealOutInTxIndex, w.SpendPubKey)
		if err != nil {
			return nil, err
		}
		in_e_sec, err := zanocrypto.DeriveSecretKey(derivation.Bytes(), src.RealOutInTxIndex, w.SpendPrivKey)
		if err != nil {
			return nil, err
		}
		src.ephemeral = &zanobase.KeyPair{Sec: &zanobase.Scalar{in_e_sec}, Pub: &zanobase.Point{in_e_pub}}
		// in_context.in_ephemeral.pub == in_context.outputs[in_context.real_out_index].stealth_address
		if !bytes.Equal(in_e_pub.Bytes(), realOut.StealthAddress.Bytes()) {
			return nil, errors.New("derived public key missmatch with output public key!")
		}
		// key image
		keyImage, err := zanocrypto.ComputeKeyImage(in_e_sec, in_e_pub)
		if err != nil {
			return nil, err
		}
		vin.KeyImage = &zanobase.Point{keyImage}
		//RealOutTxKey               Value256 // crypto::public_key
		//RealOutAmountBlindingMask  Value256 // crypto::scalar_t
		//RealOutAssetIdBlindingMask Value256 // crypto::scalar_t
		//RealOutInTxIndex           uint64   // size_t, index in transaction outputs vector
		tx.Vin = append(tx.Vin, zanobase.VariantFor(vin))
	}

	// TODO use zc_inputs_count instead of len(ftp.Sources)
	ogc.Resize(len(ftp.Sources), len(ftp.PreparedDestinations))

	// asset_descriptor_operation* pado = get_type_in_variant_container<asset_descriptor_operation>(tx.extra);
	// bool r = construct_tx_handle_ado(sender_account_keys, ftp, *pado, gen_context, gen_context.tx_key, shuffled_dsts);

	// TODO shuffle
	indices := make([]int, len(ftp.PreparedDestinations))
	for i := range indices {
		indices[i] = i
	}

	hints := make(map[uint16]bool)

	// prepared outs
	for _, i := range indices {
		outputIndex := len(tx.Vout)
		dst := ftp.PreparedDestinations[i]
		// derivation = (crypto::scalar_t(tx_sec_key) * crypto::point_t(apa.view_public_key)).modify_mul8().to_public_key(); // d = 8 * r * V
		dstViewKey, err := new(edwards25519.Point).SetBytes(dst.Addr[0].ViewKey[:])
		if err != nil {
			return nil, err
		}
		derivation, err := zanocrypto.GenerateKeyDerivation(dstViewKey, priv)
		if err != nil {
			return nil, err
		}

		// store derivation hint into the tx
		hint := zanocrypto.DerivationHint(derivation)
		hints[hint] = true

		// compute scalar for derivation
		// crypto::derivation_to_scalar((const crypto::key_derivation&)derivation, output_index, h.as_secret_key()); // h = Hs(8 * r * V, i)
		scalar := zanocrypto.HashToScalar(slices.Concat(derivation.Bytes(), zanobase.Varint(outputIndex).Bytes()))

		amountMask := zanocrypto.HashToScalar(slices.Concat([]byte("ZANO_HDS_OUT_AMOUNT_MASK_______\x00"), scalar.Bytes()))
		amountBlindingMask := zanocrypto.HashToScalar(slices.Concat(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, scalar.Bytes()))
		ogc.AmountBlindingMasks[i] = &zanobase.Scalar{new(edwards25519.Scalar).Set(amountBlindingMask)}

		//UnlockTime      uint64               //
		vout := &zanobase.TxOutZarcanium{
			EncryptedAmount: dst.Amount ^ binary.LittleEndian.Uint64(amountMask.Bytes()[:8]),
		}
		copy(vout.StealthAddress[:], dst.StealthAddress(scalar, ogc, i).Bytes())
		copy(vout.ConcealingPoint[:], dst.ConcealingPoint(scalar, ogc, i).Bytes())
		copy(vout.BlindedAssetId[:], dst.BlindedAssetId(scalar, ogc, i).Bytes())
		copy(vout.AmountCommitment[:], dst.AmountCommitment(scalar, ogc, i).Bytes())

		// if audit address, set vout.MixAttr=1
		if dst.Addr[0].Flags&1 == 1 {
			vout.MixAttr = 1 // CURRENCY_TO_KEY_OUT_FORCED_NO_MIX
		}

		// gen_context.amounts[output_index] = dst_entr.amount
		ogc.Amounts[i] = &zanobase.Scalar{zanocrypto.ScalarInt(dst.Amount)}
		// gen_context.asset_ids[output_index] = crypto::point_t(dst_entr.asset_id)
		ogc.AssetIds[i] = dst.AssetId
		// gen_context.asset_id_blinding_mask_x_amount_sum += gen_context.asset_id_blinding_masks[output_index] * dst_entr.amount
		addRefScalar(&ogc.AssetIdBlindingMaskXAmountSum, new(edwards25519.Scalar).Multiply(ogc.AssetIdBlindingMasks[i].Scalar, zanocrypto.ScalarInt(dst.Amount)))
		// gen_context.amount_blinding_masks_sum += gen_context.amount_blinding_masks[output_index]
		addRefScalar(&ogc.AmountBlindingMasksSum, ogc.AmountBlindingMasks[i].Scalar)
		// gen_context.amount_commitments_sum += gen_context.amount_commitments[output_index]
		addRefPoint(&ogc.AmountCommitmentsSum, ogc.AmountCommitments[i].Point)

		tx.Vout = append(tx.Vout, zanobase.VariantFor(vout))
	}

	for len(hints) < len(tx.Vout) {
		// add_random_derivation_hints_and_put_them_to_tx
		// uint16_t hint = crypto::rand<uint16_t>()
		var rndHint [2]byte
		_, err := io.ReadFull(rnd, rndHint[:])
		if err != nil {
			return nil, err
		}
		rndHintV := binary.LittleEndian.Uint16(rndHint[:])
		hints[rndHintV+uint16(len(hints))] = true // add +len(hints) so we don't loop to infinity if using a fixed rndreader
	}

	hintsArray := make([]uint16, 0, len(hints))
	for hint := range hints {
		hintsArray = append(hintsArray, hint)
	}
	slices.Sort(hintsArray)

	for _, hint := range hintsArray {
		tx.Extra = append(tx.Extra, &zanobase.Variant{Tag: zanobase.TagDerivationHint, Value: []byte{byte(hint & 0xff), byte((hint >> 8) & 0xff)}})
	}

	// compute total in & total out, compute fee
	var totalIn, totalOut uint64
	for _, src := range ftp.Sources {
		totalIn += src.Amount
	}
	for _, dst := range ftp.PreparedDestinations {
		totalOut += dst.Amount
	}

	// sort tx.Vin & ftp.Sources by Vin.KeyImage
	// duplicate ftp
	sort.Sort(&ftpSrcSorter{tx, ftp})

	if totalIn > totalOut {
		// add fee to extras
		tx.Extra = append(tx.Extra, &zanobase.Variant{Tag: zanobase.TagZarcaniumTxDataV1, Value: &zanobase.ZarcaniumTxDataV1{Fee: totalIn - totalOut}})
	}

	// generate proofs and signatures
	// (any changes made below should only affect the signatures/proofs and should not impact the prefix hash calculation)

	txId, err := tx.Prefix().Hash()
	if err != nil {
		return nil, err
	}
	//log.Printf("tx_id = %x (1e78c6f279553e4832a888e429fcc1b2c049d4e8b68cdb8ea9f98a50bc4a95b6)", txId)

	for n, src := range ftp.Sources {
		if src.IsZC() {
			// r = generate_ZC_sig(tx_hash_for_signature, i_ + input_starter_index, source_entry, in_contexts[i_mapped], sender_account_keys, flags, gen_context, tx, i_ + 1 == sources.size(), separately_signed_tx_complete)
			sig := new(zanobase.ZCSig)

			txHashForSig, err := zanocrypto.PreparePrefixHashForSign(tx, n, txId)
			if err != nil {
				return nil, err
			}
			src.generateZCSig(rnd, tx, n, sig, txHashForSig, ogc)
			tx.Signatures = append(tx.Signatures, &zanobase.Variant{Tag: zanobase.TagZCSig, Value: sig})
		}
	}

	// proofs (transaction-wise, not pre-input)
	// if (tx.version > TRANSACTION_VERSION_PRE_HF4 && (append_mode || (flags & TX_FLAG_SIGNATURE_MODE_SEPARATE) == 0))

	// asset surjection proof
	//bool r = generate_asset_surjection_proof(tx_prefix_hash, has_non_zc_inputs, gen_context, asp);
	err = zanoproof.GenerateAssetSurjectionProof(rnd, tx, txId, ogc)
	if err != nil {
		return nil, fmt.Errorf("while generating asset surjection proof: %w", err)
	}

	// range proofs
	// r = generate_zc_outs_range_proof(tx_prefix_hash, gen_context, tx.vout, range_proofs)
	err = zanoproof.GenerateZcOutsRangeProof(rnd, tx, txId, ogc)
	if err != nil {
		return nil, fmt.Errorf("while generating zc outs range proof: %w", err)
	}

	// balance proof
	// r = generate_tx_balance_proof(tx, tx_prefix_hash, gen_context, 0, balance_proof)
	err = zanoproof.GenerateTxBalanceProof(rnd, tx, txId, ogc, 0)
	if err != nil {
		return nil, fmt.Errorf("while generating tx balance proof: %w", err)
	}

	return res, nil
}

func addRefScalar(v **zanobase.Scalar, a *edwards25519.Scalar) {
	if (*v) == nil {
		(*v) = &zanobase.Scalar{new(edwards25519.Scalar).Set(a)}
		return
	}
	(*v).Scalar = new(edwards25519.Scalar).Add((*v).Scalar, a)
}

func addRefPoint(v **zanobase.Point, a *edwards25519.Point) {
	if (*v) == nil {
		(*v) = &zanobase.Point{new(edwards25519.Point).Set(a)}
		return
	}
	(*v).Point = new(edwards25519.Point).Add((*v).Point, a)
}
