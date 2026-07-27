//! Transaction construction and signing.

use crate::base::gencontext::GenContext;
use crate::base::tx::{
    TRANSACTION_VERSION_POST_HF4, TRANSACTION_VERSION_POST_HF5, Transaction, TxInZcInput,
    TxOutZarcanum,
};
use crate::base::types::{KeyPair, Value256};
use crate::base::variant::Variant;
use crate::crypto::consts::NATIVE_COIN_ASSET_ID_PT;
use crate::crypto::{
    Point, Scalar, derivation_hint, derive_public_key, generate_key_derivation, hash_to_scalar,
    pub_from_priv, scalar_int,
};
use crate::error::{Error, Result};
use crate::finalized::FinalizedTx;
use crate::ftp::FinalizeTxParam;
use crate::inputsigner::{InputSigner, LocalInputSigner};
use crate::proof;
use crate::rng::RngCore;
use crate::txdest::{CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, CRYPTO_HDS_OUT_AMOUNT_MASK, hs_domain};
use crate::wallet::Wallet;
use std::collections::{BTreeMap, BTreeSet};

impl Wallet {
    /// Constructs and signs a transaction from finalization parameters, using
    /// the wallet's own spend secret.
    ///
    /// If `one_time_key` is `None` a fresh key is generated from `rnd`.
    pub fn sign(
        &self,
        rnd: &mut dyn RngCore,
        ftp: &FinalizeTxParam,
        one_time_key: Option<Scalar>,
    ) -> Result<FinalizedTx> {
        let spend = self.spend_priv_key.clone().ok_or_else(|| {
            Error::msg("cannot sign with a view-only wallet (no spend secret key)")
        })?;
        let mut signer = LocalInputSigner::new(spend);
        self.sign_with(rnd, ftp, one_time_key, &mut signer)
    }

    /// Like [`Wallet::sign`], but the spend-key-dependent steps (key image and
    /// CLSAG signature) go through `signer`.
    ///
    /// This lets a view-only wallet drive signing via a threshold/MPC signer:
    /// the spend secret is never held locally. The wallet's view key and spend
    /// public key are still used for the (public) ephemeral-key derivation and
    /// output construction.
    pub fn sign_with(
        &self,
        rnd: &mut dyn RngCore,
        ftp: &FinalizeTxParam,
        one_time_key: Option<Scalar>,
        signer: &mut dyn InputSigner,
    ) -> Result<FinalizedTx> {
        if ftp.spend_pub_key != self.spend_pub_key {
            return Err(Error::msg("spend key does not match"));
        }
        // Both post-HF4 (v2) and post-HF5 (v3) transactions are supported; v3
        // only adds a hardfork_id byte to the prefix, the crypto is identical.
        if ftp.tx_version != TRANSACTION_VERSION_POST_HF4
            && ftp.tx_version != TRANSACTION_VERSION_POST_HF5
        {
            return Err(crate::err!("unsupported tx version = {}", ftp.tx_version));
        }

        let mut ftp = ftp.clone();
        let mut tx = Transaction {
            version: ftp.tx_version,
            hardfork_id: if ftp.tx_version >= TRANSACTION_VERSION_POST_HF5 {
                ftp.tx_hardfork_id as u8
            } else {
                0
            },
            ..Default::default()
        };

        let mut ogc = GenContext {
            ao_amount_blinding_mask: Some(Scalar::ZERO),
            ..Default::default()
        };

        let priv_key = match one_time_key {
            Some(k) => k,
            None => crate::crypto::generate_key_scalar(rnd),
        };
        let pub_key = pub_from_priv(&priv_key);

        ogc.tx_pub_key_p = Some(pub_key);
        ogc.tx_key = Some(KeyPair {
            pub_key,
            sec: priv_key.clone(),
        });

        tx.extra
            .push(Variant::PubKey(Value256::from_point(&pub_key)));
        tx.extra.push(Variant::EtcTxFlags16(0));

        // Inputs: ring references, ephemeral key derivation and key images.
        for src in ftp.sources.iter_mut() {
            let real_out = src
                .outputs
                .get(src.real_output as usize)
                .ok_or_else(|| Error::msg("real output index out of range"))?
                .clone();

            let mut key_offsets = Vec::with_capacity(src.outputs.len());
            let mut prev = 0u64;
            for out in &src.outputs {
                let val = out
                    .out_reference
                    .as_uint64()
                    .ok_or_else(|| Error::msg("unsupported output reference type"))?;
                key_offsets.push(Variant::Uint64(val - prev));
                prev = val;
            }

            // derivation = 8 * v * R
            let derivation = generate_key_derivation(&src.real_out_tx_key, &self.view_priv_key);
            let derivation_bytes = derivation.compress();
            let in_e_pub = derive_public_key(
                &derivation_bytes,
                src.real_out_in_tx_index,
                &self.spend_pub_key,
            )?;
            // hi = Hs(8*v*R, i): the public part of the per-output secret. The
            // effective spend ephemeral is secret0Xp = hi + x, held by the signer.
            let mut hi_buf = derivation_bytes.to_vec();
            crate::base::varint::append_varint(&mut hi_buf, src.real_out_in_tx_index);
            let hi = hash_to_scalar(&hi_buf);
            src.hi = Some(hi.clone());

            if in_e_pub != real_out.stealth_address {
                return Err(Error::msg(
                    "derived public key mismatch with output public key!",
                ));
            }

            let key_image = signer.key_image(&hi, &in_e_pub)?;
            tx.vin.push(Variant::TxInZcInput(TxInZcInput {
                key_offsets,
                key_image,
                etc_details: Vec::new(),
            }));
        }

        ogc.resize(ftp.sources.len(), ftp.prepared_destinations.len());

        // Outputs.
        let mut hints: BTreeSet<u16> = BTreeSet::new();
        for (i, dst) in ftp.prepared_destinations.iter().enumerate() {
            let output_index = tx.vout.len() as u64;
            if dst.addr.is_empty() {
                return Err(Error::msg("destination has no address"));
            }
            let dst_view_key = crate::crypto::point_from_bytes(dst.addr[0].view_key.as_bytes())?;
            // d = 8 * r * V
            let derivation = generate_key_derivation(&dst_view_key, &priv_key);
            hints.insert(derivation_hint(&derivation));

            // h = Hs(8 * r * V, i)
            let mut buf = derivation.compress().to_vec();
            crate::base::varint::append_varint(&mut buf, output_index);
            let scalar = hash_to_scalar(&buf);

            let amount_mask = hs_domain(CRYPTO_HDS_OUT_AMOUNT_MASK, &scalar);
            let amount_blinding_mask = hs_domain(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, &scalar);
            ogc.amount_blinding_masks[i] = amount_blinding_mask.clone();

            let mut amount_mask_u64 = [0u8; 8];
            amount_mask_u64.copy_from_slice(&amount_mask.to_bytes()[..8]);
            let mut vout = TxOutZarcanum {
                encrypted_amount: dst.amount ^ u64::from_le_bytes(amount_mask_u64),
                ..Default::default()
            };
            vout.stealth_address = Value256::from_point(&dst.stealth_address(&scalar)?);
            vout.concealing_point = Value256::from_point(&dst.concealing_point(&scalar)?);
            vout.blinded_asset_id =
                Value256::from_point(&dst.blinded_asset_id(&scalar, &mut ogc, i)?);
            vout.amount_commitment =
                Value256::from_point(&dst.amount_commitment(&scalar, &mut ogc, i));
            if dst.addr[0].flags & 1 == 1 {
                vout.mix_attr = 1; // CURRENCY_TO_KEY_OUT_FORCED_NO_MIX
            }

            ogc.amounts[i] = scalar_int(dst.amount);
            ogc.asset_ids[i] = dst
                .asset_id
                .ok_or_else(|| Error::msg("destination has no asset id"))?;
            GenContext::add_scalar(
                &mut ogc.asset_id_blinding_mask_x_amount_sum,
                &ogc.asset_id_blinding_masks[i].mul(&scalar_int(dst.amount)),
            );
            let m = ogc.amount_blinding_masks[i].clone();
            GenContext::add_scalar(&mut ogc.amount_blinding_masks_sum, &m);
            let c = ogc.amount_commitments[i];
            GenContext::add_point(&mut ogc.amount_commitments_sum, &c);

            tx.vout.push(Variant::TxOutZarcanum(vout));
        }

        // Pad the hint list so it never reveals how many outputs are ours.
        while hints.len() < tx.vout.len() {
            let mut rnd_hint = [0u8; 2];
            rnd.fill_bytes(&mut rnd_hint);
            // The +len offset keeps this terminating even with a fixed reader.
            hints.insert(u16::from_le_bytes(rnd_hint).wrapping_add(hints.len() as u16));
        }
        for hint in &hints {
            tx.extra
                .push(Variant::DerivationHint(hint.to_le_bytes().to_vec()));
        }

        // The fee is the native-asset surplus; every other asset must balance.
        let mut native_in = 0u64;
        let mut native_out = 0u64;
        let mut asset_in: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        let mut asset_out: BTreeMap<[u8; 32], u64> = BTreeMap::new();
        for src in &ftp.sources {
            match asset_key(&src.asset_id) {
                None => native_in += src.amount,
                Some(k) => *asset_in.entry(k).or_default() += src.amount,
            }
        }
        for dst in &ftp.prepared_destinations {
            match asset_key(&dst.asset_id) {
                None => native_out += dst.amount,
                Some(k) => *asset_out.entry(k).or_default() += dst.amount,
            }
        }
        for (k, v) in &asset_in {
            let out = asset_out.get(k).copied().unwrap_or(0);
            if out != *v {
                return Err(crate::err!(
                    "asset {} unbalanced: in={v} out={out}",
                    hex::encode(k)
                ));
            }
        }
        for (k, v) in &asset_out {
            let inp = asset_in.get(k).copied().unwrap_or(0);
            if inp != *v {
                return Err(crate::err!(
                    "asset {} has outputs ({v}) with no matching inputs",
                    hex::encode(k)
                ));
            }
        }
        if native_out > native_in {
            return Err(crate::err!(
                "insufficient native funds: out={native_out} > in={native_in}"
            ));
        }

        // Inputs must be sorted by key image; sources follow along.
        sort_inputs_by_key_image(&mut tx, &mut ftp);

        if native_in > native_out {
            tx.extra.push(Variant::ZarcanumTxDataV1 {
                fee: native_in - native_out,
            });
        }

        // From here on nothing may change the prefix hash.
        let tx_id = tx.prefix().hash();

        let mut signatures = Vec::new();
        let source_count = ftp.sources.len();
        for n in 0..source_count {
            let src = ftp.sources[n].clone();
            if !src.is_zc() {
                continue;
            }
            // TODO: TX_FLAG_SIGNATURE_MODE_SEPARATE would hash a subset here.
            let tx_hash_for_sig = tx_id.0;
            let sig = src.generate_zc_sig(
                rnd,
                &tx,
                n,
                &tx_hash_for_sig,
                &mut ogc,
                n + 1 == source_count,
                signer,
            )?;
            signatures.push(Variant::ZcSig(sig));
        }
        tx.signatures = signatures;

        // Transaction-wide proofs.
        proof::generate_asset_surjection_proof(rnd, &mut tx, &tx_id.0, &ogc)
            .map_err(|e| crate::err!("while generating asset surjection proof: {e}"))?;
        proof::generate_zc_outs_range_proof(rnd, &mut tx, &tx_id.0, &ogc)
            .map_err(|e| crate::err!("while generating zc outs range proof: {e}"))?;
        proof::generate_tx_balance_proof(rnd, &mut tx, &tx_id.0, &ogc, 0)
            .map_err(|e| crate::err!("while generating tx balance proof: {e}"))?;

        Ok(FinalizedTx {
            tx,
            tx_id: Value256::ZERO,
            one_time_key: priv_key,
            ftp,
            htlc_origin: String::new(),
            outs_key_images: Vec::new(),
            derivation: Value256::ZERO,
            was_not_prepared: false,
        })
    }
}

/// A map key for an asset id, or `None` for the native coin. An unset asset id
/// is treated as native, as single-asset blobs may leave it empty.
fn asset_key(p: &Option<Point>) -> Option<[u8; 32]> {
    match p {
        None => None,
        Some(p) if *p == *NATIVE_COIN_ASSET_ID_PT => None,
        Some(p) => Some(p.compress()),
    }
}

/// Sorts `tx.vin` (and the matching sources) by key image, as consensus requires.
fn sort_inputs_by_key_image(tx: &mut Transaction, ftp: &mut FinalizeTxParam) {
    let mut order: Vec<usize> = (0..tx.vin.len()).collect();
    let key_of = |v: &Variant| -> [u8; 32] {
        v.as_txin_zc_input()
            .map(|i| i.key_image.compress())
            .unwrap_or([0xff; 32])
    };
    order.sort_by_key(|i| key_of(&tx.vin[*i]));
    tx.vin = order.iter().map(|i| tx.vin[*i].clone()).collect();
    if ftp.sources.len() == order.len() {
        ftp.sources = order.iter().map(|i| ftp.sources[*i].clone()).collect();
    }
}
