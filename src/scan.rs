//! Receive-side scanning: detecting and decoding outputs paid to a wallet.

use crate::address::payment_id_from_intrinsic;
use crate::base::tx::{TRANSACTION_VERSION_POST_HF6, Transaction, TxOutZarcanum};
use crate::base::types::Value256;
use crate::base::variant::{
    PAYMENT_ID_SERVICE_ID, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY,
    TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE, Variant,
};
use crate::crypto::consts::{C_POINT_G, C_POINT_X, NATIVE_COIN_ASSET_ID_PT};
use crate::crypto::{
    Point, Scalar, chacha_generate_key_and_iv, chacha8, chacha8_generate_key, chacha20,
    generate_key_derivation, hash_to_scalar, mul8, scalar_int,
};
use crate::error::{Error, Result};
use crate::signature::split_amount_mask;
use crate::txdest::{
    CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, CRYPTO_HDS_OUT_AMOUNT_MASK,
    CRYPTO_HDS_OUT_ASSET_BLIND_MASK, CRYPTO_HDS_OUT_CONCEALING_POINT, hs_domain,
};
use crate::wallet::Wallet;
use serde::{Deserialize, Serialize};

/// An output detected as belonging to the wallet.
///
/// The blinding masks are kept so the output can later be turned into a
/// spendable source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedOutput {
    /// Index of the output within its transaction.
    pub output_index: usize,
    /// Amount, in atomic units.
    pub amount: u64,
    /// Unblinded asset id.
    pub asset_id: Value256,
    /// Whether the asset is the native coin.
    pub is_native: bool,
    /// The output's one-time public key.
    pub stealth_address: Value256,
    /// Amount blinding mask, hex-encoded in JSON.
    #[serde(with = "hex_scalar")]
    pub amount_blinding_mask: Scalar,
    /// Asset id blinding mask, hex-encoded in JSON.
    #[serde(with = "hex_scalar")]
    pub asset_id_blinding_mask: Scalar,
    /// The intrinsic payment id carried by this output (post-HF6
    /// transactions), as the 8 little-endian bytes zano reports; `None` when
    /// the output has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<Vec<u8>>,
}

/// The outputs of one transaction that belong to the wallet.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScanResult {
    /// The transaction's public key.
    pub tx_pub_key: Value256,
    /// The outputs paid to this wallet.
    pub outputs: Vec<ReceivedOutput>,
    /// The decrypted tx-wide payment id (the legacy `"P"` service
    /// attachment), if the tx carried one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_id: Option<Vec<u8>>,
}

impl ScanResult {
    /// Whether any output of the scanned transaction belongs to the wallet.
    pub fn found(&self) -> bool {
        !self.outputs.is_empty()
    }

    /// The payment id an output was received with, following zano's wallet:
    /// a tx-wide payment id applies to every output and takes precedence;
    /// otherwise each output carries its own intrinsic payment id (HF6).
    pub fn payment_id_for(&self, out: &ReceivedOutput) -> Option<Vec<u8>> {
        self.payment_id.clone().or_else(|| out.payment_id.clone())
    }
}

/// `CRYPTO_HDS_CHACHA_TX_PAYLOAD_ITEMS`: the key/IV domain for post-HF6
/// payload item encryption.
const CRYPTO_HDS_CHACHA_TX_PAYLOAD_ITEMS: &[u8; 32] = b"ZANO_HDS_CHACHA_TX_PAYLOAD_ITEM\x00";

/// Hex (de)serialization for scalars in JSON.
mod hex_scalar {
    use crate::crypto::Scalar;
    use serde::Serializer;
    use serde::de::{Deserialize, Deserializer, Error as _};

    pub fn serialize<S: Serializer>(v: &Scalar, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Scalar, D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 32] = b
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("scalar must be 32 bytes"))?;
        Scalar::from_bytes_canonical(&arr).ok_or_else(|| D::Error::custom("non-canonical scalar"))
    }
}

impl Wallet {
    /// Returns the outputs of `tx` that belong to this wallet, decoding each
    /// one's amount, asset id and intrinsic payment id, plus the decrypted
    /// tx-wide payment id if present.
    ///
    /// Only the view secret key is required, so this works for view-only
    /// wallets. A transaction with no tx public key, or none of whose outputs
    /// are ours, yields an empty result rather than an error.
    ///
    /// Like zano's wallet, this ignores the outputs of non-coinbase
    /// transactions that carry an unlock time: they cannot be spent when
    /// expected, and HF6 forbids such transactions altogether.
    ///
    /// This mirrors `currency::lookup_acc_outs` /
    /// `decode_output_amount_and_asset_id`.
    pub fn scan_tx(&self, tx: &Transaction) -> Result<ScanResult> {
        let mut res = ScanResult::default();

        let is_coinbase = tx.vin.iter().any(|v| matches!(v, Variant::Gen(_)));
        let has_unlock_time = tx
            .extra
            .iter()
            .any(|e| matches!(e, Variant::UnlockTime(_) | Variant::UnlockTime2(_)));
        if !is_coinbase && has_unlock_time {
            return Ok(res);
        }

        let Some(tx_pub) = tx.tx_pub_key() else {
            return Ok(res); // no tx pub key => nothing addressed to us
        };
        res.tx_pub_key = tx_pub;
        let tx_pub_pt = tx_pub
            .to_point()
            .ok_or_else(|| Error::msg("scan: invalid tx public key in extra"))?;

        // recv_derivation = 8 * view_secret * tx_pub_key
        let derivation = generate_key_derivation(&tx_pub_pt, &self.view_priv_key);
        let derivation_bytes = derivation.compress();

        for (i, v) in tx.vout.iter().enumerate() {
            // Only Zarcanum (HF4+) outputs are supported.
            let Some(zo) = v.as_tx_out_zarcanum() else {
                continue;
            };

            // h = Hs(8 * r * V, i)
            let mut buf = derivation_bytes.to_vec();
            crate::base::varint::append_varint(&mut buf, i as u64);
            let h = hash_to_scalar(&buf);

            // P' = h*G + spend_public_key =? stealth_address
            let exp_stealth = Point::mul_base(&h).add(&self.spend_pub_key);
            if exp_stealth.compress() != zo.stealth_address.0 {
                continue;
            }

            res.outputs.push(self.decode_output(i, zo, &h)?);
        }

        res.payment_id = self.recover_payment_id(tx, &derivation_bytes);
        Ok(res)
    }

    /// Decodes an output already confirmed to be ours, recovering the amount and
    /// asset id and validating the amount commitment and concealing point.
    fn decode_output(&self, i: usize, zo: &TxOutZarcanum, h: &Scalar) -> Result<ReceivedOutput> {
        // amount = encrypted_amount XOR Hs(AMOUNT_MASK, h)[0..8], and since HF6
        // payment_id = encrypted_payment_id XOR Hs(AMOUNT_MASK, h)[8..16]. A
        // zero field means "no payment id" (pre-HF6 outputs always read as 0).
        let (amount_mask, payment_id_mask) =
            split_amount_mask(&hs_domain(CRYPTO_HDS_OUT_AMOUNT_MASK, h));
        let amount = zo.encrypted_amount ^ amount_mask;
        let payment_id = match zo.encrypted_payment_id {
            0 => None,
            enc => Some(payment_id_from_intrinsic(enc ^ payment_id_mask)).filter(|p| !p.is_empty()),
        };

        let amount_blinding_mask = hs_domain(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, h);

        let blinded_asset_id_pt = zo
            .blinded_asset_id
            .to_point()
            .ok_or_else(|| Error::msg("scan: invalid blinded_asset_id"))?;
        let blinded_asset_full = mul8(&blinded_asset_id_pt);

        // A' = amount*T + mask*G =? 8*amount_commitment
        let a_prime = blinded_asset_full
            .mul(&scalar_int(amount))
            .add(&C_POINT_G.mul(&amount_blinding_mask));
        let amount_commitment_pt = zo
            .amount_commitment
            .to_point()
            .ok_or_else(|| Error::msg("scan: invalid amount_commitment"))?;
        if a_prime != mul8(&amount_commitment_pt) {
            return Err(Error::msg(
                "scan: amount commitment mismatch for owned output (malformed tx?)",
            ));
        }

        // Hs(CONCEALING, h) * view_public_key =? concealing_point
        let h_q = hs_domain(CRYPTO_HDS_OUT_CONCEALING_POINT, h);
        let q_prime = self.view_pub_key.mul(&h_q);
        if q_prime.compress() != zo.concealing_point.0 {
            return Err(Error::msg(
                "scan: concealing point mismatch for owned output (malformed tx?)",
            ));
        }

        // Asset id: H = blinded_asset_id - asset_id_blinding_mask * X.
        let (is_native, asset_id, asset_id_blinding_mask) =
            if blinded_asset_full == *NATIVE_COIN_ASSET_ID_PT {
                // Unblinded native coin.
                (
                    true,
                    Value256::from_point(&NATIVE_COIN_ASSET_ID_PT),
                    Scalar::ZERO,
                )
            } else {
                let mask = hs_domain(CRYPTO_HDS_OUT_ASSET_BLIND_MASK, h);
                let asset_pt = blinded_asset_full.sub(&C_POINT_X.mul(&mask));
                (
                    asset_pt == *NATIVE_COIN_ASSET_ID_PT,
                    Value256::from_point(&asset_pt),
                    mask,
                )
            };

        Ok(ReceivedOutput {
            output_index: i,
            amount,
            asset_id,
            is_native,
            stealth_address: zo.stealth_address,
            amount_blinding_mask,
            asset_id_blinding_mask,
            payment_id,
        })
    }

    /// Finds the tx-wide payment-id service attachment (`service_id == "P"`)
    /// and decrypts its body with the income key derivation.
    fn recover_payment_id(&self, tx: &Transaction, derivation_bytes: &[u8; 32]) -> Option<Vec<u8>> {
        if tx.version >= TRANSACTION_VERSION_POST_HF6 {
            return recover_payment_id_hf6(tx, derivation_bytes);
        }

        let find = |items: &[Variant]| -> Option<crate::base::variant::TxServiceAttachment> {
            items
                .iter()
                .filter_map(|e| e.as_service_attachment())
                .find(|sa| sa.service_id == PAYMENT_ID_SERVICE_ID)
                .cloned()
        };

        let sa = find(&tx.extra).or_else(|| find(&tx.attachment))?;

        let mut body = sa.body.clone();
        if sa.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY != 0 {
            // chacha_crypt(body, derivation): the key comes from the derivation.
            let code = chacha8_generate_key(derivation_bytes).ok()?;
            body = chacha8(&code, &[0u8; 8], &body).ok()?;
        }
        Some(body)
    }
}

/// Post-HF6 payload decryption (`decrypt_payload_items_visitor`): every
/// encrypted item in extra, then in the attachments, is ChaCha20-encrypted
/// under one key, with an IV that starts from the derived value and is
/// incremented (as a little-endian `u64`) after each encrypted item. Comments
/// are always encrypted; service attachments only with `ENCRYPT_BODY`.
///
/// Bodies encrypted with `ENCRYPT_BODY_ISOLATE_AUDITABLE` need the spend secret
/// key and are skipped, as zano's view-only wallets do.
fn recover_payment_id_hf6(tx: &Transaction, derivation_bytes: &[u8; 32]) -> Option<Vec<u8>> {
    let (key, iv) =
        chacha_generate_key_and_iv(CRYPTO_HDS_CHACHA_TX_PAYLOAD_ITEMS, derivation_bytes, 0);
    let mut iv = u64::from_le_bytes(iv);
    for item in tx.extra.iter().chain(&tx.attachment) {
        let this_iv = iv;
        match item {
            Variant::Comment(_) => iv = iv.wrapping_add(1),
            Variant::ServiceAttachment(sa) => {
                if sa.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY != 0 {
                    iv = iv.wrapping_add(1);
                }
                if sa.service_id != PAYMENT_ID_SERVICE_ID {
                    continue;
                }
                if sa.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY == 0 {
                    return Some(sa.body.clone());
                }
                if sa.flags & TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE != 0 {
                    return None;
                }
                return chacha20(&key, &this_iv.to_le_bytes(), &sa.body).ok();
            }
            _ => {}
        }
    }
    None
}
