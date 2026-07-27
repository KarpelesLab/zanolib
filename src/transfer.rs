//! Building a spend from received outputs.

use crate::address::Address;
use crate::base::types::{AccountPublicAddr, Value256};
use crate::base::variant::Variant;
use crate::crypto::Scalar;
use crate::crypto::consts::NATIVE_COIN_ASSET_ID_PT;
use crate::error::{Error, Result};
use crate::finalized::FinalizedTx;
use crate::ftp::FinalizeTxParam;
use crate::rng::RngCore;
use crate::txdest::TxDest;
use crate::txsource::{TxSource, TxSourceOutputEntry};
use crate::wallet::Wallet;

/// One output in an input's decoy ring, identified by its chain-wide global
/// index. The point fields are the on-chain (1/8-premultiplied) values, exactly
/// as the daemon returns them.
#[derive(Clone, Copy, Debug)]
pub struct RingMember {
    /// Chain-wide global output index.
    pub global_index: u64,
    /// One-time public key.
    pub stealth_address: Value256,
    /// Concealing point.
    pub concealing_point: Value256,
    /// Amount commitment.
    pub amount_commitment: Value256,
    /// Blinded asset id.
    pub blinded_asset_id: Value256,
}

/// One output to spend: what [`Wallet::scan_tx`](crate::Wallet::scan_tx)
/// recovered, plus a ring of decoys that must include the real output.
#[derive(Clone, Debug)]
pub struct TransferInput {
    /// Amount held by the output.
    pub amount: u64,
    /// Unblinded asset id.
    pub asset_id: Value256,
    /// Amount blinding mask.
    pub amount_blinding_mask: Scalar,
    /// Asset id blinding mask.
    pub asset_id_blinding_mask: Scalar,
    /// Transaction public key of the depositing transaction.
    pub real_out_tx_key: Value256,
    /// Output index within the depositing transaction.
    pub real_out_index: u64,
    /// Chain-wide global index of the real output.
    pub real_global_index: u64,
    /// Decoys plus the real output.
    pub ring: Vec<RingMember>,
}

/// An output to create: send `amount` of `asset_id` to `address`.
#[derive(Clone, Debug)]
pub struct TransferDest {
    /// Recipient address.
    pub address: Address,
    /// Asset to send.
    pub asset_id: Value256,
    /// Amount, in atomic units.
    pub amount: u64,
}

/// The native coin's asset id.
pub fn native_coin_asset_id() -> Value256 {
    Value256::from_point(&NATIVE_COIN_ASSET_ID_PT)
}

impl TransferInput {
    /// Converts this input into a [`TxSource`], sorting the ring by global index
    /// and locating the real output within it.
    pub fn to_source(&self) -> Result<TxSource> {
        if self.ring.is_empty() {
            return Err(Error::msg("input has empty ring"));
        }
        let mut ring = self.ring.clone();
        ring.sort_by_key(|m| m.global_index);

        let mut real_index: Option<usize> = None;
        let mut outs = Vec::with_capacity(ring.len());
        for (i, m) in ring.iter().enumerate() {
            if i > 0 && ring[i - 1].global_index == m.global_index {
                return Err(crate::err!(
                    "duplicate ring member global index {}",
                    m.global_index
                ));
            }
            let point = |v: &Value256, what: &str| {
                v.to_point().ok_or_else(|| {
                    crate::err!(
                        "ring member {i} (gindex {}) has an invalid {what}",
                        m.global_index
                    )
                })
            };
            outs.push(TxSourceOutputEntry {
                out_reference: Variant::Uint64(m.global_index),
                stealth_address: point(&m.stealth_address, "stealth address")?,
                concealing_point: point(&m.concealing_point, "concealing point")?,
                amount_commitment: point(&m.amount_commitment, "amount commitment")?,
                blinded_asset_id: point(&m.blinded_asset_id, "blinded asset id")?,
            });
            if m.global_index == self.real_global_index {
                real_index = Some(i);
            }
        }
        let real_index = real_index.ok_or_else(|| {
            crate::err!(
                "real output (gindex {}) not found in ring",
                self.real_global_index
            )
        })?;

        let tx_key = self
            .real_out_tx_key
            .to_point()
            .ok_or_else(|| Error::msg("invalid real_out_tx_key"))?;
        let asset_pt = self
            .asset_id
            .to_point()
            .ok_or_else(|| Error::msg("invalid source asset id"))?;

        Ok(TxSource {
            outputs: outs,
            real_output: real_index as u64,
            real_out_tx_key: tx_key,
            real_out_amount_blinding_mask: self.amount_blinding_mask.clone(),
            real_out_asset_id_blinding_mask: self.asset_id_blinding_mask.clone(),
            real_out_in_tx_index: self.real_out_index,
            amount: self.amount,
            transfer_index: 0,
            multisig_id: Value256::ZERO,
            ms_sigs_count: 0,
            ms_keys_count: 0,
            separately_signed_tx_complete: false,
            htlc_origin: String::new(),
            asset_id: Some(asset_pt),
            is_zc_input: true,
            hi: None,
        })
    }
}

impl Wallet {
    /// Assembles a transaction from spendable inputs and destinations, then
    /// signs it.
    ///
    /// The fee is implicit: it is the native-asset surplus (native inputs minus
    /// native outputs), so the caller controls it by choosing destination
    /// amounts. Every non-native asset must balance exactly.
    pub fn build_transfer(
        &self,
        rnd: &mut dyn RngCore,
        inputs: &[TransferInput],
        dests: &[TransferDest],
        version: u64,
        hardfork_id: u64,
    ) -> Result<FinalizedTx> {
        if self.is_view_only() {
            return Err(Error::msg(
                "cannot build a transfer with a view-only wallet",
            ));
        }
        if inputs.is_empty() {
            return Err(Error::msg("no inputs"));
        }

        let mut ftp = FinalizeTxParam {
            unlock_time: 0,
            extra: Vec::new(),
            attachments: Vec::new(),
            crypt_address: AccountPublicAddr::default(),
            tx_outs_attr: 0,
            shuffle: false,
            flags: 0,
            multisig_id: Value256::ZERO,
            sources: Vec::new(),
            selected_transfers: Vec::new(),
            prepared_destinations: Vec::new(),
            expiration_time: 0,
            spend_pub_key: self.spend_pub_key,
            tx_version: version,
            tx_hardfork_id: hardfork_id,
            mode_separate_fee: 0,
        };

        for input in inputs {
            ftp.sources.push(input.to_source()?);
        }

        for d in dests {
            let asset_pt = d
                .asset_id
                .to_point()
                .ok_or_else(|| Error::msg("destination has invalid asset id"))?;
            let mut acc = AccountPublicAddr {
                flags: d.address.flags,
                ..Default::default()
            };
            copy_into(&mut acc.spend_key.0, &d.address.spend_key);
            copy_into(&mut acc.view_key.0, &d.address.view_key);
            ftp.prepared_destinations.push(TxDest {
                amount: d.amount,
                addr: vec![acc],
                asset_id: Some(asset_pt),
                ..Default::default()
            });
        }

        self.sign(rnd, &ftp, None)
    }
}

fn copy_into(dst: &mut [u8; 32], src: &[u8]) {
    let n = src.len().min(32);
    dst[..n].copy_from_slice(&src[..n]);
}
