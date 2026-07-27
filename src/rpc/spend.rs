//! Sweeping received deposits back out, with decoy rings fetched per input.

use super::client::Client;
use super::scanner::Deposit;
use crate::base::{EpeeWrite, TRANSACTION_VERSION_POST_HF5, Value256};
use crate::error::{Error, Result};
use crate::rng::OsRng;
use crate::{
    Address, FinalizedTx, RingMember, TransferDest, TransferInput, Wallet, native_coin_asset_id,
};
use std::collections::BTreeMap;

/// Total ring size for confidential inputs on mainnet
/// (`CURRENCY_HF4_MANDATORY_DECOY_SET_SIZE` = 15 decoys + 1 real).
pub const RING_SIZE: usize = 16;

/// The hardfork id carried by current (post-HF5) mainnet transactions.
pub const TX_HARDFORK_ID: u64 = 5;

/// The result of [`Client::sweep_to`].
pub struct SweepResult {
    /// The signed transaction.
    pub signed: FinalizedTx,
    /// Its serialized bytes.
    pub raw: Vec<u8>,
    /// The daemon's status string, if it was broadcast.
    pub status: Option<String>,
}

impl Client {
    /// Builds, signs and optionally broadcasts a transaction sending all of
    /// `deposits` to `recipient`, deducting `fee` (native atomic units) from the
    /// native amount. Confidential-asset deposits are forwarded in full.
    ///
    /// Decoy rings are fetched per input via `getrandom_outs3`. The wallet must
    /// hold the spend secret.
    pub fn sweep_to(
        &self,
        wallet: &Wallet,
        deposits: &[Deposit],
        recipient: &str,
        fee: u64,
        broadcast: bool,
    ) -> Result<SweepResult> {
        if deposits.is_empty() {
            return Err(Error::msg("no deposits to sweep"));
        }
        let addr = Address::parse(recipient).map_err(|e| crate::err!("recipient address: {e}"))?;
        let native = native_coin_asset_id();

        // Build inputs (fetching a decoy ring for each) and tally per-asset totals.
        let mut inputs = Vec::with_capacity(deposits.len());
        let mut totals: BTreeMap<Value256, u64> = BTreeMap::new();
        let mut asset_order: Vec<Value256> = Vec::new();

        for d in deposits {
            let ring = self
                .get_ring_for_output(d.global_index, RING_SIZE)
                .map_err(|e| crate::err!("decoys for gindex {}: {e}", d.global_index))?;
            let members: Vec<RingMember> = ring
                .iter()
                .map(|o| RingMember {
                    global_index: o.global_index,
                    stealth_address: o.stealth_address,
                    concealing_point: o.concealing_point,
                    amount_commitment: o.amount_commitment,
                    blinded_asset_id: o.blinded_asset_id,
                })
                .collect();
            inputs.push(TransferInput {
                amount: d.out.amount,
                asset_id: d.out.asset_id,
                amount_blinding_mask: d.out.amount_blinding_mask.clone(),
                asset_id_blinding_mask: d.out.asset_id_blinding_mask.clone(),
                real_out_tx_key: d.tx_pub_key,
                real_out_index: d.out.output_index as u64,
                real_global_index: d.global_index,
                ring: members,
            });
            if !totals.contains_key(&d.out.asset_id) {
                asset_order.push(d.out.asset_id);
            }
            *totals.entry(d.out.asset_id).or_default() += d.out.amount;
        }

        // One destination per asset, all to the recipient; the fee comes off native.
        let mut dests = Vec::new();
        for asset in &asset_order {
            let mut amount = totals[asset];
            if *asset == native {
                if amount < fee {
                    return Err(crate::err!("native total {amount} is less than fee {fee}"));
                }
                amount -= fee;
            }
            if amount == 0 {
                continue;
            }
            dests.push(TransferDest {
                address: addr.clone(),
                asset_id: *asset,
                amount,
            });
        }

        let signed = wallet
            .build_transfer(
                &mut OsRng,
                &inputs,
                &dests,
                TRANSACTION_VERSION_POST_HF5,
                TX_HARDFORK_ID,
            )
            .map_err(|e| crate::err!("build transfer: {e}"))?;

        let raw = signed.tx.to_epee_bytes();
        if !broadcast {
            return Ok(SweepResult {
                signed,
                raw,
                status: None,
            });
        }
        let status = self.send_raw_tx(&raw)?;
        Ok(SweepResult {
            signed,
            raw,
            status: Some(status),
        })
    }
}
