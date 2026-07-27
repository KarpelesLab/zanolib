//! Walking confirmed blocks and reporting the outputs that belong to a wallet.

use super::client::{BlockDetails, Client};
use crate::base::{Transaction, Value256};
use crate::error::Result;
use crate::{ReceivedOutput, Wallet};

/// A received output discovered by the [`Scanner`], with enough context to
/// credit a user and to later build a spendable source.
#[derive(Clone, Debug)]
pub struct Deposit {
    /// Height of the block containing the depositing transaction.
    pub height: u64,
    /// Depositing transaction id, hex.
    pub tx_id: String,
    /// The depositing transaction's public key (`real_out_tx_key` when spending).
    pub tx_pub_key: Value256,
    /// Chain-assigned global output index (0 if unavailable).
    pub global_index: u64,
    /// Integrated-address payment id, if the transaction carried one.
    pub payment_id: Option<Vec<u8>>,
    /// The decoded output.
    pub out: ReceivedOutput,
}

/// The default number of blocks fetched per RPC round-trip.
pub const DEFAULT_BATCH_SIZE: u64 = 100;

/// Walks confirmed blocks from a Zano daemon and reports outputs belonging to
/// `wallet`.
///
/// Persisting the last scanned height (and re-scanning a small tail on restart
/// to absorb reorgs) is the caller's responsibility.
pub struct Scanner {
    /// The wallet to scan for.
    pub wallet: Wallet,
    /// The daemon client.
    pub rpc: Client,
    /// Blocks requested per `get_blocks_details` call; 0 means
    /// [`DEFAULT_BATCH_SIZE`].
    pub batch_size: u64,
}

impl Scanner {
    /// Builds a scanner for `wallet` against the daemon at `endpoint`.
    pub fn new(wallet: Wallet, endpoint: &str) -> Scanner {
        Scanner {
            wallet,
            rpc: Client::new(endpoint),
            batch_size: 0,
        }
    }

    /// Scans the inclusive height range `[from, to]`, invoking `fn_` for every
    /// deposit found.
    ///
    /// Returns the height of the last fully scanned block, so the caller can
    /// persist progress; on error it returns the last height completed before
    /// the failure. If `fn_` returns an error, scanning stops and that error is
    /// returned along with the last completed height.
    pub fn scan_range<F>(&self, from: u64, to: u64, mut fn_: F) -> (u64, Result<()>)
    where
        F: FnMut(Deposit) -> Result<()>,
    {
        if to < from {
            return (from.saturating_sub(1), Ok(()));
        }
        let batch = if self.batch_size == 0 {
            DEFAULT_BATCH_SIZE
        } else {
            self.batch_size
        };

        let mut last_done = from.saturating_sub(1);
        let mut h = from;
        while h <= to {
            let count = batch.min(to - h + 1);
            let blocks = match self.rpc.get_blocks_details(h, count, false) {
                Ok(b) => b,
                Err(e) => return (last_done, Err(e)),
            };

            for blk in &blocks {
                if let Err(e) = self.scan_block(blk, &mut fn_) {
                    return (last_done, Err(e));
                }
                last_done = blk.height;
            }

            // Advance even if the daemon returned fewer blocks than requested
            // (e.g. near the tip): never loop forever.
            let got = blocks.len() as u64;
            if got == 0 {
                break;
            }
            h += got;
        }
        (last_done, Ok(()))
    }

    /// Scans from `from` up to the current chain tip.
    ///
    /// Returns the next height to resume from (one past the last fully scanned
    /// block), which the caller should persist. If `from` is already at or
    /// beyond the tip it is returned unchanged.
    pub fn sync<F>(&self, from: u64, fn_: F) -> (u64, Result<()>)
    where
        F: FnMut(Deposit) -> Result<()>,
    {
        let count = match self.rpc.get_block_count() {
            Ok(c) => c,
            Err(e) => return (from, Err(e)),
        };
        if count == 0 || from >= count {
            return (from, Ok(()));
        }
        let tip = count - 1;
        let (last, res) = self.scan_range(from, tip, fn_);
        (last + 1, res)
    }

    fn scan_block<F>(&self, blk: &BlockDetails, fn_: &mut F) -> Result<()>
    where
        F: FnMut(Deposit) -> Result<()>,
    {
        for txb in &blk.transactions {
            let td = self
                .rpc
                .get_tx_details(&txb.id)
                .map_err(|e| crate::err!("block {} tx {}: {e}", blk.height, txb.id))?;
            // Parse only the prefix + attachments (enough for output detection
            // and payment-id recovery); this skips the signature and proof
            // sections, such as the large PoS zarcanum_sig.
            let tx = Transaction::deserialize_for_scan(&td.blob)
                .map_err(|e| crate::err!("block {} tx {}: parse blob: {e}", blk.height, txb.id))?;
            let res = self
                .wallet
                .scan_tx(&tx)
                .map_err(|e| crate::err!("block {} tx {}: scan: {e}", blk.height, txb.id))?;
            for out in res.outputs {
                let global_index = td
                    .outs
                    .get(out.output_index)
                    .map(|o| o.global_index)
                    .unwrap_or(0);
                fn_(Deposit {
                    height: blk.height,
                    tx_id: txb.id.clone(),
                    tx_pub_key: res.tx_pub_key,
                    global_index,
                    payment_id: res.payment_id.clone(),
                    out,
                })?;
            }
        }
        Ok(())
    }
}
