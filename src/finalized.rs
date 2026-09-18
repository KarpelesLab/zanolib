//! The `finalized_tx` blob: a fully constructed transaction plus its metadata.

use crate::base::ser::{EpeeRead, EpeeWrite, Reader, write_vec};
use crate::base::tx::Transaction;
use crate::base::types::{KeyImageIndex, Value256};
use crate::crypto::{Scalar, chacha8, chacha8_generate_key};
use crate::error::Result;
use crate::ftp::{FinalizeTxParam, WalletBlobLayout, try_both_layouts};

/// A constructed (and usually signed) transaction with the parameters it was
/// built from.
#[derive(Clone, Debug)]
pub struct FinalizedTx {
    /// The transaction itself.
    pub tx: Transaction,
    /// Its id; may be zero in blobs produced before signing.
    pub tx_id: Value256,
    /// The one-time transaction secret key.
    pub one_time_key: Scalar,
    /// The parameters this transaction was built from.
    pub ftp: FinalizeTxParam,
    /// HTLC origin, for HTLC transactions.
    pub htlc_origin: String,
    /// `(out_index, key_image)` pairs for each change output.
    pub outs_key_images: Vec<KeyImageIndex>,
    /// The key derivation used for the outputs.
    pub derivation: Value256,
    /// True when the transaction was deliberately not prepared.
    pub was_not_prepared: bool,
}

impl EpeeWrite for FinalizedTx {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.tx.write_epee(out);
        self.tx_id.write_epee(out);
        self.one_time_key.write_epee(out);
        self.ftp.write_epee(out);
        self.htlc_origin.write_epee(out);
        write_vec(&self.outs_key_images, out);
        self.derivation.write_epee(out);
        self.was_not_prepared.write_epee(out);
    }
}

impl EpeeRead for FinalizedTx {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        FinalizedTx::read_with(r, WalletBlobLayout::default())
    }
}

impl FinalizedTx {
    /// Parses the given blob layout.
    pub fn read_with(r: &mut Reader<'_>, layout: WalletBlobLayout) -> Result<Self> {
        Ok(FinalizedTx {
            tx: Transaction::read_epee(r)?,
            tx_id: Value256::read_epee(r)?,
            one_time_key: Scalar::read_epee(r)?,
            ftp: FinalizeTxParam::read_with(r, layout)?,
            htlc_origin: String::read_epee(r)?,
            outs_key_images: r.read_vec()?,
            derivation: Value256::read_epee(r)?,
            was_not_prepared: bool::read_epee(r)?,
        })
    }

    /// Decrypts `buf` with the given view secret key and parses it, trying the
    /// current blob layout first and the legacy one as a fallback.
    pub fn parse(buf: &[u8], view_secret_key: &[u8]) -> Result<FinalizedTx> {
        let code = chacha8_generate_key(view_secret_key)?;
        let plain = chacha8(&code, &[0u8; 8], buf)?;
        try_both_layouts(&plain, FinalizedTx::read_with)
    }

    /// The serialized transaction, ready to broadcast.
    pub fn raw_tx(&self) -> Vec<u8> {
        self.tx.to_epee_bytes()
    }
}
