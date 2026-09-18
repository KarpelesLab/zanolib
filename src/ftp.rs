//! The `finalize_tx_param` blob: everything needed to finalize and sign a
//! transaction, as handed over by a view-only wallet.

use crate::base::ser::{EpeeRead, EpeeWrite, MAX_VEC_LEN, Reader, write_vec};
use crate::base::types::{AccountPublicAddr, Value256};
use crate::base::variant::Variant;
use crate::base::varint::append_varint;
use crate::crypto::{Point, chacha8, chacha8_generate_key};
use crate::error::{Error, Result};
use crate::txdest::TxDest;
use crate::txsource::TxSource;

/// Which revision of the wallet-blob layout a `finalize_tx_param` /
/// `finalized_tx` blob uses.
///
/// Zano's blobs carry no version marker of their own, and two fields grew over
/// time: `tx_source_entry` gained `asset_id` and `gateway_origin`, and
/// `tx_destination_entry` gained tagged addresses and an intrinsic
/// `payment_id`. [`FinalizeTxParam::parse`] tries [`WalletBlobLayout::Current`]
/// first and falls back to [`WalletBlobLayout::Legacy`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WalletBlobLayout {
    /// The layout used by zano 2.2 (HF6) wallets.
    #[default]
    Current,
    /// The layout used by wallets predating the `asset_id` source field.
    Legacy,
}

/// Parameters for finalizing and signing a transaction.
#[derive(Clone, Debug)]
pub struct FinalizeTxParam {
    /// Global unlock time.
    pub unlock_time: u64,
    /// Extra fields to place in the transaction.
    pub extra: Vec<Variant>,
    /// Attachments.
    pub attachments: Vec<Variant>,
    /// Address used to encrypt attachments.
    pub crypt_address: AccountPublicAddr,
    /// Output attributes.
    pub tx_outs_attr: u8,
    /// Whether destinations should be shuffled.
    pub shuffle: bool,
    /// Construction flags.
    pub flags: u8,
    /// Multisig id, when spending a multisig output.
    pub multisig_id: Value256,
    /// The inputs to spend.
    pub sources: Vec<TxSource>,
    /// Indices of the wallet transfers being spent.
    pub selected_transfers: Vec<u64>,
    /// The outputs to create.
    pub prepared_destinations: Vec<TxDest>,
    /// Transaction expiration time.
    pub expiration_time: u64,
    /// The wallet's public spend key (used for validation only).
    pub spend_pub_key: Point,
    /// Transaction version.
    pub tx_version: u64,
    /// Hardfork id, for version >= 3.
    pub tx_hardfork_id: u64,
    /// Separate-mode fee.
    pub mode_separate_fee: u64,
    /// The blob layout this value was parsed from; re-serialization uses it.
    pub layout: WalletBlobLayout,
}

impl EpeeWrite for FinalizeTxParam {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.write_with(self.layout, out)
    }
}

impl EpeeRead for FinalizeTxParam {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        FinalizeTxParam::read_with(r, WalletBlobLayout::default())
    }
}

impl FinalizeTxParam {
    /// Serializes in the given blob layout.
    pub fn write_with(&self, layout: WalletBlobLayout, out: &mut Vec<u8>) {
        self.unlock_time.write_epee(out);
        write_vec(&self.extra, out);
        write_vec(&self.attachments, out);
        self.crypt_address.write_epee(out);
        out.push(self.tx_outs_attr);
        self.shuffle.write_epee(out);
        out.push(self.flags);
        self.multisig_id.write_epee(out);
        append_varint(out, self.sources.len() as u64);
        for src in &self.sources {
            src.write_with(layout, out);
        }
        append_varint(out, self.selected_transfers.len() as u64);
        for t in &self.selected_transfers {
            append_varint(out, *t);
        }
        append_varint(out, self.prepared_destinations.len() as u64);
        for dst in &self.prepared_destinations {
            dst.write_with(layout, out);
        }
        self.expiration_time.write_epee(out);
        self.spend_pub_key.write_epee(out);
        self.tx_version.write_epee(out);
        self.tx_hardfork_id.write_epee(out);
        self.mode_separate_fee.write_epee(out);
    }

    /// Parses the given blob layout.
    pub fn read_with(r: &mut Reader<'_>, layout: WalletBlobLayout) -> Result<Self> {
        let unlock_time = u64::read_epee(r)?;
        let extra = r.read_vec()?;
        let attachments = r.read_vec()?;
        let crypt_address = AccountPublicAddr::read_epee(r)?;
        let tx_outs_attr = r.read_byte()?;
        let shuffle = bool::read_epee(r)?;
        let flags = r.read_byte()?;
        let multisig_id = Value256::read_epee(r)?;
        let sources = read_vec_with(r, |r| TxSource::read_with(r, layout))?;
        let n = r.read_varint()?;
        if n > MAX_VEC_LEN {
            return Err(crate::err!("selected_transfers too large: {n}"));
        }
        let mut selected_transfers = Vec::with_capacity(n as usize);
        for _ in 0..n {
            selected_transfers.push(r.read_varint()?);
        }
        Ok(FinalizeTxParam {
            unlock_time,
            extra,
            attachments,
            crypt_address,
            tx_outs_attr,
            shuffle,
            flags,
            multisig_id,
            sources,
            selected_transfers,
            prepared_destinations: read_vec_with(r, |r| TxDest::read_with(r, layout))?,
            expiration_time: u64::read_epee(r)?,
            spend_pub_key: Point::read_epee(r)?,
            tx_version: u64::read_epee(r)?,
            tx_hardfork_id: u64::read_epee(r)?,
            mode_separate_fee: u64::read_epee(r)?,
            layout,
        })
    }

    /// Decrypts `buf` with the given view secret key and parses it, trying the
    /// current blob layout first and the legacy one as a fallback.
    pub fn parse(buf: &[u8], view_secret_key: &[u8]) -> Result<FinalizeTxParam> {
        let code = chacha8_generate_key(view_secret_key)?;
        let plain = chacha8(&code, &[0u8; 8], buf)?;
        try_both_layouts(&plain, FinalizeTxParam::read_with)
    }
}

/// Reads a length-prefixed vector whose elements need a layout argument.
pub(crate) fn read_vec_with<T>(
    r: &mut Reader<'_>,
    mut read: impl FnMut(&mut Reader<'_>) -> Result<T>,
) -> Result<Vec<T>> {
    let n = r.read_varint()?;
    if n > MAX_VEC_LEN {
        return Err(crate::err!("vector too large: {n}"));
    }
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        v.push(read(r)?);
    }
    Ok(v)
}

/// Parses `plain` with the current blob layout, falling back to the legacy one.
///
/// A blob must be consumed exactly, which is what tells the two layouts apart:
/// the fields that changed are followed by more data, so reading the wrong
/// layout leaves the reader misaligned and it fails or ends up with trailing
/// bytes.
pub(crate) fn try_both_layouts<T>(
    plain: &[u8],
    read: impl Fn(&mut Reader<'_>, WalletBlobLayout) -> Result<T>,
) -> Result<T> {
    let mut first_err = None;
    for layout in [WalletBlobLayout::Current, WalletBlobLayout::Legacy] {
        let mut r = Reader::new(plain);
        match read(&mut r, layout) {
            Ok(v) if r.is_empty() => return Ok(v),
            Ok(_) => {
                first_err.get_or_insert_with(|| Error::msg("trailing data"));
            }
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.unwrap_or_else(|| Error::msg("cannot parse wallet blob")))
}
