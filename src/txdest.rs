//! Transaction destinations (outputs to create).

use crate::base::gencontext::GenContext;
use crate::base::ser::{EpeeRead, EpeeWrite, Reader, write_vec};
use crate::base::types::{AccountPublicAddr, Value256};
use crate::crypto::consts::{C_POINT_G, C_POINT_X, SC_1DIV8};
use crate::crypto::{Point, Scalar, hash_to_scalar};
use crate::error::Result;

/// Domain separator for the per-output concealing point.
pub const CRYPTO_HDS_OUT_CONCEALING_POINT: &[u8; 32] = b"ZANO_HDS_OUT_CONCEALING_POINT__\x00";
/// Domain separator for the per-output asset blinding mask.
pub const CRYPTO_HDS_OUT_ASSET_BLIND_MASK: &[u8; 32] = b"ZANO_HDS_OUT_ASSET_BLIND_MASK__\x00";
/// Domain separator for the per-output amount blinding mask.
pub const CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK: &[u8; 32] = b"ZANO_HDS_OUT_AMOUNT_BLIND_MASK_\x00";
/// Domain separator for the per-output amount mask.
pub const CRYPTO_HDS_OUT_AMOUNT_MASK: &[u8; 32] = b"ZANO_HDS_OUT_AMOUNT_MASK_______\x00";

/// HTLC (hash time-locked contract) options for a destination.
#[derive(Clone, Copy, Debug, Default)]
pub struct TxDestHtlcOut {
    /// Expiration height.
    pub expiration: u64,
    /// Hash the spender must preimage.
    pub htlc_hash: Value256,
}

impl EpeeWrite for TxDestHtlcOut {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.expiration.write_epee(out);
        self.htlc_hash.write_epee(out);
    }
}
impl EpeeRead for TxDestHtlcOut {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxDestHtlcOut {
            expiration: u64::read_epee(r)?,
            htlc_hash: Value256::read_epee(r)?,
        })
    }
}

/// An output to create: an amount of an asset, to one (or more) addresses.
#[derive(Clone, Debug, Default)]
pub struct TxDest {
    /// Amount, in atomic units.
    pub amount: u64,
    /// Destination address(es); more than one means a multisig output.
    pub addr: Vec<AccountPublicAddr>,
    /// Minimum signatures for a multisig output.
    pub minimum_sigs: u64,
    /// Amount provided by the initial creator of a partially-built tx.
    pub amount_to_provide: u64,
    /// Output unlock time.
    pub unlock_time: u64,
    /// HTLC options, if any.
    pub htlc_options: Option<TxDestHtlcOut>,
    /// Unblinded asset id (not premultiplied).
    pub asset_id: Option<Point>,
    /// Destination flags.
    pub flags: u64,
}

impl EpeeWrite for TxDest {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.amount.write_epee(out);
        write_vec(&self.addr, out);
        self.minimum_sigs.write_epee(out);
        self.amount_to_provide.write_epee(out);
        self.unlock_time.write_epee(out);
        match &self.htlc_options {
            Some(h) => h.write_epee(out),
            None => TxDestHtlcOut::default().write_epee(out),
        }
        match &self.asset_id {
            Some(p) => p.write_epee(out),
            None => out.extend_from_slice(&[0u8; 32]),
        }
        self.flags.write_epee(out);
    }
}

impl EpeeRead for TxDest {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let amount = u64::read_epee(r)?;
        let addr = r.read_vec()?;
        let minimum_sigs = u64::read_epee(r)?;
        let amount_to_provide = u64::read_epee(r)?;
        let unlock_time = u64::read_epee(r)?;
        let htlc_options = TxDestHtlcOut::read_epee(r)?;
        // The blob always carries a point here; reject anything off-curve, as
        // the Go reader did.
        let asset_id = Point::read_epee(r)?;
        let flags = u64::read_epee(r)?;
        Ok(TxDest {
            amount,
            addr,
            minimum_sigs,
            amount_to_provide,
            unlock_time,
            htlc_options: Some(htlc_options),
            asset_id: Some(asset_id),
            flags,
        })
    }
}

impl TxDest {
    /// The one-time stealth address `h*G + spend_public_key`.
    pub fn stealth_address(&self, scalar: &Scalar) -> Result<Point> {
        let p = crate::crypto::point_from_bytes(self.addr[0].spend_key.as_bytes())?;
        Ok(Point::mul_base(scalar).add(&p))
    }

    /// The concealing point `Hs(CONCEALING, h) * view_public_key`.
    pub fn concealing_point(&self, scalar: &Scalar) -> Result<Point> {
        let h = hs_domain(CRYPTO_HDS_OUT_CONCEALING_POINT, scalar);
        let v = crate::crypto::point_from_bytes(self.addr[0].view_key.as_bytes())?;
        Ok(v.mul(&h))
    }

    /// The blinded asset id `T = asset_id + s*X`, premultiplied by 1/8. The
    /// blinding mask `s` and the unpremultiplied `T` are recorded in `ogc`.
    pub fn blinded_asset_id(
        &self,
        scalar: &Scalar,
        ogc: &mut GenContext,
        i: usize,
    ) -> Result<Point> {
        let asset_blinding_mask = hs_domain(CRYPTO_HDS_OUT_ASSET_BLIND_MASK, scalar);
        ogc.asset_id_blinding_masks[i] = asset_blinding_mask.clone();

        let q = self
            .asset_id
            .ok_or_else(|| crate::err!("destination has no asset id"))?;
        let s = q.add(&C_POINT_X.mul(&asset_blinding_mask));
        ogc.blinded_asset_ids[i] = s;
        Ok(s.mul(&SC_1DIV8))
    }

    /// The amount commitment `amount*T + mask*G`, premultiplied by 1/8. The
    /// unpremultiplied commitment is recorded in `ogc`.
    pub fn amount_commitment(&self, scalar: &Scalar, ogc: &mut GenContext, i: usize) -> Point {
        let amount_blinding_mask = hs_domain(CRYPTO_HDS_OUT_AMOUNT_BLINDING_MASK, scalar);
        let amount = crate::crypto::scalar_int(self.amount);
        let t = ogc.blinded_asset_ids[i];
        let r = t.mul(&amount).add(&C_POINT_G.mul(&amount_blinding_mask));
        ogc.amount_commitments[i] = r;
        r.mul(&SC_1DIV8)
    }
}

/// `Hs(domain || scalar)`.
pub fn hs_domain(domain: &[u8; 32], scalar: &Scalar) -> Scalar {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(domain);
    buf.extend_from_slice(&scalar.to_bytes());
    hash_to_scalar(&buf)
}
