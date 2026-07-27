//! Signature and proof structures carried by a transaction.

use super::ser::{EpeeRead, EpeeWrite, Reader, write_vec};
use crate::crypto::{Point, Scalar};
use crate::error::Result;

/// A Confidential Linkable Spontaneous Anonymous Group signature, GGX variant:
/// three layers authenticating the stealth address, the amount blinding mask
/// and the asset id blinding mask.
#[derive(Clone, Debug)]
pub struct ClsagSig {
    /// The ring's starting challenge.
    pub c: Scalar,
    /// Responses for the G-components (layers 0 and 1); one per ring member.
    pub rg: Vec<Scalar>,
    /// Responses for the X-component (layer 2); one per ring member.
    pub rx: Vec<Scalar>,
    /// Auxiliary key image for layer 1 (G), premultiplied by 1/8.
    pub k1: Point,
    /// Auxiliary key image for layer 2 (X), premultiplied by 1/8.
    pub k2: Point,
}

impl EpeeWrite for ClsagSig {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.c.write_epee(out);
        write_vec(&self.rg, out);
        write_vec(&self.rx, out);
        self.k1.write_epee(out);
        self.k2.write_epee(out);
    }
}
impl EpeeRead for ClsagSig {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ClsagSig {
            c: Scalar::read_epee(r)?,
            rg: r.read_vec()?,
            rx: r.read_vec()?,
            k1: Point::read_epee(r)?,
            k2: Point::read_epee(r)?,
        })
    }
}

/// A zero-confidential input signature: the pseudo-output commitments plus the
/// CLSAG-GGX ring signature.
#[derive(Clone, Debug)]
pub struct ZcSig {
    /// Pseudo-output amount commitment, premultiplied by 1/8.
    pub pseudo_out_amount_commitment: Point,
    /// Pseudo-output blinded asset id, premultiplied by 1/8.
    pub pseudo_out_blinded_asset_id: Point,
    /// The ring signature.
    pub ggx: ClsagSig,
}

impl EpeeWrite for ZcSig {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.pseudo_out_amount_commitment.write_epee(out);
        self.pseudo_out_blinded_asset_id.write_epee(out);
        self.ggx.write_epee(out);
    }
}
impl EpeeRead for ZcSig {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ZcSig {
            pseudo_out_amount_commitment: Point::read_epee(r)?,
            pseudo_out_blinded_asset_id: Point::read_epee(r)?,
            ggx: ClsagSig::read_epee(r)?,
        })
    }
}

/// An aggregated Bulletproof+ range proof.
#[derive(Clone, Debug)]
pub struct BppSignature {
    /// Left commitments, one per reduction round.
    pub lv: Vec<Point>,
    /// Right commitments, one per reduction round.
    pub rv: Vec<Point>,
    /// The initial commitment `A0`.
    pub a0: Point,
    /// Final round commitment `A`.
    pub a: Point,
    /// Final round commitment `B`.
    pub b: Point,
    /// Final response `r`.
    pub r: Scalar,
    /// Final response `s`.
    pub s: Scalar,
    /// Final blinding response.
    pub delta: Scalar,
}

impl EpeeWrite for BppSignature {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_vec(&self.lv, out);
        write_vec(&self.rv, out);
        self.a0.write_epee(out);
        self.a.write_epee(out);
        self.b.write_epee(out);
        self.r.write_epee(out);
        self.s.write_epee(out);
        self.delta.write_epee(out);
    }
}
impl EpeeRead for BppSignature {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(BppSignature {
            lv: r.read_vec()?,
            rv: r.read_vec()?,
            a0: Point::read_epee(r)?,
            a: Point::read_epee(r)?,
            b: Point::read_epee(r)?,
            r: Scalar::read_epee(r)?,
            s: Scalar::read_epee(r)?,
            delta: Scalar::read_epee(r)?,
        })
    }
}

/// A vector UG aggregation proof, linking amount commitments to the
/// commitments the range proof aggregates over.
#[derive(Clone, Debug)]
pub struct UgAggProof {
    /// `E' = e*U + y'*G` for each output, premultiplied by 1/8.
    pub amount_commitments_for_rp_agg: Vec<Point>,
    /// Responses for the U-component.
    pub y0s: Vec<Scalar>,
    /// Responses for the G-component.
    pub y1s: Vec<Scalar>,
    /// The common challenge.
    pub c: Scalar,
}

impl EpeeWrite for UgAggProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_vec(&self.amount_commitments_for_rp_agg, out);
        write_vec(&self.y0s, out);
        write_vec(&self.y1s, out);
        self.c.write_epee(out);
    }
}
impl EpeeRead for UgAggProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(UgAggProof {
            amount_commitments_for_rp_agg: r.read_vec()?,
            y0s: r.read_vec()?,
            y1s: r.read_vec()?,
            c: Scalar::read_epee(r)?,
        })
    }
}

/// The range proof for all zero-confidential outputs.
#[derive(Clone, Debug)]
pub struct ZcOutsRangeProof {
    /// Bulletproof+ over `amount*U + mask*G` commitments.
    pub bpp: BppSignature,
    /// Proof that those commitments match the outputs' amount commitments.
    pub aggregation_proof: UgAggProof,
}

impl EpeeWrite for ZcOutsRangeProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.bpp.write_epee(out);
        self.aggregation_proof.write_epee(out);
    }
}
impl EpeeRead for ZcOutsRangeProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ZcOutsRangeProof {
            bpp: BppSignature::read_epee(r)?,
            aggregation_proof: UgAggProof::read_epee(r)?,
        })
    }
}

/// A one-out-of-many (BGE) proof, used for asset surjection.
#[derive(Clone, Debug)]
pub struct BgeProof {
    /// Commitment `A`, premultiplied by 1/8.
    pub a: Point,
    /// Commitment `B`, premultiplied by 1/8.
    pub b: Point,
    /// Per-digit commitments, premultiplied by 1/8.
    pub pk: Vec<Point>,
    /// Digit responses, `m*(n-1)` of them.
    pub f: Vec<Scalar>,
    /// Blinding response for A/B.
    pub y: Scalar,
    /// Blinding response for the Pk chain.
    pub z: Scalar,
}

impl EpeeWrite for BgeProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.a.write_epee(out);
        self.b.write_epee(out);
        write_vec(&self.pk, out);
        write_vec(&self.f, out);
        self.y.write_epee(out);
        self.z.write_epee(out);
    }
}
impl EpeeRead for BgeProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(BgeProof {
            a: Point::read_epee(r)?,
            b: Point::read_epee(r)?,
            pk: r.read_vec()?,
            f: r.read_vec()?,
            y: Scalar::read_epee(r)?,
            z: Scalar::read_epee(r)?,
        })
    }
}

/// Proves each output's asset type matches one of the inputs', without
/// revealing which.
#[derive(Clone, Debug)]
pub struct ZcAssetSurjectionProof {
    /// One BGE proof per output.
    pub bge_proofs: Vec<BgeProof>,
}

impl EpeeWrite for ZcAssetSurjectionProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_vec(&self.bge_proofs, out);
    }
}
impl EpeeRead for ZcAssetSurjectionProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ZcAssetSurjectionProof {
            bge_proofs: r.read_vec()?,
        })
    }
}

/// A double Schnorr signature: knowledge of two discrete logarithms with
/// respect to two (possibly different) generators.
#[derive(Clone, Debug)]
pub struct GenericDoubleSchnorrSig {
    /// The challenge.
    pub c: Scalar,
    /// Response for the first generator.
    pub y0: Scalar,
    /// Response for the second generator.
    pub y1: Scalar,
}

impl EpeeWrite for GenericDoubleSchnorrSig {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.c.write_epee(out);
        self.y0.write_epee(out);
        self.y1.write_epee(out);
    }
}
impl EpeeRead for GenericDoubleSchnorrSig {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(GenericDoubleSchnorrSig {
            c: Scalar::read_epee(r)?,
            y0: Scalar::read_epee(r)?,
            y1: Scalar::read_epee(r)?,
        })
    }
}

/// Proves that inputs equal outputs plus fee.
#[derive(Clone, Debug)]
pub struct ZcBalanceProof {
    /// The double Schnorr signature over the commitment to zero.
    pub dss: GenericDoubleSchnorrSig,
}

impl EpeeWrite for ZcBalanceProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.dss.write_epee(out);
    }
}
impl EpeeRead for ZcBalanceProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ZcBalanceProof {
            dss: GenericDoubleSchnorrSig::read_epee(r)?,
        })
    }
}
