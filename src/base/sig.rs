//! Signature and proof structures carried by a transaction.

use super::gateway::Signature64;
use super::ser::{EpeeRead, EpeeWrite, Reader, write_optional, write_vec};
use super::varint::append_varint;
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

/// An aggregated Bulletproof+ range proof over doubly-blinded commitments
/// (`bppe_signature`). Identical to [`BppSignature`] except for the second
/// blinding response.
#[derive(Clone, Debug)]
pub struct BppeSignature {
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
    /// First final blinding response.
    pub delta_1: Scalar,
    /// Second final blinding response.
    pub delta_2: Scalar,
}

impl EpeeWrite for BppeSignature {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_vec(&self.lv, out);
        write_vec(&self.rv, out);
        self.a0.write_epee(out);
        self.a.write_epee(out);
        self.b.write_epee(out);
        self.r.write_epee(out);
        self.s.write_epee(out);
        self.delta_1.write_epee(out);
        self.delta_2.write_epee(out);
    }
}
impl EpeeRead for BppeSignature {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(BppeSignature {
            lv: r.read_vec()?,
            rv: r.read_vec()?,
            a0: Point::read_epee(r)?,
            a: Point::read_epee(r)?,
            b: Point::read_epee(r)?,
            r: Scalar::read_epee(r)?,
            s: Scalar::read_epee(r)?,
            delta_1: Scalar::read_epee(r)?,
            delta_2: Scalar::read_epee(r)?,
        })
    }
}

/// A CLSAG signature with five layers (G, G, X, X, G), used by the PoS stake
/// input. Same shape as [`ClsagSig`] — the responses of same-generator layers
/// are aggregated, so there is still one `rg`/`rx` scalar per ring member —
/// plus two more auxiliary key images.
#[derive(Clone, Debug)]
pub struct ClsagGgxxgSig {
    /// The ring's starting challenge.
    pub c: Scalar,
    /// Responses for the G-components (layers 0, 1 and 4); one per ring member.
    pub rg: Vec<Scalar>,
    /// Responses for the X-components (layers 2 and 3); one per ring member.
    pub rx: Vec<Scalar>,
    /// Auxiliary key image `K1`, premultiplied by 1/8.
    pub k1: Point,
    /// Auxiliary key image `K2`, premultiplied by 1/8.
    pub k2: Point,
    /// Auxiliary key image `K3`, premultiplied by 1/8.
    pub k3: Point,
    /// Auxiliary key image `K4`, premultiplied by 1/8.
    pub k4: Point,
}

impl EpeeWrite for ClsagGgxxgSig {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.c.write_epee(out);
        write_vec(&self.rg, out);
        write_vec(&self.rx, out);
        self.k1.write_epee(out);
        self.k2.write_epee(out);
        self.k3.write_epee(out);
        self.k4.write_epee(out);
    }
}
impl EpeeRead for ClsagGgxxgSig {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ClsagGgxxgSig {
            c: Scalar::read_epee(r)?,
            rg: r.read_vec()?,
            rx: r.read_vec()?,
            k1: Point::read_epee(r)?,
            k2: Point::read_epee(r)?,
            k3: Point::read_epee(r)?,
            k4: Point::read_epee(r)?,
        })
    }
}

/// The stake-input signature of a PoS coinbase transaction
/// (`crypto::zarcanum_proof`): the Zarcanum proof of a valid stake kernel,
/// a range proof over `E`, and the ring signature over the stake input.
#[derive(Clone, Debug)]
pub struct ZarcanumSig {
    /// Blinding response `d`.
    pub d: Scalar,
    /// Commitment `C`, premultiplied by 1/8.
    pub c_point: Point,
    /// Commitment `C'`, premultiplied by 1/8.
    pub c_prime: Point,
    /// Commitment `E`, premultiplied by 1/8.
    pub e: Point,
    /// The shared Fiat-Shamir challenge.
    pub c: Scalar,
    /// Response `y0` (first linear composition proof).
    pub y0: Scalar,
    /// Response `y1` (first linear composition proof).
    pub y1: Scalar,
    /// Response `y2` (second linear composition proof).
    pub y2: Scalar,
    /// Response `y3` (second linear composition proof).
    pub y3: Scalar,
    /// Response `y4` (Schnorr proof).
    pub y4: Scalar,
    /// Range proof over `E`.
    pub e_range_proof: BppeSignature,
    /// Pseudo-output amount commitment, premultiplied by 1/8.
    pub pseudo_out_amount_commitment: Point,
    /// The stake input's ring signature.
    pub clsag_ggxxg: ClsagGgxxgSig,
}

impl EpeeWrite for ZarcanumSig {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.d.write_epee(out);
        self.c_point.write_epee(out);
        self.c_prime.write_epee(out);
        self.e.write_epee(out);
        self.c.write_epee(out);
        self.y0.write_epee(out);
        self.y1.write_epee(out);
        self.y2.write_epee(out);
        self.y3.write_epee(out);
        self.y4.write_epee(out);
        self.e_range_proof.write_epee(out);
        self.pseudo_out_amount_commitment.write_epee(out);
        self.clsag_ggxxg.write_epee(out);
    }
}
impl EpeeRead for ZarcanumSig {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ZarcanumSig {
            d: Scalar::read_epee(r)?,
            c_point: Point::read_epee(r)?,
            c_prime: Point::read_epee(r)?,
            e: Point::read_epee(r)?,
            c: Scalar::read_epee(r)?,
            y0: Scalar::read_epee(r)?,
            y1: Scalar::read_epee(r)?,
            y2: Scalar::read_epee(r)?,
            y3: Scalar::read_epee(r)?,
            y4: Scalar::read_epee(r)?,
            e_range_proof: BppeSignature::read_epee(r)?,
            pseudo_out_amount_commitment: Point::read_epee(r)?,
            clsag_ggxxg: ClsagGgxxgSig::read_epee(r)?,
        })
    }
}

/// Proves an asset operation's amount commitment is well formed
/// (`asset_operation_proof`). Exactly one of the two proofs is present: the
/// linear composition proof for an asset with hidden supply, the plain
/// signature otherwise.
#[derive(Clone, Debug)]
pub struct AssetOperationProof {
    /// Structure version.
    pub version: u64,
    /// Linear composition proof over the amount commitment.
    pub amount_commitment_composition_proof: Option<GenericDoubleSchnorrSig>,
    /// Schnorr signature over the amount commitment's G-component.
    pub amount_commitment_g_proof: Option<Signature64>,
}

impl EpeeWrite for AssetOperationProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        write_optional(&self.amount_commitment_composition_proof, out);
        write_optional(&self.amount_commitment_g_proof, out);
    }
}
impl EpeeRead for AssetOperationProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!(
                "unsupported asset_operation_proof version {version}"
            ));
        }
        Ok(AssetOperationProof {
            version,
            amount_commitment_composition_proof: r.read_optional()?,
            amount_commitment_g_proof: r.read_optional()?,
        })
    }
}

/// Proves ownership of the asset an operation touches
/// (`asset_operation_ownership_proof`).
#[derive(Clone, Debug)]
pub struct AssetOperationOwnershipProof {
    /// Structure version.
    pub version: u64,
    /// Challenge scalar `c`.
    pub c: Scalar,
    /// Response scalar `y`.
    pub y: Scalar,
}

impl EpeeWrite for AssetOperationOwnershipProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.c.write_epee(out);
        self.y.write_epee(out);
    }
}
impl EpeeRead for AssetOperationOwnershipProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!(
                "unsupported asset_operation_ownership_proof version {version}"
            ));
        }
        Ok(AssetOperationOwnershipProof {
            version,
            c: Scalar::read_epee(r)?,
            y: Scalar::read_epee(r)?,
        })
    }
}

/// The same ownership proof, signed with a secp256k1 (ethereum) key
/// (`asset_operation_ownership_proof_eth`).
#[derive(Clone, Copy, Debug)]
pub struct AssetOperationOwnershipProofEth {
    /// Structure version.
    pub version: u64,
    /// The signature.
    pub eth_sig: Signature64,
}

impl EpeeWrite for AssetOperationOwnershipProofEth {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.eth_sig.write_epee(out);
    }
}
impl EpeeRead for AssetOperationOwnershipProofEth {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!(
                "unsupported asset_operation_ownership_proof_eth version {version}"
            ));
        }
        Ok(AssetOperationOwnershipProofEth {
            version,
            eth_sig: Signature64::read_epee(r)?,
        })
    }
}
