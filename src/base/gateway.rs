//! Gateway-address structures introduced by HF6.
//!
//! A gateway address is an explicit-amount (non-confidential) account managed
//! by a third party. This crate does not build gateway transactions; the types
//! here exist so that every on-chain transaction can be parsed and
//! re-serialized byte-for-byte, including the ones that touch gateways.

use super::ser::{EpeeRead, EpeeWrite, Reader, write_var_bytes, write_vec};
use super::types::Value256;
use super::variant::tag;
use super::varint::append_varint;
use crate::error::Result;

/// A 64-byte signature (eddsa or secp256k1).
#[derive(Clone, Copy, Debug)]
pub struct Signature64(pub [u8; 64]);

impl Default for Signature64 {
    fn default() -> Signature64 {
        Signature64([0u8; 64])
    }
}

impl EpeeWrite for Signature64 {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}
impl EpeeRead for Signature64 {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let mut v = [0u8; 64];
        v.copy_from_slice(r.read_exact(64)?);
        Ok(Signature64(v))
    }
}

/// A signature by a gateway address owner: `gateway_owner_signature_v`.
#[derive(Clone, Copy, Debug)]
pub enum GatewayOwnerSignature {
    /// `generic_schnorr_sig_s`: challenge and response scalars.
    Schnorr {
        /// Challenge scalar `c`.
        c: Value256,
        /// Response scalar `y`.
        y: Value256,
    },
    /// A secp256k1 (ethereum) signature.
    Eth(Signature64),
    /// An ed25519 (eddsa) signature.
    Eddsa(Signature64),
}

impl GatewayOwnerSignature {
    /// The wire discriminator for this value.
    pub fn tag(&self) -> u8 {
        match self {
            GatewayOwnerSignature::Schnorr { .. } => tag::GENERIC_SCHNORR_SIG_S,
            GatewayOwnerSignature::Eth(_) => tag::ETH_SIGNATURE,
            GatewayOwnerSignature::Eddsa(_) => tag::EDDSA_SIGNATURE,
        }
    }
}

impl EpeeWrite for GatewayOwnerSignature {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            GatewayOwnerSignature::Schnorr { c, y } => {
                c.write_epee(out);
                y.write_epee(out);
            }
            GatewayOwnerSignature::Eth(v) | GatewayOwnerSignature::Eddsa(v) => v.write_epee(out),
        }
    }
}
impl EpeeRead for GatewayOwnerSignature {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match r.read_byte()? {
            tag::GENERIC_SCHNORR_SIG_S => GatewayOwnerSignature::Schnorr {
                c: Value256::read_epee(r)?,
                y: Value256::read_epee(r)?,
            },
            tag::ETH_SIGNATURE => GatewayOwnerSignature::Eth(Signature64::read_epee(r)?),
            tag::EDDSA_SIGNATURE => GatewayOwnerSignature::Eddsa(Signature64::read_epee(r)?),
            other => return Err(crate::err!("unsupported gateway signature tag {other}")),
        })
    }
}

/// A gateway input signature (`gateway_sig`), or the equivalent proof of
/// address ownership (`gateway_address_ownership_proof`). Both are a version
/// followed by one [`GatewayOwnerSignature`].
#[derive(Clone, Copy, Debug)]
pub struct GatewaySig {
    /// Structure version.
    pub version: u64,
    /// The owner's signature.
    pub sign: GatewayOwnerSignature,
}

impl EpeeWrite for GatewaySig {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.sign.write_epee(out);
    }
}
impl EpeeRead for GatewaySig {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!("unsupported gateway_sig version {version}"));
        }
        Ok(GatewaySig {
            version,
            sign: GatewayOwnerSignature::read_epee(r)?,
        })
    }
}

/// The balance proof used by transactions with no confidential input
/// (`zc_gw_balance_proof`): a linear-composition-and-schnorr signature.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZcGwBalanceProof {
    /// Challenge scalar `c`.
    pub c: Value256,
    /// Response scalar `y0`.
    pub y0: Value256,
    /// Response scalar `y1`.
    pub y1: Value256,
    /// Response scalar `y2`.
    pub y2: Value256,
}

impl EpeeWrite for ZcGwBalanceProof {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.c.write_epee(out);
        self.y0.write_epee(out);
        self.y1.write_epee(out);
        self.y2.write_epee(out);
    }
}
impl EpeeRead for ZcGwBalanceProof {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(ZcGwBalanceProof {
            c: Value256::read_epee(r)?,
            y0: Value256::read_epee(r)?,
            y1: Value256::read_epee(r)?,
            y2: Value256::read_epee(r)?,
        })
    }
}

/// A gateway owner's public key: `gateway_owner_key_v`.
#[derive(Clone, Copy, Debug)]
pub enum GatewayOwnerKey {
    /// An ed25519 public key.
    PubKey(Value256),
    /// A compressed secp256k1 (ethereum) public key.
    Eth([u8; 33]),
    /// An eddsa public key.
    Eddsa(Value256),
}

impl GatewayOwnerKey {
    /// The wire discriminator for this value.
    pub fn tag(&self) -> u8 {
        match self {
            GatewayOwnerKey::PubKey(_) => tag::PUB_KEY,
            GatewayOwnerKey::Eth(_) => tag::ETH_PUBLIC_KEY,
            GatewayOwnerKey::Eddsa(_) => tag::EDDSA_PUBLIC_KEY,
        }
    }
}

impl EpeeWrite for GatewayOwnerKey {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            GatewayOwnerKey::PubKey(v) | GatewayOwnerKey::Eddsa(v) => v.write_epee(out),
            GatewayOwnerKey::Eth(v) => out.extend_from_slice(v),
        }
    }
}
impl EpeeRead for GatewayOwnerKey {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match r.read_byte()? {
            tag::PUB_KEY => GatewayOwnerKey::PubKey(Value256::read_epee(r)?),
            tag::ETH_PUBLIC_KEY => {
                let mut v = [0u8; 33];
                v.copy_from_slice(r.read_exact(33)?);
                GatewayOwnerKey::Eth(v)
            }
            tag::EDDSA_PUBLIC_KEY => GatewayOwnerKey::Eddsa(Value256::read_epee(r)?),
            other => return Err(crate::err!("unsupported gateway owner key tag {other}")),
        })
    }
}

/// A placeholder entry kept for forward compatibility (`dummy`): a tag with no
/// payload.
#[derive(Clone, Copy, Debug, Default)]
pub struct GatewayEtcField;

impl EpeeWrite for GatewayEtcField {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(tag::DUMMY);
    }
}
impl EpeeRead for GatewayEtcField {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        match r.read_byte()? {
            tag::DUMMY => Ok(GatewayEtcField),
            other => Err(crate::err!("unsupported gateway etc field tag {other}")),
        }
    }
}

/// The common body of a gateway address descriptor.
#[derive(Clone, Debug)]
pub struct GatewayAddressDescriptorBase {
    /// Structure version.
    pub version: u64,
    /// The key that authorizes operations on this gateway address.
    pub owner_key: GatewayOwnerKey,
    /// Reserved for future optional parameters.
    pub etc: Vec<GatewayEtcField>,
    /// Free-form metadata.
    pub meta_info: String,
}

impl EpeeWrite for GatewayAddressDescriptorBase {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.owner_key.write_epee(out);
        write_vec(&self.etc, out);
        write_var_bytes(self.meta_info.as_bytes(), out);
    }
}
impl EpeeRead for GatewayAddressDescriptorBase {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!(
                "unsupported gateway address descriptor version {version}"
            ));
        }
        Ok(GatewayAddressDescriptorBase {
            version,
            owner_key: GatewayOwnerKey::read_epee(r)?,
            etc: r.read_vec()?,
            meta_info: r.read_var_string()?,
        })
    }
}

/// An operation on a gateway address descriptor, carried in tx extra.
#[derive(Clone, Debug)]
pub enum GatewayAddressDescriptorOperationKind {
    /// Registers a new gateway address.
    Register {
        /// Structure version.
        version: u64,
        /// View public key, not premultiplied by 1/8.
        view_pub_key: Value256,
        /// The descriptor being registered.
        descriptor: GatewayAddressDescriptorBase,
    },
    /// Updates an existing gateway address.
    Update {
        /// Structure version.
        version: u64,
        /// The gateway address being updated.
        address_id: Value256,
        /// The new descriptor.
        descriptor: GatewayAddressDescriptorBase,
    },
}

impl GatewayAddressDescriptorOperationKind {
    /// The wire discriminator for this value.
    pub fn tag(&self) -> u8 {
        match self {
            GatewayAddressDescriptorOperationKind::Register { .. } => {
                tag::GATEWAY_ADDRESS_DESCRIPTOR_OPERATION_REGISTER
            }
            GatewayAddressDescriptorOperationKind::Update { .. } => {
                tag::GATEWAY_ADDRESS_DESCRIPTOR_OPERATION_UPDATE
            }
        }
    }
}

impl EpeeWrite for GatewayAddressDescriptorOperationKind {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            GatewayAddressDescriptorOperationKind::Register {
                version,
                view_pub_key,
                descriptor,
            } => {
                append_varint(out, *version);
                view_pub_key.write_epee(out);
                descriptor.write_epee(out);
            }
            GatewayAddressDescriptorOperationKind::Update {
                version,
                address_id,
                descriptor,
            } => {
                append_varint(out, *version);
                address_id.write_epee(out);
                descriptor.write_epee(out);
            }
        }
    }
}
impl EpeeRead for GatewayAddressDescriptorOperationKind {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let t = r.read_byte()?;
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!(
                "unsupported gateway address operation version {version}"
            ));
        }
        Ok(match t {
            tag::GATEWAY_ADDRESS_DESCRIPTOR_OPERATION_REGISTER => {
                GatewayAddressDescriptorOperationKind::Register {
                    version,
                    view_pub_key: Value256::read_epee(r)?,
                    descriptor: GatewayAddressDescriptorBase::read_epee(r)?,
                }
            }
            tag::GATEWAY_ADDRESS_DESCRIPTOR_OPERATION_UPDATE => {
                GatewayAddressDescriptorOperationKind::Update {
                    version,
                    address_id: Value256::read_epee(r)?,
                    descriptor: GatewayAddressDescriptorBase::read_epee(r)?,
                }
            }
            other => {
                return Err(crate::err!(
                    "unsupported gateway address operation tag {other}"
                ));
            }
        })
    }
}

/// The tx-extra entry wrapping a [`GatewayAddressDescriptorOperationKind`].
#[derive(Clone, Debug)]
pub struct GatewayAddressDescriptorOperation {
    /// Structure version.
    pub version: u64,
    /// The operation itself.
    pub operation: GatewayAddressDescriptorOperationKind,
}

impl EpeeWrite for GatewayAddressDescriptorOperation {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.operation.write_epee(out);
    }
}
impl EpeeRead for GatewayAddressDescriptorOperation {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 0 {
            return Err(crate::err!(
                "unsupported gateway address descriptor operation version {version}"
            ));
        }
        Ok(GatewayAddressDescriptorOperation {
            version,
            operation: GatewayAddressDescriptorOperationKind::read_epee(r)?,
        })
    }
}
