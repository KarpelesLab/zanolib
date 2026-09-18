//! Confidential-asset operations carried in tx extra.
//!
//! An `asset_descriptor_operation` deploys, emits, updates or burns an asset.
//! Two shapes exist on chain: the HF4 one (version 1, with a mandatory
//! descriptor and amount commitment) and the HF5 one (version 2, where every
//! field is optional and an explicit amount replaces the commitment for
//! emit/burn). This crate parses both so that every transaction can be read;
//! it does not build them.

use super::ser::{EpeeRead, EpeeWrite, Reader, write_optional, write_var_bytes, write_vec};
use super::types::Value256;
use super::variant::tag;
use super::varint::append_varint;
use crate::error::Result;

/// `ASSET_DESCRIPTOR_OPERATION_UNDEFINED`.
pub const ASSET_DESCRIPTOR_OPERATION_UNDEFINED: u8 = 0;
/// `ASSET_DESCRIPTOR_OPERATION_REGISTER`: deploys a new asset.
pub const ASSET_DESCRIPTOR_OPERATION_REGISTER: u8 = 1;
/// `ASSET_DESCRIPTOR_OPERATION_EMIT`: mints more of an asset.
pub const ASSET_DESCRIPTOR_OPERATION_EMIT: u8 = 2;
/// `ASSET_DESCRIPTOR_OPERATION_UPDATE`: changes an asset's descriptor.
pub const ASSET_DESCRIPTOR_OPERATION_UPDATE: u8 = 3;
/// `ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN`: destroys some of an asset.
pub const ASSET_DESCRIPTOR_OPERATION_PUBLIC_BURN: u8 = 4;

/// `ASSET_DESCRIPTOR_OPERATION_HF4_VER`.
pub const ASSET_DESCRIPTOR_OPERATION_HF4_VER: u64 = 1;
/// `ASSET_DESCRIPTOR_OPERATION_HF5_VER` (also the last supported version).
pub const ASSET_DESCRIPTOR_OPERATION_HF5_VER: u64 = 2;

/// A placeholder entry reserved for future fields (`dummy`): a tag with no
/// payload.
#[derive(Clone, Copy, Debug, Default)]
pub struct AssetEtcField;

impl EpeeWrite for AssetEtcField {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(tag::DUMMY);
    }
}
impl EpeeRead for AssetEtcField {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        match r.read_byte()? {
            tag::DUMMY => Ok(AssetEtcField),
            other => Err(crate::err!("unsupported asset etc field tag {other}")),
        }
    }
}

/// An asset's metadata (`asset_descriptor_base`).
#[derive(Clone, Debug, Default)]
pub struct AssetDescriptorBase {
    /// Structure version: 0 (HF4) or 2 (HF5); the later fields are absent in
    /// the earlier versions.
    pub version: u64,
    /// Maximum supply that may ever exist.
    pub total_max_supply: u64,
    /// Supply in existence.
    pub current_supply: u64,
    /// Where the decimal point sits when displaying amounts.
    pub decimal_point: u8,
    /// Short ticker, as raw bytes.
    pub ticker: Vec<u8>,
    /// Display name, as raw bytes.
    pub full_name: Vec<u8>,
    /// Free-form metadata, as raw bytes.
    pub meta_info: Vec<u8>,
    /// The key that may update or emit the asset.
    pub owner: Value256,
    /// Whether the supply is confidential.
    pub hidden_supply: bool,
    /// An ethereum owner key, from version 1 on.
    pub owner_eth_pub_key: Option<[u8; 33]>,
    /// Reserved for future fields, from version 2 on.
    pub etc: Vec<AssetEtcField>,
}

impl EpeeWrite for AssetDescriptorBase {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        self.total_max_supply.write_epee(out);
        self.current_supply.write_epee(out);
        out.push(self.decimal_point);
        write_var_bytes(&self.ticker, out);
        write_var_bytes(&self.full_name, out);
        write_var_bytes(&self.meta_info, out);
        self.owner.write_epee(out);
        out.push(self.hidden_supply as u8);
        if self.version < 1 {
            return;
        }
        match &self.owner_eth_pub_key {
            Some(k) => {
                out.push(0);
                out.extend_from_slice(k);
            }
            None => out.push(1),
        }
        if self.version < 2 {
            return;
        }
        write_vec(&self.etc, out);
    }
}
impl EpeeRead for AssetDescriptorBase {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > 2 {
            return Err(crate::err!(
                "unsupported asset_descriptor_base version {version}"
            ));
        }
        let mut adb = AssetDescriptorBase {
            version,
            total_max_supply: u64::read_epee(r)?,
            current_supply: u64::read_epee(r)?,
            decimal_point: r.read_byte()?,
            ticker: r.read_var_bytes()?,
            full_name: r.read_var_bytes()?,
            meta_info: r.read_var_bytes()?,
            owner: Value256::read_epee(r)?,
            hidden_supply: bool::read_epee(r)?,
            owner_eth_pub_key: None,
            etc: Vec::new(),
        };
        if version < 1 {
            return Ok(adb);
        }
        adb.owner_eth_pub_key = match r.read_byte()? {
            0 => {
                let mut k = [0u8; 33];
                k.copy_from_slice(r.read_exact(33)?);
                Some(k)
            }
            1 => None,
            other => return Err(crate::err!("invalid optional flag {other}")),
        };
        if version < 2 {
            return Ok(adb);
        }
        adb.etc = r.read_vec()?;
        Ok(adb)
    }
}

/// An operation on a confidential asset (`asset_descriptor_operation`).
///
/// The wire version decides which fields are present, so it is kept verbatim
/// and re-emitted as read.
#[derive(Clone, Debug, Default)]
pub struct AssetDescriptorOperation {
    /// Structure version: 0 or 1 (HF4 shape) or 2 (HF5 shape).
    pub version: u64,
    /// Which operation this is; see the `ASSET_DESCRIPTOR_OPERATION_*`
    /// constants.
    pub operation_type: u8,
    /// The asset's metadata. Mandatory in the HF4 shape.
    pub descriptor: Option<AssetDescriptorBase>,
    /// Commitment to the amount emitted or burned, premultiplied by 1/8.
    pub amount_commitment: Option<Value256>,
    /// The asset being operated on (absent when deploying).
    pub asset_id: Option<Value256>,
    /// Explicit amount, used by emit/burn from version 2 on.
    pub amount: Option<u64>,
    /// Salt mixed into a newly derived asset id, from version 2 on.
    pub asset_id_salt: Option<u32>,
    /// Reserved for future fields, from version 2 on.
    pub etc: Vec<AssetEtcField>,
}

impl EpeeWrite for AssetDescriptorOperation {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.version);
        out.push(self.operation_type);
        if self.version < ASSET_DESCRIPTOR_OPERATION_HF5_VER {
            // The HF4 shape: a mandatory descriptor and amount commitment,
            // then an optional asset id.
            self.descriptor.clone().unwrap_or_default().write_epee(out);
            self.amount_commitment
                .unwrap_or(Value256::ZERO)
                .write_epee(out);
            write_optional(&self.asset_id, out);
            return;
        }
        write_optional(&self.amount_commitment, out);
        write_optional(&self.asset_id, out);
        write_optional(&self.descriptor, out);
        write_optional(&self.amount, out);
        write_optional(&self.asset_id_salt, out);
        write_vec(&self.etc, out);
    }
}
impl EpeeRead for AssetDescriptorOperation {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        let version = r.read_varint()?;
        if version > ASSET_DESCRIPTOR_OPERATION_HF5_VER {
            return Err(crate::err!(
                "unsupported asset_descriptor_operation version {version}"
            ));
        }
        let operation_type = r.read_byte()?;
        if version < ASSET_DESCRIPTOR_OPERATION_HF5_VER {
            return Ok(AssetDescriptorOperation {
                version,
                operation_type,
                descriptor: Some(AssetDescriptorBase::read_epee(r)?),
                amount_commitment: Some(Value256::read_epee(r)?),
                asset_id: r.read_optional()?,
                amount: None,
                asset_id_salt: None,
                etc: Vec::new(),
            });
        }
        Ok(AssetDescriptorOperation {
            version,
            operation_type,
            amount_commitment: r.read_optional()?,
            asset_id: r.read_optional()?,
            descriptor: r.read_optional()?,
            amount: r.read_optional()?,
            asset_id_salt: r.read_optional()?,
            etc: r.read_vec()?,
        })
    }
}
