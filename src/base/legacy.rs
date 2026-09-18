//! Structures from Zano's pre-Zarcanum era: transparent inputs and outputs,
//! the older address encoding, and alias registrations.
//!
//! Transactions older than HF4 are still on the chain, so a scanner that walks
//! history from the start must be able to read them. This crate never builds
//! them.

use super::gateway::Signature64;
use super::ser::{EpeeRead, EpeeWrite, Reader, write_var_bytes, write_vec};
use super::types::{AccountPublicAddr, Value256};
use super::variant::{Variant, tag};
use super::varint::append_varint;
use crate::error::Result;

/// The pre-HF2 account address: a spend and a view key, without flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountPublicAddrOld {
    /// Public spend key.
    pub spend_key: Value256,
    /// Public view key.
    pub view_key: Value256,
}

impl EpeeWrite for AccountPublicAddrOld {
    fn write_epee(&self, out: &mut Vec<u8>) {
        self.spend_key.write_epee(out);
        self.view_key.write_epee(out);
    }
}
impl EpeeRead for AccountPublicAddrOld {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(AccountPublicAddrOld {
            spend_key: Value256::read_epee(r)?,
            view_key: Value256::read_epee(r)?,
        })
    }
}

/// A transparent input spending a multisig output.
#[derive(Clone, Debug)]
pub struct TxInMultisig {
    /// Input amount.
    pub amount: u64,
    /// Id of the multisig output being spent.
    pub multisig_out_id: Value256,
    /// Number of signatures provided.
    pub sigs_count: u64,
    /// Additional input details.
    pub etc_details: Vec<Variant>,
}

impl EpeeWrite for TxInMultisig {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.amount);
        self.multisig_out_id.write_epee(out);
        append_varint(out, self.sigs_count);
        write_vec(&self.etc_details, out);
    }
}
impl EpeeRead for TxInMultisig {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxInMultisig {
            amount: r.read_varint()?,
            multisig_out_id: Value256::read_epee(r)?,
            sigs_count: r.read_varint()?,
            etc_details: r.read_vec()?,
        })
    }
}

/// A transparent output's target: who may spend it.
#[derive(Clone, Debug)]
pub enum TxoutTarget {
    /// Payable to one key.
    ToKey {
        /// The output's one-time public key.
        key: Value256,
        /// Mixin attribute (0 = relaxed, 1 = no mixing, >= 2 = minimum ring).
        mix_attr: u8,
    },
    /// Payable by `minimum_sigs` of `keys`.
    Multisig {
        /// Signatures required to spend.
        minimum_sigs: u64,
        /// The keys that may sign.
        keys: Vec<Value256>,
    },
}

impl TxoutTarget {
    /// The wire discriminator for this value.
    pub fn tag(&self) -> u8 {
        match self {
            TxoutTarget::ToKey { .. } => tag::TXOUT_TO_KEY,
            TxoutTarget::Multisig { .. } => tag::TXOUT_MULTISIG,
        }
    }
}

impl EpeeWrite for TxoutTarget {
    fn write_epee(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            // txout_to_key is a packed POD: the key followed by mix_attr.
            TxoutTarget::ToKey { key, mix_attr } => {
                key.write_epee(out);
                out.push(*mix_attr);
            }
            TxoutTarget::Multisig { minimum_sigs, keys } => {
                append_varint(out, *minimum_sigs);
                write_vec(keys, out);
            }
        }
    }
}
impl EpeeRead for TxoutTarget {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(match r.read_byte()? {
            tag::TXOUT_TO_KEY => TxoutTarget::ToKey {
                key: Value256::read_epee(r)?,
                mix_attr: r.read_byte()?,
            },
            tag::TXOUT_MULTISIG => TxoutTarget::Multisig {
                minimum_sigs: r.read_varint()?,
                keys: r.read_vec()?,
            },
            other => return Err(crate::err!("unsupported txout target tag {other}")),
        })
    }
}

/// A transparent output: an explicit amount and its target.
#[derive(Clone, Debug)]
pub struct TxOutBare {
    /// Amount, in atomic units.
    pub amount: u64,
    /// Who may spend it.
    pub target: TxoutTarget,
}

impl EpeeWrite for TxOutBare {
    fn write_epee(&self, out: &mut Vec<u8>) {
        append_varint(out, self.amount);
        self.target.write_epee(out);
    }
}
impl EpeeRead for TxOutBare {
    fn read_epee(r: &mut Reader<'_>) -> Result<Self> {
        Ok(TxOutBare {
            amount: r.read_varint()?,
            target: TxoutTarget::read_epee(r)?,
        })
    }
}

/// An alias registration or update carried in tx extra.
///
/// The address is the older two-key form for [`tag::EXTRA_ALIAS_ENTRY_OLD`]
/// (pre-HF2) and the current one for [`tag::EXTRA_ALIAS_ENTRY`]. Both write
/// the alias name first, before the inherited fields.
#[derive(Clone, Debug)]
pub struct ExtraAliasEntry {
    /// The alias name, as raw bytes.
    pub alias: Vec<u8>,
    /// The address it resolves to.
    pub address: AliasAddress,
    /// Free-form comment, as raw bytes.
    pub text_comment: Vec<u8>,
    /// The tracking (view) key, when the alias publishes one.
    pub view_key: Vec<Value256>,
    /// The signature authorizing an update.
    pub sign: Vec<Signature64>,
}

/// The address an alias resolves to, in whichever form its entry uses.
#[derive(Clone, Copy, Debug)]
pub enum AliasAddress {
    /// The current form, with flags.
    Current(AccountPublicAddr),
    /// The pre-HF2 form.
    Old(AccountPublicAddrOld),
}

impl ExtraAliasEntry {
    /// Reads an entry whose address is in the given form.
    pub fn read_with(r: &mut Reader<'_>, old: bool) -> Result<Self> {
        let alias = r.read_var_bytes()?;
        let address = if old {
            AliasAddress::Old(AccountPublicAddrOld::read_epee(r)?)
        } else {
            AliasAddress::Current(AccountPublicAddr::read_epee(r)?)
        };
        Ok(ExtraAliasEntry {
            alias,
            address,
            text_comment: r.read_var_bytes()?,
            view_key: r.read_vec()?,
            sign: r.read_vec()?,
        })
    }
}

impl EpeeWrite for ExtraAliasEntry {
    fn write_epee(&self, out: &mut Vec<u8>) {
        write_var_bytes(&self.alias, out);
        match &self.address {
            AliasAddress::Current(a) => a.write_epee(out),
            AliasAddress::Old(a) => a.write_epee(out),
        }
        write_var_bytes(&self.text_comment, out);
        write_vec(&self.view_key, out);
        write_vec(&self.sign, out);
    }
}
