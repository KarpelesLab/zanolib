//! Zano's on-the-wire data model: varints, the binary codec, transactions and
//! the tagged-union payloads they carry.
//!
//! Port of the Go `zanobase` package. Where Go used reflection plus struct
//! tags, each type here implements [`EpeeWrite`]/[`EpeeRead`] explicitly, so the
//! byte layout of every field is visible at the definition site.

pub mod gencontext;
pub mod ser;
pub mod sig;
pub mod tx;
pub mod types;
pub mod variant;
pub mod varint;

pub use gencontext::GenContext;
pub use ser::{EpeeRead, EpeeWrite, Reader, write_var_bytes, write_vec};
pub use sig::{
    BgeProof, BppSignature, ClsagSig, GenericDoubleSchnorrSig, UgAggProof, ZcAssetSurjectionProof,
    ZcBalanceProof, ZcOutsRangeProof, ZcSig,
};
pub use tx::{
    TRANSACTION_VERSION_INITIAL, TRANSACTION_VERSION_POST_HF4, TRANSACTION_VERSION_POST_HF5,
    TRANSACTION_VERSION_PRE_HF4, Transaction, TransactionPrefix, TxInGen, TxInToKey, TxInZcInput,
    TxOutZarcanum,
};
pub use types::{AccountPublicAddr, KeyImageIndex, KeyPair, RefById, Value256};
pub use variant::{
    ExtraAttachmentInfo, ExtraPadding, ExtraUserData, PAYMENT_ID_SERVICE_ID, SignedParts,
    TX_SERVICE_ATTACHMENT_DEFLATE_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF,
    TX_SERVICE_ATTACHMENT_ENCRYPT_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE,
    TxComment, TxCryptoChecksum, TxServiceAttachment, Variant, tag,
};
pub use varint::{append_varint, take_varint, varint_bytes, varint_packed_size};
