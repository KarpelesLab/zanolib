//! Zano's on-the-wire data model: varints, the binary codec, transactions and
//! the tagged-union payloads they carry.
//!
//! Port of the Go `zanobase` package. Where Go used reflection plus struct
//! tags, each type here implements [`EpeeWrite`]/[`EpeeRead`] explicitly, so the
//! byte layout of every field is visible at the definition site.

pub mod gateway;
pub mod gencontext;
pub mod ser;
pub mod sig;
pub mod tx;
pub mod types;
pub mod variant;
pub mod varint;

pub use gateway::{
    GatewayAddressDescriptorBase, GatewayAddressDescriptorOperation,
    GatewayAddressDescriptorOperationKind, GatewayEtcField, GatewayOwnerKey, GatewayOwnerSignature,
    GatewaySig, Signature64, ZcGwBalanceProof,
};
pub use gencontext::GenContext;
pub use ser::{EpeeRead, EpeeWrite, Reader, write_var_bytes, write_vec};
pub use sig::{
    BgeProof, BppSignature, ClsagSig, GenericDoubleSchnorrSig, UgAggProof, ZcAssetSurjectionProof,
    ZcBalanceProof, ZcOutsRangeProof, ZcSig,
};
pub use tx::{
    CURRENCY_HF4_MANDATORY_MIN_COINAGE, CURRENCY_TX_MAX_ALLOWED_INPUTS,
    CURRENCY_TX_MAX_ALLOWED_OUTS, CURRENCY_TX_MIN_ALLOWED_OUTS, CURRENCY_TX_PRACTICAL_MAX_INPUTS,
    TRANSACTION_VERSION_INITIAL, TRANSACTION_VERSION_POST_HF4, TRANSACTION_VERSION_POST_HF5,
    TRANSACTION_VERSION_POST_HF6, TRANSACTION_VERSION_PRE_HF4, Transaction, TransactionPrefix,
    TxInGateway, TxInGen, TxInToKey, TxInZcInput, TxOutGateway, TxOutZarcanum,
    ZANO_HARDFORK_04_AFTER_HEIGHT, ZANO_HARDFORK_05_AFTER_HEIGHT, ZANO_HARDFORK_06_AFTER_HEIGHT,
    tx_version_and_hardfork_id,
};
pub use types::{AccountPublicAddr, AddressV, KeyImageIndex, KeyPair, RefById, Value256};
pub use variant::{
    ExtraAttachmentInfo, ExtraPadding, ExtraUserData, PAYMENT_ID_SERVICE_ID, SignedParts,
    TX_SERVICE_ATTACHMENT_DEFLATE_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_ADD_PROOF,
    TX_SERVICE_ATTACHMENT_ENCRYPT_BODY, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY_ISOLATE_AUDITABLE,
    TxComment, TxCryptoChecksum, TxServiceAttachment, Variant, tag,
};
pub use varint::{append_varint, take_varint, varint_bytes, varint_packed_size};
