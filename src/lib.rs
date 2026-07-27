//! # zanolib
//!
//! A Zano wallet library: address parsing, transaction (de)serialization,
//! offline signing, deposit scanning, and threshold (MPC) spend keys.
//!
//! ## Layout
//!
//! | module | contents |
//! |--------|----------|
//! | [`crypto`] | curve helpers, hash-to-point, key derivation, CLSAG-GGX, Bulletproof+, BGE |
//! | [`base`] | varints, the binary codec, transactions and their variant payloads |
//! | [`epee`] | the portable-storage codec used by the daemon's `.bin` endpoints |
//! | [`proof`] | transaction-wide balance, range and asset surjection proofs |
//! | [`rpc`] | JSON-RPC client and deposit scanner (feature `rpc`) |
//! | [`mpc`] | threshold spend key via FROST (feature `mpc`) |
//!
//! Everything else — addresses, wallets, scanning and signing — lives at the
//! crate root.
//!
//! ```no_run
//! use zanolib::Wallet;
//!
//! let mut secret = [0u8; 32];
//! secret[0] = 1; // any canonical scalar
//! let wallet = Wallet::load_spend_secret(&secret, 0)?;
//! println!("{}", wallet.address());
//! # Ok::<(), zanolib::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod base;
pub mod crypto;
pub mod epee;
mod error;
pub mod proof;
pub mod rng;

mod address;
mod finalized;
mod ftp;
mod inputsigner;
mod scan;
mod signature;
mod transfer;
mod txdest;
mod txsource;
mod wallet;

#[cfg(feature = "mpc")]
pub mod mpc;
#[cfg(feature = "rpc")]
pub mod rpc;

pub use address::{Address, AddressType};
pub use error::{Error, Result};
pub use finalized::FinalizedTx;
pub use ftp::FinalizeTxParam;
pub use inputsigner::{ClsagRequest, InputSigner, LocalInputSigner};
pub use scan::{ReceivedOutput, ScanResult};
pub use transfer::{RingMember, TransferDest, TransferInput, native_coin_asset_id};
pub use txdest::{TxDest, TxDestHtlcOut};
pub use txsource::{TxSource, TxSourceOutputEntry};
pub use wallet::{ViewWalletData, Wallet};
