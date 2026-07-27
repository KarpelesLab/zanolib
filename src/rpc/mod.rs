//! A minimal client for a Zano daemon, plus the deposit scanner built on it.
//!
//! The networking lives here, separate from the pure crypto and serialization
//! in [`crate::crypto`] and [`crate::base`]. Requests are synchronous.
//!
//! Port of the Go `zanorpc` package.

pub mod client;
pub mod scanner;
pub mod send;
pub mod spend;

pub use client::{
    AssetDescriptor, BlockDetails, Client, MODCHAIN_ZANO, TxBrief, TxDetails, TxOutInfo,
    format_atomic,
};
pub use scanner::{DEFAULT_BATCH_SIZE, Deposit, Scanner};
pub use send::{OutEntry, build_decoy_offsets};
pub use spend::{RING_SIZE, SweepResult, TX_HARDFORK_ID};
