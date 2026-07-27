//! A Zano spend key under multi-party threshold control, using tsslib's
//! FROST-ed25519 protocol.
//!
//! The spend secret is generated and held as `{t,n}` shares across machines and
//! never reconstructed; spending runs a threshold protocol (see [`signer`]).
//!
//! Unlike a normal Zano wallet, the view key is *not* `keccak(spend_secret)` —
//! that derivation cannot run under MPC. Instead
//! [`ThresholdInputSigner::derive_view_secret`] runs tsslib's threshold
//! key-image ceremony (a distributed PRF, with DLEQ-proved point-to-point
//! partials) over a fixed identifier, so a threshold wallet still has a stable
//! view key and address without any out-of-band agreement. A Zano address is
//! just `(spend_pub, view_pub)`, so the result is valid on-chain — at the cost
//! of the usual seed-phrase recovery.
//!
//! Port of the Go `zanompc` package. The threshold view secret differs in value
//! from the Go `DeriveViewSecret()`, which hand-rolled the same construction
//! with Zano's hash-to-point and no DLEQ proofs; see [`viewkey`].

pub mod clsag;
pub mod keygen;
pub mod sign;
pub mod signer;
pub mod transport;
pub mod viewkey;

pub use clsag::{ClsagContext, ClsagCoordinator, ClsagParty};
pub use keygen::{address, spend_public_key, spend_public_key_bytes};
pub use sign::{additive_share, combine_points, committee_share_ids, partial_key_image};
pub use signer::ThresholdInputSigner;
pub use transport::exchange;
pub use viewkey::VIEW_KEY_IDENTIFIER;
