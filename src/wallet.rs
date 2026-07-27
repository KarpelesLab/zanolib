//! Wallet key material: full wallets derived from a spend secret, and view-only
//! wallets built from a view secret plus a spend public key.

use crate::address::{Address, AddressType};
use crate::base::EpeeWrite;
use crate::crypto::{
    Point, Scalar, chacha8, chacha8_generate_key, pub_from_priv, scalar_from_canonical,
    scalar_from_wide,
};
use crate::error::{Error, Result};
use crate::finalized::FinalizedTx;
use crate::ftp::FinalizeTxParam;
use purecrypto::hash::keccak256;
use serde::{Deserialize, Serialize};

/// A Zano wallet: the spend and view key pairs, plus the address flags.
///
/// `spend_priv_key` is `None` for a view-only wallet, which can scan for
/// deposits but cannot sign.
#[derive(Clone, Debug)]
pub struct Wallet {
    /// Secret spend key, absent in a view-only wallet.
    pub spend_priv_key: Option<Scalar>,
    /// Public spend key.
    pub spend_pub_key: Point,
    /// Secret view key.
    pub view_priv_key: Scalar,
    /// Public view key.
    pub view_pub_key: Point,
    /// Address flags; bit 0 marks an auditable wallet.
    pub flags: u8,
}

impl Wallet {
    /// Builds a wallet from a spend secret (what `spendkey` prints in the Zano
    /// wallet), deriving the view key the way Zano does:
    /// `view_secret = keccak256(spend_secret) mod L`.
    ///
    /// Note that Zano does *not* clamp view keys; clamping would derive a
    /// different key and break everything downstream.
    ///
    /// Pass `flags = 1` for an auditable wallet, otherwise 0.
    pub fn load_spend_secret(pk: &[u8], flags: u8) -> Result<Wallet> {
        let spend_priv = scalar_from_canonical(pk)?;
        let view_priv = scalar_from_wide(&keccak256(pk));
        Ok(Wallet {
            spend_pub_key: pub_from_priv(&spend_priv),
            spend_priv_key: Some(spend_priv),
            view_pub_key: pub_from_priv(&view_priv),
            view_priv_key: view_priv,
            flags,
        })
    }

    /// Generates a fresh wallet from `rnd`.
    pub fn generate(rnd: &mut dyn crate::rng::RngCore, flags: u8) -> Result<Wallet> {
        let mut seed = [0u8; 64];
        rnd.fill_bytes(&mut seed);
        // Reduce to a canonical scalar: Zano secret keys are reduced scalars.
        let s = Scalar::from_bytes_mod_order(&seed);
        Wallet::load_spend_secret(&s.to_bytes(), flags)
    }

    /// Builds a view-only wallet from a view secret key and a spend public key
    /// (what a Zano watch-only wallet exports).
    pub fn load_view_only(
        view_secret_key: &[u8],
        spend_public_key: &[u8],
        flags: u8,
    ) -> Result<Wallet> {
        if view_secret_key.len() != 32 {
            return Err(crate::err!(
                "view secret key must be 32 bytes, got {}",
                view_secret_key.len()
            ));
        }
        if spend_public_key.len() != 32 {
            return Err(crate::err!(
                "spend public key must be 32 bytes, got {}",
                spend_public_key.len()
            ));
        }
        let view_priv = scalar_from_canonical(view_secret_key)
            .map_err(|_| Error::msg("invalid view secret key"))?;
        let spend_pub = crate::crypto::point_from_bytes(spend_public_key)
            .map_err(|_| Error::msg("invalid spend public key"))?;
        Ok(Wallet {
            spend_priv_key: None,
            spend_pub_key: spend_pub,
            view_pub_key: pub_from_priv(&view_priv),
            view_priv_key: view_priv,
            flags,
        })
    }

    /// Whether this wallet lacks a spend secret (scan-only).
    pub fn is_view_only(&self) -> bool {
        self.spend_priv_key.is_none()
    }

    /// This wallet's address.
    pub fn address(&self) -> Address {
        let typ = if self.flags & 1 == 1 {
            AddressType::Audit
        } else {
            AddressType::Public
        };
        Address {
            typ,
            flags: self.flags,
            spend_key: self.spend_pub_key.compress().to_vec(),
            view_key: self.view_pub_key.compress().to_vec(),
            payment_id: Vec::new(),
        }
    }

    /// Decrypts and parses a finalize-transaction-parameter blob.
    pub fn parse_ftp(&self, buf: &[u8]) -> Result<FinalizeTxParam> {
        FinalizeTxParam::parse(buf, &self.view_priv_key.to_bytes())
    }

    /// Decrypts and parses a finalized-transaction blob.
    pub fn parse_finalized(&self, buf: &[u8]) -> Result<FinalizedTx> {
        FinalizedTx::parse(buf, &self.view_priv_key.to_bytes())
    }

    /// Serializes and encrypts a value the way the Zano wallet stores transfer
    /// blobs, so it can be read back with [`Wallet::parse_ftp`] or
    /// [`Wallet::parse_finalized`].
    pub fn encrypt<T: EpeeWrite>(&self, data: &T) -> Result<Vec<u8>> {
        let plain = data.to_epee_bytes();
        let code = chacha8_generate_key(&self.view_priv_key.to_bytes())?;
        chacha8(&code, &[0u8; 8], &plain)
    }

    /// The JSON-marshalable view-only description of this wallet, for handing
    /// to a scanner. `start_height` is where scanning should begin.
    pub fn export_view(&self, start_height: u64) -> ViewWalletData {
        ViewWalletData {
            address: Some(self.address().to_string()),
            spend_public_key: Some(hex::encode(self.spend_pub_key.compress())),
            view_public_key: Some(hex::encode(self.view_pub_key.compress())),
            view_secret_key: hex::encode(self.view_priv_key.to_bytes()),
            flags: self.flags,
            start_height,
        }
    }
}

/// A JSON-marshalable view-only wallet plus the height to resume scanning from.
///
/// Either `address` or `spend_public_key` must be set; `view_public_key` is
/// optional and validated against `view_secret_key` when present.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ViewWalletData {
    /// Standard Zano address (an alternative to the explicit keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Public spend key, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_public_key: Option<String>,
    /// Public view key, hex (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view_public_key: Option<String>,
    /// Secret view key, hex.
    pub view_secret_key: String,
    /// Address flags; 1 = auditable.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub flags: u8,
    /// Block height to resume scanning from.
    pub start_height: u64,
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

impl ViewWalletData {
    /// Builds the view-only [`Wallet`] this describes. `start_height` is
    /// scanner metadata and is not part of the wallet.
    pub fn load_view_wallet(&self) -> Result<Wallet> {
        let view_sec =
            hex::decode(&self.view_secret_key).map_err(|e| crate::err!("view_secret_key: {e}"))?;

        let (spend_pub, flags) = match (&self.spend_public_key, &self.address) {
            (Some(s), _) if !s.is_empty() => (
                hex::decode(s).map_err(|e| crate::err!("spend_public_key: {e}"))?,
                self.flags,
            ),
            (_, Some(a)) if !a.is_empty() => {
                let addr = Address::parse(a).map_err(|e| crate::err!("address: {e}"))?;
                (addr.spend_key.clone(), addr.flags)
            }
            _ => {
                return Err(Error::msg(
                    "view wallet data needs either address or spend_public_key",
                ));
            }
        };

        let w = Wallet::load_view_only(&view_sec, &spend_pub, flags)?;

        if let Some(vpub) = self.view_public_key.as_deref().filter(|s| !s.is_empty()) {
            let want = hex::decode(vpub).map_err(|e| crate::err!("view_public_key: {e}"))?;
            if w.view_pub_key.compress()[..] != want[..] {
                return Err(Error::msg("view_public_key does not match view_secret_key"));
            }
        }
        if let Some(addr) = self.address.as_deref().filter(|s| !s.is_empty()) {
            let got = w.address().to_string();
            if got != addr {
                return Err(crate::err!(
                    "address {addr:?} does not match the provided keys (derived {got:?})"
                ));
            }
        }
        Ok(w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::FixedRng;

    /// A valid (canonical, i.e. < L) spend secret, as used by the Go tests.
    fn spend_secret(first: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = first;
        b
    }

    #[test]
    fn view_key_is_keccak_of_spend_secret() {
        let spend = spend_secret(1);
        let w = Wallet::load_spend_secret(&spend, 0).unwrap();
        let want = scalar_from_wide(&keccak256(&spend));
        assert_eq!(w.view_priv_key.to_bytes(), want.to_bytes());
        assert_eq!(w.view_pub_key, Point::mul_base(&w.view_priv_key));
        assert_eq!(
            w.spend_pub_key,
            Point::mul_base(w.spend_priv_key.as_ref().unwrap())
        );
        assert!(!w.is_view_only());
    }

    #[test]
    fn wallet_is_deterministic() {
        let a = Wallet::load_spend_secret(&spend_secret(7), 0).unwrap();
        let b = Wallet::load_spend_secret(&spend_secret(7), 0).unwrap();
        assert_eq!(a.address().to_string(), b.address().to_string());
    }

    #[test]
    fn auditable_flag_changes_the_address_type() {
        let w = Wallet::load_spend_secret(&spend_secret(9), 1).unwrap();
        assert_eq!(w.address().typ, AddressType::Audit);
        assert!(w.address().to_string().starts_with("aZx"));
    }

    #[test]
    fn short_or_non_canonical_keys_are_rejected() {
        assert!(Wallet::load_spend_secret(&[1, 2, 3], 0).is_err());
        // 0xff.. is larger than the group order L.
        assert!(Wallet::load_spend_secret(&[0xff; 32], 0).is_err());
    }

    #[test]
    fn view_only_round_trip() {
        let mut rnd = FixedRng(0x42);
        let full = Wallet::generate(&mut rnd, 0).unwrap();
        let data = full.export_view(1234);
        let view = data.load_view_wallet().unwrap();
        assert!(view.is_view_only());
        assert_eq!(view.address().to_string(), full.address().to_string());
        assert_eq!(view.view_priv_key.to_bytes(), full.view_priv_key.to_bytes());
    }

    #[test]
    fn view_wallet_data_json_round_trip() {
        let full = Wallet::load_spend_secret(&spend_secret(3), 0).unwrap();
        let json = serde_json::to_string(&full.export_view(10)).unwrap();
        let back: ViewWalletData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.start_height, 10);
        assert_eq!(
            back.load_view_wallet().unwrap().address().to_string(),
            full.address().to_string()
        );
    }

    #[test]
    fn mismatched_view_public_key_is_rejected() {
        let full = Wallet::load_spend_secret(&spend_secret(3), 0).unwrap();
        let mut data = full.export_view(0);
        data.view_public_key = Some(hex::encode([0x02u8; 32]));
        assert!(data.load_view_wallet().is_err());
    }

    #[test]
    fn view_only_needs_a_key_source() {
        let data = ViewWalletData {
            view_secret_key: hex::encode([1u8; 32]),
            ..Default::default()
        };
        assert!(data.load_view_wallet().is_err());
    }
}
