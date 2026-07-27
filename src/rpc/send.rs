//! Decoy-ring selection and transaction broadcast.

use super::client::Client;
use crate::base::Value256;
use crate::epee::{Section, marshal, unmarshal};
use crate::error::{Error, Result};
use crate::rng::{OsRng, RngCore};

/// One ring-member output returned by `getrandom_outs3`: its global index plus
/// the public data needed to use it as a decoy. The point fields are stored
/// pre-multiplied by 1/8, as on-chain.
#[derive(Clone, Copy, Debug)]
pub struct OutEntry {
    /// Chain-wide global output index.
    pub global_index: u64,
    /// One-time public key.
    pub stealth_address: Value256,
    /// Concealing point.
    pub concealing_point: Value256,
    /// Amount commitment.
    pub amount_commitment: Value256,
    /// Blinded asset id.
    pub blinded_asset_id: Value256,
    /// Output flags.
    pub flags: u64,
}

/// Packed size of `currency::out_entry` (`#pragma pack(1)`):
/// `uint64 + 4*public_key + uint64`.
const OUT_ENTRY_SIZE: usize = 144;

impl Client {
    /// Fetches a ring (the real output plus decoys) for a confidential output
    /// via `getrandom_outs3` on the daemon's binary endpoint — the method
    /// Zano's own send path uses, with client-chosen decoy global offsets.
    ///
    /// `ring_size - 1` distinct random indices strictly below
    /// `real_global_index` are sampled (so every decoy is an older, valid
    /// confidential output) alongside the real index itself, so the daemon
    /// returns the real output's public data with the decoys. The caller
    /// locates the real one by global index.
    pub fn get_ring_for_output(
        &self,
        real_global_index: u64,
        ring_size: usize,
    ) -> Result<Vec<OutEntry>> {
        let offsets = build_decoy_offsets(real_global_index, ring_size, &mut OsRng)?;

        let mut dist = Section::new();
        dist.set("amount", 0u64) // 0 => the ZC (post-zarcanum) zone
            .set("global_offsets", offsets);
        let mut req = Section::new();
        req.set("amounts", vec![dist])
            .set("height_upper_limit", 0u64)
            .set("use_forced_mix_outs", false)
            .set("coinbase_percents", 0u64);

        let resp_bytes = self
            .post_bin("getrandom_outs3", marshal(&req))
            .map_err(|e| crate::err!("getrandom_outs3.bin: {e}"))?;
        let resp =
            unmarshal(&resp_bytes).map_err(|e| crate::err!("getrandom_outs3.bin: decode: {e}"))?;

        if let Some(st) = resp.bytes("status") {
            let st = String::from_utf8_lossy(st);
            if st != "OK" && !st.is_empty() {
                return Err(crate::err!("getrandom_outs3.bin: status {st:?}"));
            }
        }

        let batches = resp
            .sections("outs")
            .filter(|b| !b.is_empty())
            .ok_or_else(|| Error::msg("getrandom_outs3.bin: empty outs"))?;
        let blob = batches[0]
            .bytes("outs")
            .ok_or_else(|| Error::msg("getrandom_outs3.bin: missing out_entry blob"))?;
        if blob.len() % OUT_ENTRY_SIZE != 0 {
            return Err(crate::err!(
                "getrandom_outs3.bin: blob length {} not a multiple of {OUT_ENTRY_SIZE}",
                blob.len()
            ));
        }

        Ok(blob.chunks(OUT_ENTRY_SIZE).map(parse_out_entry).collect())
    }
}

fn parse_out_entry(rec: &[u8]) -> OutEntry {
    let v256 = |r: &[u8]| -> Value256 {
        let mut v = [0u8; 32];
        v.copy_from_slice(r);
        Value256(v)
    };
    OutEntry {
        global_index: u64::from_le_bytes(rec[0..8].try_into().unwrap()),
        stealth_address: v256(&rec[8..40]),
        concealing_point: v256(&rec[40..72]),
        amount_commitment: v256(&rec[72..104]),
        blinded_asset_id: v256(&rec[104..136]),
        flags: u64::from_le_bytes(rec[136..144].try_into().unwrap()),
    }
}

/// Returns `ring_size` sorted, unique global indices to request:
/// `real_global_index` plus `ring_size - 1` distinct random indices in
/// `[0, real_global_index)` — all older than the real output, hence valid ring
/// members of sufficient age.
pub fn build_decoy_offsets(
    real_global_index: u64,
    ring_size: usize,
    rnd: &mut dyn RngCore,
) -> Result<Vec<u64>> {
    if ring_size < 1 {
        return Err(Error::msg("ringSize must be >= 1"));
    }
    if (ring_size - 1) as u64 > real_global_index {
        return Err(crate::err!(
            "not enough older outputs ({real_global_index}) for {} decoys",
            ring_size - 1
        ));
    }
    let mut set = std::collections::BTreeSet::new();
    set.insert(real_global_index);
    while set.len() < ring_size {
        set.insert(rand_u64_below(real_global_index, rnd)?);
    }
    Ok(set.into_iter().collect())
}

/// A uniform random value in `[0, n)`, by rejection sampling.
fn rand_u64_below(n: u64, rnd: &mut dyn RngCore) -> Result<u64> {
    if n == 0 {
        return Err(Error::msg("rand_u64_below: n must be > 0"));
    }
    // Reject the tail that would bias the modulo.
    let limit = u64::MAX - (u64::MAX % n);
    loop {
        let mut b = [0u8; 8];
        rnd.fill_bytes(&mut b);
        let v = u64::from_le_bytes(b);
        if v < limit {
            return Ok(v % n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::ShakeRng;

    #[test]
    fn decoy_offsets_are_sorted_unique_and_include_the_real_output() {
        let mut rnd = ShakeRng::new(b"decoys");
        let real = 10_000u64;
        let offsets = build_decoy_offsets(real, 16, &mut rnd).unwrap();
        assert_eq!(offsets.len(), 16);
        assert!(offsets.contains(&real));
        assert!(offsets.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert!(offsets.iter().all(|o| *o <= real), "decoys must be older");
    }

    #[test]
    fn decoy_offsets_need_enough_history() {
        let mut rnd = ShakeRng::new(b"decoys");
        assert!(build_decoy_offsets(3, 16, &mut rnd).is_err());
        assert!(build_decoy_offsets(0, 1, &mut rnd).is_ok());
        assert!(build_decoy_offsets(10, 0, &mut rnd).is_err());
    }

    #[test]
    fn out_entry_parsing_matches_the_packed_layout() {
        let mut rec = vec![0u8; OUT_ENTRY_SIZE];
        rec[0..8].copy_from_slice(&7u64.to_le_bytes());
        rec[8..40].copy_from_slice(&[1u8; 32]);
        rec[40..72].copy_from_slice(&[2u8; 32]);
        rec[72..104].copy_from_slice(&[3u8; 32]);
        rec[104..136].copy_from_slice(&[4u8; 32]);
        rec[136..144].copy_from_slice(&9u64.to_le_bytes());
        let e = parse_out_entry(&rec);
        assert_eq!(e.global_index, 7);
        assert_eq!(e.stealth_address.0, [1u8; 32]);
        assert_eq!(e.concealing_point.0, [2u8; 32]);
        assert_eq!(e.amount_commitment.0, [3u8; 32]);
        assert_eq!(e.blinded_asset_id.0, [4u8; 32]);
        assert_eq!(e.flags, 9);
    }

    #[test]
    fn rand_below_stays_in_range() {
        let mut rnd = ShakeRng::new(b"range");
        for _ in 0..200 {
            assert!(rand_u64_below(10, &mut rnd).unwrap() < 10);
        }
        assert!(rand_u64_below(0, &mut rnd).is_err());
    }
}
