//! ChaCha8 and ChaCha20 in Bernstein's original layout (64-bit nonce, 64-bit
//! counter), the stream ciphers Zano uses to encrypt wallet blobs and tx
//! payload items.
//!
//! purecrypto ships the IETF ChaCha20 layout (96-bit nonce, 32-bit counter),
//! so both variants are implemented here.

use crate::error::{Error, Result};

/// Derives a 32-byte ChaCha8 key from a seed by hashing it with Keccak-256.
/// The seed must be at least 32 bytes.
pub fn chacha8_generate_key(seed: &[u8]) -> Result<[u8; 32]> {
    if seed.len() < 32 {
        return Err(Error::msg(
            "size of hash must be at least that of chacha8_key",
        ));
    }
    Ok(purecrypto::hash::keccak256(seed))
}

fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);

    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

/// Applies the ChaCha8 keystream to `input` with a 32-byte key and 8-byte nonce.
/// Encryption and decryption are the same operation.
pub fn chacha8(key: &[u8], nonce: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    chacha(4, key, nonce, input)
}

/// Applies the ChaCha20 keystream to `input` with a 32-byte key and 8-byte
/// nonce. Encryption and decryption are the same operation.
pub fn chacha20(key: &[u8], nonce: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    chacha(10, key, nonce, input)
}

/// `chacha_generate_key_and_iv`: derives a ChaCha key and IV from a 32-byte
/// domain separator, some data and an index, as the first 40 bytes of zano's
/// variable-length Keccak over `hdss || data || index`.
pub fn chacha_generate_key_and_iv(hdss: &[u8; 32], data: &[u8], index: u64) -> ([u8; 32], [u8; 8]) {
    let mut buf = Vec::with_capacity(32 + data.len() + 8);
    buf.extend_from_slice(hdss);
    buf.extend_from_slice(data);
    buf.extend_from_slice(&index.to_le_bytes());
    let h = crate::crypto::hash::keccak_variable(&buf, 40);
    let mut key = [0u8; 32];
    let mut iv = [0u8; 8];
    key.copy_from_slice(&h[..32]);
    iv.copy_from_slice(&h[32..40]);
    (key, iv)
}

/// The ChaCha core with `double_rounds` double rounds.
fn chacha(double_rounds: usize, key: &[u8], nonce: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::msg("chacha: key length must be 32 bytes"));
    }
    if nonce.len() != 8 {
        return Err(Error::msg("chacha: nonce (IV) length must be 8 bytes"));
    }

    let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut state = [
        0x61707865u32, // "expa"
        0x3320646e,    // "nd 3"
        0x79622d32,    // "2-by"
        0x6b206574,    // "te k"
        le(&key[0..4]),
        le(&key[4..8]),
        le(&key[8..12]),
        le(&key[12..16]),
        le(&key[16..20]),
        le(&key[20..24]),
        le(&key[24..28]),
        le(&key[28..32]),
        0, // counter low
        0, // counter high
        le(&nonce[0..4]),
        le(&nonce[4..8]),
    ];

    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(64) {
        let mut x = state;
        for _ in 0..double_rounds {
            let [
                mut x0,
                mut x1,
                mut x2,
                mut x3,
                mut x4,
                mut x5,
                mut x6,
                mut x7,
                mut x8,
                mut x9,
                mut x10,
                mut x11,
                mut x12,
                mut x13,
                mut x14,
                mut x15,
            ] = x;
            quarter_round(&mut x0, &mut x4, &mut x8, &mut x12);
            quarter_round(&mut x1, &mut x5, &mut x9, &mut x13);
            quarter_round(&mut x2, &mut x6, &mut x10, &mut x14);
            quarter_round(&mut x3, &mut x7, &mut x11, &mut x15);
            quarter_round(&mut x0, &mut x5, &mut x10, &mut x15);
            quarter_round(&mut x1, &mut x6, &mut x11, &mut x12);
            quarter_round(&mut x2, &mut x7, &mut x8, &mut x13);
            quarter_round(&mut x3, &mut x4, &mut x9, &mut x14);
            x = [
                x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
            ];
        }

        let mut block = [0u8; 64];
        for i in 0..16 {
            block[i * 4..i * 4 + 4].copy_from_slice(&x[i].wrapping_add(state[i]).to_le_bytes());
        }
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ block[i]);
        }

        state[12] = state[12].wrapping_add(1);
        if state[12] == 0 {
            state[13] = state[13].wrapping_add(1);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let key = [7u8; 32];
        let nonce = [0u8; 8];
        let msg = b"the quick brown fox jumps over the lazy dog, repeatedly and at length!!";
        let enc = chacha8(&key, &nonce, msg).unwrap();
        assert_ne!(&enc[..], &msg[..]);
        let dec = chacha8(&key, &nonce, &enc).unwrap();
        assert_eq!(&dec[..], &msg[..]);
    }

    #[test]
    fn spans_block_boundaries() {
        // 200 bytes exercises the counter increment across 64-byte blocks.
        let key = [0x42u8; 32];
        let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let msg = vec![0u8; 200];
        let ks = chacha8(&key, &nonce, &msg).unwrap();
        // Each block must differ (the counter changes).
        assert_ne!(&ks[0..64], &ks[64..128]);
        assert_ne!(&ks[64..128], &ks[128..192]);
    }

    #[test]
    fn chacha20_matches_the_reference_keystream() {
        // Bernstein's ChaCha20 with an all-zero key and nonce (the first test
        // vector of draft-agl-tls-chacha20poly1305).
        let ks = chacha20(&[0u8; 32], &[0u8; 8], &[0u8; 64]).unwrap();
        assert_eq!(
            hex::encode(ks),
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
        );
    }

    #[test]
    fn rejects_bad_lengths() {
        assert!(chacha8(&[0u8; 31], &[0u8; 8], b"x").is_err());
        assert!(chacha8(&[0u8; 32], &[0u8; 7], b"x").is_err());
        assert!(chacha8_generate_key(&[0u8; 31]).is_err());
    }
}
