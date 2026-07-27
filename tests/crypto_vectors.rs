//! Known-answer tests for the low-level crypto, using the vector files carried
//! over from the Go implementation (`tests/vectors/*.txt`).
//!
//! These pin the port to the exact behaviour of Zano's C++ reference code: the
//! `ge_fromfe_frombytes_vartime` map, key derivations and key images.

use zanolib::crypto::{
    compute_key_image, derive_public_key, derive_secret_key, generate_key_derivation, hash_to_ec,
    hash_to_point, hash_to_scalar, point_from_bytes, scalar_from_canonical,
};

fn fields(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex {s:?}: {e}"))
}

#[test]
fn hash_to_point_vectors() {
    let data = include_str!("vectors/hash_to_point.txt");
    let mut n = 0;
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v = fields(line);
        let got = hash_to_point(&unhex(v[0]));
        assert_eq!(hex::encode(got.compress()), v[1], "hash_to_point({})", v[0]);
        n += 1;
    }
    assert!(n > 300, "expected the full vector set, got {n}");
}

#[test]
fn hash_to_ec_vectors() {
    let data = include_str!("vectors/hash_to_ec.txt");
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v = fields(line);
        let got = hash_to_ec(&unhex(v[0]));
        assert_eq!(hex::encode(got.compress()), v[1], "hash_to_ec({})", v[0]);
    }
}

#[test]
fn hash_to_scalar_vectors() {
    let data = include_str!("vectors/hash_to_scalar.txt");
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v = fields(line);
        // "x" is the vector set's sentinel for the empty input.
        let input = if v[0] == "x" { Vec::new() } else { unhex(v[0]) };
        let got = hash_to_scalar(&input);
        assert_eq!(
            hex::encode(got.to_bytes()),
            v[1],
            "hash_to_scalar({})",
            v[0]
        );
    }
}

#[test]
fn key_image_vectors() {
    let data = include_str!("vectors/key_image.txt");
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v = fields(line);
        let pub_key = point_from_bytes(&unhex(v[0])).unwrap();
        let sec = scalar_from_canonical(&unhex(v[1])).unwrap();
        let got = compute_key_image(&sec, &pub_key);
        assert_eq!(hex::encode(got.compress()), v[2], "key_image({})", v[0]);
    }
}

#[test]
fn key_derivation_vectors() {
    // Layout: pub sec expect_ok result
    let data = include_str!("vectors/key_derivation.txt");
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v = fields(line);
        let ok = v[2] == "true";
        let (Ok(pub_key), Ok(sec)) = (
            point_from_bytes(&unhex(v[0])),
            scalar_from_canonical(&unhex(v[1])),
        ) else {
            assert!(!ok, "vector {} should have parsed", v[0]);
            continue;
        };
        assert!(ok, "vector {} should have failed to parse", v[0]);
        let got = generate_key_derivation(&pub_key, &sec);
        assert_eq!(
            hex::encode(got.compress()),
            v[3],
            "generate_key_derivation({}, {})",
            v[0],
            v[1]
        );
    }
}

#[test]
fn derive_public_key_vectors() {
    // Layout: derivation index base_pub expect_ok result
    let data = include_str!("vectors/derive_public_key.txt");
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v = fields(line);
        let index: u64 = v[1].parse().unwrap();
        let Ok(base) = point_from_bytes(&unhex(v[2])) else {
            assert_eq!(v[3], "false", "vector {} should have parsed", v[2]);
            continue;
        };
        let got = derive_public_key(&unhex(v[0]), index, &base).unwrap();
        assert_eq!(
            hex::encode(got.compress()),
            v[4],
            "derive_public_key({}, {index}, {})",
            v[0],
            v[2]
        );
    }
}

#[test]
fn derive_secret_key_vectors() {
    // Layout: derivation index base_sec result
    let data = include_str!("vectors/derive_secret_key.txt");
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v = fields(line);
        let index: u64 = v[1].parse().unwrap();
        let base = scalar_from_canonical(&unhex(v[2])).unwrap();
        let got = derive_secret_key(&unhex(v[0]), index, &base);
        assert_eq!(
            hex::encode(got.to_bytes()),
            v[3],
            "derive_secret_key({}, {index})",
            v[0]
        );
    }
}
