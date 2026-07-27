//! Round-trip tests against real mainnet transaction blobs (captured from
//! `get_tx_details`.blob, base64-decoded).
//!
//! These pin the binary layout: every blob must parse, re-serialize to the exact
//! same bytes, and hash to its known transaction id.

use zanolib::base::{EpeeRead, EpeeWrite, Reader, TRANSACTION_VERSION_POST_HF5, Transaction};

struct Fixture {
    name: &'static str,
    blob: &'static [u8],
    id: &'static str,
    extra: &'static [&'static str],
    vout: &'static [&'static str],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "coinbase_v3",
        blob: include_bytes!("testdata/coinbase_v3.bin"),
        id: "5412e0a8a4d8eb4394eeea4ec6b821c5b920f21d6c7903d3bfa4692994efea00",
        extra: &[
            "pub_key",
            "user_data",
            "extra_padding",
            "derivation_hint",
            "derivation_hint",
            "unlock_time",
        ],
        vout: &["tx_out_zarcanum", "tx_out_zarcanum"],
    },
    Fixture {
        name: "transfer_v3",
        blob: include_bytes!("testdata/transfer_v3.bin"),
        id: "0d1dc9acc18202344a69e1a62ead03e3ae1d5fd7a316c9a6172db57accaf8d00",
        extra: &[
            "pub_key",
            "etc_tx_flags16",
            "derivation_hint",
            "derivation_hint",
            "zarcanum_tx_data_v1",
        ],
        vout: &["tx_out_zarcanum", "tx_out_zarcanum"],
    },
];

#[test]
fn on_chain_blobs_round_trip() {
    for f in FIXTURES {
        let mut r = Reader::new(f.blob);
        let tx = Transaction::read_epee(&mut r)
            .unwrap_or_else(|e| panic!("{}: deserialize: {e}", f.name));
        assert!(r.is_empty(), "{}: trailing bytes after deserialize", f.name);
        assert_eq!(tx.version, TRANSACTION_VERSION_POST_HF5, "{}", f.name);

        // Re-serializing must reproduce the exact on-chain bytes.
        let out = tx.to_epee_bytes();
        assert_eq!(
            out.len(),
            f.blob.len(),
            "{}: re-serialized length differs",
            f.name
        );
        assert!(out == f.blob, "{}: re-serialized blob differs", f.name);
    }
}

#[test]
fn on_chain_blobs_have_the_expected_shape() {
    for f in FIXTURES {
        let tx = Transaction::from_epee_bytes(f.blob).unwrap();
        let extra: Vec<&str> = tx.extra.iter().map(|v| v.type_name()).collect();
        assert_eq!(extra, f.extra, "{}: extra variants", f.name);
        let vout: Vec<&str> = tx.vout.iter().map(|v| v.type_name()).collect();
        assert_eq!(vout, f.vout, "{}: vout variants", f.name);
    }
}

#[test]
fn on_chain_blobs_hash_to_their_transaction_id() {
    for f in FIXTURES {
        let tx = Transaction::from_epee_bytes(f.blob).unwrap();
        assert_eq!(tx.id().to_string(), f.id, "{}: transaction id", f.name);
    }
}

#[test]
fn scan_parsing_stops_before_the_signatures() {
    // deserialize_for_scan must recover the same prefix + attachments as a full
    // parse, without reading the (large) signature and proof sections.
    for f in FIXTURES {
        let full = Transaction::from_epee_bytes(f.blob).unwrap();
        let partial = Transaction::deserialize_for_scan(f.blob).unwrap();
        assert_eq!(partial.version, full.version, "{}", f.name);
        assert_eq!(partial.hardfork_id, full.hardfork_id, "{}", f.name);
        assert_eq!(partial.vin.len(), full.vin.len(), "{}", f.name);
        assert_eq!(partial.vout.len(), full.vout.len(), "{}", f.name);
        assert_eq!(partial.extra.len(), full.extra.len(), "{}", f.name);
        assert_eq!(
            partial.attachment.len(),
            full.attachment.len(),
            "{}",
            f.name
        );
        // Same prefix bytes, hence the same id.
        assert_eq!(partial.id(), full.id(), "{}", f.name);
        assert!(partial.signatures.is_empty(), "{}", f.name);
    }
}

#[test]
fn transfer_carries_a_fee_and_coinbase_does_not() {
    let coinbase = Transaction::from_epee_bytes(FIXTURES[0].blob).unwrap();
    let transfer = Transaction::from_epee_bytes(FIXTURES[1].blob).unwrap();
    assert_eq!(coinbase.fee(), None);
    assert!(transfer.fee().is_some_and(|f| f > 0));
    assert_eq!(coinbase.zc_inputs_count(), 0);
    assert!(transfer.zc_inputs_count() > 0);
    assert!(coinbase.tx_pub_key().is_some());
}
