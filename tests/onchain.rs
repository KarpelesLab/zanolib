//! Round-trip tests against real mainnet transaction blobs (captured from
//! `get_tx_details`.blob, base64-decoded).
//!
//! These pin the binary layout: every blob must parse, re-serialize to the exact
//! same bytes, and hash to its known transaction id.

use zanolib::base::{
    AliasAddress, EpeeRead, EpeeWrite, Reader, TRANSACTION_VERSION_POST_HF4,
    TRANSACTION_VERSION_POST_HF5, TRANSACTION_VERSION_POST_HF6, TRANSACTION_VERSION_PRE_HF4,
    Transaction, TxoutTarget, Variant,
};

struct Fixture {
    name: &'static str,
    blob: &'static [u8],
    version: u64,
    id: &'static str,
    extra: &'static [&'static str],
    vout: &'static [&'static str],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "coinbase_v3",
        blob: include_bytes!("testdata/coinbase_v3.bin"),
        version: TRANSACTION_VERSION_POST_HF5,
        id: "5412e0a8a4d8eb4394eeea4ec6b821c5b920f21d6c7903d3bfa4692994efea00",
        extra: &[
            "pub_key",
            "user_data",
            "extra_padding",
            "derivation_hint",
            "derivation_hint",
            "unlock_time",
        ],
        vout: &["tx_out_zarcanum_v1", "tx_out_zarcanum_v1"],
    },
    Fixture {
        name: "transfer_v3",
        blob: include_bytes!("testdata/transfer_v3.bin"),
        version: TRANSACTION_VERSION_POST_HF5,
        id: "0d1dc9acc18202344a69e1a62ead03e3ae1d5fd7a316c9a6172db57accaf8d00",
        extra: &[
            "pub_key",
            "etc_tx_flags16",
            "derivation_hint",
            "derivation_hint",
            "zarcanum_tx_data_v1",
        ],
        vout: &["tx_out_zarcanum_v1", "tx_out_zarcanum_v1"],
    },
    // Post-HF6 (v4) transactions: outputs use the tx_out_zarcanum tag (63) and
    // carry an encrypted payment id; every coinbase carries the cumulative
    // block size.
    Fixture {
        name: "coinbase_v4",
        blob: include_bytes!("testdata/coinbase_v4.bin"),
        version: TRANSACTION_VERSION_POST_HF6,
        id: "4fcd5ff79f58f1855ab3263580e6806548d2c25c995975a4ffb6970239dd6ff4",
        extra: &[
            "etc_coinbase_block_cumulative_size",
            "pub_key",
            "user_data",
            "extra_padding",
            "derivation_hint",
            "derivation_hint",
        ],
        vout: &["tx_out_zarcanum", "tx_out_zarcanum"],
    },
    Fixture {
        name: "transfer_v4",
        blob: include_bytes!("testdata/transfer_v4.bin"),
        version: TRANSACTION_VERSION_POST_HF6,
        id: "1a79f343b41f69dfcc64be5386667fdce477fae766ede327a3ae8830f9d13f41",
        extra: &[
            "pub_key",
            "etc_tx_flags16",
            "derivation_hint",
            "derivation_hint",
            "zarcanum_tx_data_v1",
        ],
        vout: &["tx_out_zarcanum", "tx_out_zarcanum"],
    },
    // A pre-HF4 (v1) PoS coinbase: the old prefix layout (vin, vout, extra)
    // with untagged transparent outputs, a transparent stake input and NLSAG
    // signatures.
    Fixture {
        name: "pos_coinbase_v1",
        blob: include_bytes!("testdata/coinbase_v1.bin"),
        version: TRANSACTION_VERSION_PRE_HF4,
        id: "b61d3966c1aee7b995b694640bdeeec4afdf10a899e639d5a0d02c4d37f66f46",
        extra: &[
            "pub_key",
            "extra_padding",
            "etc_tx_flags16",
            "unlock_time",
            "etc_tx_time",
        ],
        vout: &["tx_out_bare", "tx_out_bare"],
    },
    // A PoS coinbase: its stake input carries a zarcanum_sig.
    Fixture {
        name: "pos_coinbase_v2",
        blob: include_bytes!("testdata/pos_coinbase_v2.bin"),
        version: TRANSACTION_VERSION_POST_HF4,
        id: "12e0f7d93af6797ac88fff1eeda635b92a9a926744825c17957b5489ca5b8ab9",
        extra: &[
            "pub_key",
            "extra_padding",
            "derivation_hint",
            "unlock_time",
            "attachment",
        ],
        vout: &["tx_out_zarcanum_v1"],
    },
    // An alias registration, carried in tx extra.
    Fixture {
        name: "alias_v3",
        blob: include_bytes!("testdata/alias_v3.bin"),
        version: TRANSACTION_VERSION_POST_HF5,
        id: "2102e22bd7c8d9167323af86189e041a4b39ece3c7d25528943caf3ac9c8454d",
        extra: &[
            "alias_entry2",
            "pub_key",
            "etc_tx_flags16",
            "derivation_hint",
            "derivation_hint",
            "zarcanum_tx_data_v1",
        ],
        vout: &["tx_out_zarcanum_v1", "tx_out_zarcanum_v1"],
    },
];

#[test]
fn on_chain_blobs_round_trip() {
    for f in FIXTURES {
        let mut r = Reader::new(f.blob);
        let tx = Transaction::read_epee(&mut r)
            .unwrap_or_else(|e| panic!("{}: deserialize: {e}", f.name));
        assert!(r.is_empty(), "{}: trailing bytes after deserialize", f.name);
        assert_eq!(tx.version, f.version, "{}", f.name);

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
        if f.version > TRANSACTION_VERSION_PRE_HF4 {
            assert!(partial.signatures.is_empty(), "{}", f.name);
        } else {
            // A pre-HF4 transaction stores its attachments after the
            // signatures, so those have to be read to reach them.
            assert_eq!(
                partial.signatures.len(),
                full.signatures.len(),
                "{}",
                f.name
            );
        }
    }
}

#[test]
fn transfer_carries_a_fee_and_coinbase_does_not() {
    for (coinbase, transfer) in [(&FIXTURES[0], &FIXTURES[1]), (&FIXTURES[2], &FIXTURES[3])] {
        let coinbase = Transaction::from_epee_bytes(coinbase.blob).unwrap();
        let transfer = Transaction::from_epee_bytes(transfer.blob).unwrap();
        assert_eq!(coinbase.fee(), None);
        assert!(transfer.fee().is_some_and(|f| f > 0));
        assert_eq!(coinbase.zc_inputs_count(), 0);
        assert!(transfer.zc_inputs_count() > 0);
        assert!(coinbase.tx_pub_key().is_some());
    }
}

#[test]
fn post_hf6_transactions_use_the_new_output_layout() {
    for f in FIXTURES {
        let tx = Transaction::from_epee_bytes(f.blob).unwrap();
        let post_hf6 = f.version >= TRANSACTION_VERSION_POST_HF6;
        let want_hf = match f.version {
            TRANSACTION_VERSION_POST_HF6 => 6,
            TRANSACTION_VERSION_POST_HF5 => 5,
            _ => 0, // v1 and v2 prefixes have no hardfork id
        };
        assert_eq!(tx.hardfork_id, want_hf, "{}", f.name);
        for v in &tx.vout {
            let Some(out) = v.as_tx_out_zarcanum() else {
                continue; // a pre-HF4 transparent output
            };
            assert_eq!(out.version, 0, "{}", f.name);
            if post_hf6 {
                // The field holds payment_id XOR mask, and the mask is
                // overwhelmingly unlikely to be zero, so a payment-id-less
                // output still has a non-zero value here.
                assert_ne!(out.encrypted_payment_id, 0, "{}", f.name);
            } else {
                assert_eq!(out.encrypted_payment_id, 0, "{}", f.name);
            }
        }
    }
}

#[test]
fn legacy_and_pos_shapes_are_recognized() {
    let by_name = |n: &str| {
        let f = FIXTURES.iter().find(|f| f.name == n).unwrap();
        (f, Transaction::from_epee_bytes(f.blob).unwrap())
    };

    // A v1 coinbase: transparent outputs and one NLSAG signature, no proofs.
    let (_, v1) = by_name("pos_coinbase_v1");
    assert_eq!(
        v1.vin.iter().map(|v| v.type_name()).collect::<Vec<_>>(),
        ["gen", "key"]
    );
    assert_eq!(
        v1.signatures
            .iter()
            .map(|v| v.type_name())
            .collect::<Vec<_>>(),
        ["NLSAG_sig"]
    );
    assert!(v1.proofs.is_empty());
    match &v1.vout[0] {
        Variant::TxOutBare(o) => {
            assert!(o.amount > 0);
            assert!(matches!(o.target, TxoutTarget::ToKey { .. }));
        }
        other => panic!("unexpected output {}", other.type_name()),
    }

    // A PoS coinbase: a coinbase input plus the staked confidential input,
    // whose signature is a zarcanum_sig.
    let (_, pos) = by_name("pos_coinbase_v2");
    assert_eq!(
        pos.vin.iter().map(|v| v.type_name()).collect::<Vec<_>>(),
        ["gen", "txin_zc_input"]
    );
    let Variant::ZarcanumSig(sig) = &pos.signatures[0] else {
        panic!("expected a zarcanum_sig");
    };
    // One scalar per ring member in each response vector, and a range proof
    // over E with two blinding responses.
    assert_eq!(sig.clsag_ggxxg.rg.len(), sig.clsag_ggxxg.rx.len());
    assert!(!sig.clsag_ggxxg.rg.is_empty());
    assert_eq!(sig.e_range_proof.lv.len(), sig.e_range_proof.rv.len());

    // An alias registration.
    let (_, alias) = by_name("alias_v3");
    let Some(Variant::ExtraAliasEntry(entry)) = alias
        .extra
        .iter()
        .find(|v| matches!(v, Variant::ExtraAliasEntry(_)))
    else {
        panic!("expected an alias entry");
    };
    assert!(!entry.alias.is_empty());
    assert!(matches!(entry.address, AliasAddress::Current(_)));
}
