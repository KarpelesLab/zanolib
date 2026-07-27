//! End-to-end test over the committed signed-transaction fixture: decrypt the
//! `finalized_tx` blob, rebuild and re-sign the transaction, then scan the
//! result with the same wallet.
//!
//! This exercises the whole pipeline — blob decryption, FTP parsing, output
//! construction, CLSAG-GGX signing, the range/balance/surjection proofs, and the
//! receive-side scan — against data produced by a real Zano wallet.

use zanolib::Wallet;
use zanolib::base::{EpeeRead, EpeeWrite};
use zanolib::rng::FixedRng;

const SPEND_SECRET: &str = "d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209";
const FIXTURE: &[u8] = include_bytes!("testdata/zano_tx_signed3.bin");

fn wallet() -> Wallet {
    Wallet::load_spend_secret(&hex::decode(SPEND_SECRET).unwrap(), 0).unwrap()
}

#[test]
fn finalized_blob_parses() {
    let w = wallet();
    let fin = w.parse_finalized(FIXTURE).expect("parse finalized");
    assert_eq!(fin.tx.version, 2); // the fixture is a post-HF4 (v2) transaction
    assert!(!fin.ftp.sources.is_empty());
    assert!(!fin.ftp.prepared_destinations.is_empty());
    assert_eq!(fin.ftp.spend_pub_key, w.spend_pub_key);
    // The blob's own transaction must round-trip through our serializer.
    let re = fin.tx.to_epee_bytes();
    assert_eq!(
        zanolib::base::Transaction::from_epee_bytes(&re)
            .unwrap()
            .id(),
        fin.tx.id()
    );
}

#[test]
fn resigning_reproduces_a_valid_transaction() {
    let w = wallet();
    let fin = w.parse_finalized(FIXTURE).expect("parse finalized");

    let mut rnd = FixedRng(0x42);
    let signed = w
        .sign(&mut rnd, &fin.ftp, Some(fin.one_time_key.clone()))
        .expect("sign");

    // Same shape as the fixture's own transaction.
    assert_eq!(signed.tx.version, fin.tx.version);
    assert_eq!(signed.tx.vin.len(), fin.tx.vin.len());
    assert_eq!(signed.tx.vout.len(), fin.tx.vout.len());
    assert_eq!(signed.tx.signatures.len(), fin.tx.signatures.len());
    assert_eq!(signed.tx.proofs.len(), fin.tx.proofs.len());

    // The prefix is fully determined by the inputs plus the (fixed) random
    // derivation hints, so re-signing is reproducible. This id is the one the
    // Go implementation produces from the same fixture, one-time key and RNG:
    // it pins the port to byte-for-byte agreement with it.
    assert_eq!(
        signed.tx.id().to_string(),
        "cce9add3dfa3002023d9920d6620cf7139116dbc4330cd288d60b1ec16168031",
        "re-signed transaction prefix changed"
    );
    // The fixture itself was signed with real randomness, so its own hints (and
    // therefore its id) differ.
    assert_ne!(signed.tx.id(), fin.tx.id());

    // And it must serialize/parse cleanly, reproducing the exact bytes the Go
    // implementation emits (7285 bytes: prefix + CLSAG signatures + range,
    // surjection and balance proofs).
    let raw = signed.raw_tx();
    assert_eq!(raw.len(), 7285, "signed transaction size changed");
    assert_eq!(
        hex::encode(purecrypto::hash::sha256(&raw)),
        "305a1ceb948658f678422b3d3636ce0c00e31e8280e017d58ae1b262235fc0f5",
        "signed transaction bytes changed"
    );
    let back = zanolib::base::Transaction::from_epee_bytes(&raw).expect("re-parse signed tx");
    assert_eq!(back.id(), signed.tx.id());
}

#[test]
fn signed_ring_signatures_verify() {
    use zanolib::base::Variant;
    use zanolib::crypto::{ClsagGgxInputRef, mul8, verify_clsag_ggx};

    let w = wallet();
    let fin = w.parse_finalized(FIXTURE).expect("parse finalized");
    let mut rnd = FixedRng(0x42);
    let signed = w
        .sign(&mut rnd, &fin.ftp, Some(fin.one_time_key.clone()))
        .expect("sign");

    let tx_id = signed.tx.id();
    for (n, sig_v) in signed.tx.signatures.iter().enumerate() {
        let Variant::ZcSig(sig) = sig_v else {
            panic!("signature {n} is not a ZC_sig");
        };
        let src = &signed.ftp.sources[n];
        let ring: Vec<ClsagGgxInputRef> = src
            .outputs
            .iter()
            .map(|o| ClsagGgxInputRef {
                stealth_address: o.stealth_address,
                amount_commitment: o.amount_commitment,
                blinded_asset_id: o.blinded_asset_id,
            })
            .collect();
        let key_image = signed.tx.vin[n]
            .as_txin_zc_input()
            .expect("txin_zc_input")
            .key_image;
        let ok = verify_clsag_ggx(
            &tx_id.0,
            &ring,
            &key_image,
            &mul8(&sig.pseudo_out_amount_commitment),
            &mul8(&sig.pseudo_out_blinded_asset_id),
            &sig.ggx,
        )
        .expect("verify");
        assert!(ok, "input {n}: CLSAG-GGX signature does not verify");
    }
}

#[test]
fn scan_detects_every_own_destination() {
    let w = wallet();
    let fin = w.parse_finalized(FIXTURE).expect("parse finalized");
    let mut rnd = FixedRng(0x42);
    let signed = w
        .sign(&mut rnd, &fin.ftp, Some(fin.one_time_key.clone()))
        .expect("sign");

    let res = w.scan_tx(&signed.tx).expect("scan");

    // Multiset of amounts for destinations addressed to this wallet.
    let mut own: Vec<u64> = Vec::new();
    for dst in &fin.ftp.prepared_destinations {
        if let Some(addr) = dst.addr.first()
            && addr.spend_key.0 == w.spend_pub_key.compress()
            && addr.view_key.0 == w.view_pub_key.compress()
        {
            own.push(dst.amount);
        }
    }
    own.sort_unstable();

    let mut got: Vec<u64> = res.outputs.iter().map(|o| o.amount).collect();
    got.sort_unstable();
    assert_eq!(got, own, "detected outputs do not match own destinations");
    assert!(res.found());
    for out in &res.outputs {
        assert!(
            out.is_native,
            "output {} should be native",
            out.output_index
        );
    }
}

#[test]
fn view_only_wallet_scans_identically() {
    let full = wallet();
    let view = full.export_view(0).load_view_wallet().unwrap();
    assert!(view.is_view_only());

    let fin = full.parse_finalized(FIXTURE).expect("parse finalized");
    let mut rnd = FixedRng(0x42);
    let signed = full
        .sign(&mut rnd, &fin.ftp, Some(fin.one_time_key.clone()))
        .expect("sign");

    let a = full.scan_tx(&signed.tx).unwrap();
    let b = view.scan_tx(&signed.tx).unwrap();
    assert_eq!(a.outputs.len(), b.outputs.len());
    for (x, y) in a.outputs.iter().zip(b.outputs.iter()) {
        assert_eq!(x.amount, y.amount);
        assert_eq!(x.stealth_address, y.stealth_address);
        assert_eq!(
            x.amount_blinding_mask.to_bytes(),
            y.amount_blinding_mask.to_bytes()
        );
    }
}

#[test]
fn view_only_wallet_cannot_sign() {
    let full = wallet();
    let view = full.export_view(0).load_view_wallet().unwrap();
    let fin = full.parse_finalized(FIXTURE).expect("parse finalized");
    let mut rnd = FixedRng(0x42);
    assert!(view.sign(&mut rnd, &fin.ftp, None).is_err());
}
