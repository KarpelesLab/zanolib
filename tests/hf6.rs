//! Post-HF6 (v4) transactions end to end: building and signing, output
//! layout, intrinsic payment ids, scanning, the wallet-blob layouts and the
//! post-HF6 payload encryption.

use zanolib::base::{
    EpeeRead, EpeeWrite, PAYMENT_ID_SERVICE_ID, Reader, TRANSACTION_VERSION_POST_HF5,
    TRANSACTION_VERSION_POST_HF6, TX_SERVICE_ATTACHMENT_ENCRYPT_BODY, Transaction, TxComment,
    TxServiceAttachment, Value256, Variant, tag,
};
use zanolib::crypto::{
    ClsagGgxInputRef, chacha_generate_key_and_iv, chacha8, chacha8_generate_key, chacha20,
    generate_key_derivation, mul8, pub_from_priv, verify_clsag_ggx,
};
use zanolib::rng::FixedRng;
use zanolib::{FinalizeTxParam, FinalizedTx, Wallet, WalletBlobLayout};

const SPEND_SECRET: &str = "d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209";
const FIXTURE: &[u8] = include_bytes!("testdata/zano_tx_signed3.bin");

const PAYMENT_ID: u64 = 0x8877_6655_4433_2211;

fn wallet() -> Wallet {
    Wallet::load_spend_secret(&hex::decode(SPEND_SECRET).unwrap(), 0).unwrap()
}

fn is_own(w: &Wallet, dst: &zanolib::TxDest) -> bool {
    dst.account().is_ok_and(|a| {
        a.spend_key.0 == w.spend_pub_key.compress() && a.view_key.0 == w.view_pub_key.compress()
    })
}

/// The fixture's parameters, re-targeted at a post-HF6 transaction with an
/// intrinsic payment id on the first destination paying this wallet.
fn v4_params(w: &Wallet) -> (FinalizedTx, FinalizeTxParam, usize) {
    let fin = w.parse_finalized(FIXTURE).expect("parse finalized");
    let mut ftp = fin.ftp.clone();
    ftp.tx_version = TRANSACTION_VERSION_POST_HF6;
    ftp.tx_hardfork_id = 6;
    let own = ftp
        .prepared_destinations
        .iter()
        .position(|d| is_own(w, d))
        .expect("the fixture pays this wallet");
    ftp.prepared_destinations[own].payment_id = PAYMENT_ID;
    (fin, ftp, own)
}

#[test]
fn signs_a_v4_transaction() {
    let w = wallet();
    let (fin, ftp, _) = v4_params(&w);
    let signed = w
        .sign(&mut FixedRng(0x42), &ftp, Some(fin.one_time_key.clone()))
        .expect("sign");
    let tx = &signed.tx;

    assert_eq!(tx.version, TRANSACTION_VERSION_POST_HF6);
    assert_eq!(tx.hardfork_id, 6);
    for v in &tx.vout {
        assert_eq!(
            v.tag(),
            tag::TX_OUT_ZARCANUM,
            "v4 outputs use the HF6 layout"
        );
        // Every output is masked, so none reads as a plain zero.
        assert_ne!(v.as_tx_out_zarcanum().unwrap().encrypted_payment_id, 0);
    }

    // The serialized transaction parses back to the same bytes and id.
    let raw = signed.raw_tx();
    let mut r = Reader::new(&raw);
    let parsed = Transaction::read_epee(&mut r).expect("parse signed tx");
    assert!(r.is_empty());
    assert_eq!(parsed.to_epee_bytes(), raw);
    assert_eq!(parsed.id(), tx.id());

    // Only the output layout changed, so the fixture's (v2) inputs, outputs and
    // proofs line up one to one.
    assert_eq!(tx.vout.len(), fin.tx.vout.len());
    assert_eq!(tx.proofs.len(), fin.tx.proofs.len());
}

#[test]
fn v4_ring_signatures_verify() {
    let w = wallet();
    let (fin, ftp, _) = v4_params(&w);
    let signed = w
        .sign(&mut FixedRng(0x42), &ftp, Some(fin.one_time_key.clone()))
        .expect("sign");

    // The CLSAG message is the v4 prefix hash, which covers the new output
    // layout and the encrypted payment ids.
    let tx_id = signed.tx.id();
    for (n, sig_v) in signed.tx.signatures.iter().enumerate() {
        let Variant::ZcSig(sig) = sig_v else {
            panic!("signature {n} is not a ZC_sig");
        };
        let ring: Vec<ClsagGgxInputRef> = signed.ftp.sources[n]
            .outputs
            .iter()
            .map(|o| ClsagGgxInputRef {
                stealth_address: o.stealth_address,
                amount_commitment: o.amount_commitment,
                blinded_asset_id: o.blinded_asset_id,
            })
            .collect();
        let key_image = signed.tx.vin[n].as_txin_zc_input().unwrap().key_image;
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
fn scan_recovers_the_intrinsic_payment_id() {
    let w = wallet();
    let (fin, ftp, own) = v4_params(&w);
    let signed = w
        .sign(&mut FixedRng(0x42), &ftp, Some(fin.one_time_key.clone()))
        .expect("sign");

    let res = w.scan_tx(&signed.tx).expect("scan");
    assert!(res.found());
    assert_eq!(res.payment_id, None, "no tx-wide payment id");
    for out in &res.outputs {
        let dst = &ftp.prepared_destinations[out.output_index];
        assert_eq!(out.amount, dst.amount);
        if out.output_index == own {
            // zano reports the 8 little-endian bytes of the intrinsic id.
            let want = PAYMENT_ID.to_le_bytes().to_vec();
            assert_eq!(out.payment_id.as_deref(), Some(&want[..]));
            assert_eq!(res.payment_id_for(out), Some(want));
        } else {
            assert_eq!(out.payment_id, None);
        }
    }

    // A view-only wallet recovers the same payment ids.
    let view = w.export_view(0).load_view_wallet().unwrap();
    let res_view = view.scan_tx(&signed.tx).unwrap();
    let ids = |r: &zanolib::ScanResult| {
        r.outputs
            .iter()
            .map(|o| o.payment_id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&res_view), ids(&res));
}

#[test]
fn intrinsic_payment_ids_need_a_v4_transaction() {
    let w = wallet();
    let (fin, mut ftp, _) = v4_params(&w);
    ftp.tx_version = TRANSACTION_VERSION_POST_HF5;
    ftp.tx_hardfork_id = 5;
    let err = w
        .sign(&mut FixedRng(0x42), &ftp, Some(fin.one_time_key.clone()))
        .unwrap_err();
    assert!(err.to_string().contains("post-HF6"), "{err}");
}

#[test]
fn hardfork_id_must_match_the_version() {
    let w = wallet();
    let (fin, mut ftp, _) = v4_params(&w);
    ftp.tx_hardfork_id = 5;
    assert!(
        w.sign(&mut FixedRng(0x42), &ftp, Some(fin.one_time_key.clone()))
            .is_err()
    );
}

#[test]
fn a_transaction_needs_two_outputs() {
    let w = wallet();
    let (fin, mut ftp, _) = v4_params(&w);
    ftp.prepared_destinations.truncate(1);
    let err = w
        .sign(&mut FixedRng(0x42), &ftp, Some(fin.one_time_key.clone()))
        .unwrap_err();
    assert!(err.to_string().contains("at least 2 outputs"), "{err}");
}

#[test]
fn legacy_wallet_blob_round_trips() {
    // The fixture predates the tx_source_entry asset_id field, so it parses
    // through the legacy-layout fallback and must re-serialize byte-for-byte.
    let w = wallet();
    let fin = w.parse_finalized(FIXTURE).expect("parse finalized");
    assert_eq!(fin.ftp.layout, WalletBlobLayout::Legacy);

    let code = chacha8_generate_key(&w.view_priv_key.to_bytes()).unwrap();
    let plain = chacha8(&code, &[0u8; 8], FIXTURE).unwrap();
    assert_eq!(fin.to_epee_bytes(), plain);
}

#[test]
fn current_wallet_blob_round_trips() {
    let w = wallet();
    let (_, mut ftp, own) = v4_params(&w);
    ftp.layout = WalletBlobLayout::Current;
    ftp.sources[0].gateway_origin = Value256([7u8; 32]);

    let bytes = ftp.to_epee_bytes();
    let mut r = Reader::new(&bytes);
    let back = FinalizeTxParam::read_with(&mut r, WalletBlobLayout::Current).unwrap();
    assert!(r.is_empty());
    assert_eq!(back.to_epee_bytes(), bytes);
    assert_eq!(back.prepared_destinations[own].payment_id, PAYMENT_ID);
    assert_eq!(back.sources[0].gateway_origin, Value256([7u8; 32]));
    assert!(back.sources.iter().all(|s| s.asset_id.is_some()));

    // The encrypted blob a current wallet hands over parses without a hint.
    let code = chacha8_generate_key(&w.view_priv_key.to_bytes()).unwrap();
    let blob = chacha8(&code, &[0u8; 8], &bytes).unwrap();
    let parsed = w.parse_ftp(&blob).unwrap();
    assert_eq!(parsed.layout, WalletBlobLayout::Current);
    assert_eq!(parsed.to_epee_bytes(), bytes);
}

#[test]
fn scan_decrypts_a_v4_tx_wide_payment_id() {
    // Encrypt a comment and a "P" attachment the way zano's
    // encrypt_payload_items_visitor does for v4: one ChaCha20 key, and an IV
    // incremented after each encrypted item, extra first.
    let w = wallet();
    let tx_sec = zanolib::crypto::Scalar::from_bytes_mod_order(&[0x11; 64]);
    let tx_pub = pub_from_priv(&tx_sec);
    let derivation = generate_key_derivation(&w.view_pub_key, &tx_sec).compress();
    let (key, iv) =
        chacha_generate_key_and_iv(b"ZANO_HDS_CHACHA_TX_PAYLOAD_ITEM\0", &derivation, 0);
    let iv0 = u64::from_le_bytes(iv);
    let comment = chacha20(&key, &iv0.to_le_bytes(), b"hello").unwrap();
    let payment_id = b"a long legacy payment id".to_vec();
    let body = chacha20(&key, &(iv0 + 1).to_le_bytes(), &payment_id).unwrap();

    let tx = Transaction {
        version: TRANSACTION_VERSION_POST_HF6,
        hardfork_id: 6,
        extra: vec![
            Variant::PubKey(Value256::from_point(&tx_pub)),
            Variant::Comment(TxComment { comment }),
        ],
        attachment: vec![Variant::ServiceAttachment(TxServiceAttachment {
            service_id: PAYMENT_ID_SERVICE_ID.to_string(),
            instruction: String::new(),
            body,
            security: Vec::new(),
            flags: TX_SERVICE_ATTACHMENT_ENCRYPT_BODY,
        })],
        ..Default::default()
    };
    let res = w.scan_tx(&tx).unwrap();
    assert_eq!(res.payment_id, Some(payment_id));
}

#[test]
fn outputs_of_non_coinbase_txs_with_unlock_time_are_ignored() {
    let w = wallet();
    let fin = w.parse_finalized(FIXTURE).expect("parse finalized");
    let mut signed = w
        .sign(
            &mut FixedRng(0x42),
            &fin.ftp,
            Some(fin.one_time_key.clone()),
        )
        .expect("sign");
    assert!(w.scan_tx(&signed.tx).unwrap().found());

    signed
        .tx
        .extra
        .push(Variant::UnlockTime2(vec![0; signed.tx.vout.len()]));
    assert!(!w.scan_tx(&signed.tx).unwrap().found());
}
