//! Prints the same values as the Go reference program, for byte-level
//! comparison of the two implementations.
use zanolib::Wallet;
use zanolib::base::EpeeWrite;
use zanolib::rng::FixedRng;

fn main() {
    let w = Wallet::load_spend_secret(
        &hex::decode("d3604ff3032bbd10c072f8a768e9c2bdab9ef94fb2ed51b81b379289afa09209").unwrap(),
        0,
    )
    .unwrap();
    let data = std::fs::read("testdata/zano_tx_signed3.bin").unwrap();
    let fin = w.parse_finalized(&data).unwrap();
    println!("fixture_version={}", fin.tx.version);
    println!("fixture_txid={}", fin.tx.id());
    let mut rnd = FixedRng(0x42);
    let signed = w
        .sign(&mut rnd, &fin.ftp, Some(fin.one_time_key.clone()))
        .unwrap();
    println!("resigned_txid={}", signed.tx.id());
    let raw = signed.tx.to_epee_bytes();
    println!("resigned_len={}", raw.len());
    println!("resigned_sha={}", hex::encode(&raw[..64]));
    println!("resigned_full={}", hex::encode(&raw));
    let res = w.scan_tx(&signed.tx).unwrap();
    println!("scan_outputs={}", res.outputs.len());
    for o in &res.outputs {
        println!(
            "scan_out idx={} amount={} native={} mask={}",
            o.output_index,
            o.amount,
            o.is_native,
            hex::encode(o.amount_blinding_mask.to_bytes())
        );
    }
}
