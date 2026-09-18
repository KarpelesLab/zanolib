//! Round-trip coverage for every variant a transaction can carry, including
//! the ones this crate never builds (legacy transparent inputs and outputs,
//! alias registrations, asset operations, gateway structures and the PoS stake
//! signature).
//!
//! On-chain fixtures pin the common ones (see `onchain.rs`); these tests pin
//! the layouts that no current mainnet transaction exercises, and check the
//! exact bytes for the asset operation, whose shape depends on its version.

use zanolib::base::{
    AccountPublicAddr, AccountPublicAddrOld, AliasAddress, AssetDescriptorBase,
    AssetDescriptorOperation, AssetOperationOwnershipProof, AssetOperationOwnershipProofEth,
    AssetOperationProof, BppeSignature, ClsagGgxxgSig, EpeeRead, EpeeWrite, ExtraAliasEntry,
    GatewayOwnerSignature, GatewaySig, Reader, Signature64, TxInGateway, TxInMultisig, TxOutBare,
    TxOutGateway, TxoutTarget, Value256, Variant, ZarcanumSig, ZcGwBalanceProof, tag,
};
use zanolib::crypto::{Point, Scalar};

fn point(seed: u8) -> Point {
    Point::mul_base(&scalar(seed))
}

fn scalar(seed: u8) -> Scalar {
    Scalar::from_bytes_mod_order(&[seed; 64])
}

fn v256(seed: u8) -> Value256 {
    Value256::from_point(&point(seed))
}

fn sig64(seed: u8) -> Signature64 {
    Signature64([seed; 64])
}

/// Every variant below must survive write → read → write unchanged, and keep
/// its tag and name.
fn round_trip(v: &Variant, expect_tag: u8, expect_name: &str) {
    assert_eq!(v.tag(), expect_tag, "{expect_name}: tag");
    assert_eq!(v.type_name(), expect_name, "tag {expect_tag}: name");

    let bytes = v.to_epee_bytes();
    assert_eq!(bytes[0], expect_tag, "{expect_name}: first byte is the tag");

    let mut r = Reader::new(&bytes);
    let back = Variant::read_epee(&mut r).unwrap_or_else(|e| panic!("{expect_name}: read: {e}"));
    assert!(r.is_empty(), "{expect_name}: trailing bytes");
    assert_eq!(back.tag(), expect_tag, "{expect_name}: tag after re-read");
    assert_eq!(
        back.to_epee_bytes(),
        bytes,
        "{expect_name}: re-serialized bytes differ"
    );
}

fn descriptor(version: u64) -> AssetDescriptorBase {
    AssetDescriptorBase {
        version,
        total_max_supply: 2_100_000_000_000_000,
        current_supply: 1_000,
        decimal_point: 8,
        ticker: b"TEST".to_vec(),
        full_name: b"Test asset".to_vec(),
        meta_info: "\u{1f525}".as_bytes().to_vec(),
        owner: v256(3),
        hidden_supply: true,
        owner_eth_pub_key: if version >= 1 { Some([9u8; 33]) } else { None },
        etc: Vec::new(),
    }
}

#[test]
fn legacy_inputs_and_outputs_round_trip() {
    round_trip(
        &Variant::TxInMultisig(TxInMultisig {
            amount: 1234,
            multisig_out_id: v256(1),
            sigs_count: 2,
            etc_details: vec![Variant::Uint64(7)],
        }),
        tag::TXIN_MULTISIG,
        "multisig",
    );
    round_trip(
        &Variant::TxOutBare(TxOutBare {
            amount: 500,
            target: TxoutTarget::ToKey {
                key: v256(2),
                mix_attr: 1,
            },
        }),
        tag::TX_OUT_BARE,
        "tx_out_bare",
    );
    round_trip(
        &Variant::TxOutBare(TxOutBare {
            amount: 0,
            target: TxoutTarget::Multisig {
                minimum_sigs: 2,
                keys: vec![v256(3), v256(4)],
            },
        }),
        tag::TX_OUT_BARE,
        "tx_out_bare",
    );

    // A txout_to_key is a packed 33-byte record: the key then mix_attr.
    let out = Variant::TxOutBare(TxOutBare {
        amount: 1,
        target: TxoutTarget::ToKey {
            key: v256(5),
            mix_attr: 3,
        },
    });
    let bytes = out.to_epee_bytes();
    assert_eq!(bytes[0], tag::TX_OUT_BARE);
    assert_eq!(bytes[1], 1, "amount varint");
    assert_eq!(bytes[2], tag::TXOUT_TO_KEY);
    assert_eq!(&bytes[3..35], v256(5).as_bytes());
    assert_eq!(bytes[35], 3);
    assert_eq!(bytes.len(), 36);
}

#[test]
fn legacy_extra_entries_round_trip() {
    let old_addr = AccountPublicAddrOld {
        spend_key: v256(1),
        view_key: v256(2),
    };
    round_trip(&Variant::PayerOld(old_addr), tag::PAYER_OLD, "payer");
    round_trip(
        &Variant::ReceiverOld(old_addr),
        tag::RECEIVER_OLD,
        "receiver",
    );
    // Raw bytes, not a UTF-8 string: zano puts arbitrary payloads here.
    round_trip(
        &Variant::StringData(vec![0xff, 0x00, 0xfe]),
        tag::STRING,
        "string",
    );
    round_trip(
        &Variant::UnlockTime2(vec![0, 12345, u64::MAX]),
        tag::UNLOCK_TIME2,
        "unlock_time2",
    );

    let entry = |address| ExtraAliasEntry {
        alias: b"alice".to_vec(),
        address,
        text_comment: vec![0xff, 0x01],
        view_key: vec![v256(7)],
        sign: vec![sig64(8)],
    };
    round_trip(
        &Variant::ExtraAliasEntryOld(entry(AliasAddress::Old(old_addr))),
        tag::EXTRA_ALIAS_ENTRY_OLD,
        "alias_entry",
    );
    round_trip(
        &Variant::ExtraAliasEntry(entry(AliasAddress::Current(AccountPublicAddr {
            spend_key: v256(1),
            view_key: v256(2),
            flags: 1,
        }))),
        tag::EXTRA_ALIAS_ENTRY,
        "alias_entry2",
    );
}

#[test]
fn asset_operations_round_trip() {
    // The HF4 shape (version 1): a mandatory descriptor and amount commitment.
    let v1 = AssetDescriptorOperation {
        version: 1,
        operation_type: 1, // register
        descriptor: Some(descriptor(0)),
        amount_commitment: Some(v256(4)),
        asset_id: None,
        amount: None,
        asset_id_salt: None,
        etc: Vec::new(),
    };
    round_trip(
        &Variant::AssetDescriptorOperation(v1.clone()),
        tag::ASSET_DESCRIPTOR_OPERATION,
        "asset_descriptor_base",
    );

    // The HF5 shape (version 2): everything optional, with an explicit amount.
    let v2 = AssetDescriptorOperation {
        version: 2,
        operation_type: 2, // emit
        descriptor: Some(descriptor(2)),
        amount_commitment: Some(v256(5)),
        asset_id: Some(v256(6)),
        amount: Some(42),
        asset_id_salt: Some(7),
        etc: Vec::new(),
    };
    round_trip(
        &Variant::AssetDescriptorOperation(v2.clone()),
        tag::ASSET_DESCRIPTOR_OPERATION,
        "asset_descriptor_base",
    );

    // An emit in the HF5 shape carries no descriptor at all.
    round_trip(
        &Variant::AssetDescriptorOperation(AssetDescriptorOperation {
            descriptor: None,
            amount_commitment: None,
            ..v2.clone()
        }),
        tag::ASSET_DESCRIPTOR_OPERATION,
        "asset_descriptor_base",
    );

    // Field order, version 2: version, operation_type, then the optionals in
    // the order amount_commitment, asset_id, descriptor, amount, salt, etc.
    // A present optional is a 0 byte, an absent one a 1 byte.
    let bytes = AssetDescriptorOperation {
        version: 2,
        operation_type: 4, // public burn
        descriptor: None,
        amount_commitment: None,
        asset_id: Some(v256(6)),
        amount: Some(0x1122_3344_5566_7788),
        asset_id_salt: None,
        etc: Vec::new(),
    }
    .to_epee_bytes();
    let mut want = vec![2, 4, 1, 0];
    want.extend_from_slice(v256(6).as_bytes());
    want.extend_from_slice(&[1, 0]);
    want.extend_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    want.extend_from_slice(&[1, 0]);
    assert_eq!(bytes, want, "version 2 field order");

    // The descriptor's own version decides where its record stops.
    for version in [0u64, 1, 2] {
        let d = descriptor(version);
        let bytes = d.to_epee_bytes();
        let mut r = Reader::new(&bytes);
        let back = AssetDescriptorBase::read_epee(&mut r).unwrap();
        assert!(r.is_empty(), "descriptor v{version}: trailing bytes");
        assert_eq!(back.to_epee_bytes(), bytes, "descriptor v{version}");
        assert_eq!(back.version, version);
        assert_eq!(back.owner_eth_pub_key.is_some(), version >= 1);
        assert_eq!(back.meta_info, d.meta_info);
    }
    // A version-0 descriptor has no room for an ethereum key.
    let mut d0 = descriptor(0);
    d0.owner_eth_pub_key = Some([1u8; 33]);
    let back = AssetDescriptorBase::read_epee(&mut Reader::new(&d0.to_epee_bytes())).unwrap();
    assert_eq!(back.owner_eth_pub_key, None);
}

#[test]
fn asset_proofs_round_trip() {
    round_trip(
        &Variant::AssetOperationProof(AssetOperationProof {
            version: 0,
            amount_commitment_composition_proof: Some(zanolib::base::GenericDoubleSchnorrSig {
                c: scalar(1),
                y0: scalar(2),
                y1: scalar(3),
            }),
            amount_commitment_g_proof: None,
        }),
        tag::ASSET_OPERATION_PROOF,
        "asset_operation_proof",
    );
    round_trip(
        &Variant::AssetOperationProof(AssetOperationProof {
            version: 0,
            amount_commitment_composition_proof: None,
            amount_commitment_g_proof: Some(sig64(4)),
        }),
        tag::ASSET_OPERATION_PROOF,
        "asset_operation_proof",
    );
    round_trip(
        &Variant::AssetOperationOwnershipProof(AssetOperationOwnershipProof {
            version: 0,
            c: scalar(5),
            y: scalar(6),
        }),
        tag::ASSET_OPERATION_OWNERSHIP_PROOF,
        "asset_operation_ownership_proof",
    );
    round_trip(
        &Variant::AssetOperationOwnershipProofEth(AssetOperationOwnershipProofEth {
            version: 0,
            eth_sig: sig64(7),
        }),
        tag::ASSET_OPERATION_OWNERSHIP_PROOF_ETH,
        "asset_operation_ownership_proof_eth",
    );

    // An optional is present when its flag byte is 0 and absent when it is 1,
    // the inverse of the usual convention.
    let bytes = AssetOperationProof {
        version: 0,
        amount_commitment_composition_proof: None,
        amount_commitment_g_proof: None,
    }
    .to_epee_bytes();
    assert_eq!(bytes, vec![0, 1, 1]);
}

#[test]
fn signature_variants_round_trip() {
    let bppe = BppeSignature {
        lv: vec![point(1), point(2)],
        rv: vec![point(3), point(4)],
        a0: point(5),
        a: point(6),
        b: point(7),
        r: scalar(8),
        s: scalar(9),
        delta_1: scalar(10),
        delta_2: scalar(11),
    };
    round_trip(
        &Variant::BppeSignature(bppe.clone()),
        tag::BPPE_SIGNATURE,
        "bppe_signature_serialized",
    );
    round_trip(
        &Variant::BppSignature(zanolib::base::BppSignature {
            lv: vec![point(1)],
            rv: vec![point(2)],
            a0: point(3),
            a: point(4),
            b: point(5),
            r: scalar(6),
            s: scalar(7),
            delta: scalar(8),
        }),
        tag::BPP_SIGNATURE,
        "bpp_signature_serialized",
    );
    round_trip(
        &Variant::NlsagSig(vec![sig64(1), sig64(2)]),
        tag::NLSAG_SIG,
        "NLSAG_sig",
    );
    // A void_sig is the tag byte and nothing else.
    let void = Variant::VoidSig;
    assert_eq!(void.to_epee_bytes(), vec![tag::VOID_SIG]);
    round_trip(&void, tag::VOID_SIG, "void_sig");

    round_trip(
        &Variant::ZarcanumSig(Box::new(ZarcanumSig {
            d: scalar(1),
            c_point: point(2),
            c_prime: point(3),
            e: point(4),
            c: scalar(5),
            y0: scalar(6),
            y1: scalar(7),
            y2: scalar(8),
            y3: scalar(9),
            y4: scalar(10),
            e_range_proof: bppe,
            pseudo_out_amount_commitment: point(11),
            clsag_ggxxg: ClsagGgxxgSig {
                c: scalar(12),
                rg: vec![scalar(13), scalar(14)],
                rx: vec![scalar(15), scalar(16)],
                k1: point(17),
                k2: point(18),
                k3: point(19),
                k4: point(20),
            },
        })),
        tag::ZARCANUM_SIG,
        "zarcanum_sig",
    );
}

#[test]
fn gateway_variants_round_trip() {
    round_trip(
        &Variant::TxInGateway(TxInGateway {
            version: 0,
            gateway_addr: v256(1),
            asset_id: v256(2),
            amount: 1_000,
        }),
        tag::TXIN_GATEWAY,
        "txin_gateway",
    );
    round_trip(
        &Variant::TxOutGateway(TxOutGateway {
            version: 0,
            gateway_addr: v256(3),
            asset_id: v256(4),
            amount: 2_000,
            payment_id: 42,
        }),
        tag::TX_OUT_GATEWAY,
        "tx_out_gateway",
    );
    for sign in [
        GatewayOwnerSignature::Schnorr {
            c: v256(5),
            y: v256(6),
        },
        GatewayOwnerSignature::Eth(sig64(7)),
        GatewayOwnerSignature::Eddsa(sig64(8)),
    ] {
        round_trip(
            &Variant::GatewaySig(GatewaySig { version: 0, sign }),
            tag::GATEWAY_SIG,
            "gateway_signature",
        );
        round_trip(
            &Variant::GatewayAddressOwnershipProof(GatewaySig { version: 0, sign }),
            tag::GATEWAY_ADDRESS_OWNERSHIP_PROOF,
            "gateway_address_ownership_proof",
        );
    }
    round_trip(
        &Variant::ZcGwBalanceProof(ZcGwBalanceProof {
            c: v256(9),
            y0: v256(10),
            y1: v256(11),
            y2: v256(12),
        }),
        tag::ZC_GW_BALANCE_PROOF,
        "zc_gw_balance_proof",
    );

    // txin_gateway writes its version a second time after the amount, as zano
    // does; the whole record is version, 2 keys, amount, version.
    let bytes = Variant::TxInGateway(TxInGateway {
        version: 0,
        gateway_addr: v256(1),
        asset_id: v256(2),
        amount: 5,
    })
    .to_epee_bytes();
    assert_eq!(bytes.len(), 1 + 1 + 32 + 32 + 1 + 1);
    assert_eq!(bytes[bytes.len() - 2], 5, "amount");
    assert_eq!(bytes[bytes.len() - 1], 0, "trailing version");
}

#[test]
fn unknown_tags_are_rejected() {
    // Tags that exist in zano's table but are not members of any transaction
    // container (13 was never defined; 34 and 35 were removed with HTLC).
    for t in [13u8, 34, 35, 200] {
        let mut r = Reader::new(std::slice::from_ref(&t));
        assert!(
            Variant::read_epee(&mut r).is_err(),
            "tag {t} should be rejected"
        );
    }
}
