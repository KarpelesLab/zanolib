//! Multi-party tests for the threshold spend key: DKG, address derivation,
//! threshold key images, threshold CLSAG signing, and the deterministic view
//! key — all driven concurrently over an in-process broker hub.

#![cfg(feature = "mpc")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tsslib::frost::Ed25519;
use tsslib::frost::binding::lagrange_coefficient;
use tsslib::frosttss::{Key, Keygen};
use tsslib::tss::{BrokerResult, JsonMessage, MessageBroker, MessageReceiver, Parameters, PartyId};

use zanolib::crypto::{
    ClsagGgxInputRef, Point, Scalar, hp, point_from_bytes, random_scalar, verify_clsag_ggx,
};
use zanolib::mpc::{self, ClsagContext, ClsagCoordinator, ClsagParty, ThresholdInputSigner};
use zanolib::rng::OsRng;
use zanolib::{InputSigner, LocalInputSigner};

// ---------------------------------------------------------------------------
// In-process transport
// ---------------------------------------------------------------------------

/// A set of interconnected in-process brokers, one per party. Outbound messages
/// are routed to the other parties' brokers; inbound messages are dispatched to
/// the registered handler, buffering until one is connected.
struct TestHub {
    brokers: Vec<Arc<HubBroker>>,
}

impl TestHub {
    fn new(n: usize) -> Arc<TestHub> {
        let brokers: Vec<Arc<HubBroker>> = (0..n)
            .map(|i| {
                Arc::new(HubBroker {
                    party_index: i,
                    peers: OnceLock::new(),
                    inner: Mutex::new(HubInner {
                        handlers: HashMap::new(),
                        pending: HashMap::new(),
                    }),
                })
            })
            .collect();
        for b in &brokers {
            b.peers.set(brokers.clone()).ok();
        }
        Arc::new(TestHub { brokers })
    }

    fn broker(&self, i: usize) -> Arc<dyn MessageBroker + Send + Sync> {
        self.brokers[i].clone()
    }
}

struct HubBroker {
    party_index: usize,
    peers: OnceLock<Vec<Arc<HubBroker>>>,
    inner: Mutex<HubInner>,
}

struct HubInner {
    handlers: HashMap<String, Arc<dyn MessageReceiver + Send + Sync>>,
    pending: HashMap<String, Vec<JsonMessage>>,
}

impl HubBroker {
    fn deliver_inbound(&self, msg: &JsonMessage) -> BrokerResult {
        let handler = {
            let mut inner = self.inner.lock().unwrap();
            match inner.handlers.get(&msg.typ) {
                Some(h) => Some(h.clone()),
                None => {
                    inner
                        .pending
                        .entry(msg.typ.clone())
                        .or_default()
                        .push(msg.clone());
                    None
                }
            }
        };
        match handler {
            Some(h) => h.receive(msg),
            None => Ok(()),
        }
    }
}

impl MessageReceiver for HubBroker {
    fn receive(&self, msg: &JsonMessage) -> BrokerResult {
        let from_index = msg.from.as_ref().map(|p| p.index).unwrap_or(-1);
        if from_index == self.party_index as i32 {
            let peers = self.peers.get().expect("peers wired");
            match &msg.to {
                Some(to) => peers[to.index as usize].deliver_inbound(msg),
                None => {
                    for (j, peer) in peers.iter().enumerate() {
                        if j != self.party_index {
                            peer.deliver_inbound(msg)?;
                        }
                    }
                    Ok(())
                }
            }
        } else {
            self.deliver_inbound(msg)
        }
    }
}

impl MessageBroker for HubBroker {
    fn connect(&self, typ: &str, dest: Arc<dyn MessageReceiver + Send + Sync>) {
        let queued = {
            let mut inner = self.inner.lock().unwrap();
            inner.handlers.insert(typ.to_string(), dest.clone());
            inner.pending.remove(typ).unwrap_or_default()
        };
        for msg in queued {
            let _ = dest.receive(&msg);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn party_ids(n: usize) -> Vec<PartyId> {
    PartyId::sort(
        (1..=n)
            .map(|i| PartyId::new(i.to_string(), format!("P{i}"), vec![i as u8]))
            .collect(),
        0,
    )
}

/// Runs the FROST DKG for `n` parties with reconstruction threshold `t`.
fn run_dkg(n: usize, t: usize) -> Vec<Key> {
    let ids = party_ids(n);
    let hub = TestHub::new(n);
    let keygens: Vec<Keygen> = (0..n)
        .map(|i| {
            let params = Parameters::new(ids.clone(), &ids[i], t, hub.broker(i));
            Keygen::new(params).expect("keygen starts")
        })
        .collect();
    keygens
        .iter()
        .map(|kg| kg.wait().expect("keygen succeeds"))
        .collect()
}

/// Reconstructs the group secret from a committee — test-only; the protocol
/// itself never does this.
fn reconstruct_secret(committee: &[&Key]) -> Scalar {
    let ids: Vec<Vec<u8>> = committee
        .iter()
        .map(|k| k.share_id.as_be_bytes().to_vec())
        .collect();
    let mut secret = Scalar::ZERO;
    for k in committee {
        let lambda = lagrange_coefficient::<Ed25519>(k.share_id.as_be_bytes(), &ids).unwrap();
        secret = secret.add(&lambda.mul(&k.xi));
    }
    secret
}

/// Reindexes each key to the given committee, as the signing code does.
fn subset(committee: &[&Key], ids: &[PartyId]) -> Vec<Key> {
    committee
        .iter()
        .map(|k| k.subset_for_parties(ids).expect("subset"))
        .collect()
}

/// A synthetic single-input CLSAG context whose real member is spendable with
/// `hi + x`.
struct Fixture {
    ring: Vec<ClsagGgxInputRef>,
    p_ac: Point,
    p_baid: Point,
    hi: Scalar,
    s1: Scalar,
    s2: Scalar,
    in_e_pub: Point,
    msg: Vec<u8>,
    secret_index: u64,
}

fn fixture(spend_pub: &Point, ring_size: usize, secret_index: u64) -> Fixture {
    let mut rnd = OsRng;
    let hi = random_scalar(&mut rnd);
    let s1 = random_scalar(&mut rnd);
    let s2 = random_scalar(&mut rnd);
    let p_ac = Point::mul_base(&random_scalar(&mut rnd));
    let p_baid = Point::mul_base(&random_scalar(&mut rnd));

    let mut ring: Vec<ClsagGgxInputRef> = (0..ring_size)
        .map(|_| ClsagGgxInputRef {
            stealth_address: Point::mul_base(&random_scalar(&mut rnd)),
            amount_commitment: Point::mul_base(&random_scalar(&mut rnd)),
            blinded_asset_id: Point::mul_base(&random_scalar(&mut rnd)),
        })
        .collect();

    let in_e_pub = Point::mul_base(&hi).add(spend_pub);
    let one_div8 = &*zanolib::crypto::consts::SC_1DIV8;
    let x_gen = &*zanolib::crypto::consts::C_POINT_X;
    ring[secret_index as usize].stealth_address = in_e_pub;
    ring[secret_index as usize].amount_commitment = Point::mul_base(&s1).add(&p_ac).mul(one_div8);
    ring[secret_index as usize].blinded_asset_id = x_gen.mul(&s2).add(&p_baid).mul(one_div8);

    let msg: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(2))
        .collect();

    Fixture {
        ring,
        p_ac,
        p_baid,
        hi,
        s1,
        s2,
        in_e_pub,
        msg,
        secret_index,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn threshold_spend_key_and_address_agree_across_parties() {
    let keys = run_dkg(3, 1);

    // Any view key works; it is independent of the (threshold) spend key.
    let view_pub = Point::mul_base(&random_scalar(&mut OsRng)).compress();

    let mut first: Option<String> = None;
    for (i, k) in keys.iter().enumerate() {
        let spend = mpc::spend_public_key_bytes(&k.group_public_key).unwrap();
        let addr = mpc::address(&k.group_public_key, &view_pub, 0).unwrap();
        assert_eq!(addr.spend_key, spend.0.to_vec());
        assert_eq!(addr.view_key, view_pub.to_vec());
        let s = addr.to_string();
        match &first {
            None => first = Some(s.clone()),
            Some(f) => assert_eq!(&s, f, "party {i} derived a different address"),
        }
        // The address must round-trip through the parser.
        let parsed = zanolib::Address::parse(&s).unwrap();
        assert_eq!(parsed.spend_key, spend.0.to_vec());
    }

    // An auditable wallet gets the auditable prefix.
    let audit = mpc::address(&keys[0].group_public_key, &view_pub, 1).unwrap();
    assert!(audit.to_string().starts_with("aZx"));
}

#[test]
fn additive_shares_reconstruct_the_group_secret() {
    let keys = run_dkg(3, 1);
    let ids = party_ids(3);

    // Full committee.
    let all: Vec<&Key> = keys.iter().collect();
    let sub = subset(&all, &ids);
    let sum = sub
        .iter()
        .map(|k| mpc::additive_share(k).unwrap())
        .fold(Scalar::ZERO, |a, b| a.add(&b));
    assert_eq!(
        Point::mul_base(&sum),
        keys[0].group_public_key,
        "sum of additive shares must be the group secret"
    );

    // A t+1 subset must reconstruct the same secret.
    let two_ids = vec![ids[0].clone(), ids[1].clone()];
    let two: Vec<&Key> = vec![&keys[0], &keys[1]];
    let sub2 = subset(&two, &two_ids);
    let sum2 = sub2
        .iter()
        .map(|k| mpc::additive_share(k).unwrap())
        .fold(Scalar::ZERO, |a, b| a.add(&b));
    assert_eq!(sum2.to_bytes(), sum.to_bytes());
}

#[test]
fn threshold_key_image_matches_a_local_signer() {
    let keys = run_dkg(3, 1);
    let ids = party_ids(3);
    let all: Vec<&Key> = keys.iter().collect();
    let sub = subset(&all, &ids);

    let spend_pub = mpc::spend_public_key(&keys[0].group_public_key).unwrap();
    let f = fixture(&spend_pub, 8, 2);

    let ki_base = hp(&f.in_e_pub.compress());
    let partials: Vec<Point> = sub
        .iter()
        .map(|k| mpc::partial_key_image(k, &ki_base).unwrap())
        .collect();
    let threshold_ki = ki_base.mul(&f.hi).add(&mpc::combine_points(&partials));

    let x = reconstruct_secret(&all);
    let want = LocalInputSigner::new(x)
        .key_image(&f.hi, &f.in_e_pub)
        .unwrap();
    assert_eq!(threshold_ki, want);
}

#[test]
fn threshold_clsag_verifies_for_every_committee() {
    let keys = run_dkg(3, 1);
    let ids = party_ids(3);
    let spend_pub = mpc::spend_public_key(&keys[0].group_public_key).unwrap();
    let f = fixture(&spend_pub, 8, 5);

    let committees: Vec<(Vec<&Key>, Vec<PartyId>)> = vec![
        (keys.iter().collect(), ids.clone()),
        (
            vec![&keys[0], &keys[1]],
            vec![ids[0].clone(), ids[1].clone()],
        ),
    ];

    let mut first_ki: Option<Point> = None;
    for (committee, cids) in committees {
        let sub = subset(&committee, &cids);
        let parties: Vec<ClsagParty> = sub
            .iter()
            .map(|k| ClsagParty::new(k, None, &mut OsRng).unwrap())
            .collect();

        let ctx = ClsagContext {
            message: &f.msg,
            ring: &f.ring,
            pseudo_out_amount_commitment: &f.p_ac,
            pseudo_out_blinded_asset_id: &f.p_baid,
            secret1_f: &f.s1,
            secret2_t: &f.s2,
            hi: &f.hi,
            spend_pub: &spend_pub,
            secret_index: f.secret_index,
        };

        let ki_base = ClsagCoordinator::ki_base(&ctx);
        let mut pkis = Vec::new();
        let mut cgs = Vec::new();
        let mut cks = Vec::new();
        for p in &parties {
            let (a, b, c) = p.round1(&ki_base);
            pkis.push(a);
            cgs.push(b);
            cks.push(c);
        }

        let (mut coord, c_prev, agg0) =
            ClsagCoordinator::phase1(&mut OsRng, &ctx, &pkis, &cgs, &cks).expect("phase1");
        let resps: Vec<Scalar> = parties.iter().map(|p| p.round2(&c_prev, &agg0)).collect();
        let (sig, ki) = coord.phase2(&ctx, &resps).expect("phase2");

        assert!(
            verify_clsag_ggx(&f.msg, &f.ring, &ki, &f.p_ac, &f.p_baid, &sig).unwrap(),
            "threshold signature failed to verify"
        );
        match &first_ki {
            None => first_ki = Some(ki),
            Some(k) => assert_eq!(&ki, k, "key image differs between committees"),
        }
    }
}

#[test]
fn threshold_input_signer_runs_the_whole_committee_concurrently() {
    const N: usize = 3;
    const T: usize = 1;
    let keys = run_dkg(N, T);
    let spend_pub = mpc::spend_public_key(&keys[0].group_public_key).unwrap();
    let f = fixture(&spend_pub, 8, 2);

    // The signing party ids carry the keygen share ids as their key.
    let ids = PartyId::sort(
        keys.iter()
            .enumerate()
            .map(|(i, k)| PartyId::new(format!("p{i}"), "", k.share_id.as_be_bytes().to_vec()))
            .collect(),
        0,
    );

    // Reference key image from a local signer holding the reconstructed secret.
    let all: Vec<&Key> = keys.iter().collect();
    let want_ki = LocalInputSigner::new(reconstruct_secret(&all))
        .key_image(&f.hi, &f.in_e_pub)
        .unwrap();

    let hub = TestHub::new(N);
    let results: Vec<(Point, bool)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let params = Parameters::new(ids.clone(), &ids[i], T, hub.broker(i));
                let key = keys[i].clone();
                let f = &f;
                scope.spawn(move || {
                    let mut signer = ThresholdInputSigner::new(params, &key).expect("signer");
                    let ki = signer.key_image(&f.hi, &f.in_e_pub).expect("key image");
                    let sig = signer
                        .sign_clsag(
                            &mut OsRng,
                            &zanolib::ClsagRequest {
                                hi: &f.hi,
                                msg: &f.msg,
                                ring: &f.ring,
                                key_image: &ki,
                                pseudo_out_amount_commitment: &f.p_ac,
                                pseudo_out_blinded_asset_id: &f.p_baid,
                                secret1_f: &f.s1,
                                secret2_t: &f.s2,
                                secret_index: f.secret_index,
                            },
                        )
                        .expect("sign_clsag");
                    let ok = verify_clsag_ggx(&f.msg, &f.ring, &ki, &f.p_ac, &f.p_baid, &sig)
                        .expect("verify");
                    (ki, ok)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    for (i, (ki, ok)) in results.iter().enumerate() {
        assert!(*ok, "party {i}: signature did not verify");
        assert_eq!(ki, &want_ki, "party {i}: key image != local signer's");
    }
}

#[test]
fn deterministic_view_secret_is_identical_across_parties() {
    const N: usize = 3;
    const T: usize = 1;
    let keys = run_dkg(N, T);

    let ids = PartyId::sort(
        keys.iter()
            .enumerate()
            .map(|(i, k)| PartyId::new(format!("p{i}"), "", k.share_id.as_be_bytes().to_vec()))
            .collect(),
        0,
    );

    let hub = TestHub::new(N);
    let secrets: Vec<Scalar> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let params = Parameters::new(ids.clone(), &ids[i], T, hub.broker(i));
                let key = keys[i].clone();
                scope.spawn(move || {
                    let signer = ThresholdInputSigner::new(params, &key).expect("signer");
                    signer.derive_view_secret().expect("derive view secret")
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    for s in &secrets[1..] {
        assert_eq!(
            s.to_bytes(),
            secrets[0].to_bytes(),
            "parties derived different view secrets"
        );
    }
    assert_ne!(secrets[0].to_bytes(), [0u8; 32]);

    // The base point is a pure function of the spend key, and domain-separated
    // from a real key image (whose base is Hp(stealth_address), unprefixed).
    let spend_pub = mpc::spend_public_key(&keys[0].group_public_key).unwrap();
    let base = mpc::view_key_base(&spend_pub);
    assert_eq!(base, mpc::view_key_base(&spend_pub));
    assert_ne!(base, hp(&spend_pub.compress()));

    // The derived secret is a canonical scalar usable as a Zano view key.
    let view_pub = Point::mul_base(&secrets[0]);
    let addr = mpc::address(&keys[0].group_public_key, &view_pub.compress(), 0).unwrap();
    let parsed = zanolib::Address::parse(&addr.to_string()).unwrap();
    assert_eq!(
        point_from_bytes(&parsed.view_key).unwrap(),
        view_pub,
        "view key must survive the address round-trip"
    );
}
