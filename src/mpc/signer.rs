//! [`ThresholdInputSigner`]: an [`InputSigner`] whose spend key lives in FROST
//! shares.

use super::clsag::{ClsagContext, ClsagCoordinator, ClsagParty};
use super::keygen::spend_public_key;
use super::transport::exchange;
use crate::base::sig::ClsagSig;
use crate::crypto::clsag::ClsagGgxInputRef;
use crate::crypto::{Point, Scalar, hp};
use crate::error::{Error, Result};
use crate::inputsigner::{ClsagRequest, InputSigner};
use crate::rng::{OsRng, RngCore, ShakeRng};
use purecrypto::hash::{Digest, Keccak256};
use serde::{Deserialize, Serialize};
use tsslib::frosttss::Key;
use tsslib::tss::Parameters;

/// Round-1 broadcast: this party's partial key image and nonce commitments.
#[derive(Clone, Serialize, Deserialize)]
struct Round1Msg {
    /// `w_i * kiBase`, hex.
    ki: String,
    /// `alphaG_i * G`, hex.
    commit_g: String,
    /// `alphaG_i * kiBase`, hex.
    commit_k: String,
}

/// Round-2 broadcast: this party's partial layer-0 response.
#[derive(Clone, Serialize, Deserialize)]
struct Round2Msg {
    /// `alphaG_i - cPrev*aggCoeff0*w_i`, hex.
    resp: String,
}

fn point_hex(p: &Point) -> String {
    hex::encode(p.compress())
}

fn parse_point(s: &str) -> Result<Point> {
    crate::crypto::point_from_bytes(&hex::decode(s)?)
}

fn parse_scalar(s: &str) -> Result<Scalar> {
    crate::crypto::scalar_from_canonical(&hex::decode(s)?)
}

/// Per-input state carried between [`InputSigner::key_image`] and
/// [`InputSigner::sign_clsag`].
struct ThresholdInput {
    idx: usize,
    party: ClsagParty,
    r1: Vec<Round1Msg>,
    partial_kis: Vec<Point>,
    commit_gs: Vec<Point>,
    commit_ks: Vec<Point>,
}

/// An [`InputSigner`] backed by a FROST-ed25519 key share, run over tsslib's
/// transport.
///
/// The spend secret exists only as shares; this signer contributes its partials
/// and, together with the other committee members, produces the key image and
/// the CLSAG signature without anyone reconstructing the secret. Every
/// committee member runs an identical `ThresholdInputSigner`, exchanging round
/// messages over the broker.
///
/// [`InputSigner::key_image`] and [`InputSigner::sign_clsag`] are called by
/// [`Wallet::sign_with`](crate::Wallet::sign_with) once per input, in source
/// order (all key images first, then — once the prefix hash is known — all
/// signatures); this signer pairs them by call order.
pub struct ThresholdInputSigner {
    params: Parameters,
    subset: Key,
    spend_pub: Point,
    inputs: Vec<ThresholdInput>,
    sign_n: usize,
}

impl ThresholdInputSigner {
    /// Builds a signer for this party's key share over the signing committee
    /// `params.parties()`, whose ids must carry the keygen share ids.
    pub fn new(params: Parameters, key: &Key) -> Result<ThresholdInputSigner> {
        let subset = key
            .subset_for_parties(params.parties())
            .map_err(|e| crate::err!("zanompc: {e}"))?;
        let spend_pub = spend_public_key(&subset.group_public_key)?;
        Ok(ThresholdInputSigner {
            params,
            subset,
            spend_pub,
            inputs: Vec::new(),
            sign_n: 0,
        })
    }

    /// The threshold wallet's spend public key.
    pub fn spend_pub_key(&self) -> Point {
        self.spend_pub
    }

    /// The signing committee parameters.
    pub fn params(&self) -> &Parameters {
        &self.params
    }

    /// The reindexed key share for this committee.
    pub fn subset(&self) -> &Key {
        &self.subset
    }

    /// Runs round 1 for `ki_base` and records the collected commitments.
    fn round1(&mut self, ki_base: &Point, topic: &str) -> Result<usize> {
        let idx = self.inputs.len();
        let party = ClsagParty::new(&self.subset, None, &mut OsRng)?;
        let (my_ki, my_cg, my_ck) = party.round1(ki_base);
        let mine = Round1Msg {
            ki: point_hex(&my_ki),
            commit_g: point_hex(&my_cg),
            commit_k: point_hex(&my_ck),
        };

        let collected: Vec<Round1Msg> = exchange(&self.params, topic, &mine)?;
        let mut partial_kis = Vec::with_capacity(collected.len());
        let mut commit_gs = Vec::with_capacity(collected.len());
        let mut commit_ks = Vec::with_capacity(collected.len());
        for m in &collected {
            partial_kis.push(parse_point(&m.ki)?);
            commit_gs.push(parse_point(&m.commit_g)?);
            commit_ks.push(parse_point(&m.commit_k)?);
        }

        self.inputs.push(ThresholdInput {
            idx,
            party,
            r1: collected,
            partial_kis,
            commit_gs,
            commit_ks,
        });
        Ok(idx)
    }
}

impl InputSigner for ThresholdInputSigner {
    /// Runs round 1 over the broker and returns the combined key image
    /// `hi*kiBase + sum_j(w_j*kiBase) = (hi+x)*Hp(in_e_pub)`.
    fn key_image(&mut self, hi: &Scalar, in_e_pub: &Point) -> Result<Point> {
        let ki_base = hp(&in_e_pub.compress());
        let idx = self.inputs.len();
        self.round1(&ki_base, &format!("zano:clsag:ki:{idx}"))?;
        let input = &self.inputs[idx];
        Ok(ki_base
            .mul(hi)
            .add(&super::sign::combine_points(&input.partial_kis)))
    }

    /// Runs the challenge and response round over the broker and assembles the
    /// CLSAG-GGX signature.
    ///
    /// The non-secret per-signature randomness (the X-layer nonce and the decoy
    /// responses) is derived deterministically from the round-1 transcript, so
    /// every party agrees without a coordinator.
    fn sign_clsag(&mut self, _rnd: &mut dyn RngCore, req: &ClsagRequest<'_>) -> Result<ClsagSig> {
        if self.sign_n >= self.inputs.len() {
            return Err(Error::msg(
                "zanompc: sign_clsag called more times than key_image",
            ));
        }
        let n = self.sign_n;
        self.sign_n += 1;

        let ctx = ClsagContext {
            message: req.msg,
            ring: req.ring,
            pseudo_out_amount_commitment: req.pseudo_out_amount_commitment,
            pseudo_out_blinded_asset_id: req.pseudo_out_blinded_asset_id,
            secret1_f: req.secret1_f,
            secret2_t: req.secret2_t,
            hi: req.hi,
            spend_pub: &self.spend_pub,
            secret_index: req.secret_index,
        };

        let mut det = transcript_rng(req.msg, req.ring, &self.inputs[n].r1);
        let (mut coord, c_prev, agg0) = ClsagCoordinator::phase1(
            &mut det,
            &ctx,
            &self.inputs[n].partial_kis,
            &self.inputs[n].commit_gs,
            &self.inputs[n].commit_ks,
        )?;

        let my_resp = self.inputs[n].party.round2(&c_prev, &agg0);
        let topic = format!("zano:clsag:resp:{}", self.inputs[n].idx);
        let collected: Vec<Round2Msg> = exchange(
            &self.params,
            &topic,
            &Round2Msg {
                resp: hex::encode(my_resp.to_bytes()),
            },
        )?;
        let responses: Vec<Scalar> = collected
            .iter()
            .map(|m| parse_scalar(&m.resp))
            .collect::<Result<_>>()?;

        let (sig, _ki) = coord.phase2(&ctx, &responses)?;
        Ok(sig)
    }
}

/// A deterministic byte stream seeded by the message, ring and round-1
/// transcript — used for the non-secret per-signature randomness so all parties
/// agree.
fn transcript_rng(msg: &[u8], ring: &[ClsagGgxInputRef], r1: &[Round1Msg]) -> ShakeRng {
    let mut h = Keccak256::new();
    h.update(b"ZANO_THRESHOLD_CLSAG_DETRAND\x00");
    h.update(msg);
    for r in ring {
        h.update(&r.stealth_address.compress());
        h.update(&r.amount_commitment.compress());
        h.update(&r.blinded_asset_id.compress());
    }
    for m in r1 {
        h.update(&hex::decode(&m.ki).unwrap_or_default());
        h.update(&hex::decode(&m.commit_g).unwrap_or_default());
        h.update(&hex::decode(&m.commit_k).unwrap_or_default());
    }
    ShakeRng::new(&h.finalize())
}
