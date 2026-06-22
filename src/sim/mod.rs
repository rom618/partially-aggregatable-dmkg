//! Phase-steppable orchestration of the DMKG for the interactive UI.
//!
//! `DkgSession` drives the `crate::dkg::*` machinery one phase at a time and
//! exposes a `Snapshot` describing, per participant, which state is public (on the
//! broadcast channel) and which is private. It instantiates BLS12-381 directly and
//! only sequences and renders the protocol; the crypto lives in the dkg modules.

use crate::{
    dkg::{
        aggregator::DKGAggregator,
        complaint::{run_complaint_phase, Complaint, DisqualificationReason},
        config::Config,
        dealer::Dealer,
        dmkg::{aggregate_public_key, reconstruct_pk_components, DMKGContribution, PublicKey},
        encryption::{ElGamalBase, ElGamalKeypair, EncryptedPedersenShare, RecoveredShareMessages},
        node::Node,
        participant::{Participant, ParticipantState},
        pedersen::{PedersenDistribution, PedersenGenerators},
        share::{message_from_c_i, DKGShare, DKGTranscript},
        srs::SRS,
    },
    signature::{
        bls::{srs::SRS as BLSSRS, BLSSignature, BLSSignatureG1, BLSSignatureG2},
        scheme::SignatureScheme,
    },
};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use rand::thread_rng;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

type E = Bls12_381;
type SPOK = BLSSignature<BLSSignatureG2<Bls12_381>>;
type SSIG = BLSSignature<BLSSignatureG1<Bls12_381>>;

/// The protocol phases the session steps through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Setup,
    Distribution,
    /// z-layer binary-tree aggregation (one advance per tree level).
    ZAggregation,
    Verification,
    Complaints,
    KeyGeneration,
    Done,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Setup => "Setup",
            Phase::Distribution => "Distribution",
            Phase::ZAggregation => "z-Aggregation",
            Phase::Verification => "Verification",
            Phase::Complaints => "Complaints",
            Phase::KeyGeneration => "KeyGeneration",
            Phase::Done => "Done",
        }
    }
    fn index(self) -> usize {
        match self {
            Phase::Setup => 0,
            Phase::Distribution => 1,
            Phase::ZAggregation => 2,
            Phase::Verification => 3,
            Phase::Complaints => 4,
            Phase::KeyGeneration => 5,
            Phase::Done => 6,
        }
    }
    fn next(self) -> Phase {
        match self {
            Phase::Setup => Phase::Distribution,
            Phase::Distribution => Phase::ZAggregation,
            Phase::ZAggregation => Phase::Verification,
            Phase::Verification => Phase::Complaints,
            Phase::Complaints => Phase::KeyGeneration,
            Phase::KeyGeneration => Phase::Done,
            Phase::Done => Phase::Done,
        }
    }
}

/// How (and when) a participant misbehaves. The two single-layer modes let the UI
/// demonstrate the two disqualification paths in isolation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malice {
    /// Plays honestly throughout.
    Honest,
    /// Corrupts its `z` commitment `c_i`, so the publicly-verifiable `z` layer
    /// catches it before `z` is aggregated → it lands in `Qagg`. Honest in the
    /// Pedersen layer (deals consistent shares).
    ZCommitment,
    /// Honest in `z` (its share verifies, so it never enters `Qagg`), but deals one
    /// inconsistent Pedersen share to a victim. It is therefore caught only by
    /// the complaint/disputation phase - i.e. after `Qagg` is resolved - and the
    /// `Qagg` short-circuit does not apply, so a full disputation runs.
    PedersenShare,
    /// Corrupts both layers (the original demo dealer): in `Qagg` *and* the target
    /// of a complaint, so the `Qagg` short-circuit disqualifies it without a
    /// disputation.
    Both,
}

impl Malice {
    /// Stable string tag used on the wire / in the UI.
    pub fn tag(self) -> &'static str {
        match self {
            Malice::Honest => "honest",
            Malice::ZCommitment => "z",
            Malice::PedersenShare => "pedersen",
            Malice::Both => "both",
        }
    }
    /// Parse a tag (unknown / missing ⇒ `Honest`).
    pub fn from_tag(s: &str) -> Malice {
        match s {
            "z" => Malice::ZCommitment,
            "pedersen" => Malice::PedersenShare,
            "both" => Malice::Both,
            _ => Malice::Honest,
        }
    }
    /// Human-readable description for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Malice::Honest => "honest",
            Malice::ZCommitment => "corrupt z (→ Qagg)",
            Malice::PedersenShare => "corrupt Pedersen share (→ complaint)",
            Malice::Both => "corrupt both",
        }
    }
    fn is_malicious(self) -> bool {
        self != Malice::Honest
    }
    fn corrupt_z(self) -> bool {
        matches!(self, Malice::ZCommitment | Malice::Both)
    }
    fn corrupt_pedersen(self) -> bool {
        matches!(self, Malice::PedersenShare | Malice::Both)
    }
}

// ---- z-tree data structures -------------------------------------------------

/// One node in the pre-computed binary aggregation tree plan.
struct ZTreePlanNode {
    /// Real participant IDs whose shares are combined in this subtree.
    real: Vec<usize>,
    /// The aggregator for this subtree: the rightmost real participant in the
    /// subtree (the one that receives all left-side transcripts and combines).
    aggregator: Option<usize>,
}

impl Clone for ZTreePlanNode {
    fn clone(&self) -> Self {
        ZTreePlanNode {
            real: self.real.clone(),
            aggregator: self.aggregator,
        }
    }
}

/// A node in the z-aggregation tree, exposed via the Snapshot.
pub struct ZTreeNodeView {
    /// Real participant IDs in this subtree.
    pub real_participants: Vec<usize>,
    /// The aggregator (rightmost real participant in this subtree), if any.
    pub aggregator: Option<usize>,
    /// For leaf nodes (level 0): was the PVSS share verified successfully?
    pub leaf_ok: Option<bool>,
    /// 0-indexed position within this level (for layout).
    pub position: usize,
}

/// One level (round) of the z-aggregation tree.
pub struct ZTreeLevelView {
    /// 0 = leaf level, max = root.
    pub level: usize,
    pub is_leaf_level: bool,
    pub is_root_level: bool,
    pub description: String,
    pub nodes: Vec<ZTreeNodeView>,
}

/// The common public reference every party shares from the start: the SRS (the
/// CRS), `u_1`, the Pedersen generators, the ElGamal base, and the z-layer domain.
pub struct CommonReferenceView {
    pub g_g1: String,
    pub h_g2: String,
    pub u_1: String,
    pub ped_g1: String,
    pub ped_g2: String,
    pub ped_h1: String,
    pub ped_h2: String,
    pub elgamal_base: String,
    pub domain_size: usize,
}

/// One participant's keys, contribution and private decrypted state.
struct Party {
    malice: Malice,
    sig_sk: Fr,
    sig_pk: G2Affine,
    elgamal: ElGamalKeypair<E>,
    // Filled at Distribution (private):
    z_i: Option<Fr>,
    x1: Option<Fr>,
    x2: Option<Fr>,
    y1: Option<Fr>,
    y2: Option<Fr>,
    // Filled at Verification (private to this receiver):
    received: Vec<Option<RecoveredShareMessages<E>>>,
    received_ok: Vec<Option<bool>>,
    accumulated_z: Option<G2Affine>,
    /// Whether this participant verified & approved the final broadcast
    /// z-transcript (public - the approval is announced on the channel).
    z_transcript_approved: Option<bool>,
}

/// A labelled field shown in the inspector.
pub struct Field {
    pub label: String,
    pub value: String,
}

/// Per-participant view: public vs private data plus status flags.
pub struct ParticipantView {
    pub id: usize,
    pub malicious: bool,
    /// The malice mode tag ("honest" | "z" | "pedersen" | "both").
    pub malice: String,
    /// Human-readable malice label.
    pub malice_label: String,
    pub in_qagg: bool,
    pub complaints_against: usize,
    pub in_qual: bool,
    pub disqualified_reason: Option<String>,
    pub public: Vec<Field>,
    pub private: Vec<Field>,
    /// Messages this participant sends/receives on each channel (observable).
    pub communication: Vec<Field>,
}

/// The public key view (`pk = (c1,c2,c3)`), with the reconstruction check.
pub struct PublicKeyView {
    pub c1: String,
    pub c2: String,
    pub c3: String,
    pub reconstructed_ok: Option<bool>,
}

/// A full snapshot of the session for the UI to render.
pub struct Snapshot {
    pub phase: String,
    pub phase_index: usize,
    pub can_advance: bool,
    pub next_phase: Option<String>,
    pub n: usize,
    pub degree: usize,
    pub reconstruction_threshold: usize,
    pub malicious: Vec<usize>,
    /// Per-participant malice mode tag, for non-honest participants: (id, tag).
    pub malice: Vec<(usize, String)>,
    pub qagg: Vec<usize>,
    pub qual: Vec<usize>,
    pub complaints: Vec<(usize, usize)>,
    pub public_key: Option<PublicKeyView>,
    pub participants: Vec<ParticipantView>,
    pub log: Vec<String>,
    /// z-aggregation binary tree (all levels, including pending ones).
    pub z_tree: Vec<ZTreeLevelView>,
    /// Total number of tree levels (including leaf level 0).
    pub z_total_levels: usize,
    /// How many tree levels have been processed so far.
    pub z_levels_done: usize,
    /// The root aggregator that ends up holding the final candidate transcript.
    pub z_root: Option<usize>,
    /// Whether the root has broadcast the final transcript and peers approved it.
    pub z_transcript_broadcast: bool,
    /// Per-participant approval of the broadcast transcript (id, approved).
    pub z_approvals: Vec<(usize, bool)>,
    /// The common public reference (CRS, generators, domain) shared from setup.
    pub common: CommonReferenceView,
}

/// The interactive DMKG session.
pub struct DkgSession {
    n: usize,
    degree: usize,
    malice: BTreeMap<usize, Malice>,

    /// Size of the SCRAPE Radix2 evaluation domain for the `z` layer; this is
    /// `next_power_of_two(n)`, since the upstream PVSS requires a power-of-two
    /// domain. The first `n` entries are the real participants; any remaining
    /// slots are padding with throwaway keys, ignored by the rest of the protocol.
    domain_size: usize,
    config: Config<E>,
    scheme_pok: SPOK,
    scheme_sig: SSIG,
    generators: PedersenGenerators<E>,
    base: ElGamalBase<E>,
    participants_map: BTreeMap<usize, Participant<E, SSIG>>,
    receiver_pks: Vec<<E as PairingEngine>::G1Affine>,

    parties: Vec<Party>,
    phase: Phase,

    contributions: BTreeMap<usize, DMKGContribution<E, SPOK, SSIG>>,
    distributions: BTreeMap<usize, PedersenDistribution<E>>,
    qagg: BTreeSet<usize>,
    complaints: Vec<Complaint>,
    qual: BTreeSet<usize>,
    disqualified: BTreeMap<usize, DisqualificationReason>,
    pk: Option<PublicKey<E>>,
    reconstructed_ok: Option<bool>,
    log: Vec<String>,

    // z-aggregation binary tree state
    /// Pre-computed tree plan: levels[level][node] = subtree description.
    z_tree_plan: Vec<Vec<ZTreePlanNode>>,
    /// Per-real-participant leaf verification result (populated at z_levels_done==1).
    z_leaf_results: BTreeMap<usize, bool>,
    /// How many tree levels have been processed (0 until ZAggregation starts).
    z_levels_done: usize,
    /// The aggregated z-transcript produced at tree level 0, stored for use
    /// by the Pedersen verification phase.
    z_agg_transcript: Option<DKGTranscript<E, SPOK, SSIG>>,
    /// Whether the root has broadcast the final transcript for approval, the
    /// last sub-step of the z-layer (after all tree levels are folded).
    z_transcript_broadcast: bool,
}

impl DkgSession {
    /// Build a fresh session in the `Setup` phase. `degree` defaults to `n/2` when
    /// `None`. Returns an error string for invalid configuration.
    pub fn new(
        n: usize,
        degree: Option<usize>,
        malice: BTreeMap<usize, Malice>,
    ) -> Result<Self, String> {
        if !(2..=10).contains(&n) {
            return Err(format!("n must be between 2 and 10 (got {})", n));
        }
        let degree = degree.unwrap_or(n / 2).max(1);
        if degree >= n {
            return Err(format!(
                "threshold/degree t must satisfy 1 <= t < n (got t={}, n={})",
                degree, n
            ));
        }
        // Drop honest entries so the map only holds actual misbehaviour.
        let malice: BTreeMap<usize, Malice> = malice
            .into_iter()
            .filter(|(_, m)| m.is_malicious())
            .collect();
        if let Some((&bad, _)) = malice.iter().find(|(&id, _)| id >= n) {
            return Err(format!("malicious id {} out of range [0,{})", bad, n));
        }

        let rng = &mut thread_rng();
        let srs = SRS::<E>::setup(rng).map_err(|e| e.to_string())?;
        let scheme_sig = BLSSignature::<BLSSignatureG1<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.h_g2,
                g_signature: srs.g_g1,
            },
        };
        let scheme_pok = BLSSignature::<BLSSignatureG2<Bls12_381>> {
            srs: BLSSRS {
                g_public_key: srs.g_g1,
                g_signature: srs.h_g2,
            },
        };
        let u_1 = G2Projective::rand(rng).into_affine();
        let config = Config {
            srs: srs.clone(),
            u_1,
            degree,
        };
        let generators = PedersenGenerators::<E>::setup().map_err(|e| e.to_string())?;
        let base = ElGamalBase::<E>::setup().map_err(|e| e.to_string())?;

        let mut parties = Vec::with_capacity(n);
        for id in 0..n {
            let (sig_sk, sig_pk) = scheme_sig
                .generate_keypair(rng)
                .map_err(|e| e.to_string())?;
            let elgamal = ElGamalKeypair::<E>::generate(&base, rng);
            parties.push(Party {
                malice: malice.get(&id).copied().unwrap_or(Malice::Honest),
                sig_sk,
                sig_pk,
                elgamal,
                z_i: None,
                x1: None,
                x2: None,
                y1: None,
                y2: None,
                received: vec![None; n],
                received_ok: vec![None; n],
                accumulated_z: None,
                z_transcript_approved: None,
            });
        }
        // The SCRAPE PVSS uses a Radix2 domain, so the participant set for the `z`
        // layer must have power-of-two size. Real participants are 0..n; slots
        // n..m are padding with throwaway public keys (never used elsewhere).
        let m = n.next_power_of_two();
        let mut participants_map = BTreeMap::new();
        for (id, party) in parties.iter().enumerate() {
            participants_map.insert(
                id,
                Participant::<E, SSIG> {
                    pairing_type: PhantomData,
                    id,
                    public_key_sig: party.sig_pk,
                    state: ParticipantState::Dealer,
                },
            );
        }
        for id in n..m {
            let (_dummy_sk, dummy_pk) = scheme_sig
                .generate_keypair(rng)
                .map_err(|e| e.to_string())?;
            participants_map.insert(
                id,
                Participant::<E, SSIG> {
                    pairing_type: PhantomData,
                    id,
                    public_key_sig: dummy_pk,
                    state: ParticipantState::Dealer,
                },
            );
        }
        let receiver_pks = parties.iter().map(|p| p.elgamal.pk).collect::<Vec<_>>();

        let mut log = vec![];
        let malice_desc = if malice.is_empty() {
            "none".to_string()
        } else {
            malice
                .iter()
                .map(|(id, m)| format!("P{}={}", id, m.tag()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        log.push(format!(
            "Setup: n={}, threshold t={} (reconstruct from t+1={}), malicious=[{}].",
            n,
            degree,
            degree + 1,
            malice_desc
        ));
        if degree.saturating_sub(1) >= n.div_ceil(2) {
            log.push(format!(
                "Note: t-1={} is not < n/2={}; the paper's adversary bound is exceeded.",
                degree.saturating_sub(1),
                n / 2
            ));
        }

        Ok(Self {
            n,
            degree,
            malice,
            domain_size: m,
            config,
            scheme_pok,
            scheme_sig,
            generators,
            base,
            participants_map,
            receiver_pks,
            parties,
            phase: Phase::Setup,
            contributions: BTreeMap::new(),
            distributions: BTreeMap::new(),
            qagg: BTreeSet::new(),
            complaints: vec![],
            qual: BTreeSet::new(),
            disqualified: BTreeMap::new(),
            pk: None,
            reconstructed_ok: None,
            log,
            z_tree_plan: vec![],
            z_leaf_results: BTreeMap::new(),
            z_levels_done: 0,
            z_agg_transcript: None,
            z_transcript_broadcast: false,
        })
    }

    fn build_node(&self, id: usize) -> Node<E, SPOK, SSIG> {
        Node {
            aggregator: DKGAggregator {
                config: self.config.clone(),
                scheme_pok: self.scheme_pok.clone(),
                scheme_sig: self.scheme_sig.clone(),
                participants: self.participants_map.clone(),
                transcript: DKGTranscript::empty(self.degree, self.domain_size),
                qagg: BTreeSet::new(),
            },
            dealer: Dealer {
                private_key_sig: self.parties[id].sig_sk,
                accumulated_secret: G2Projective::zero().into_affine(),
                participant: self.participants_map[&id].clone(),
            },
        }
    }

    /// Advance one phase (or one tree level during z-Aggregation).
    pub fn advance(&mut self) -> Result<(), String> {
        match self.phase {
            Phase::Setup => self.do_distribution(),
            Phase::Distribution => self.do_z_tree_init(),
            Phase::ZAggregation => self.do_z_tree_advance(),
            Phase::Verification => self.do_complaints(),
            Phase::Complaints => self.do_key_generation(),
            Phase::KeyGeneration => {
                self.phase = Phase::Done;
                self.log.push("Protocol complete.".to_string());
                Ok(())
            }
            Phase::Done => Ok(()),
        }
    }

    // ---- z-tree helpers -------------------------------------------------------

    /// Build the binary aggregation tree plan for `n` real participants.
    /// Returns `levels[k][j]` where `k=0` is the leaf level.
    /// The "aggregator" at each internal node is the rightmost real participant
    /// in the pair that arrives from the right - matching the tree_gossip in
    /// `network.rs`: left sends to right, right aggregates.
    fn build_z_tree_plan(n: usize) -> Vec<Vec<ZTreePlanNode>> {
        let mut current: Vec<ZTreePlanNode> = (0..n)
            .map(|i| ZTreePlanNode {
                real: vec![i],
                aggregator: Some(i),
            })
            .collect();
        let mut levels = vec![current.clone()];
        while current.len() > 1 {
            let mut next = vec![];
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    let left = &current[i];
                    let right = &current[i + 1];
                    let real: Vec<usize> =
                        left.real.iter().chain(right.real.iter()).copied().collect();
                    // Right subtree's aggregator is the aggregator of the merged node.
                    let aggregator = right.aggregator;
                    next.push(ZTreePlanNode { real, aggregator });
                    i += 2;
                } else {
                    // Odd node carries up unchanged.
                    next.push(current[i].clone());
                    i += 1;
                }
            }
            levels.push(next.clone());
            current = next;
        }
        levels
    }

    // ---- z-aggregation tree (one advance per level) --------------------------

    /// Called from Distribution: verify all PVSS shares (leaf level 0), build
    /// Qagg, store the aggregated transcript, set up the tree plan.
    fn do_z_tree_init(&mut self) -> Result<(), String> {
        let rng = &mut thread_rng();
        let n = self.n;

        // Build the static tree plan.
        self.z_tree_plan = Self::build_z_tree_plan(n);

        // Level 0: verify every dealer's PVSS z-share individually.
        let mut agg = self.build_node(0).aggregator;
        self.log
            .push("z-Aggregation [level 0 - leaf verification]:".to_string());
        for i in 0..n {
            let share = self.contributions[&i].dkg_share.clone();
            let ok = agg.receive_share(rng, &share).is_ok();
            self.z_leaf_results.insert(i, ok);
            if ok {
                self.log
                    .push(format!("  P{} z-share verified ✓ (added to transcript)", i));
            } else {
                self.log
                    .push(format!("  P{} z-share REJECTED ✗ → added to Qagg", i));
            }
        }
        self.qagg = agg.qagg.clone();
        self.z_agg_transcript = Some(agg.transcript.clone());

        if self.qagg.is_empty() {
            self.log
                .push("  All shares accepted - Qagg = ∅.".to_string());
        } else {
            self.log.push(format!(
                "  Qagg = {{{}}}.",
                self.qagg
                    .iter()
                    .map(|id| format!("P{}", id))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        self.z_levels_done = 1;
        self.phase = Phase::ZAggregation;
        Ok(())
    }

    /// Called for each advance during ZAggregation: process the next tree level
    /// (purely visual - the actual transcript was already computed in
    /// `do_z_tree_init`), or transition to Pedersen verification when all levels
    /// are done.
    fn do_z_tree_advance(&mut self) -> Result<(), String> {
        let total = self.z_tree_plan.len();
        if self.z_levels_done < total {
            let level = self.z_levels_done;
            let nodes = &self.z_tree_plan[level];
            let is_root = nodes.len() == 1;
            if is_root {
                self.log.push(format!(
                    "z-Aggregation [level {} - root]: all remaining transcripts folded into one.",
                    level
                ));
            } else {
                self.log.push(format!(
                    "z-Aggregation [level {} - {} groups aggregate pairwise]:",
                    level,
                    nodes.len()
                ));
            }
            for (pos, node) in nodes.iter().enumerate() {
                let parts: Vec<String> = node.real.iter().map(|id| format!("P{}", id)).collect();
                let agg_str = node
                    .aggregator
                    .map_or("-".to_string(), |a| format!("P{}", a));
                let any_qagg = node.real.iter().any(|id| self.qagg.contains(id));
                self.log.push(format!(
                    "  group {}: [{}] → aggregator: {}{}",
                    pos,
                    parts.join("+"),
                    agg_str,
                    if any_qagg {
                        " (contains Qagg member)"
                    } else {
                        ""
                    }
                ));
            }
            self.z_levels_done += 1;
            Ok(())
        } else if !self.z_transcript_broadcast {
            // All tree levels folded - the root broadcasts the candidate
            // transcript and every participant verifies & approves it.
            self.do_z_transcript_broadcast()
        } else {
            // z-layer fully done - run the Pedersen verification layer.
            self.log
                .push("z-Aggregation complete. Moving to Pedersen share verification.".to_string());
            self.do_pedersen_verification()
        }
    }

    /// The final z-layer sub-step: the root aggregator (which now holds the
    /// single folded candidate transcript) broadcasts it to all participants;
    /// each one verifies it (`receive_transcript`: batch signature + PoK + PVSS
    /// checks) and, on approval, decrypts its own `z`-secret share
    /// (`receive_transcript_and_decrypt`). This is the publicly-verifiable
    /// approval the aggregatable `z` layer buys (no per-dealer complaint round).
    fn do_z_transcript_broadcast(&mut self) -> Result<(), String> {
        let rng = &mut thread_rng();
        let n = self.n;
        let root = self.z_root();

        let transcript = match &self.z_agg_transcript {
            Some(t) if !t.contributions.is_empty() => t.clone(),
            _ => {
                self.log.push(
                    "z-Transcript broadcast: no valid transcript to broadcast (all dealers in Qagg)."
                        .to_string(),
                );
                self.z_transcript_broadcast = true;
                return Ok(());
            }
        };

        match root {
            Some(r) => self.log.push(format!(
                "z-Transcript broadcast: root P{} broadcasts the candidate transcript to all {} participants for approval.",
                r, n
            )),
            None => self
                .log
                .push("z-Transcript broadcast: broadcasting candidate transcript.".to_string()),
        }

        for i in 0..n {
            let mut node = self.build_node(i);
            let approved = node
                .receive_transcript_and_decrypt(rng, transcript.clone())
                .is_ok();
            self.parties[i].z_transcript_approved = Some(approved);
            if approved {
                self.parties[i].accumulated_z = Some(node.dealer.accumulated_secret);
                self.log
                    .push(format!("  P{} verified & approved the transcript ✓", i));
            } else {
                self.log.push(format!("  P{} rejected the transcript ✗", i));
            }
        }
        self.z_transcript_broadcast = true;
        Ok(())
    }

    /// The root aggregator id (rightmost real participant), which ends up holding
    /// the final folded transcript. `None` before the tree plan is built.
    fn z_root(&self) -> Option<usize> {
        self.z_tree_plan
            .last()
            .and_then(|level| level.first())
            .and_then(|node| node.aggregator)
    }

    // ---- Distribution --------------------------------------------------------
    fn do_distribution(&mut self) -> Result<(), String> {
        let rng = &mut thread_rng();
        let n = self.n;
        for i in 0..n {
            // Reproduce dmkg::deal inline so we can capture z_i and the secrets and
            // apply malicious tampering (the UI needs the private values).
            let mut node = self.build_node(i);
            let (pvss_share, pvss_secrets) = node.share_pvss(rng).map_err(|e| e.to_string())?;
            let z_i = pvss_secrets.f_0;
            let c_i = self.config.srs.g_g1.mul(z_i.into_repr()).into_affine();
            let pok_keypair = self.scheme_pok.from_sk(&z_i).map_err(|e| e.to_string())?;
            let c_i_pok = self
                .scheme_pok
                .sign(
                    rng,
                    &pok_keypair.0,
                    &message_from_c_i::<E>(c_i).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
            let sig_keypair = self
                .scheme_sig
                .from_sk(&self.parties[i].sig_sk)
                .map_err(|e| e.to_string())?;
            let signature_on_c_i = self
                .scheme_sig
                .sign(
                    rng,
                    &sig_keypair.0,
                    &message_from_c_i::<E>(c_i).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
            let mut dkg_share = DKGShare {
                participant_id: i,
                c_i,
                pvss_share,
                c_i_pok,
                signature_on_c_i,
            };

            let (mut distribution, secrets) =
                PedersenDistribution::deal(&self.generators, self.degree, n, rng)
                    .map_err(|e| e.to_string())?;

            // Apply the chosen misbehaviour. The two layers are corrupted
            // independently so the UI can isolate the two disqualification paths.
            let malice = self.parties[i].malice;
            let victim = (i + 1) % n;
            if malice.corrupt_z() {
                // Break the z commitment so the dealer is caught by the public z
                // layer (lands in Qagg), before z is aggregated.
                dkg_share.c_i = G1Projective::rand(rng).into_affine();
            }
            if malice.corrupt_pedersen() {
                // Deal an inconsistent Pedersen share to one victim: corrupt the
                // cleartext share itself (not just its ciphertext) so the victim's
                // Eq.(1) check fails AND the disputation later finds the opening
                // inconsistent. Honest in z ⇒ caught only by the complaint phase.
                distribution.shares[victim].sf += Fr::rand(rng);
            }

            // Encrypt the (possibly corrupted) shares to each receiver.
            let encrypted_shares = (0..n)
                .map(|j| {
                    EncryptedPedersenShare::encrypt(
                        &self.generators,
                        &self.base,
                        &self.receiver_pks[j],
                        &distribution.shares[j],
                        rng,
                    )
                })
                .collect::<Vec<_>>();

            let c1_i = (self.generators.g1.mul(secrets.x1.into_repr())
                + self.generators.g2.mul(secrets.x2.into_repr()))
            .into_affine();
            let c2_i = (self.generators.g1.mul(secrets.y1.into_repr())
                + self.generators.g2.mul(secrets.y2.into_repr()))
            .into_affine();
            let c3_i = self.generators.g1.mul(z_i.into_repr()).into_affine();

            // Record this dealer's private secrets for the inspector.
            self.parties[i].z_i = Some(z_i);
            self.parties[i].x1 = Some(secrets.x1);
            self.parties[i].x2 = Some(secrets.x2);
            self.parties[i].y1 = Some(secrets.y1);
            self.parties[i].y2 = Some(secrets.y2);

            match (malice.corrupt_z(), malice.corrupt_pedersen()) {
                (true, true) => self.log.push(format!(
                    "Distribution: dealer {} (malicious) tampered its z commitment \
                     (→ Qagg) AND its Pedersen share to receiver {} (→ complaint).",
                    i,
                    victim + 1
                )),
                (true, false) => self.log.push(format!(
                    "Distribution: dealer {} (malicious) tampered its z commitment \
                     (→ Qagg); its Pedersen shares are honest.",
                    i
                )),
                (false, true) => self.log.push(format!(
                    "Distribution: dealer {} (malicious) dealt an inconsistent Pedersen \
                     share to receiver {} (→ complaint); its z share is honest.",
                    i,
                    victim + 1
                )),
                (false, false) => self.log.push(format!(
                    "Distribution: dealer {} dealt {} commitments and {} encrypted shares.",
                    i,
                    distribution.commitments.len(),
                    n
                )),
            }

            let contribution = DMKGContribution {
                dealer_id: i,
                dkg_share,
                commitments: distribution.commitments.clone(),
                encrypted_shares,
                c1_i,
                c2_i,
                c3_i,
            };
            self.contributions.insert(i, contribution);
            self.distributions.insert(i, distribution);
        }
        self.phase = Phase::Distribution;
        Ok(())
    }

    // ---- Pedersen verification (after z-aggregation is done) -----------------
    fn do_pedersen_verification(&mut self) -> Result<(), String> {
        let n = self.n;

        // Pedersen layer: every receiver decrypts each dealer's share and checks
        // Eq. (1); a failure becomes a complaint.
        self.log.push("Verification (Pedersen layer):".to_string());
        let mut complaints = vec![];
        for dealer_id in 0..n {
            for j in 0..n {
                let recovered = self.contributions[&dealer_id].encrypted_shares[j]
                    .decrypt(self.parties[j].elgamal.sk);
                let ok = recovered
                    .verify(&self.contributions[&dealer_id].commitments, j + 1)
                    .is_ok();
                self.parties[j].received[dealer_id] = Some(recovered);
                self.parties[j].received_ok[dealer_id] = Some(ok);
                if !ok {
                    complaints.push(Complaint {
                        dealer: dealer_id,
                        complainer: j + 1,
                    });
                    self.log.push(format!(
                        "  P{} could not verify P{}'s Pedersen share → complaint filed.",
                        j + 1,
                        dealer_id
                    ));
                }
            }
        }
        if complaints.is_empty() {
            self.log
                .push("  All Pedersen shares verified - no complaints.".to_string());
        }
        self.complaints = complaints;
        self.phase = Phase::Verification;
        Ok(())
    }

    // ---- Complaint resolution ------------------------------------------------
    fn do_complaints(&mut self) -> Result<(), String> {
        let rng = &mut thread_rng();
        let n = self.n;
        let all_dealers: BTreeSet<usize> = (0..n).collect();
        let mut commitments = BTreeMap::new();
        let mut openings = BTreeMap::new();
        for id in 0..n {
            commitments.insert(id, self.contributions[&id].commitments.clone());
            openings.insert(id, self.distributions[&id].shares.clone());
        }
        let neutral_count = n.saturating_sub(2).max(1);
        let outcome = run_complaint_phase(
            &self.generators,
            self.degree,
            &all_dealers,
            &self.qagg,
            &commitments,
            &openings,
            &self.complaints,
            neutral_count,
            rng,
        )
        .map_err(|e| e.to_string())?;

        let mut qual = outcome.qual;
        let mut disqualified = outcome.disqualified;
        // Qagg members are disqualified from the common key even absent a complaint.
        for &m in self.qagg.iter() {
            qual.remove(&m);
            disqualified
                .entry(m)
                .or_insert(DisqualificationReason::InQagg);
        }
        for (id, reason) in disqualified.iter() {
            self.log.push(format!(
                "Complaints: dealer {} disqualified ({:?}).",
                id, reason
            ));
        }
        self.log.push(format!(
            "Complaints: QUAL = {:?}.",
            qual.iter().collect::<Vec<_>>()
        ));
        self.qual = qual;
        self.disqualified = disqualified;
        self.phase = Phase::Complaints;
        Ok(())
    }

    // ---- Key generation + reconstruction -------------------------------------
    fn do_key_generation(&mut self) -> Result<(), String> {
        if self.qual.is_empty() {
            self.log
                .push("KeyGeneration: QUAL is empty - no key can be formed.".to_string());
            self.phase = Phase::KeyGeneration;
            return Ok(());
        }
        let pk = aggregate_public_key(&self.contributions, &self.qual);
        self.log
            .push("KeyGeneration: aggregated pk = (c1,c2,c3) over QUAL.".to_string());

        // Reconstruct (c1,c2) from t+1 receivers' aggregated group-element shares.
        if self.degree < self.n {
            let mut receiver_msgs = vec![];
            for j in 0..self.n {
                let mut mf = G1Projective::zero();
                let mut mg = G1Projective::zero();
                for id in self.qual.iter() {
                    if let Some(rec) = &self.parties[j].received[*id] {
                        mf += rec.m_sf.into_projective();
                        mg += rec.m_sg.into_projective();
                    }
                }
                receiver_msgs.push((j + 1, mf.into_affine(), mg.into_affine()));
            }
            let subset = &receiver_msgs[..self.degree + 1];
            match reconstruct_pk_components::<E>(subset) {
                Ok((c1, c2)) => {
                    let ok = c1 == pk.c1 && c2 == pk.c2;
                    self.reconstructed_ok = Some(ok);
                    self.log.push(format!(
                        "KeyGeneration: reconstructed (c1,c2) from t+1={} receivers - match: {}.",
                        self.degree + 1,
                        ok
                    ));
                }
                Err(e) => self
                    .log
                    .push(format!("KeyGeneration: reconstruction failed: {}.", e)),
            }
        }
        self.pk = Some(pk);
        self.phase = Phase::KeyGeneration;
        Ok(())
    }

    // ---- Snapshot ------------------------------------------------------------

    /// A full snapshot of the current state for the UI.
    pub fn snapshot(&self) -> Snapshot {
        let participants = (0..self.n).map(|i| self.participant_view(i)).collect();
        let public_key = self.pk.as_ref().map(|pk| PublicKeyView {
            c1: hexs(&pk.c1),
            c2: hexs(&pk.c2),
            c3: hexs(&pk.c3),
            reconstructed_ok: self.reconstructed_ok,
        });

        // Describe what the next advance will do.
        let next_phase = match self.phase {
            Phase::Done => None,
            Phase::ZAggregation if self.z_levels_done < self.z_tree_plan.len() => {
                let next_level = self.z_levels_done;
                let total = self.z_tree_plan.len();
                if next_level + 1 == total {
                    Some(format!(
                        "z-Aggregation (root, level {}/{})",
                        next_level,
                        total - 1
                    ))
                } else {
                    Some(format!(
                        "z-Aggregation (level {}/{})",
                        next_level,
                        total - 1
                    ))
                }
            }
            Phase::ZAggregation if !self.z_transcript_broadcast => {
                Some("z-Transcript broadcast & approval".to_string())
            }
            Phase::ZAggregation => Some("Verification".to_string()),
            _ => Some(self.phase.next().name().to_string()),
        };

        let z_tree = self.build_z_tree_snapshot();
        let z_total_levels = self.z_tree_plan.len();
        let z_approvals: Vec<(usize, bool)> = (0..self.n)
            .filter_map(|i| self.parties[i].z_transcript_approved.map(|a| (i, a)))
            .collect();

        Snapshot {
            phase: self.phase.name().to_string(),
            phase_index: self.phase.index(),
            can_advance: self.phase != Phase::Done,
            next_phase,
            n: self.n,
            degree: self.degree,
            reconstruction_threshold: self.degree + 1,
            malicious: self.malice.keys().copied().collect(),
            malice: self
                .malice
                .iter()
                .map(|(id, m)| (*id, m.tag().to_string()))
                .collect(),
            qagg: self.qagg.iter().copied().collect(),
            qual: self.qual.iter().copied().collect(),
            complaints: self
                .complaints
                .iter()
                .map(|c| (c.dealer, c.complainer))
                .collect(),
            public_key,
            participants,
            log: self.log.clone(),
            z_tree,
            z_total_levels,
            z_levels_done: self.z_levels_done,
            z_root: self.z_root(),
            z_transcript_broadcast: self.z_transcript_broadcast,
            z_approvals,
            common: CommonReferenceView {
                g_g1: hexs(&self.config.srs.g_g1),
                h_g2: hexs(&self.config.srs.h_g2),
                u_1: hexs(&self.config.u_1),
                ped_g1: hexs(&self.generators.g1),
                ped_g2: hexs(&self.generators.g2),
                ped_h1: hexs(&self.generators.h1),
                ped_h2: hexs(&self.generators.h2),
                elgamal_base: hexs(&self.base.g),
                domain_size: self.domain_size,
            },
        }
    }

    /// Build the z-tree level views for the Snapshot.
    fn build_z_tree_snapshot(&self) -> Vec<ZTreeLevelView> {
        if self.z_tree_plan.is_empty() {
            return vec![];
        }
        let total = self.z_tree_plan.len();
        self.z_tree_plan
            .iter()
            .enumerate()
            .map(|(level_idx, nodes)| {
                let is_leaf = level_idx == 0;
                let is_root = level_idx + 1 == total;
                let description = if is_leaf {
                    "Individual z-share verification - each dealer's PVSS share is checked"
                        .to_string()
                } else if is_root {
                    format!(
                        "Root - {} transcript(s) folded into the final aggregated transcript",
                        nodes.len()
                    )
                } else {
                    format!(
                        "{} groups aggregate pairwise (⌈log₂ n⌉ round {})",
                        nodes.len(),
                        level_idx
                    )
                };

                let node_views: Vec<ZTreeNodeView> = nodes
                    .iter()
                    .enumerate()
                    .map(|(pos, node)| {
                        let leaf_ok = if is_leaf && level_idx < self.z_levels_done {
                            // Leaf: exactly one participant per node.
                            node.real
                                .first()
                                .and_then(|id| self.z_leaf_results.get(id).copied())
                        } else {
                            None
                        };
                        ZTreeNodeView {
                            real_participants: node.real.clone(),
                            aggregator: node.aggregator,
                            leaf_ok,
                            position: pos,
                        }
                    })
                    .collect();

                ZTreeLevelView {
                    level: level_idx,
                    is_leaf_level: is_leaf,
                    is_root_level: is_root,
                    description,
                    nodes: node_views,
                }
            })
            .collect()
    }

    fn participant_view(&self, i: usize) -> ParticipantView {
        let p = &self.parties[i];
        let mut public = vec![
            Field {
                label: "Participant ID".into(),
                value: i.to_string(),
            },
            Field {
                label: "Signature public key (G2)".into(),
                value: hexs(&p.sig_pk),
            },
            Field {
                label: "ElGamal public key (G1)".into(),
                value: hexs(&p.elgamal.pk),
            },
        ];
        let mut private = vec![
            Field {
                label: "Signature secret key (Fr)".into(),
                value: hexs(&p.sig_sk),
            },
            Field {
                label: "ElGamal secret key (Fr)".into(),
                value: hexs(&p.elgamal.sk),
            },
        ];

        // After z-aggregation: z-share verification status (public - on the transcript).
        if let Some(&z_ok) = self.z_leaf_results.get(&i) {
            public.push(Field {
                label: "z-share verification".into(),
                value: if z_ok {
                    "✓ accepted (in transcript)".into()
                } else {
                    "✗ rejected → Qagg".into()
                },
            });
        }

        // After the transcript broadcast: this participant's public approval vote.
        if let Some(approved) = p.z_transcript_approved {
            public.push(Field {
                label: "z-transcript approval (broadcast)".into(),
                value: if approved {
                    "✓ approved final transcript".into()
                } else {
                    "✗ rejected final transcript".into()
                },
            });
        }

        // After Distribution: public commitments + pk contributions; private secrets.
        if let Some(contribution) = self.contributions.get(&i) {
            public.push(Field {
                label: "z commitment c_i (G1)".into(),
                value: hexs(&contribution.dkg_share.c_i),
            });
            public.push(Field {
                label: format!("Pedersen commitments CM_0..CM_{}", self.degree),
                value: format!(
                    "{} commitments, CM_0 = {}",
                    contribution.commitments.len(),
                    hexs(&contribution.commitments[0])
                ),
            });
            public.push(Field {
                label: "pk contribution c1_i (G1)".into(),
                value: hexs(&contribution.c1_i),
            });
            public.push(Field {
                label: "pk contribution c2_i (G1)".into(),
                value: hexs(&contribution.c2_i),
            });
            public.push(Field {
                label: "pk contribution c3_i = g1^{z_i} (G1)".into(),
                value: hexs(&contribution.c3_i),
            });
            public.push(Field {
                label: "Encrypted shares dealt".into(),
                value: format!(
                    "{} ciphertexts (one per receiver)",
                    contribution.encrypted_shares.len()
                ),
            });
        }
        if let Some(z) = p.z_i {
            private.push(Field {
                label: "secret z_i (Fr)".into(),
                value: hexs(&z),
            });
        }
        for (label, v) in [
            ("secret x1 (Fr)", p.x1),
            ("secret x2 (Fr)", p.x2),
            ("secret y1 (Fr)", p.y1),
            ("secret y2 (Fr)", p.y2),
        ] {
            if let Some(v) = v {
                private.push(Field {
                    label: label.into(),
                    value: hexs(&v),
                });
            }
        }

        // After Verification: private decrypted shares + accumulated z secret.
        let received: Vec<String> = (0..self.n)
            .filter_map(|d| {
                p.received_ok[d].map(|ok| {
                    format!(
                        "from dealer {}: {}",
                        d,
                        if ok { "verified" } else { "FAILED (complaint)" }
                    )
                })
            })
            .collect();
        if !received.is_empty() {
            private.push(Field {
                label: "Decrypted Pedersen shares (group elements)".into(),
                value: received.join("; "),
            });
        }
        if let Some(acc) = p.accumulated_z {
            private.push(Field {
                label: "Accumulated z-secret share (G2)".into(),
                value: hexs(&acc),
            });
        }

        let complaints_against = self.complaints.iter().filter(|c| c.dealer == i).count();
        ParticipantView {
            id: i,
            malicious: p.malice.is_malicious(),
            malice: p.malice.tag().to_string(),
            malice_label: p.malice.label().to_string(),
            in_qagg: self.qagg.contains(&i),
            complaints_against,
            in_qual: self.qual.contains(&i),
            disqualified_reason: self.disqualified.get(&i).map(|r| format!("{:?}", r)),
            public,
            private,
            communication: self.communication_view(i),
        }
    }

    /// Build the per-participant communication summary (messages on each channel).
    /// All of this is observable - both layers use public channels.
    fn communication_view(&self, i: usize) -> Vec<Field> {
        let n = self.n;
        let mut comm = vec![];

        // Pedersen + z dealing - populated once Distribution has run.
        if let Some(contribution) = self.contributions.get(&i) {
            // z layer: the dealer first broadcasts its individual PVSS share.
            let z_msg_bytes = ser_size(&contribution.dkg_share);
            comm.push(Field {
                label: "z-layer · PVSS share sent".into(),
                value: format!("1 broadcast ({})", human_bytes(z_msg_bytes)),
            });
            // Pedersen layer: all-to-all - one encrypted share to every receiver.
            let one_share_bytes = contribution
                .encrypted_shares
                .first()
                .map(ser_size)
                .unwrap_or(0);
            comm.push(Field {
                label: "Pedersen · encrypted shares dealt".into(),
                value: format!(
                    "{} sent → every receiver ({} total)",
                    n,
                    human_bytes(one_share_bytes * n)
                ),
            });
            comm.push(Field {
                label: "Pedersen · encrypted shares received".into(),
                value: format!("{} received ← every dealer", n),
            });
        }

        // z-tree gossip - count messages on completed tree transitions.
        let (tree_sent, tree_recv) = self.z_tree_counts_for(i);
        if tree_sent > 0 || tree_recv > 0 {
            comm.push(Field {
                label: "z-tree · gossip (aggregation)".into(),
                value: format!(
                    "{} partial transcript(s) sent up, {} received",
                    tree_sent, tree_recv
                ),
            });
        }

        // Final transcript broadcast.
        if self.z_transcript_broadcast {
            if self.z_root() == Some(i) {
                comm.push(Field {
                    label: "z-tree · final transcript".into(),
                    value: format!("root: broadcast to {} peers", n.saturating_sub(1)),
                });
            } else {
                comm.push(Field {
                    label: "z-tree · final transcript".into(),
                    value: self
                        .z_root()
                        .map(|r| format!("1 received ← root P{}", r))
                        .unwrap_or_else(|| "1 received ← root".into()),
                });
            }
        }

        comm
    }

    /// (sent, received) count of partial transcripts for participant `i` over the
    /// tree-gossip transitions that have completed so far. Matches the pairing in
    /// [`build_z_tree_plan`]: the left node's aggregator sends to the right's.
    fn z_tree_counts_for(&self, i: usize) -> (usize, usize) {
        let mut sent = 0;
        let mut recv = 0;
        // A transition from level k to k+1 is "done" once level k+1 has been shown,
        // i.e. for k in 0..(z_levels_done - 1).
        let done_transitions = self.z_levels_done.saturating_sub(1);
        for level in self.z_tree_plan.iter().take(done_transitions) {
            let mut idx = 0;
            while idx < level.len() {
                if idx + 1 < level.len() {
                    if level[idx].aggregator == Some(i) {
                        sent += 1;
                    }
                    if level[idx + 1].aggregator == Some(i) {
                        recv += 1;
                    }
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
        }
        (sent, recv)
    }
}

/// Serialized (canonical) byte size of a value, for communication accounting.
fn ser_size<T: CanonicalSerialize>(v: &T) -> usize {
    let mut bytes = vec![];
    if v.serialize(&mut bytes).is_err() {
        return 0;
    }
    bytes.len()
}

/// Human-readable byte count (B / KiB).
fn human_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{} B", n)
    } else {
        format!("{:.1} KiB", n as f64 / 1024.0)
    }
}

/// Hex of the canonical serialization, truncated for display.
fn hexs<T: CanonicalSerialize>(v: &T) -> String {
    let mut bytes = vec![];
    if v.serialize(&mut bytes).is_err() {
        return "<unserializable>".into();
    }
    let size = bytes.len();
    let head: String = bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect();
    let tail: String = bytes
        .iter()
        .rev()
        .take(4)
        .rev()
        .map(|b| format!("{:02x}", b))
        .collect();
    if size <= 12 {
        format!("0x{}{} ({} B)", head, tail, size)
    } else {
        format!("0x{}…{} ({} B)", head, tail, size)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_full_run_honest() {
        let mut s = DkgSession::new(4, Some(2), BTreeMap::new()).unwrap();
        while s.phase != Phase::Done {
            s.advance().unwrap();
        }
        let snap = s.snapshot();
        assert_eq!(snap.phase, "Done");
        assert_eq!(snap.qual.len(), 4);
        assert!(snap.qagg.is_empty());
        assert_eq!(
            snap.public_key.as_ref().unwrap().reconstructed_ok,
            Some(true)
        );
    }

    #[test]
    fn test_z_tree_levels() {
        // The z-tree for n=4 has 3 levels (leaf, one aggregation, root).
        let mut s = DkgSession::new(4, Some(2), BTreeMap::new()).unwrap();
        // Setup → Distribution
        s.advance().unwrap();
        assert_eq!(s.phase, Phase::Distribution);
        // Distribution → ZAggregation (level 0 done)
        s.advance().unwrap();
        assert_eq!(s.phase, Phase::ZAggregation);
        assert_eq!(s.z_levels_done, 1);
        let snap = s.snapshot();
        assert_eq!(snap.z_total_levels, 3); // leaf + 2 aggregation levels
        assert_eq!(snap.z_levels_done, 1);
        // Advance through remaining tree levels.
        s.advance().unwrap();
        assert_eq!(s.z_levels_done, 2);
        s.advance().unwrap();
        assert_eq!(s.z_levels_done, 3);
        // Next advance is the transcript broadcast & approval step (still ZAgg).
        s.advance().unwrap();
        assert_eq!(s.phase, Phase::ZAggregation);
        assert!(s.z_transcript_broadcast);
        let snap = s.snapshot();
        assert_eq!(snap.z_approvals.len(), 4);
        assert!(snap.z_approvals.iter().all(|(_, ok)| *ok));
        assert_eq!(snap.z_root, Some(3)); // rightmost real participant
                                          // Then the next advance transitions to Verification.
        s.advance().unwrap();
        assert_eq!(s.phase, Phase::Verification);
    }

    #[test]
    fn test_run_with_malicious() {
        let mut mal = BTreeMap::new();
        mal.insert(1usize, Malice::Both);
        let mut s = DkgSession::new(5, Some(2), mal).unwrap();
        while s.phase != Phase::Done {
            s.advance().unwrap();
        }
        let snap = s.snapshot();
        // The malicious dealer is reported and excluded.
        assert!(snap.qagg.contains(&1));
        assert!(!snap.qual.contains(&1));
        // Honest dealers survive and the key still reconstructs.
        for h in [0usize, 2, 3, 4] {
            assert!(snap.qual.contains(&h));
        }
        assert_eq!(
            snap.public_key.as_ref().unwrap().reconstructed_ok,
            Some(true)
        );
    }

    // A dealer malicious only in the `z` layer is caught by the public z
    // verification (lands in Qagg) - before z is aggregated - with no complaint.
    #[test]
    fn test_z_only_malice_caught_by_qagg() {
        let mut mal = BTreeMap::new();
        mal.insert(1usize, Malice::ZCommitment);
        let mut s = DkgSession::new(5, Some(2), mal).unwrap();
        while s.phase != Phase::Done {
            s.advance().unwrap();
        }
        let snap = s.snapshot();
        assert!(snap.qagg.contains(&1));
        // Honest in the Pedersen layer ⇒ nobody complains.
        assert!(snap.complaints.is_empty());
        assert!(!snap.qual.contains(&1));
        assert_eq!(
            snap.participants[1].disqualified_reason.as_deref(),
            Some("InQagg")
        );
        assert_eq!(
            snap.public_key.as_ref().unwrap().reconstructed_ok,
            Some(true)
        );
    }

    // A dealer malicious only in the Pedersen layer is honest in `z` (never in
    // Qagg), so it is caught only by the complaint/disputation phase - after Qagg
    // is resolved - and the Qagg short-circuit does not apply.
    #[test]
    fn test_pedersen_only_malice_caught_by_disputation() {
        let mut mal = BTreeMap::new();
        mal.insert(1usize, Malice::PedersenShare);
        let mut s = DkgSession::new(5, Some(2), mal).unwrap();
        while s.phase != Phase::Done {
            s.advance().unwrap();
        }
        let snap = s.snapshot();
        assert!(!snap.qagg.contains(&1));
        assert!(snap.complaints.iter().any(|(dealer, _)| *dealer == 1));
        assert!(!snap.qual.contains(&1));
        assert_eq!(
            snap.participants[1].disqualified_reason.as_deref(),
            Some("LostDisputation")
        );
        for h in [0usize, 2, 3, 4] {
            assert!(snap.qual.contains(&h));
        }
        assert_eq!(
            snap.public_key.as_ref().unwrap().reconstructed_ok,
            Some(true)
        );
    }

    #[test]
    fn test_config_validation() {
        assert!(DkgSession::new(1, None, BTreeMap::new()).is_err());
        assert!(DkgSession::new(11, None, BTreeMap::new()).is_err());
        assert!(DkgSession::new(4, Some(4), BTreeMap::new()).is_err()); // t must be < n
    }
}
