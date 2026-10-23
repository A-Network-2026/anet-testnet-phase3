use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    activation::{GenesisConfig, ANTS_PER_ANET},
    bitcoin,
    block::Block,
    db,
    dex::{
        self, DexLiquidityResult, DexPool, DexPoolAuditView, DexPoolView, DexQuoteView,
        DexRemoveLiquidityResult, DexSwapResult,
    },
    events::ChainEvent,
    session_commit::{SessionInclusionProof, SessionTree},
    token::{Anrc20Token, Anrc20TokenView},
    transaction::{canonical_json_string, verify_tpow_proof_crypto, TPoWProofSubmission, Transaction},
};

pub const SYSTEM_FEE_RESERVE_ADDRESS: &str = "__tpow_fee_reserve__";
pub const WANET_SYMBOL: &str = "WANET";
const MAX_MEMPOOL_TRANSACTIONS: usize = 10_000;

/// Synthetic, valid-format ANET address used as the sender for durable EVM
/// bridge credits. It never holds real value: it is pre-funded in memory just
/// before a credit block seals, and auto-funded on replay by
/// `reconcile_replay_sender_balances`, so every treasury→recipient credit
/// transaction reconstructs deterministically and nets the treasury to zero.
pub const BRIDGE_TREASURY_ADDRESS: &str = "ANET000000000000000000000000000000000000";

/// Memo prefix that marks a block transaction as an EVM bridge credit. Used to
/// rebuild the idempotency dedup set from durable block history on startup.
pub const BRIDGE_CREDIT_MEMO_PREFIX: &str = "bridge:evm:";

/// Memo prefix that marks a block transaction as a legacy -> secp migration
/// re-sweep: recovery of funds credited to a legacy address *after* it was
/// already migrated. Used to rebuild the bridge-funded spend exemption for the
/// destination secp wallet from durable block history on startup.
pub const MIGRATION_SWEEP_MEMO_PREFIX: &str = "migration:resweep:";

pub type SharedState = Arc<RwLock<NodeState>>;

/// Derive the active validator set from on-chain account state alone.
///
/// Bitcoin-aligned (deterministic, no governance, no off-chain registry):
///   1. Any account with `sessions >= MIN_SESSIONS_FOR_ANET` is eligible.
///   2. Sort by `sessions` DESC (more proof-of-work history → higher seat
///      priority), then by `address` ASC for a deterministic tie-break.
///   3. Take the top `MAX_VALIDATORS` (= 2,100).
///
/// This function is referentially transparent — given the same accounts
/// map it always returns the same vector — so every node arrives at the
/// same validator set without consulting any external service.
pub fn compute_validators_from_accounts(accounts: &HashMap<String, AccountState>) -> Vec<String> {
    let mut eligible: Vec<&AccountState> = accounts
        .values()
        .filter(|a| crate::activation::is_session_eligible(a.sessions))
        .collect();
    eligible.sort_by(|a, b| {
        b.sessions
            .cmp(&a.sessions)
            .then_with(|| a.address.cmp(&b.address))
    });
    eligible
        .into_iter()
        .take(crate::activation::MAX_VALIDATORS)
        .map(|a| a.address.clone())
        .collect()
}

/// Minimum number of independent *organic* validators that must exist before
/// every operator-seeded bootstrap seat is automatically retired.
///
/// An organic validator is any account with `sessions >= MIN_SESSIONS_FOR_ANET`
/// that was **not** placed there by `seed_bootstrap_validators`. Until this many
/// organic validators are eligible, bootstrap seats are used only to *backfill*
/// the active set so block production never halts. The instant organic
/// validators reach this quorum, all bootstrap seats drop out of the active set
/// — no operator action, no governance vote. This mirrors Bitcoin's earliest
/// era ending automatically as independent miners came online (the `21` is a
/// deliberate nod to Bitcoin's recurring 21 motif and a sane decentralization
/// floor).
pub const BOOTSTRAP_SUNSET_ORGANIC_QUORUM: usize = 21;

/// Compute the active validator set with automatic, Bitcoin-style bootstrap
/// sunset.
///
/// This is the bootstrap-aware superset of [`compute_validators_from_accounts`]
/// and is the function the running node uses to seat validators. It is still
/// fully deterministic and referentially transparent: given the same accounts
/// map and the same bootstrap address list, every node computes the identical
/// vector without consulting any external service.
///
/// Rules:
///   1. Organic validators (eligible accounts that are *not* bootstrap seats)
///      always take seats first, ranked by sessions DESC then address ASC.
///   2. If at least [`BOOTSTRAP_SUNSET_ORGANIC_QUORUM`] organic validators are
///      eligible, bootstrap seats are retired entirely — the set is 100%
///      organic.
///   3. Otherwise, bootstrap seats backfill the remaining capacity (also ranked
///      deterministically) only up to `MAX_VALIDATORS`, keeping the chain live
///      during the earliest phase. As organic validators join, the number of
///      backfilled bootstrap seats shrinks automatically.
pub fn compute_active_validator_set(
    accounts: &HashMap<String, AccountState>,
    bootstrap: &[String],
) -> Vec<String> {
    let bootstrap_set: HashSet<&str> = bootstrap.iter().map(|s| s.as_str()).collect();

    let mut organic: Vec<&AccountState> = accounts
        .values()
        .filter(|a| {
            crate::activation::is_session_eligible(a.sessions)
                && !bootstrap_set.contains(a.address.as_str())
        })
        .collect();
    organic.sort_by(|a, b| {
        b.sessions
            .cmp(&a.sessions)
            .then_with(|| a.address.cmp(&b.address))
    });

    // Auto-sunset: enough independent organic validators exist — retire all
    // bootstrap seats and run a fully organic set.
    if organic.len() >= BOOTSTRAP_SUNSET_ORGANIC_QUORUM {
        return organic
            .into_iter()
            .take(crate::activation::MAX_VALIDATORS)
            .map(|a| a.address.clone())
            .collect();
    }

    // Below quorum: organic first, then backfill remaining seats with bootstrap
    // so block production never halts during the bootstrap phase.
    let mut result: Vec<String> = organic
        .iter()
        .take(crate::activation::MAX_VALIDATORS)
        .map(|a| a.address.clone())
        .collect();

    if result.len() < crate::activation::MAX_VALIDATORS {
        let mut boot: Vec<&AccountState> = accounts
            .values()
            .filter(|a| {
                crate::activation::is_session_eligible(a.sessions)
                    && bootstrap_set.contains(a.address.as_str())
            })
            .collect();
        boot.sort_by(|a, b| {
            b.sessions
                .cmp(&a.sessions)
                .then_with(|| a.address.cmp(&b.address))
        });
        for a in boot {
            if result.len() >= crate::activation::MAX_VALIDATORS {
                break;
            }
            result.push(a.address.clone());
        }
    }

    result
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    pub address: String,
    pub ants_balance: u64,
    pub activated_ants: u64,
    pub total_activated_ants: u64,
    pub sessions: u64,
    pub asset_balances: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub address: String,
    pub ants_balance: u64,
    pub anet_balance: String,
    pub asset_balances: HashMap<String, u64>,
    pub sessions: u64,
    /// Block-derived count of accepted TPoW mining proofs by this wallet,
    /// independently re-verified from chain history alone (no oracle/admin).
    pub mined_proofs: u64,
    pub is_validator: bool,
    /// Lifetime mined (activated) ANTS credited to this wallet.
    pub total_activated_ants: u64,
    /// First-activation timestamp (ms) anchoring the wANET vesting schedule,
    /// derived from sealed `SessionActivation` block events.
    pub vesting_anchor_ms: Option<i64>,
    /// Basis points (0..=10000) of mined coins currently vested for wANET
    /// swap-out: 0 during the 6-month cliff, then +2500 every 3 months.
    pub swap_vested_bps: u64,
    /// ANTS in this wallet that cannot leave via bridge burn / DEX wrap /
    /// ANET-out swaps yet. P2P transfers are unaffected.
    pub swap_locked_ants: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSummary {
    pub chain_id: String,
    pub epoch_seconds: u64,
    pub total_ants: u64,
    pub total_anet: String,
    pub used_supply_history_fallback: bool,
    pub active_miners: usize,
    pub used_validator_history_fallback: bool,
    pub latest_block_height: Option<u64>,
    pub current_epoch_start: DateTime<Utc>,
    pub current_epoch_end: DateTime<Utc>,
    pub seconds_until_epoch_end: i64,
    pub mempool_depth: u64,
    pub pending_activated_supply_ants: u64,
    pub has_pending_block_work: bool,
    pub last_web2_sync_at: Option<DateTime<Utc>>,
    pub last_web2_sync_error: Option<String>,
}

/// Phase 0 (decentralization): minimal chain-tip descriptor served at
/// `/sync/head` and consumed by follower nodes. `Deserialize` is derived so a
/// follower can parse a peer's head directly into this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHead {
    pub chain_id: String,
    pub genesis_hash: String,
    pub tip_height: Option<u64>,
    pub tip_hash: String,
    pub block_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivationSyncResult {
    pub accounts_updated: usize,
    pub credited_ants: u64,
}

/// Read-only summary of the latest on-chain session-progress commitment.
#[derive(Debug, Clone, Serialize)]
pub struct SessionRootView {
    /// Latest committed Merkle root (hex), or `None` before the first commit.
    pub root: Option<String>,
    /// Number of miners committed under the root, if a tree is in memory.
    pub leaf_count: Option<usize>,
    pub as_of: Option<DateTime<Utc>>,
    /// Whether per-wallet inclusion proofs can currently be served.
    pub proofs_available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatorHeartbeatView {
    pub wallet: String,
    pub endpoint: Option<String>,
    pub client_version: Option<String>,
    pub last_seen_at: DateTime<Utc>,
    pub is_eligible: bool,
}

/// One seat in the read-only validator directory served to the explorer.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorView {
    pub rank: usize,
    pub address: String,
    pub sessions: u64,
    pub anet_balance: String,
    pub ants_balance: u64,
    pub eligible: bool,
    pub is_bootstrap: bool,
    /// Share of total eligible session weight, in basis points (0–10000).
    pub voting_power_bps: u32,
    pub online: bool,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub endpoint: Option<String>,
    pub client_version: Option<String>,
}

/// Aggregate view of the active validator set for the public explorer.
#[derive(Debug, Clone, Serialize)]
pub struct ValidatorDirectory {
    pub threshold_sessions: u64,
    pub max_validators: usize,
    pub total_eligible: usize,
    pub bootstrap_count: usize,
    pub organic_count: usize,
    pub online_count: usize,
    pub total_session_weight: u64,
    /// Number of independent organic validators required before all bootstrap
    /// seats are automatically retired.
    pub sunset_quorum: usize,
    /// True once the network is running fully organic — every operator-seeded
    /// bootstrap validator has been auto-retired from the active set.
    pub bootstrap_retired: bool,
    pub validators: Vec<ValidatorView>,
}

#[derive(Debug, Clone)]
pub struct ValidatorHeartbeatState {
    pub endpoint: Option<String>,
    pub client_version: Option<String>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMiningProof {
    /// The complete, self-verifying proof exactly as the miner submitted it.
    /// Sealed verbatim into the block's `tpow_proofs` so any third party can
    /// re-verify the work from chain history alone — no database, oracle, or
    /// admin input required.
    pub submission: TPoWProofSubmission,
    pub submitted_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct NodeState {
    pub chain_id: String,
    pub genesis_time: DateTime<Utc>,
    pub accounts: HashMap<String, AccountState>,
    persisted_accounts: HashMap<String, AccountState>,
    pub eligible_miners: Vec<String>,
    pub mempool: Vec<Transaction>,
    pub account_nonces: HashMap<String, u64>,
    pub blocks: Vec<Block>,
    pub chain_db: Arc<tokio_postgres::Client>,
    pub pending_activated_supply_ants: u64,
    pub pending_state_commit: bool,
    pub pending_block_event: Option<String>,
    pub pending_events: Vec<ChainEvent>,
    pub dex_pools: HashMap<String, DexPool>,
    pub token_registry: HashMap<String, Anrc20Token>,
    pub genesis_path: PathBuf,
    pub epoch_seconds: u64,
    pub last_web2_sync_at: Option<DateTime<Utc>>,
    pub last_web2_sync_error: Option<String>,
    pub validator_heartbeats: HashMap<String, ValidatorHeartbeatState>,
    /// Operator-seeded bootstrap (Satoshi-mode) validator addresses. Tracked
    /// only so the read-only explorer can label seats as bootstrap vs organic.
    /// Has no effect on consensus or validator selection (which is derived
    /// purely from on-chain session counts).
    pub bootstrap_validators: Vec<String>,
    pub pending_mining_proofs: Vec<PendingMiningProof>,
    /// In-memory dedup set for EVM bridge credits — prevents double-crediting the
    /// same BSC tx hash within a server session. Populated in post_admin_bridge_evm_credit.
    /// NOTE: cleared on restart; the pi-backend `processed` flag provides the primary
    /// persistence-layer guard across restarts.
    pub processed_evm_bridge_hashes: HashSet<String>,
    /// In-memory dedup set for EVM wallet activity events (send/swap) — prevents
    /// duplicate block events for the same BSC tx hash within a server session.
    pub processed_evm_activity_hashes: HashSet<String>,
    /// In-memory dedup set for protocol/whitepaper update attestations — prevents
    /// duplicate block events for the same document hash within a server session.
    /// See `/admin/protocol/update` — sealing a version's document hash into a
    /// block makes "whitepaper vX.Y was published with hash Z at block N" an
    /// independently verifiable historical fact, not just a claim on a website.
    pub processed_protocol_update_hashes: HashSet<String>,
    /// Addresses that have received at least one EVM bridge credit. These
    /// holders paid real value (USDC/BNB) for their ANET, so — unlike mined
    /// ANTS — their balance is NOT subject to the `MIN_SESSIONS_FOR_ANET`
    /// activation gate that guards spending/transfer/DEX. Rebuilt durably on
    /// startup from block memos (`bridge:evm:<hash>`) via
    /// `collect_bridge_funded_accounts`, so the exemption survives restarts.
    pub bridge_funded_accounts: HashSet<String>,
    /// Block-derived ledger of accepted TPoW mining proofs per miner. Rebuilt
    /// purely from block history (`collect_mining_accrual_from_blocks`) on
    /// startup and incremented as each new block is sealed. Every counted proof
    /// is independently re-verified from the sealed block bytes alone (no
    /// database, oracle, or admin), so this is the chain's own trustless record
    /// of mining work — the foundation for deriving issuance from on-chain
    /// history rather than a trusted Web2 feed.
    pub mined_proof_counts: HashMap<String, u64>,
    /// Per-wallet vesting anchor for mined coins: the millisecond timestamp of
    /// the wallet's FIRST sealed `SessionActivation` credit event. Drives the
    /// wANET swap-out vesting schedule (6-month cliff, then 25% per 3 months —
    /// see `activation::vested_fraction_bps`). Rebuilt purely from block
    /// history on startup (`collect_activation_anchors`), so the schedule is
    /// an immutable function of the chain's own records.
    pub activation_anchors: HashMap<String, i64>,
    /// Latest in-memory session-progress commitment (a Merkle tree over EVERY
    /// miner's completed-session count, including sub-threshold miners). The
    /// root is sealed on-chain as a `SessionProgressRoot` event each time it
    /// changes; this tree serves per-wallet inclusion proofs. Rebuilt on the
    /// next Web2 sync after a restart (the on-chain roots persist regardless).
    pub session_commitment: Option<SessionTree>,
    /// The most recently committed session-progress root (hex). Used to avoid
    /// re-sealing an identical root every sync. Restored from block history on
    /// startup so a restart does not emit a duplicate commitment.
    pub last_session_root: Option<String>,
    /// When the in-memory `session_commitment` was last built.
    pub session_committed_at: Option<DateTime<Utc>>,
    /// Legacy -> secp map for completed (revealed) wallet migrations. Lets the
    /// node forward any later credit (e.g. a bridge credit) addressed to an
    /// already-migrated legacy address to its signable secp wallet, so funds
    /// can never strand again on an address that cannot sign. Loaded from the
    /// `wallet_migrations` table on startup and updated as migrations complete.
    pub migrated_secp: HashMap<String, String>,
}

impl NodeState {
    pub async fn from_genesis(
        genesis: GenesisConfig,
        genesis_path: PathBuf,
        _chain_path: PathBuf,
        epoch_seconds: u64,
    ) -> Result<Self> {
        let mut accounts = HashMap::new();
        for account in genesis.accounts {
            let total_activated_ants = account.total_activated_ants.max(account.ants_balance);
            accounts.insert(
                account.address.clone(),
                AccountState {
                    address: account.address,
                    ants_balance: account.ants_balance,
                    activated_ants: account.ants_balance,
                    total_activated_ants,
                    sessions: account.sessions,
                    asset_balances: HashMap::new(),
                },
            );
        }

        let chain_db = db::connect().await?;
        db::ensure_chain_initialized(chain_db.as_ref(), &genesis.chain_id, genesis.genesis_time)
            .await?;
        let blocks = db::load_chain_blocks(chain_db.as_ref()).await?;
        validate_block_sequence(&blocks)?;
        replay_blocks(&mut accounts, &blocks)?;
        // Replay can restore newer session snapshots, so validator selection
        // must run after replay rather than against the genesis-only accounts.
        let eligible_miners = compute_validators_from_accounts(&accounts);
        let persisted_accounts = accounts.clone();
        let account_nonces = rebuild_account_nonces(&blocks)?;
        let dex_pools = rebuild_dex_pools_from_blocks(&blocks);
        let token_registry = rebuild_token_registry_from_blocks(&blocks);
        // Reconstruct the EVM bridge dedup set from durable block history so a
        // restart cannot allow the same BSC tx hash to be credited twice.
        let processed_evm_bridge_hashes = collect_processed_bridge_hashes(&blocks);
        // Reconstruct the set of bridge-funded recipients so the
        // session-gate exemption for real (paid-for) ANET survives restarts.
        let bridge_funded_accounts = collect_bridge_funded_accounts(&blocks);
        // Rebuild the trustless, block-derived TPoW mining ledger by
        // re-verifying every proof sealed in block history. No DB/oracle input.
        let mined_proof_counts = collect_mining_accrual_from_blocks(&blocks, &genesis.chain_id);
        // Rebuild each wallet's first-activation vesting anchor from the
        // sealed SessionActivation events, so the wANET vesting schedule is
        // derived from immutable chain history alone.
        let activation_anchors = collect_activation_anchors(&blocks);
        // Restore the last sealed session-progress root so a restart does not
        // re-emit an identical commitment before the next sync rebuilds the
        // in-memory tree.
        let last_session_root = collect_last_session_root(&blocks);

        // Load the completed (revealed) migration map so credits to an
        // already-migrated legacy address are forwarded to its signable secp
        // wallet. Degrade gracefully if the lookup fails — forwarding simply
        // stays inactive until the next restart rather than blocking startup.
        let migrated_secp = match db::list_revealed_wallet_migrations(chain_db.as_ref()).await {
            Ok(rows) => rows
                .into_iter()
                .map(|row| {
                    (
                        row.legacy_address.trim().to_uppercase(),
                        row.secp_address.trim().to_uppercase(),
                    )
                })
                .filter(|(legacy, secp)| legacy != secp)
                .collect(),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "failed to load wallet migration map; bridge credit forwarding inactive until restart"
                );
                HashMap::new()
            }
        };

        Ok(Self {
            chain_id: genesis.chain_id,
            genesis_time: genesis.genesis_time,
            accounts,
            persisted_accounts,
            eligible_miners,
            mempool: Vec::new(),
            account_nonces,
            blocks,
            chain_db,
            pending_activated_supply_ants: 0,
            pending_state_commit: false,
            pending_block_event: None,
            pending_events: Vec::new(),
            dex_pools,
            token_registry,
            genesis_path,
            epoch_seconds,
            last_web2_sync_at: None,
            last_web2_sync_error: None,
            validator_heartbeats: HashMap::new(),
            bootstrap_validators: Vec::new(),
            pending_mining_proofs: Vec::new(),
            processed_evm_bridge_hashes,
            processed_evm_activity_hashes: HashSet::new(),
            processed_protocol_update_hashes: HashSet::new(),
            bridge_funded_accounts,
            mined_proof_counts,
            activation_anchors,
            session_commitment: None,
            last_session_root,
            session_committed_at: None,
            migrated_secp,
        })
    }

    pub fn mark_web2_sync_success(&mut self) {
        self.last_web2_sync_at = Some(Utc::now());
        self.last_web2_sync_error = None;
    }

    pub fn mark_web2_sync_failure(&mut self, error: impl Into<String>) {
        self.last_web2_sync_error = Some(error.into());
    }

    /// Accept an externally-supplied validator candidate list (currently
    /// from the pi-backend sync). The list itself is treated as advisory:
    /// it is used only to materialize stub accounts for addresses the L1
    /// has not seen yet, so that on-chain session counts can later be
    /// applied to them. The authoritative validator set is then re-derived
    /// from on-chain account state via `compute_validators_from_accounts`.
    ///
    /// This makes the validator set Bitcoin-style autonomous: pi-backend
    /// cannot promote, demote, or override which accounts are validating.
    /// Only on-chain sessions (≥ `MIN_SESSIONS_FOR_ANET`) decide.
    pub fn replace_validators(&mut self, validators: Vec<String>) {
        let mut validators = validators;
        validators.sort();
        validators.dedup();
        for validator in &validators {
            self.accounts
                .entry(validator.clone())
                .or_insert(AccountState {
                    address: validator.clone(),
                    ants_balance: 0,
                    activated_ants: 0,
                    total_activated_ants: 0,
                    sessions: 0,
                    asset_balances: HashMap::new(),
                });
        }
        // On-chain truth wins. The `validators` argument is informational.
        self.eligible_miners =
            compute_active_validator_set(&self.accounts, &self.bootstrap_validators);
    }

    /// Apply a *verified* signed session-oracle snapshot.
    ///
    /// This is the consistent, auditable replacement for trusting raw
    /// PostgreSQL session counts: the caller MUST have already verified the
    /// snapshot signature against the configured oracle address
    /// (`oracle::verify_session_snapshot`) before calling this. Session counts
    /// are applied **monotonically** — a wallet's session count is never
    /// lowered by a snapshot — so a replayed or out-of-order snapshot can only
    /// ever be a no-op, never a demotion. After applying, the validator set is
    /// re-derived from on-chain account state by the same deterministic rule
    /// used everywhere else, so Web2 supplies the input and the chain alone
    /// decides eligibility.
    ///
    /// Returns the number of accounts whose session count increased.
    pub fn apply_session_oracle(&mut self, entries: &[(String, u64)]) -> usize {
        let mut updated = 0_usize;
        let mut session_events: Vec<ChainEvent> = Vec::new();
        for (raw_wallet, sessions) in entries {
            let wallet = raw_wallet.trim().to_uppercase();
            if !crate::transaction::is_valid_anet_wallet(&wallet) {
                continue;
            }
            let entry = self.accounts.entry(wallet.clone()).or_insert(AccountState {
                address: wallet.clone(),
                ants_balance: 0,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 0,
                asset_balances: HashMap::new(),
            });
            if *sessions > entry.sessions {
                let sessions_delta = *sessions - entry.sessions;
                entry.sessions = *sessions;
                updated += 1;
                // Record the session increase as an immutable on-chain receipt,
                // attributed to the signed oracle (the future verifiable feed).
                // Mint-neutral: the oracle path only raises session counts.
                session_events.push(session_activation_event(
                    &wallet,
                    entry.sessions,
                    sessions_delta,
                    0,
                    entry.total_activated_ants,
                    "signed_oracle",
                ));
            }
        }
        if updated > 0 {
            self.eligible_miners =
                compute_active_validator_set(&self.accounts, &self.bootstrap_validators);
            self.pending_events.append(&mut session_events);
            self.pending_block_event = Some("Oracle: Session Snapshot".to_owned());
            self.pending_state_commit = true;
        }
        updated
    }

    /// Commit a Merkle root over EVERY miner's completed-session count to the
    /// chain. This is the "both" model: the single root is sealed on-chain (so
    /// even sub-threshold miners' session progress is committed and tamper-
    /// evident, while every node stores just one hash), and the in-memory tree
    /// serves per-wallet inclusion proofs (`/sessions/proof/:wallet`).
    ///
    /// In addition to the root, this emits a **bounded** set of per-wallet
    /// `SessionMilestone` events for miners — including sub-threshold miners —
    /// whose progress crossed a meaningful boundary since the previous
    /// commitment: first appearance on-chain (`joined`) and crossing the
    /// 1,000-session spend threshold (`eligible`). These are once-per-miner
    /// lifetime events, so they make each miner's key milestones explicit
    /// on-chain without the unbounded bloat of one event per session (which the
    /// Merkle root already commits). Per-session granularity stays in the root;
    /// individual events stay milestone-only.
    ///
    /// Strictly mint-neutral and balance-neutral: it records a commitment to
    /// session data; it never credits, mints, or changes any balance. Spend
    /// eligibility is still governed solely by `MIN_SESSIONS_FOR_ANET`.
    ///
    /// Returns the new root hex when the commitment changed (and was sealed for
    /// the next block), or `None` when the root is unchanged (no-op, no block).
    pub fn commit_session_progress(
        &mut self,
        entries: Vec<(String, u64)>,
        as_of: DateTime<Utc>,
    ) -> Option<String> {
        // Defensive cap so a pathological sync (e.g. the first commit after a
        // long outage) can never seal an enormous block of milestone events.
        const MILESTONE_EVENT_CAP: usize = 5_000;

        let tree = SessionTree::build(&entries);
        let root = tree.root();
        let leaf_count = tree.leaf_count();
        let unchanged = self.last_session_root.as_deref() == Some(root.as_str());

        // Detect per-wallet milestone crossings against the PREVIOUS in-memory
        // commitment. Skipped when there is no previous tree (first sync, or
        // just after a restart) so a cold start never re-emits a `joined`
        // milestone for every existing miner — the Merkle root remains the
        // authoritative record across that gap.
        let (mut milestones, milestones_truncated) = if unchanged {
            (Vec::new(), false)
        } else {
            detect_session_milestones(
                self.session_commitment.as_ref(),
                &tree,
                MILESTONE_EVENT_CAP,
            )
        };

        // Refresh the in-memory tree so proofs reflect the latest data, even
        // when the root is unchanged. Done after the diff, which needs the
        // previous tree.
        self.session_commitment = Some(tree);
        self.session_committed_at = Some(as_of);

        if unchanged {
            return None;
        }

        let milestone_count = milestones.len() as u64;
        self.pending_events.push(
            ChainEvent::new("SessionProgressRoot")
                .attr("root", &root)
                .attr("leaf_count", leaf_count as u64)
                .attr("milestones", milestone_count)
                .attr("milestones_truncated", milestones_truncated)
                .attr("as_of", as_of.to_rfc3339()),
        );
        self.pending_events.append(&mut milestones);
        if self.pending_block_event.is_none() {
            self.pending_block_event = Some(format!(
                "Sessions: Progress Commitment ({leaf_count} miners)"
            ));
        }
        self.pending_state_commit = true;
        self.last_session_root = Some(root.clone());
        Some(root)
    }

    /// Inclusion proof that a wallet's committed session count is sealed under
    /// the latest on-chain session-progress root. `None` if no commitment has
    /// been built yet (e.g. immediately after restart, before the next sync) or
    /// the wallet has no committed sessions.
    pub fn session_inclusion_proof(&self, wallet: &str) -> Option<SessionInclusionProof> {
        self.session_commitment
            .as_ref()
            .and_then(|tree| tree.inclusion_proof(wallet))
    }

    /// Summary of the current session-progress commitment for `/sessions/root`.
    pub fn session_root_view(&self) -> SessionRootView {
        SessionRootView {
            root: self.last_session_root.clone(),
            leaf_count: self
                .session_commitment
                .as_ref()
                .map(|tree| tree.leaf_count()),
            as_of: self.session_committed_at,
            proofs_available: self.session_commitment.is_some(),
        }
    }

    /// Seed bootstrap validators (Satoshi-mode).
    ///
    /// During the first phase of the chain — before any organic account has
    /// crossed `MIN_SESSIONS_FOR_ANET` — block production would halt because
    /// the deterministic validator-selection rule would return an empty set.
    ///
    /// To mirror Bitcoin's earliest era (Satoshi mining the first ~14k blocks
    /// largely alone, with no governance vote to enable him), this method
    /// admits a small operator-controlled set of addresses into the on-chain
    /// accounts map at exactly `MIN_SESSIONS_FOR_ANET` sessions and records
    /// them as bootstrap seats. They keep the chain producing blocks during the
    /// earliest phase via the backfill rule in [`compute_active_validator_set`].
    ///
    /// Sunset is fully automatic and requires no operator action: organic
    /// validators always outrank bootstrap seats, so the number of seated
    /// bootstrap validators shrinks as the network grows, and once
    /// [`BOOTSTRAP_SUNSET_ORGANIC_QUORUM`] independent organic validators are
    /// eligible, every bootstrap seat is retired from the active set at once.
    ///
    /// This call is idempotent and never decreases an existing session count,
    /// so re-running it on every periodic Web2 sync is safe.
    pub fn seed_bootstrap_validators(&mut self, addresses: &[String]) -> usize {
        let mut seeded = 0_usize;
        for raw in addresses {
            let normalized = raw.trim().to_uppercase();
            if !crate::transaction::is_valid_anet_wallet(&normalized) {
                continue;
            }
            // Remember the seat as bootstrap so the explorer can label it.
            // This is display-only metadata; it never alters selection.
            if !self.bootstrap_validators.contains(&normalized) {
                self.bootstrap_validators.push(normalized.clone());
            }
            let entry = self
                .accounts
                .entry(normalized.clone())
                .or_insert(AccountState {
                    address: normalized.clone(),
                    ants_balance: 0,
                    activated_ants: 0,
                    total_activated_ants: 0,
                    sessions: 0,
                    asset_balances: HashMap::new(),
                });
            if entry.sessions < crate::activation::MIN_SESSIONS_FOR_ANET {
                entry.sessions = crate::activation::MIN_SESSIONS_FOR_ANET;
                seeded += 1;
            }
        }
        if seeded > 0 {
            self.eligible_miners =
                compute_active_validator_set(&self.accounts, &self.bootstrap_validators);
            self.pending_block_event = Some("Consensus: Bootstrap Validators".to_owned());
            self.pending_state_commit = true;
        }
        seeded
    }

    pub fn record_validator_heartbeat(
        &mut self,
        wallet: String,
        endpoint: Option<String>,
        client_version: Option<String>,
    ) {
        let normalized_wallet = wallet.trim().to_uppercase();
        if normalized_wallet.is_empty() {
            return;
        }

        self.validator_heartbeats.insert(
            normalized_wallet,
            ValidatorHeartbeatState {
                endpoint: endpoint
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty()),
                client_version: client_version
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty()),
                last_seen_at: Utc::now(),
            },
        );
    }

    pub fn validator_heartbeat_views(&self, max_age_seconds: i64) -> Vec<ValidatorHeartbeatView> {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_seconds.max(1));
        let mut entries = self
            .validator_heartbeats
            .iter()
            .filter(|(_, heartbeat)| heartbeat.last_seen_at >= cutoff)
            .map(|(wallet, heartbeat)| ValidatorHeartbeatView {
                wallet: wallet.clone(),
                endpoint: heartbeat.endpoint.clone(),
                client_version: heartbeat.client_version.clone(),
                last_seen_at: heartbeat.last_seen_at,
                is_eligible: self.eligible_miners.iter().any(|miner| miner == wallet),
            })
            .collect::<Vec<_>>();

        entries.sort_by(|left, right| right.last_seen_at.cmp(&left.last_seen_at));
        entries
    }

    /// Build a rich, read-only directory of the active validator set for the
    /// public explorer. Combines the deterministically-derived eligible set
    /// (sessions DESC) with live heartbeat status and a session-weight voting
    /// power share. Pure read — never mutates state or touches consensus.
    pub fn validator_directory(&self, online_window_seconds: i64) -> ValidatorDirectory {
        let cutoff = Utc::now() - chrono::Duration::seconds(online_window_seconds.max(1));
        let total_session_weight: u64 = self
            .eligible_miners
            .iter()
            .filter_map(|addr| self.accounts.get(addr))
            .fold(0_u64, |total, account| {
                total.saturating_add(account.sessions)
            });

        let mut validators = Vec::with_capacity(self.eligible_miners.len());
        let mut bootstrap_count = 0_usize;
        let mut online_count = 0_usize;

        for (idx, addr) in self.eligible_miners.iter().enumerate() {
            let account = self.accounts.get(addr);
            let sessions = account.map(|a| a.sessions).unwrap_or(0);
            let ants_balance = account.map(|a| a.ants_balance).unwrap_or(0);
            let is_bootstrap = self.bootstrap_validators.iter().any(|b| b == addr);
            if is_bootstrap {
                bootstrap_count += 1;
            }
            let heartbeat = self.validator_heartbeats.get(addr);
            let online = heartbeat.map(|h| h.last_seen_at >= cutoff).unwrap_or(false);
            if online {
                online_count += 1;
            }
            let voting_power_bps = if total_session_weight > 0 {
                ((sessions as u128 * 10_000u128) / total_session_weight as u128) as u32
            } else {
                0
            };

            validators.push(ValidatorView {
                rank: idx + 1,
                address: addr.clone(),
                sessions,
                anet_balance: format_anet_fixed(ants_balance),
                ants_balance,
                eligible: true,
                is_bootstrap,
                voting_power_bps,
                online,
                last_seen_at: heartbeat.map(|h| h.last_seen_at),
                endpoint: heartbeat.and_then(|h| h.endpoint.clone()),
                client_version: heartbeat.and_then(|h| h.client_version.clone()),
            });
        }

        let total_eligible = validators.len();
        let organic_count = total_eligible.saturating_sub(bootstrap_count);
        ValidatorDirectory {
            threshold_sessions: crate::activation::MIN_SESSIONS_FOR_ANET,
            max_validators: crate::activation::MAX_VALIDATORS,
            total_eligible,
            bootstrap_count,
            organic_count,
            online_count,
            total_session_weight,
            sunset_quorum: BOOTSTRAP_SUNSET_ORGANIC_QUORUM,
            bootstrap_retired: bootstrap_count == 0 && !self.bootstrap_validators.is_empty(),
            validators,
        }
    }

    /// Buffer a freshly-verified TPoW proof for inclusion in the next block.
    ///
    /// The caller MUST have already verified the proof (signature, difficulty
    /// floor, chain id, freshness) via `verify_tpow_proof_submission`. The
    /// complete submission is stored verbatim so it can be sealed into the
    /// block unchanged and re-verified by anyone from chain history.
    pub fn record_mining_proof(&mut self, submission: TPoWProofSubmission) -> Result<()> {
        let normalized_miner = submission.miner.trim().to_uppercase();
        if !self
            .eligible_miners
            .iter()
            .any(|wallet| wallet == &normalized_miner)
        {
            return Err(anyhow!("mining proof wallet is not an active validator"));
        }
        if self.pending_mining_proofs.len() >= 10_000 {
            return Err(anyhow!("pending mining proof queue is full"));
        }

        self.pending_mining_proofs.push(PendingMiningProof {
            submission,
            submitted_at: Utc::now(),
        });
        Ok(())
    }

    pub fn pending_proofs_for_block(&self, max_age_seconds: i64) -> Vec<serde_json::Value> {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_seconds.max(60));
        self.pending_mining_proofs
            .iter()
            .filter(|proof| proof.submitted_at >= cutoff)
            .map(|proof| {
                // Serialize the proof through its own `Serialize` impl so the
                // sealed bytes round-trip exactly back into a
                // `TPoWProofSubmission` during trustless re-verification. The
                // extra `submitted_at` field is informational and ignored on
                // re-parse.
                let mut value = serde_json::to_value(&proof.submission)
                    .unwrap_or_else(|_| serde_json::json!({}));
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "submitted_at".to_owned(),
                        serde_json::Value::String(proof.submitted_at.to_rfc3339()),
                    );
                }
                value
            })
            .collect()
    }

    pub fn sync_activated_accounts(
        &mut self,
        activated_accounts: Vec<crate::activation::GenesisAccount>,
    ) -> Result<ActivationSyncResult> {
        let mut accounts_updated = 0_usize;
        let mut credited_ants = 0_u64;
        let mut removed_ants = 0_u64;
        let mut metadata_changed = false;

        let mut active_addresses = std::collections::HashSet::new();

        // Running total of all issued ANTS, used to enforce the hard supply cap
        // on-chain as accounts are credited below. The chain validates issuance
        // independently of Web2: even a buggy or compromised Web2 feed can never
        // mint ANET past `MAX_SUPPLY_ANTS` (21,000,000 ANET).
        let mut current_supply_ants = self
            .accounts
            .values()
            .fold(0_u64, |total, account| total.saturating_add(account.ants_balance));
        let mut supply_cap_logged = false;

        // B1: immutable, mint-NEUTRAL on-chain session receipts. We record one
        // structured `SessionActivation` event per account whose sessions rise
        // or whose activation is credited, then seal them into the block
        // alongside the existing account-state changes. These events never mint
        // — the credit math below is unchanged and still bounded by the supply
        // cap; the events only make each activation an explicit, immutable,
        // independently-replayable on-chain record.
        let mut session_events: Vec<ChainEvent> = Vec::new();

        for activated in activated_accounts {
            active_addresses.insert(activated.address.clone());
            let entry = self
                .accounts
                .entry(activated.address.clone())
                .or_insert(AccountState {
                    address: activated.address.clone(),
                    ants_balance: 0,
                    activated_ants: 0,
                    total_activated_ants: 0,
                    sessions: 0,
                    asset_balances: HashMap::new(),
                });

            let mut sessions_delta = 0_u64;
            if activated.sessions > entry.sessions {
                sessions_delta = activated.sessions - entry.sessions;
                entry.sessions = activated.sessions;
                metadata_changed = true;
            }

            let mut credited_delta = 0_u64;
            if activated.ants_balance > entry.total_activated_ants {
                let requested = activated
                    .ants_balance
                    .checked_sub(entry.total_activated_ants)
                    .ok_or_else(|| anyhow!("activation delta underflowed"))?;
                // Bitcoin-style hard ceiling, enforced ON-CHAIN: total issued
                // ANTS may never exceed `MAX_SUPPLY_ANTS`. Once the cap is
                // reached the node refuses to mint further activation, no matter
                // what Web2 reports — this is the chain validating its own
                // monetary policy.
                let room =
                    crate::activation::MAX_SUPPLY_ANTS.saturating_sub(current_supply_ants);
                let delta = requested.min(room);
                if delta == 0 {
                    if !supply_cap_logged {
                        tracing::warn!(
                            max_supply_ants = crate::activation::MAX_SUPPLY_ANTS,
                            current_supply_ants,
                            address = %activated.address,
                            "ANET hard supply cap reached; refusing further activation issuance"
                        );
                        supply_cap_logged = true;
                    }
                } else {
                    entry.ants_balance = entry
                        .ants_balance
                        .checked_add(delta)
                        .ok_or_else(|| anyhow!("account activation overflowed"))?;
                    entry.activated_ants = entry
                        .activated_ants
                        .checked_add(delta)
                        .ok_or_else(|| anyhow!("account activation remainder overflowed"))?;
                    // Advance the credited high-water mark only by what was
                    // actually minted. In the normal (uncapped) case this equals
                    // `activated.ants_balance`; if the cap clamps the credit, a
                    // later sync can mint the remainder only if cap room ever
                    // reopens — never more than `MAX_SUPPLY_ANTS` in aggregate.
                    entry.total_activated_ants = entry
                        .total_activated_ants
                        .checked_add(delta)
                        .ok_or_else(|| anyhow!("account activation high-water overflowed"))?;
                    current_supply_ants = current_supply_ants.saturating_add(delta);
                    credited_ants = credited_ants
                        .checked_add(delta)
                        .ok_or_else(|| anyhow!("credited activation total overflowed"))?;
                    self.pending_activated_supply_ants = self
                        .pending_activated_supply_ants
                        .checked_add(delta)
                        .ok_or_else(|| anyhow!("pending activation total overflowed"))?;
                    accounts_updated += 1;
                    metadata_changed = true;
                    credited_delta = delta;
                }
            }

            if sessions_delta > 0 || credited_delta > 0 {
                // First credited activation seals this wallet's vesting anchor.
                let now_ms = Utc::now().timestamp_millis();
                if credited_delta > 0 {
                    self.activation_anchors
                        .entry(activated.address.clone())
                        .or_insert(now_ms);
                }
                let anchor_ms = self.activation_anchors.get(&activated.address).copied();
                let mut event = session_activation_event(
                    &activated.address,
                    entry.sessions,
                    sessions_delta,
                    credited_delta,
                    entry.total_activated_ants,
                    "web2_sync",
                );
                if let Some(anchor) = anchor_ms {
                    event = event.attr("vesting_anchor_ms", anchor);
                }
                session_events.push(event);
            }
        }

        for entry in self.accounts.values_mut() {
            if entry.sessions < crate::activation::MIN_SESSIONS_FOR_ANET
                && entry.activated_ants > 0
                && !active_addresses.contains(&entry.address)
            {
                let removed = entry.activated_ants;
                entry.ants_balance = entry
                    .ants_balance
                    .checked_sub(removed)
                    .ok_or_else(|| anyhow!("retroactive activation clawback underflowed"))?;
                removed_ants = removed_ants
                    .checked_add(removed)
                    .ok_or_else(|| anyhow!("removed activation total overflowed"))?;
                entry.activated_ants = 0;
                entry.total_activated_ants = 0;
                metadata_changed = true;
                // Record the clawback too, so the on-chain event log stays a
                // faithful, immutable mirror of activation state transitions.
                session_events.push(
                    ChainEvent::new("SessionActivationClawback")
                        .attr("address", &entry.address)
                        .attr("sessions", entry.sessions)
                        .attr("removed_ants", removed)
                        .attr("eligible", false),
                );
            }
        }

        // Seal the receipts into the next block (events are committed to the
        // block hash). Done before the metadata-changed bookkeeping below so a
        // block is produced whenever any receipt was emitted.
        if !session_events.is_empty() {
            self.pending_events.append(&mut session_events);
            metadata_changed = true;
        }

        if metadata_changed {
            self.persist_genesis_snapshot()?;
            self.pending_state_commit = true;
            if self.pending_block_event.is_none() {
                self.pending_block_event = Some("Activation: Account Sync".to_owned());
            }
        }

        // Re-derive validator set whenever session counts may have changed.
        // Bitcoin-style: validation eligibility is an automatic, deterministic
        // function of on-chain state; any account that just crossed
        // `MIN_SESSIONS_FOR_ANET` becomes a validator on the next block, and
        // any account that fell below (e.g. via clawback above) drops out.
        // Bootstrap seats auto-sunset once enough organic validators exist.
        self.eligible_miners =
            compute_active_validator_set(&self.accounts, &self.bootstrap_validators);

        if removed_ants > 0 {
            tracing::info!(
                accounts_updated = accounts_updated,
                credited_ants = credited_ants,
                removed_ants = removed_ants,
                min_sessions = crate::activation::MIN_SESSIONS_FOR_ANET,
                "removed legacy Web2-derived ANET from under-threshold wallets"
            );
        }

        Ok(ActivationSyncResult {
            accounts_updated,
            credited_ants,
        })
    }

    pub fn all_blocks(&self) -> Vec<Block> {
        self.blocks.clone()
    }

    pub fn latest_blocks(&self, limit: usize) -> Vec<Block> {
        self.blocks.iter().rev().take(limit).cloned().collect()
    }

    pub fn block_by_id(&self, id: &str) -> Option<Block> {
        if let Ok(height) = id.parse::<u64>() {
            return self
                .blocks
                .iter()
                .find(|block| block.block_height == height)
                .cloned();
        }

        self.blocks.iter().find(|block| block.hash == id).cloned()
    }

    pub fn blocks_in_range(&self, from: u64, to: u64, max: usize) -> Vec<Block> {
        if to < from || max == 0 {
            return Vec::new();
        }
        self.blocks
            .iter()
            .filter(|block| block.block_height >= from && block.block_height <= to)
            .take(max)
            .cloned()
            .collect()
    }

    /// Contiguous range by linked-chain position, not the legacy height label.
    /// Early production history contains a few non-contiguous labels, so sync
    /// verification uses this mode to avoid gaps or early exit.
    pub fn blocks_in_position_range(&self, from: u64, to: u64, max: usize) -> Vec<Block> {
        if to < from || max == 0 {
            return Vec::new();
        }
        let requested = to.saturating_sub(from).saturating_add(1).min(max as u64) as usize;
        let start = usize::try_from(from).unwrap_or(usize::MAX);
        self.blocks
            .iter()
            .skip(start)
            .take(requested)
            .cloned()
            .collect()
    }

    /// Phase 0 (decentralization): the minimal chain-tip descriptor a follower
    /// needs to (a) confirm it is talking to the same chain (chain_id +
    /// genesis_hash) and (b) know how far it must sync (tip height + hash).
    /// `genesis_hash` is the hash of block 0; if the chain has no blocks yet
    /// both hashes are empty strings.
    pub fn sync_head(&self) -> SyncHead {
        let genesis_hash = self
            .blocks
            .first()
            .map(|block| block.hash.clone())
            .unwrap_or_default();
        let (tip_height, tip_hash) = self
            .blocks
            .last()
            .map(|block| (Some(block.block_height), block.hash.clone()))
            .unwrap_or((None, String::new()));
        SyncHead {
            chain_id: self.chain_id.clone(),
            genesis_hash,
            tip_height,
            tip_hash,
            block_count: self.blocks.len() as u64,
        }
    }

    pub fn account_view(&self, address: &str) -> Option<AccountView> {
        self.accounts.get(address).map(|account| {
            let now_ms = Utc::now().timestamp_millis();
            let anchor_ms = self.activation_anchors.get(address).copied();
            let unvested = crate::activation::unvested_activated_ants(
                account.total_activated_ants,
                anchor_ms,
                now_ms,
            );
            let vested_bps = match anchor_ms {
                Some(anchor) => crate::activation::vested_fraction_bps(anchor, now_ms),
                None => 0,
            };
            AccountView {
                address: account.address.clone(),
                ants_balance: account.ants_balance,
                anet_balance: format_anet_fixed(account.ants_balance),
                asset_balances: account.asset_balances.clone(),
                sessions: account.sessions,
                mined_proofs: self.mined_proof_counts.get(address).copied().unwrap_or(0),
                is_validator: self.eligible_miners.iter().any(|miner| miner == address),
                total_activated_ants: account.total_activated_ants,
                vesting_anchor_ms: anchor_ms,
                swap_vested_bps: vested_bps,
                swap_locked_ants: unvested.min(account.ants_balance),
            }
        })
    }

    pub fn network_summary(&self) -> NetworkSummary {
        let now = Utc::now();
        let (current_epoch_start, current_epoch_end) =
            crate::consensus::current_epoch_window(now, self.epoch_seconds);
        let accounts_total_ants: u64 = self.accounts.values().fold(0_u64, |total, account| {
            total.saturating_add(account.ants_balance)
        });
        let chain_activated_ants: u64 = self.blocks.iter().fold(0_u64, |total, block| {
            total.saturating_add(block.activated_supply_ants)
        });
        // If runtime account state is empty after restart/sync drift, preserve a stable
        // supply display from finalized block history instead of showing a false zero.
        let total_ants = if accounts_total_ants == 0 && chain_activated_ants > 0 {
            chain_activated_ants
        } else {
            accounts_total_ants
        };
        let used_supply_history_fallback = accounts_total_ants == 0 && chain_activated_ants > 0;
        let active_miners = if self.eligible_miners.is_empty() {
            self.blocks
                .last()
                .map(|block| block.miners.len())
                .unwrap_or(0)
        } else {
            self.eligible_miners.len()
        };
        let used_validator_history_fallback = self.eligible_miners.is_empty()
            && self
                .blocks
                .last()
                .map(|block| !block.miners.is_empty())
                .unwrap_or(false);
        let has_pending_block_work = self.has_pending_block_work();

        NetworkSummary {
            chain_id: self.chain_id.clone(),
            epoch_seconds: self.epoch_seconds,
            total_ants,
            total_anet: format_anet_fixed(total_ants),
            used_supply_history_fallback,
            active_miners,
            used_validator_history_fallback,
            latest_block_height: self.blocks.last().map(|block| block.block_height),
            current_epoch_start,
            current_epoch_end,
            seconds_until_epoch_end: (current_epoch_end - now).num_seconds().max(0),
            mempool_depth: self.mempool.len() as u64,
            pending_activated_supply_ants: self.pending_activated_supply_ants,
            has_pending_block_work,
            last_web2_sync_at: self.last_web2_sync_at,
            last_web2_sync_error: self.last_web2_sync_error.clone(),
        }
    }

    pub fn queue_transaction(&mut self, transaction: Transaction) -> Result<String> {
        transaction.validate_signed_for_chain(&self.chain_id)?;

        if self.mempool.len() >= MAX_MEMPOOL_TRANSACTIONS {
            return Err(anyhow!("mempool is full"));
        }

        // Bridge-funded holders paid real value for their ANET, so their
        // balance is exempt from the mined-ANTS activation gate on both the
        // send and receive side.
        let sender_bridge_funded = self.bridge_funded_accounts.contains(&transaction.from);
        let recipient_bridge_funded = self.bridge_funded_accounts.contains(&transaction.to);

        let sender = self
            .accounts
            .get(&transaction.from)
            .ok_or_else(|| anyhow!("sender account not found in state"))?;

        if !Self::allow_ineligible_wallet_test_mode()
            && !sender_bridge_funded
            && sender.sessions < crate::activation::MIN_SESSIONS_FOR_ANET
        {
            return Err(anyhow!(
                "sender must complete at least {} Web2 sessions before spending mined ANTS/ANET or sending P2P",
                crate::activation::MIN_SESSIONS_FOR_ANET
            ));
        }

        let recipient = self.accounts.get(&transaction.to).ok_or_else(|| {
            anyhow!("recipient must complete at least 1000 Web2 sessions before receiving ANET")
        })?;

        if !Self::allow_ineligible_wallet_test_mode()
            && !recipient_bridge_funded
            && recipient.sessions < crate::activation::MIN_SESSIONS_FOR_ANET
        {
            return Err(anyhow!(
                "recipient must complete at least {} Web2 sessions before participating in P2P ANET transfers",
                crate::activation::MIN_SESSIONS_FOR_ANET
            ));
        }

        let committed_nonce = self
            .account_nonces
            .get(&transaction.from)
            .copied()
            .unwrap_or(0);
        if transaction.nonce <= committed_nonce {
            return Err(anyhow!(
                "stale nonce: expected nonce greater than {}",
                committed_nonce
            ));
        }

        let mut pending_nonces = self
            .mempool
            .iter()
            .filter(|tx| tx.from == transaction.from)
            .map(|tx| tx.nonce)
            .collect::<Vec<_>>();
        pending_nonces.sort_unstable();

        if pending_nonces
            .iter()
            .any(|nonce| *nonce == transaction.nonce)
        {
            return Err(anyhow!("duplicate nonce already queued for sender"));
        }

        let mut expected_nonce = committed_nonce
            .checked_add(1)
            .ok_or_else(|| anyhow!("nonce overflowed"))?;
        for pending in pending_nonces {
            match pending.cmp(&expected_nonce) {
                std::cmp::Ordering::Equal => {
                    expected_nonce = expected_nonce
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("nonce overflowed"))?;
                }
                std::cmp::Ordering::Greater => break,
                std::cmp::Ordering::Less => {}
            }
        }

        if transaction.nonce != expected_nonce {
            return Err(anyhow!(
                "invalid nonce: expected {}, got {}",
                expected_nonce,
                transaction.nonce
            ));
        }

        let transaction_id = transaction.id()?;
        if self
            .mempool
            .iter()
            .any(|queued| queued.id().map(|id| id == transaction_id).unwrap_or(false))
        {
            return Err(anyhow!("duplicate transaction already queued"));
        }

        let pending_outgoing = self
            .mempool
            .iter()
            .filter(|tx| tx.from == transaction.from)
            .try_fold(0_u64, |sum, tx| {
                sum.checked_add(tx.total_debit()?)
                    .ok_or_else(|| anyhow!("pending debit overflowed"))
            })?;

        let required = transaction.total_debit()?;
        let available = sender
            .ants_balance
            .checked_sub(pending_outgoing)
            .ok_or_else(|| anyhow!("sender has no spendable balance left"))?;

        if available < required {
            return Err(anyhow!("insufficient ANTS balance for transaction and fee"));
        }

        self.mempool.push(transaction);
        Ok(transaction_id)
    }

    pub fn has_pending_block_work(&self) -> bool {
        !self.mempool.is_empty()
            || self.pending_activated_supply_ants > 0
            || self.pending_state_commit
            || !self.pending_mining_proofs.is_empty()
    }

    pub fn dex_pool_list(&self) -> Vec<DexPoolView> {
        let mut pools = self
            .dex_pools
            .values()
            .filter(|pool| self.is_l1_price_discovery_pool(pool))
            .map(|pool| pool.view(true))
            .collect::<Vec<_>>();
        pools.sort_by(|left, right| left.pair_id.cmp(&right.pair_id));
        pools
    }

    pub fn dex_pool_view(&self, token_symbol: &str) -> Result<Option<DexPoolView>> {
        let key = dex::pool_key(token_symbol)?;
        let Some(pool) = self.dex_pools.get(&key) else {
            return Ok(None);
        };
        if !self.is_l1_price_discovery_pool(pool) {
            return Ok(None);
        }
        Ok(Some(pool.view(true)))
    }

    pub fn dex_pool_audit_view(&self, token_symbol: &str) -> Result<Option<DexPoolAuditView>> {
        let key = dex::pool_key(token_symbol)?;
        let Some(pool) = self.dex_pools.get(&key) else {
            return Ok(None);
        };
        Ok(Some(build_dex_pool_audit(
            pool,
            self.token_registry.get(&pool.token_symbol),
            &self.blocks,
        )))
    }

    fn is_l1_price_discovery_pool(&self, pool: &DexPool) -> bool {
        build_dex_pool_audit(pool, self.token_registry.get(&pool.token_symbol), &self.blocks)
            .suitable_for_l1_price_discovery
    }

    fn require_l1_price_discovery_pool(&self, token_symbol: &str) -> Result<DexPool> {
        let pair_id = dex::pool_key(token_symbol)?;
        let pool = self
            .dex_pools
            .get(&pair_id)
            .cloned()
            .ok_or_else(|| anyhow!("pool not found"))?;
        let audit = build_dex_pool_audit(
            &pool,
            self.token_registry.get(&pool.token_symbol),
            &self.blocks,
        );
        if !audit.suitable_for_l1_price_discovery {
            return Err(anyhow!(
                "pool is not an eligible native L1 price-discovery market: {}",
                audit.status
            ));
        }
        Ok(pool)
    }

    /// Durably credit a bridged EVM swap to `recipient` by encoding it as a
    /// real block transaction (a treasury → recipient transfer) rather than a
    /// bare in-memory balance bump.
    ///
    /// ⚠️  LEGACY L1 PATH — NOT an L2 canonical mint. This credit mirrors a real
    /// off-chain BSC/USDC deposit onto the *custom L1* using a synthetic bridge
    /// treasury. Per the June 11, 2026 Architecture Decision (BSC ANET = the
    /// designated L2 native gas asset; the L1 remains separate until a future
    /// migration), this is **not** part of the mining-only supply guarantee and
    /// must **not** be treated as a canonical L2 supply source. It exists solely
    /// to keep legacy L1 bridge balances consistent across restarts/replays.
    ///
    /// The legacy in-memory test-credit path only mutated `accounts` in RAM
    /// and stamped a cosmetic block-event label; because the credit was never a
    /// block transaction, `replay_blocks` could not reconstruct it and the
    /// balance evaporated on every node restart/redeploy. This path instead
    /// appends a transaction to the block, which is persisted to Postgres and
    /// re-applied on replay, so the credit is permanent.
    ///
    /// The synthetic sender (`BRIDGE_TREASURY_ADDRESS`) is pre-funded in memory
    /// here so the next live `apply_block` debit cannot underflow; on replay the
    /// identical top-up is reproduced by `reconcile_replay_sender_balances`,
    /// keeping live and replay state byte-identical and netting the treasury to
    /// zero. Returns the recipient's projected ANTS balance once the next block
    /// seals.
    pub fn queue_bridge_credit(
        &mut self,
        recipient: &str,
        amount_ants: u64,
        evm_tx_hash: &str,
    ) -> Result<u64> {
        // ONE-WAY BRIDGE POLICY (protocol invariant, 2026-08-14, whitepaper
        // v3.5): external deposits — BSC ANET/wANET, BNB, stablecoins, or any
        // spoke-chain burn — can NEVER mint native L1 ANET again. Native ANET
        // originates exclusively from the mining/activation schedule. Historical
        // bridge_credit transactions already sealed in blocks remain valid and
        // replay normally (replay applies block transactions directly and never
        // calls this function). No env var, admin key, or signer set may bypass
        // this refusal.
        if one_way_bridge_in_active() {
            return Err(anyhow!(
                "one-way bridge policy: external deposits (wANET/BSC/spoke burns) can no \
                 longer mint native L1 ANET. Native ANET originates only from mining. \
                 Market-acquired wANET carries no redemption right against L1 supply."
            ));
        }

        if amount_ants == 0 {
            return Err(anyhow!("bridge credit amount must be greater than zero"));
        }

        let requested_recipient = recipient.trim().to_uppercase();
        if !crate::transaction::is_valid_anet_wallet(&requested_recipient) {
            return Err(anyhow!(
                "bridge credit recipient must be a valid ANET wallet"
            ));
        }
        // If the recipient is an already-migrated legacy address, forward the
        // credit to its signable secp wallet so the funds land somewhere the
        // owner can actually spend from, instead of stranding on a legacy
        // address that can never sign. Durable: the resulting bridge_credit
        // transaction records the secp as its recipient.
        let recipient_norm = match resolve_forwarded_recipient(&self.migrated_secp, &requested_recipient) {
            Some(secp) => {
                tracing::info!(
                    legacy = %requested_recipient,
                    secp = %secp,
                    "bridge credit forwarded from migrated legacy to secp wallet"
                );
                secp
            }
            None => requested_recipient,
        };
        if recipient_norm == BRIDGE_TREASURY_ADDRESS {
            return Err(anyhow!("bridge credit recipient must not be the treasury"));
        }

        let fee_ants = crate::transaction::MIN_FEE_ANTS;
        let total_debit = amount_ants
            .checked_add(fee_ants)
            .ok_or_else(|| anyhow!("bridge credit total overflowed"))?;

        // Pre-fund the in-memory treasury so the next live `apply_block` can
        // debit it without underflowing. On replay this top-up is reproduced by
        // `reconcile_replay_sender_balances`, so live and replay stay identical.
        let treasury = self
            .accounts
            .entry(BRIDGE_TREASURY_ADDRESS.to_owned())
            .or_insert_with(|| empty_account_state(BRIDGE_TREASURY_ADDRESS.to_owned()));
        treasury.ants_balance = treasury
            .ants_balance
            .checked_add(total_debit)
            .ok_or_else(|| anyhow!("bridge treasury balance overflowed"))?;

        let memo = format!(
            "{BRIDGE_CREDIT_MEMO_PREFIX}{}",
            evm_tx_hash.trim().to_lowercase()
        );

        // A legacy (unsigned) transaction: `Transaction::validate` accepts it on
        // the strength of `validate_basic` alone, and `rebuild_account_nonces`
        // skips `nonce == 0`, so repeated treasury credits never break nonce
        // ordering for any real wallet.
        let mint_tx = Transaction {
            tx_type: "bridge_credit".to_owned(),
            from: BRIDGE_TREASURY_ADDRESS.to_owned(),
            to: recipient_norm.clone(),
            amount_ants,
            fee_ants,
            nonce: 0,
            memo,
            timestamp: Utc::now(),
            chain_id: self.chain_id.clone(),
            payload: serde_json::Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        };
        self.mempool.push(mint_tx);

        self.pending_block_event = Some(format!(
            "EVM Bridge Credit: {amount_ants} ANTS → {recipient_norm}"
        ));
        self.pending_state_commit = true;

        // Mark the recipient as bridge-funded so their paid-for ANET is exempt
        // from the mined-ANTS activation gate (they can swap/transfer it even
        // with fewer than MIN_SESSIONS_FOR_ANET sessions).
        self.bridge_funded_accounts.insert(recipient_norm.clone());

        let projected = self
            .accounts
            .get(&recipient_norm)
            .map(|account| account.ants_balance)
            .unwrap_or(0)
            .saturating_add(amount_ants);
        Ok(projected)
    }

    /// Permanently burn `amount_ants` from `address` for an L1 → BSC
    /// bridge transfer. The ants disappear from L1 supply entirely;
    /// the relayer is responsible for releasing the equivalent wANET
    /// (or USDC/USDT) on BSC. Returns the new L1 ants balance.
    ///
    /// Validator fee (Bitcoin-style, sender-pays-on-top):
    /// in addition to `amount_ants`, the sender is charged
    /// `MIN_FEE_ANTS` (1,000 ANTS) which is distributed equally to the
    /// current active validator set. The bridged amount stays clean —
    /// L1 ants destroyed equals wANET minted on BSC, exactly — so the
    /// fee never reduces the user's bridged value.
    pub fn bridge_burn_anet(&mut self, address: &str, amount_ants: u64) -> Result<u64> {
        if amount_ants == 0 {
            return Err(anyhow!("burn amount must be greater than zero"));
        }

        let fee_ants = crate::transaction::MIN_FEE_ANTS;
        let total_debit = amount_ants
            .checked_add(fee_ants)
            .ok_or_else(|| anyhow!("burn amount + validator fee overflowed u64"))?;

        let normalized = address.trim().to_uppercase();
        if !crate::transaction::is_valid_anet_wallet(&normalized) {
            return Err(anyhow!("burn sender must be a valid ANET wallet"));
        }
        // ONE-WAY BRIDGE POLICY: exports are reserved for eligible miners (or
        // historical bridge-funded wallets). This closes the transfer-shuffle
        // bypass — P2P-received coins cannot exit through a fresh wallet that
        // never mined; the holder must reach eligibility first.
        if !Self::allow_ineligible_wallet_test_mode() {
            let sessions = self
                .accounts
                .get(&normalized)
                .map(|a| a.sessions)
                .unwrap_or(0);
            if let Some(reason) = export_eligibility_error(
                sessions,
                self.bridge_funded_accounts.contains(&normalized),
            ) {
                return Err(anyhow!(reason));
            }
        }
        // Bridging out to wANET honors the mined-coin vesting schedule.
        self.ensure_vested_for_swap_out(&normalized, total_debit)?;

        // Snapshot validator set before mutable account borrows.
        let validators: Vec<String> = self.eligible_miners.clone();
        let new_balance = execute_bridge_burn(
            &mut self.accounts,
            &validators,
            &normalized,
            amount_ants,
            fee_ants,
        )?;

        self.pending_block_event = Some(format!(
            "Bridge: Burn {amount_ants} ants from {normalized} for BSC release \
             (+{fee_ants} ANTS validator fee, split across {} validators)",
            validators.len()
        ));
        self.pending_state_commit = true;
        Ok(new_balance)
    }

    /// One-shot legacy-derivation → secp-derivation wallet migration.
    /// Moves ALL balance (ants + activated + total_activated + sessions +
    /// asset balances) from `legacy` to `secp`, atomically. Used after the
    /// caller has proven, via the dual-derivation reveal in
    /// `/wallet/migrate-legacy/reveal`, that the same private key controls
    /// both addresses. After migration the legacy address is left at zero
    /// and effectively retired; future deposits to it (e.g. delayed mining
    /// rewards) can be claimed by running migrate-legacy again.
    pub fn migrate_legacy_to_secp(&mut self, legacy: &str, secp: &str) -> Result<(u64, u64, u64)> {
        let legacy_norm = legacy.trim().to_uppercase();
        let secp_norm = secp.trim().to_uppercase();
        if legacy_norm == secp_norm {
            return Err(anyhow!("legacy and secp addresses must differ"));
        }
        if !crate::transaction::is_valid_anet_wallet(&legacy_norm)
            || !crate::transaction::is_valid_anet_wallet(&secp_norm)
        {
            return Err(anyhow!(
                "legacy and secp addresses must be valid ANET wallets"
            ));
        }
        let legacy_acct = self
            .accounts
            .get(&legacy_norm)
            .cloned()
            .ok_or_else(|| anyhow!("legacy account not found"))?;
        let ants_moved = legacy_acct.ants_balance;
        let activated_moved = legacy_acct.activated_ants;
        let total_activated_moved = legacy_acct.total_activated_ants;
        let sessions_moved = legacy_acct.sessions;

        let mut secp_acct = self
            .accounts
            .get(&secp_norm)
            .cloned()
            .unwrap_or_else(|| empty_account_state(secp_norm.clone()));
        secp_acct.ants_balance = secp_acct
            .ants_balance
            .checked_add(ants_moved)
            .ok_or_else(|| anyhow!("ANET balance overflowed on secp side"))?;
        secp_acct.activated_ants = secp_acct
            .activated_ants
            .checked_add(activated_moved)
            .ok_or_else(|| anyhow!("activated_ants overflowed on secp side"))?;
        secp_acct.total_activated_ants = secp_acct
            .total_activated_ants
            .checked_add(total_activated_moved)
            .ok_or_else(|| anyhow!("total_activated_ants overflowed on secp side"))?;
        secp_acct.sessions = secp_acct
            .sessions
            .checked_add(sessions_moved)
            .ok_or_else(|| anyhow!("sessions overflowed on secp side"))?;
        for (sym, amt) in &legacy_acct.asset_balances {
            let entry = secp_acct.asset_balances.entry(sym.clone()).or_insert(0);
            *entry = entry
                .checked_add(*amt)
                .ok_or_else(|| anyhow!("asset balance overflowed on secp side"))?;
        }

        let mut next_accounts = self.accounts.clone();
        let legacy_next = next_accounts
            .get_mut(&legacy_norm)
            .ok_or_else(|| anyhow!("legacy account not found"))?;
        legacy_next.ants_balance = 0;
        legacy_next.activated_ants = 0;
        // Preserve historical total_activated on legacy for auditability.
        legacy_next.sessions = 0;
        legacy_next.asset_balances.clear();
        next_accounts.insert(secp_norm.clone(), secp_acct);

        self.accounts = next_accounts;
        self.pending_block_event = Some(format!(
            "WalletMigration: {legacy_norm} -> {secp_norm} ants={ants_moved} sessions={sessions_moved}"
        ));
        self.pending_state_commit = true;
        Ok((ants_moved, sessions_moved, total_activated_moved))
    }

    /// Record a completed legacy -> secp migration so any later credit to the
    /// legacy address is forwarded to the signable secp wallet. Idempotent.
    pub fn register_migrated_secp(&mut self, legacy: &str, secp: &str) {
        let legacy_norm = legacy.trim().to_uppercase();
        let secp_norm = secp.trim().to_uppercase();
        if crate::transaction::is_valid_anet_wallet(&legacy_norm)
            && crate::transaction::is_valid_anet_wallet(&secp_norm)
            && legacy_norm != secp_norm
        {
            self.migrated_secp.insert(legacy_norm, secp_norm);
        }
    }

    /// Durably sweep the *current* ANTS balance of an already-migrated legacy
    /// address to its bound secp address.
    ///
    /// Unlike [`NodeState::migrate_legacy_to_secp`] — which mutates account
    /// state in memory only and is therefore lost on replay — this records a
    /// real block transaction, exactly like [`NodeState::queue_bridge_credit`],
    /// so the move is reproduced deterministically on every restart. It exists
    /// to recover funds credited to a legacy address *after* it was migrated
    /// (e.g. a wANET bridge credit), which the one-shot reveal flow cannot move.
    ///
    /// The destination is the secp recorded in the proven (revealed) migration
    /// row, so funds can only ever land on the wallet that already proved
    /// ownership of this legacy address. The secp is marked bridge-funded so the
    /// recovered (paid-for) ANET stays spendable without the session gate. The
    /// `fee_ants` minimum is paid from the swept balance to block producers, as
    /// with any transaction. Returns the ANTS amount credited to the secp.
    pub fn sweep_legacy_balance_to_secp(&mut self, legacy: &str, secp: &str) -> Result<u64> {
        let legacy_norm = legacy.trim().to_uppercase();
        let secp_norm = secp.trim().to_uppercase();
        if legacy_norm == secp_norm {
            return Err(anyhow!("legacy and secp addresses must differ"));
        }
        if !crate::transaction::is_valid_anet_wallet(&legacy_norm)
            || !crate::transaction::is_valid_anet_wallet(&secp_norm)
        {
            return Err(anyhow!(
                "legacy and secp addresses must be valid ANET wallets"
            ));
        }

        let balance = self
            .accounts
            .get(&legacy_norm)
            .map(|account| account.ants_balance)
            .unwrap_or(0);
        let fee_ants = crate::transaction::MIN_FEE_ANTS;
        if balance <= fee_ants {
            return Err(anyhow!(
                "legacy balance ({balance} ANTS) is not greater than the minimum fee ({fee_ants}); nothing to sweep"
            ));
        }
        let amount_ants = balance - fee_ants;

        // A legacy (unsigned) transaction, identical in shape to a bridge
        // credit: `Transaction::validate` accepts it on `validate_basic` alone
        // and `rebuild_account_nonces` skips `nonce == 0`. On replay the
        // earlier bridge-credit transaction re-funds the legacy first, then
        // this debits it, so live and replay state stay byte-identical.
        let memo = format!("{MIGRATION_SWEEP_MEMO_PREFIX}{legacy_norm}");
        let sweep_tx = Transaction {
            tx_type: "migration_sweep".to_owned(),
            from: legacy_norm.clone(),
            to: secp_norm.clone(),
            amount_ants,
            fee_ants,
            nonce: 0,
            memo,
            timestamp: Utc::now(),
            chain_id: self.chain_id.clone(),
            payload: serde_json::Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        };
        self.mempool.push(sweep_tx);

        // The recovered balance is paid-for value (it originated from a bridge
        // credit), so keep it spendable on the secp side without the session
        // gate. Durable across restarts via `collect_bridge_funded_accounts`.
        self.bridge_funded_accounts.insert(secp_norm.clone());

        self.pending_block_event = Some(format!(
            "WalletMigrationResweep: {legacy_norm} -> {secp_norm} ants={amount_ants}"
        ));
        self.pending_state_commit = true;

        Ok(amount_ants)
    }

    pub fn dex_create_pool(
        &mut self,
        provider: &str,
        token_symbol: &str,
        anet_amount_ants: u64,
        token_amount_units: u64,
        fee_bps: Option<u16>,
    ) -> Result<DexLiquidityResult> {
        let provider = provider.trim().to_uppercase();
        if !crate::transaction::is_valid_anet_wallet(&provider) {
            return Err(anyhow!("liquidity provider must be a valid ANET wallet"));
        }
        let symbol = dex::normalize_token_symbol(token_symbol)?;
        let pair_id = dex::pool_key(&symbol)?;

        if self.dex_pools.contains_key(&pair_id) {
            return Err(anyhow!("pool already exists"));
        }
        if anet_amount_ants == 0 || token_amount_units == 0 {
            return Err(anyhow!("initial liquidity must be greater than zero"));
        }

        let fee_bps = dex::validate_fee_bps(fee_bps.unwrap_or(dex::DEFAULT_FEE_BPS))?;
        let total_lp_units =
            dex::initial_lp_units(u128::from(anet_amount_ants), u128::from(token_amount_units))?;

        let mut account = self.ensure_eligible_account(&provider)?.clone();
        debit_anet(&mut account, anet_amount_ants)?;
        debit_asset(&mut account, &symbol, token_amount_units)?;
        move_token_registry_balance(
            &mut self.token_registry,
            &symbol,
            &provider,
            &dex_pool_escrow_account(&pair_id),
            token_amount_units,
        )?;

        let mut lp_positions = HashMap::new();
        lp_positions.insert(provider.clone(), total_lp_units);

        let pool = DexPool {
            pair_id: pair_id.clone(),
            token_symbol: symbol.clone(),
            anet_reserve_ants: u128::from(anet_amount_ants),
            token_reserve_units: u128::from(token_amount_units),
            total_lp_units,
            fee_bps,
            lp_positions,
            updated_at: Utc::now(),
        };

        self.accounts.insert(provider.clone(), account);
        self.dex_pools.insert(pair_id.clone(), pool);
        self.pending_block_event = Some("DEX: Create Pool".to_string());
        self.emit_event(
            ChainEvent::new("PoolCreated")
                .attr("pair_id", &pair_id)
                .attr("provider", &provider)
                .attr("token_symbol", &symbol),
        );
        self.pending_state_commit = true;

        Ok(DexLiquidityResult {
            pair_id,
            provider,
            lp_minted: total_lp_units.to_string(),
            total_lp_units: total_lp_units.to_string(),
        })
    }

    pub fn dex_wrap_anet(&mut self, wallet: &str, amount_ants: u64) -> Result<u64> {
        if amount_ants == 0 {
            return Err(anyhow!("wrap amount must be greater than zero"));
        }

        let wallet = wallet.trim().to_uppercase();
        // Wrapping is the on-ramp for swapping mined coins out to wANET, so
        // it honors the mined-coin vesting schedule.
        self.ensure_vested_for_swap_out(&wallet, amount_ants)?;
        let mut account = self.ensure_eligible_account(&wallet)?.clone();
        debit_anet(&mut account, amount_ants)?;
        credit_asset(&mut account, WANET_SYMBOL, amount_ants)?;
        credit_wanet_registry_balance(&mut self.token_registry, &wallet, amount_ants)?;
        let wanet_balance = account
            .asset_balances
            .get(WANET_SYMBOL)
            .copied()
            .unwrap_or(0);
        self.accounts.insert(wallet, account);
        self.pending_block_event = Some("DEX: Wrap ANET -> WANET".to_string());
        self.pending_state_commit = true;

        Ok(wanet_balance)
    }

    pub fn dex_unwrap_wanet(&mut self, wallet: &str, amount_units: u64) -> Result<u64> {
        if amount_units == 0 {
            return Err(anyhow!("unwrap amount must be greater than zero"));
        }

        let wallet = wallet.trim().to_uppercase();
        let mut account = self.ensure_eligible_account(&wallet)?.clone();
        debit_asset(&mut account, WANET_SYMBOL, amount_units)?;
        debit_wanet_registry_balance(&mut self.token_registry, &wallet, amount_units)?;
        credit_anet(&mut account, amount_units)?;
        let anet_balance = account.ants_balance;
        self.accounts.insert(wallet, account);
        self.pending_block_event = Some("DEX: Unwrap WANET -> ANET".to_string());
        self.pending_state_commit = true;

        Ok(anet_balance)
    }

    pub fn dex_add_liquidity(
        &mut self,
        provider: &str,
        token_symbol: &str,
        anet_amount_ants: u64,
        token_amount_units: u64,
    ) -> Result<DexLiquidityResult> {
        let provider = provider.trim().to_uppercase();
        let market_pool = self.require_l1_price_discovery_pool(token_symbol)?;
        let pair_id = market_pool.pair_id.clone();
        if anet_amount_ants == 0 || token_amount_units == 0 {
            return Err(anyhow!("liquidity amounts must be greater than zero"));
        }

        let (pool_token_symbol, pool_anet_reserve, pool_token_reserve, pool_total_lp) = (
            market_pool.token_symbol.clone(),
            market_pool.anet_reserve_ants,
            market_pool.token_reserve_units,
            market_pool.total_lp_units,
        );

        let required_token = u128::from(anet_amount_ants)
            .checked_mul(pool_token_reserve)
            .ok_or_else(|| anyhow!("required token overflowed"))?
            / pool_anet_reserve;
        let provided_token = u128::from(token_amount_units);
        let drift = required_token.abs_diff(provided_token);
        if drift > 1 {
            return Err(anyhow!(
                "liquidity ratio mismatch: expected roughly {required_token} {}, got {provided_token}",
                pool_token_symbol
            ));
        }

        let minted_lp = u128::from(anet_amount_ants)
            .checked_mul(pool_total_lp)
            .ok_or_else(|| anyhow!("LP mint overflowed"))?
            / pool_anet_reserve;
        if minted_lp == 0 {
            return Err(anyhow!("liquidity contribution is too small"));
        }

        let mut account = self.ensure_eligible_account(&provider)?.clone();
        debit_anet(&mut account, anet_amount_ants)?;
        debit_asset(&mut account, &pool_token_symbol, token_amount_units)?;
        move_token_registry_balance(
            &mut self.token_registry,
            &pool_token_symbol,
            &provider,
            &dex_pool_escrow_account(&pair_id),
            token_amount_units,
        )?;

        let mut pool = self
            .dex_pools
            .get(&pair_id)
            .cloned()
            .ok_or_else(|| anyhow!("pool not found"))?;
        pool.anet_reserve_ants = pool
            .anet_reserve_ants
            .checked_add(u128::from(anet_amount_ants))
            .ok_or_else(|| anyhow!("pool ANET reserve overflowed"))?;
        pool.token_reserve_units = pool
            .token_reserve_units
            .checked_add(u128::from(token_amount_units))
            .ok_or_else(|| anyhow!("pool token reserve overflowed"))?;
        pool.total_lp_units = pool
            .total_lp_units
            .checked_add(minted_lp)
            .ok_or_else(|| anyhow!("pool LP overflowed"))?;
        let provider_lp = pool.lp_positions.get(&provider).copied().unwrap_or(0);
        pool.lp_positions.insert(
            provider.clone(),
            provider_lp
                .checked_add(minted_lp)
                .ok_or_else(|| anyhow!("provider LP balance overflowed"))?,
        );
        pool.updated_at = Utc::now();
        let total_lp_units = pool.total_lp_units.to_string();

        self.accounts.insert(provider.clone(), account);
        self.dex_pools.insert(pair_id.clone(), pool);

        self.pending_block_event = Some("DEX: Add Liquidity".to_string());
        self.emit_event(
            ChainEvent::new("LiquidityAdded")
                .attr("pair_id", &pair_id)
                .attr("provider", &provider)
                .attr("lp_minted", minted_lp.to_string()),
        );
        self.pending_state_commit = true;

        Ok(DexLiquidityResult {
            pair_id,
            provider,
            lp_minted: minted_lp.to_string(),
            total_lp_units,
        })
    }

    pub fn dex_remove_liquidity(
        &mut self,
        provider: &str,
        token_symbol: &str,
        lp_units: u128,
    ) -> Result<DexRemoveLiquidityResult> {
        if lp_units == 0 {
            return Err(anyhow!("LP units must be greater than zero"));
        }

        let provider = provider.trim().to_uppercase();
        if !crate::transaction::is_valid_anet_wallet(&provider) {
            return Err(anyhow!("liquidity provider must be a valid ANET wallet"));
        }

        let market_pool = self.require_l1_price_discovery_pool(token_symbol)?;
        let pair_id = market_pool.pair_id.clone();
        let provider_lp = market_pool.lp_positions.get(&provider).copied().unwrap_or(0);
        if provider_lp < lp_units {
            return Err(anyhow!("insufficient LP balance"));
        }
        if market_pool.total_lp_units == 0 {
            return Err(anyhow!("pool has no LP supply"));
        }

        let anet_out = lp_units
            .checked_mul(market_pool.anet_reserve_ants)
            .ok_or_else(|| anyhow!("ANET withdrawal math overflowed"))?
            / market_pool.total_lp_units;
        let token_out = lp_units
            .checked_mul(market_pool.token_reserve_units)
            .ok_or_else(|| anyhow!("token withdrawal math overflowed"))?
            / market_pool.total_lp_units;
        if anet_out == 0 || token_out == 0 {
            return Err(anyhow!("LP withdrawal is too small"));
        }
        let anet_out_u64 =
            u64::try_from(anet_out).map_err(|_| anyhow!("ANET withdrawal overflowed"))?;
        let token_out_u64 =
            u64::try_from(token_out).map_err(|_| anyhow!("token withdrawal overflowed"))?;

        let mut account = self
            .accounts
            .get(&provider)
            .cloned()
            .unwrap_or_else(|| empty_account_state(provider.clone()));
        credit_anet(&mut account, anet_out_u64)?;
        credit_asset(&mut account, &market_pool.token_symbol, token_out_u64)?;
        move_token_registry_balance(
            &mut self.token_registry,
            &market_pool.token_symbol,
            &dex_pool_escrow_account(&pair_id),
            &provider,
            token_out_u64,
        )?;

        let mut pool = market_pool;
        pool.anet_reserve_ants = pool
            .anet_reserve_ants
            .checked_sub(anet_out)
            .ok_or_else(|| anyhow!("pool ANET reserve underflowed"))?;
        pool.token_reserve_units = pool
            .token_reserve_units
            .checked_sub(token_out)
            .ok_or_else(|| anyhow!("pool token reserve underflowed"))?;
        pool.total_lp_units = pool
            .total_lp_units
            .checked_sub(lp_units)
            .ok_or_else(|| anyhow!("pool LP supply underflowed"))?;
        let remaining_provider_lp = provider_lp
            .checked_sub(lp_units)
            .ok_or_else(|| anyhow!("provider LP balance underflowed"))?;
        if remaining_provider_lp == 0 {
            pool.lp_positions.remove(&provider);
        } else {
            pool.lp_positions
                .insert(provider.clone(), remaining_provider_lp);
        }
        pool.updated_at = Utc::now();

        let remaining_lp_units = pool.total_lp_units.to_string();
        self.accounts.insert(provider.clone(), account);
        if pool.total_lp_units == 0 {
            self.dex_pools.remove(&pair_id);
        } else {
            self.dex_pools.insert(pair_id.clone(), pool);
        }

        self.pending_block_event = Some("DEX: Remove Liquidity".to_string());
        self.emit_event(
            ChainEvent::new("LiquidityRemoved")
                .attr("pair_id", &pair_id)
                .attr("provider", &provider)
                .attr("lp_burned", lp_units.to_string())
                .attr("anet_amount_ants", anet_out.to_string())
                .attr("token_amount_units", token_out.to_string()),
        );
        self.pending_state_commit = true;

        Ok(DexRemoveLiquidityResult {
            pair_id,
            provider,
            lp_burned: lp_units.to_string(),
            anet_amount_ants: anet_out.to_string(),
            token_amount_units: token_out.to_string(),
            remaining_lp_units,
        })
    }

    pub fn dex_quote(
        &self,
        token_symbol: &str,
        amount_in: u64,
        anet_to_token: bool,
    ) -> Result<DexQuoteView> {
        let pool = self.require_l1_price_discovery_pool(token_symbol)?;

        let (reserve_in, reserve_out, direction) = if anet_to_token {
            (
                pool.anet_reserve_ants,
                pool.token_reserve_units,
                format!("ANET->{}", pool.token_symbol),
            )
        } else {
            (
                pool.token_reserve_units,
                pool.anet_reserve_ants,
                format!("{}->ANET", pool.token_symbol),
            )
        };

        let (amount_out, fee_paid, price_impact_bps) =
            dex::quote_amount_out(reserve_in, reserve_out, u128::from(amount_in), pool.fee_bps)?;
        let min_out_1pct_slippage = amount_out
            .checked_mul(99)
            .ok_or_else(|| anyhow!("slippage math overflowed"))?
            / 100;

        Ok(DexQuoteView {
            pair_id: pool.pair_id,
            direction,
            amount_in: amount_in.to_string(),
            amount_out: amount_out.to_string(),
            fee_paid: fee_paid.to_string(),
            min_out_1pct_slippage: min_out_1pct_slippage.to_string(),
            price_impact_bps,
        })
    }

    pub fn dex_swap(
        &mut self,
        trader: &str,
        token_symbol: &str,
        amount_in: u64,
        anet_to_token: bool,
        min_amount_out: Option<u64>,
        deadline_block: Option<u64>,
    ) -> Result<DexSwapResult> {
        let current_height = self
            .blocks
            .last()
            .map(|block| block.block_height)
            .unwrap_or(0);
        if let Some(deadline_block) = deadline_block {
            let settlement_height = current_height
                .checked_add(1)
                .ok_or_else(|| anyhow!("block height overflowed"))?;
            if settlement_height > deadline_block {
                return Err(anyhow!(
                    "swap deadline expired: settlement block {} exceeds deadline {}",
                    settlement_height,
                    deadline_block
                ));
            }
        }

        let trader = trader.trim().to_uppercase();
        let market_pool = self.require_l1_price_discovery_pool(token_symbol)?;
        let pair_id = market_pool.pair_id.clone();
        if amount_in == 0 {
            return Err(anyhow!("swap amount must be greater than zero"));
        }
        if anet_to_token {
            // Swapping mined ANET into another asset honors the vesting schedule.
            self.ensure_vested_for_swap_out(&trader, amount_in)?;
        }

        let (pool_token_symbol, pool_fee_bps, reserve_in, reserve_out, direction) = {
            let (reserve_in, reserve_out, direction) = if anet_to_token {
                (
                    market_pool.anet_reserve_ants,
                    market_pool.token_reserve_units,
                    format!("ANET->{}", market_pool.token_symbol),
                )
            } else {
                (
                    market_pool.token_reserve_units,
                    market_pool.anet_reserve_ants,
                    format!("{}->ANET", market_pool.token_symbol),
                )
            };
            (
                market_pool.token_symbol.clone(),
                market_pool.fee_bps,
                reserve_in,
                reserve_out,
                direction,
            )
        };

        let (amount_out, fee_paid, _) =
            dex::quote_amount_out(reserve_in, reserve_out, u128::from(amount_in), pool_fee_bps)?;

        let min_expected = u128::from(min_amount_out.unwrap_or(0));
        if amount_out < min_expected {
            return Err(anyhow!(
                "slippage exceeded: amount_out {} is below min_amount_out {}",
                amount_out,
                min_expected
            ));
        }

        let amount_out_u64 =
            u64::try_from(amount_out).map_err(|_| anyhow!("swap output overflowed"))?;
        let mut account = self.ensure_eligible_account(&trader)?.clone();
        if anet_to_token {
            debit_anet(&mut account, amount_in)?;
            credit_asset(&mut account, &pool_token_symbol, amount_out_u64)?;
            move_token_registry_balance(
                &mut self.token_registry,
                &pool_token_symbol,
                &dex_pool_escrow_account(&pair_id),
                &trader,
                amount_out_u64,
            )?;
        } else {
            debit_asset(&mut account, &pool_token_symbol, amount_in)?;
            credit_anet(&mut account, amount_out_u64)?;
            move_token_registry_balance(
                &mut self.token_registry,
                &pool_token_symbol,
                &trader,
                &dex_pool_escrow_account(&pair_id),
                amount_in,
            )?;
        }

        let mut pool = self
            .dex_pools
            .get(&pair_id)
            .cloned()
            .ok_or_else(|| anyhow!("pool not found"))?;
        let k_before = pool
            .anet_reserve_ants
            .checked_mul(pool.token_reserve_units)
            .ok_or_else(|| anyhow!("pool invariant overflowed before swap"))?;

        if anet_to_token {
            pool.anet_reserve_ants = pool
                .anet_reserve_ants
                .checked_add(u128::from(amount_in))
                .ok_or_else(|| anyhow!("pool reserve overflowed"))?;
            pool.token_reserve_units = pool
                .token_reserve_units
                .checked_sub(amount_out)
                .ok_or_else(|| anyhow!("pool token reserve underflowed"))?;
        } else {
            pool.token_reserve_units = pool
                .token_reserve_units
                .checked_add(u128::from(amount_in))
                .ok_or_else(|| anyhow!("pool reserve overflowed"))?;
            pool.anet_reserve_ants = pool
                .anet_reserve_ants
                .checked_sub(amount_out)
                .ok_or_else(|| anyhow!("pool ANET reserve underflowed"))?;
        }

        let k_after = pool
            .anet_reserve_ants
            .checked_mul(pool.token_reserve_units)
            .ok_or_else(|| anyhow!("pool invariant overflowed after swap"))?;
        if k_after < k_before {
            return Err(anyhow!(
                "pool invariant violation detected after swap execution"
            ));
        }

        pool.updated_at = Utc::now();
        self.accounts.insert(trader.clone(), account);
        self.dex_pools.insert(pair_id.clone(), pool);
        self.pending_block_event = Some("DEX: Swap".to_string());
        self.emit_event(
            ChainEvent::new("SwapExecuted")
                .attr("pair_id", &pair_id)
                .attr("trader", &trader)
                .attr("direction", &direction)
                .attr("amount_in", amount_in)
                .attr("amount_out", amount_out),
        );
        self.pending_state_commit = true;

        Ok(DexSwapResult {
            pair_id,
            trader,
            direction,
            amount_in: amount_in.to_string(),
            amount_out: amount_out.to_string(),
            fee_paid: fee_paid.to_string(),
        })
    }

    pub fn record_pi_settlement(
        &mut self,
        pi_payment_id: &str,
        pi_txid: &str,
        pi_amount: &str,
        from_address: &str,
        to_address: &str,
    ) -> Result<()> {
        // Validate addresses
        if !crate::transaction::is_valid_anet_wallet(from_address) {
            return Err(anyhow!(
                "invalid from address for Pi settlement transaction"
            ));
        }
        if !crate::transaction::is_valid_anet_wallet(to_address) {
            return Err(anyhow!("invalid to address for Pi settlement transaction"));
        }

        let payment_marker = format!("Pi Payment Settlement: paymentId={pi_payment_id},");
        let txid_marker = format!(", txid={pi_txid},");
        let already_recorded = self
            .mempool
            .iter()
            .chain(
                self.blocks
                    .iter()
                    .flat_map(|block| block.transactions.iter()),
            )
            .any(|transaction| {
                transaction.memo.starts_with(&payment_marker)
                    || transaction.memo.contains(&txid_marker)
            });
        if already_recorded {
            return Err(anyhow!("Pi payment has already been recorded"));
        }

        // Create a settlement transaction recording Pi payment details
        let memo = format!(
            "Pi Payment Settlement: paymentId={}, txid={}, amount={}",
            pi_payment_id, pi_txid, pi_amount
        );

        let tx = crate::transaction::Transaction {
            tx_type: "pi_settlement".to_owned(),
            from: from_address.to_uppercase(),
            to: to_address.to_uppercase(),
            amount_ants: 1, // Minimal transfer to keep the settlement ledger-visible as a transaction
            fee_ants: 1_000, // Preserve minimum fee policy
            nonce: 0,
            memo,
            timestamp: Utc::now(),
            chain_id: self.chain_id.clone(),
            payload: serde_json::Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        };
        tx.validate()?;

        // Ensure the sender can cover settlement debit by topping up from system fee reserve when needed.
        let total_debit = tx.total_debit()?;
        let mut next_accounts = self.accounts.clone();
        let sender_balance = next_accounts
            .get(&tx.from)
            .ok_or_else(|| anyhow!("sender account not found for Pi settlement transaction"))?
            .ants_balance;
        if sender_balance < total_debit {
            let deficit = total_debit - sender_balance;
            let reserve = next_accounts
                .get_mut(SYSTEM_FEE_RESERVE_ADDRESS)
                .ok_or_else(|| anyhow!("system fee reserve account not found"))?;
            if reserve.ants_balance < deficit {
                return Err(anyhow!(
                    "insufficient fee reserve to backfill Pi settlement sender balance"
                ));
            }
            reserve.ants_balance = reserve
                .ants_balance
                .checked_sub(deficit)
                .ok_or_else(|| anyhow!("fee reserve underflow while funding Pi settlement"))?;

            let sender = next_accounts
                .get_mut(&tx.from)
                .ok_or_else(|| anyhow!("sender account not found for Pi settlement transaction"))?;
            sender.ants_balance = sender
                .ants_balance
                .checked_add(deficit)
                .ok_or_else(|| anyhow!("sender balance overflow while funding Pi settlement"))?;
            sender.activated_ants = sender.activated_ants.saturating_add(deficit);
            sender.total_activated_ants = sender.total_activated_ants.saturating_add(deficit);
        }

        self.accounts = next_accounts;
        self.mempool.push(tx);
        self.pending_block_event = Some("Pi: Payment Settlement".to_string());
        self.pending_state_commit = true;

        Ok(())
    }

    pub fn anrc20_list_tokens(&self) -> Vec<Anrc20TokenView> {
        let mut tokens = self
            .token_registry
            .values()
            .map(Anrc20Token::view)
            .collect::<Vec<_>>();
        tokens.sort_by(|left, right| left.symbol.cmp(&right.symbol));
        tokens
    }

    pub fn anrc20_token_view(&self, symbol: &str) -> Option<Anrc20TokenView> {
        let key = dex::normalize_token_symbol(symbol).ok()?;
        self.token_registry.get(&key).map(Anrc20Token::view)
    }

    pub fn anrc20_create_token(
        &mut self,
        owner: &str,
        symbol: &str,
        name: &str,
        decimals: u8,
        initial_supply: u64,
        mintable: bool,
    ) -> Result<Anrc20TokenView> {
        let symbol = dex::normalize_token_symbol(symbol)?;
        ensure_public_anrc20_symbol_allowed(&symbol)?;
        if self.token_registry.contains_key(&symbol) {
            return Err(anyhow!("token already exists"));
        }
        if name.trim().is_empty() || name.chars().count() > 64 {
            return Err(anyhow!("token name must be between 1 and 64 characters"));
        }
        if decimals > 18 {
            return Err(anyhow!("token decimals must be <= 18"));
        }

        let owner = owner.trim().to_uppercase();
        let is_bootstrap = self.bootstrap_validators.contains(&owner);
        ensure_anrc20_creator_eligible(
            self.accounts.get(&owner).map(|account| account.sessions),
            is_bootstrap,
        )?;
        let owner_account = self
            .accounts
            .entry(owner.clone())
            .or_insert_with(|| AccountState {
                address: owner.clone(),
                ants_balance: 0,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 0,
                asset_balances: HashMap::new(),
            });

        if initial_supply > 0 {
            credit_asset(owner_account, &symbol, initial_supply)?;
        }

        let mut balances = HashMap::new();
        if initial_supply > 0 {
            balances.insert(owner.clone(), initial_supply);
        }

        let token = Anrc20Token {
            symbol: symbol.clone(),
            name: name.trim().to_owned(),
            decimals,
            total_supply: initial_supply,
            owner: owner.clone(),
            mintable,
            balances,
        };
        self.token_registry.insert(symbol.clone(), token);

        self.pending_block_event = Some("ANRC20: Create Token".to_string());
        self.emit_event(
            ChainEvent::new("TokenTransferred")
                .attr("symbol", &symbol)
                .attr("from", "MINT")
                .attr("to", &owner)
                .attr("amount", initial_supply),
        );
        self.pending_state_commit = true;

        self.token_registry
            .get(&symbol)
            .map(Anrc20Token::view)
            .ok_or_else(|| anyhow!("token creation failed"))
    }

    pub fn anrc20_mint(
        &mut self,
        caller: &str,
        to: &str,
        symbol: &str,
        amount: u64,
    ) -> Result<Anrc20TokenView> {
        if amount == 0 {
            return Err(anyhow!("mint amount must be greater than zero"));
        }
        let symbol = dex::normalize_token_symbol(symbol)?;
        ensure_public_anrc20_symbol_allowed(&symbol)?;
        let caller = caller.trim().to_uppercase();
        let to = to.trim().to_uppercase();
        if !crate::transaction::is_valid_anet_wallet(&to) {
            return Err(anyhow!("mint recipient must be a valid ANET wallet"));
        }

        let mut token = self
            .token_registry
            .get(&symbol)
            .cloned()
            .ok_or_else(|| anyhow!("token not found"))?;
        if !token.mintable {
            return Err(anyhow!("token is not mintable"));
        }
        if token.owner != caller {
            return Err(anyhow!("only token owner can mint"));
        }
        token.total_supply = token
            .total_supply
            .checked_add(amount)
            .ok_or_else(|| anyhow!("token total supply overflowed"))?;
        let balance = token.balances.get(&to).copied().unwrap_or(0);
        token.balances.insert(
            to.clone(),
            balance
                .checked_add(amount)
                .ok_or_else(|| anyhow!("token balance overflowed"))?,
        );

        let mut to_account = self
            .accounts
            .get(&to)
            .cloned()
            .unwrap_or_else(|| empty_account_state(to.clone()));
        credit_asset(&mut to_account, &symbol, amount)?;

        self.token_registry.insert(symbol.clone(), token);
        self.accounts.insert(to.clone(), to_account);
        self.pending_block_event = Some("ANRC20: Mint".to_string());
        self.emit_event(
            ChainEvent::new("TokenTransferred")
                .attr("symbol", &symbol)
                .attr("from", "MINT")
                .attr("to", &to)
                .attr("amount", amount),
        );
        self.pending_state_commit = true;

        self.token_registry
            .get(&symbol)
            .map(Anrc20Token::view)
            .ok_or_else(|| anyhow!("token mint failed"))
    }

    pub fn anrc20_transfer(
        &mut self,
        from: &str,
        to: &str,
        symbol: &str,
        amount: u64,
    ) -> Result<()> {
        if amount == 0 {
            return Err(anyhow!("transfer amount must be greater than zero"));
        }

        let symbol = dex::normalize_token_symbol(symbol)?;
        ensure_public_anrc20_symbol_allowed(&symbol)?;
        let from = from.trim().to_uppercase();
        let to = to.trim().to_uppercase();
        if !crate::transaction::is_valid_anet_wallet(&to) {
            return Err(anyhow!("token recipient must be a valid ANET wallet"));
        }
        if from == to {
            return Err(anyhow!("token sender and recipient must differ"));
        }

        let mut token = self
            .token_registry
            .get(&symbol)
            .cloned()
            .ok_or_else(|| anyhow!("token not found"))?;
        let token_from_balance = token.balances.get(&from).copied().unwrap_or(0);
        if token_from_balance < amount {
            return Err(anyhow!("insufficient token balance"));
        }
        let token_to_balance = token.balances.get(&to).copied().unwrap_or(0);
        let next_token_to_balance = token_to_balance
            .checked_add(amount)
            .ok_or_else(|| anyhow!("token balance overflowed"))?;

        let mut from_account = self
            .accounts
            .get(&from)
            .cloned()
            .ok_or_else(|| anyhow!("sender account not found"))?;
        debit_asset(&mut from_account, &symbol, amount)?;

        let mut to_account = self
            .accounts
            .get(&to)
            .cloned()
            .unwrap_or_else(|| empty_account_state(to.clone()));
        credit_asset(&mut to_account, &symbol, amount)?;

        token
            .balances
            .insert(from.clone(), token_from_balance - amount);
        token.balances.insert(to.clone(), next_token_to_balance);

        self.accounts.insert(from.clone(), from_account);
        self.accounts.insert(to.clone(), to_account);
        self.token_registry.insert(symbol.clone(), token);

        self.pending_block_event = Some("ANRC20: Transfer".to_string());
        self.emit_event(
            ChainEvent::new("TokenTransferred")
                .attr("symbol", &symbol)
                .attr("from", &from)
                .attr("to", &to)
                .attr("amount", amount),
        );
        self.pending_state_commit = true;

        Ok(())
    }

    fn ensure_eligible_account(&self, address: &str) -> Result<&AccountState> {
        let bridge_funded = self.bridge_funded_accounts.contains(address);
        let account = self
            .accounts
            .get(address)
            .ok_or_else(|| anyhow!("account not found"))?;
        if !Self::allow_ineligible_wallet_test_mode()
            && !bridge_funded
            && account.sessions < crate::activation::MIN_SESSIONS_FOR_ANET
        {
            return Err(anyhow!(
                "wallet must complete at least {} sessions before spending mined ANTS/ANET on native DEX",
                crate::activation::MIN_SESSIONS_FOR_ANET
            ));
        }
        Ok(account)
    }

    /// Value-protection gate for moving mined coins OUT of the L1 economy
    /// (bridge burn to wANET, DEX wrap to WANET, ANET-out swaps). The wallet's
    /// balance after the debit must still cover the unvested share of its
    /// mined (activated) coins: nothing unlocks for 6 months from first
    /// activation, then 25% unlocks every 3 months. Bridge-purchased coins
    /// are on top of the mined total and stay freely swappable; P2P transfers
    /// are never gated by this rule.
    fn ensure_vested_for_swap_out(&self, address: &str, debit_ants: u64) -> Result<()> {
        let Some(account) = self.accounts.get(address) else {
            return Ok(()); // no account -> the debit path reports its own error
        };
        if account.total_activated_ants == 0 {
            return Ok(()); // bridge-only wallet: nothing mined, nothing vests
        }
        let now_ms = Utc::now().timestamp_millis();
        let anchor_ms = self.activation_anchors.get(address).copied();
        let unvested = crate::activation::unvested_activated_ants(
            account.total_activated_ants,
            anchor_ms,
            now_ms,
        )
        .min(account.ants_balance);
        let balance_after = account.ants_balance.saturating_sub(debit_ants);
        if balance_after < unvested {
            let locked_over = unvested.saturating_sub(balance_after);
            let vested_bps = match anchor_ms {
                Some(anchor) => crate::activation::vested_fraction_bps(anchor, now_ms),
                None => 0,
            };
            return Err(anyhow!(
                "mined coins are still vesting: this swap-out would move {} locked ANTS. \
                 {}% of mined coins are unlocked today; the rest unlocks 25% every 3 months \
                 after a 6-month cliff from first activation. P2P transfers are not affected.",
                locked_over,
                vested_bps / 100
            ));
        }
        Ok(())
    }

    fn emit_event(&mut self, event: ChainEvent) {
        self.pending_events.push(event);
    }

    pub fn record_app_activity_event(
        &mut self,
        action: &str,
        wallet: Option<&str>,
        detail: Option<&str>,
    ) {
        let action = action.trim();
        if action.is_empty() {
            return;
        }

        let mut event = ChainEvent::new("AppActivity").attr("action", action);
        if let Some(wallet) = wallet {
            let wallet = wallet.trim().to_uppercase();
            if !wallet.is_empty() {
                event = event.attr("wallet", wallet);
            }
        }
        if let Some(detail) = detail {
            let detail = detail.trim();
            if !detail.is_empty() {
                event = event.attr("detail", detail);
            }
        }

        self.emit_event(event);
        if self.pending_block_event.is_none() {
            self.pending_block_event = Some("App: Activity Audit".to_owned());
        }
        self.pending_state_commit = true;
    }

    fn allow_ineligible_wallet_test_mode() -> bool {
        std::env::var("ANET_ALLOW_INELIGIBLE_WALLET_TEST")
            .map(|value| {
                let normalized = value.trim().to_ascii_lowercase();
                normalized == "1"
                    || normalized == "true"
                    || normalized == "yes"
                    || normalized == "on"
            })
            .unwrap_or(false)
    }

    pub fn has_block_in_epoch(&self, epoch_start: DateTime<Utc>) -> bool {
        self.blocks
            .last()
            .map(|block| block.epoch_start == epoch_start)
            .unwrap_or(false)
    }

    pub async fn create_block(
        &mut self,
        epoch_start: DateTime<Utc>,
        epoch_end: DateTime<Utc>,
    ) -> Result<Block> {
        let block_height = self
            .blocks
            .last()
            .map(|block| {
                block
                    .block_height
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("block height overflowed"))
            })
            .transpose()?
            .unwrap_or(0);
        let previous_hash = self
            .blocks
            .last()
            .map(|block| block.hash.clone())
            .unwrap_or_else(|| "GENESIS".to_owned());
        let persisted_previous_hash = db::get_last_hash(self.chain_db.as_ref())
            .await?
            .unwrap_or_else(|| "GENESIS".to_owned());
        if persisted_previous_hash != previous_hash {
            return Err(anyhow!(
                "database chain tip does not match in-memory chain tip"
            ));
        }
        let miners = self.eligible_miners.clone();
        let mut transactions = self.mempool.clone();
        sort_transactions_for_block(&mut transactions);
        let activated_supply_ants = self.pending_activated_supply_ants;
        let pending_block_event = self.pending_block_event.clone();
        let mut events = self.pending_events.clone();

        for transaction in &transactions {
            events.push(
                ChainEvent::new("TokenTransferred")
                    .with_tx_hash(transaction.id()?)
                    .attr("symbol", "ANET")
                    .attr("from", &transaction.from)
                    .attr("to", &transaction.to)
                    .attr("amount", transaction.amount_ants),
            );
        }

        let dex_snapshot = self.dex_pools.clone();
        let token_snapshot = self.token_registry.clone();
        let tpow_proofs = self.pending_proofs_for_block(300);
        let proof_root = bitcoin_merkle_root_for_json_value_slice(&tpow_proofs)?;
        // Prefer an explicit pending event; otherwise, if this block seals
        // mining proofs, label it so the sealed work is visible in the explorer
        // and block history.
        let block_event = pending_block_event.or_else(|| {
            if tpow_proofs.is_empty() {
                None
            } else {
                Some(format!(
                    "Consensus: TPoW Proofs sealed ({})",
                    tpow_proofs.len()
                ))
            }
        });

        let mut block = Block::new(
            block_height,
            epoch_start,
            epoch_end,
            previous_hash,
            transactions,
            activated_supply_ants,
            miners,
            block_event,
            events,
            HashMap::new(),
            dex_snapshot,
            token_snapshot,
            tpow_proofs,
            Vec::new(),
            String::new(),
            proof_root,
        )?;

        let mut next_accounts = self.accounts.clone();
        apply_block(&mut next_accounts, &block)?;
        block.account_state_changes = next_accounts
            .iter()
            .filter(|(address, account)| self.persisted_accounts.get(*address) != Some(*account))
            .map(|(address, account)| (address.clone(), account.clone()))
            .collect();
        block.state_root = bitcoin_merkle_root_for_serializable(&block.account_state_changes)?;
        block.validate_structure()?;
        block.hash = block.compute_hash()?;

        if !block.validate_hash()? {
            return Err(anyhow!("generated block hash failed validation"));
        }

        db::store_block_and_update_tip(self.chain_db.as_ref(), &block).await?;

        self.accounts = next_accounts;
        self.persisted_accounts = self.accounts.clone();
        for transaction in &block.transactions {
            if transaction.nonce > 0 {
                self.account_nonces
                    .insert(transaction.from.clone(), transaction.nonce);
            }
        }
        self.blocks.push(block.clone());
        // Extend the block-derived mining ledger with the proofs just sealed,
        // re-verifying each one so the live ledger is byte-identical to what a
        // cold replay of this block would independently compute.
        for proof_value in &block.tpow_proofs {
            if let Some(miner) = verify_sealed_proof(proof_value, &self.chain_id) {
                *self.mined_proof_counts.entry(miner).or_insert(0) += 1;
            }
        }
        self.mempool.clear();
        self.pending_activated_supply_ants = 0;
        self.pending_block_event = None;
        self.pending_events.clear();
        self.pending_mining_proofs.clear();
        self.pending_state_commit = false;

        tracing::info!(
            block_height = block.block_height,
            hash = %block.hash,
            tx_count = block.transactions.len(),
            activated_supply_ants = block.activated_supply_ants,
            miners = block.miners.len(),
            total_fees_ants = block.total_fees_ants,
            "created TPoW block"
        );

        Ok(block)
    }

    fn persist_genesis_snapshot(&self) -> Result<()> {
        let mut accounts = self
            .accounts
            .values()
            .filter(|account| account.activated_ants > 0 || account.sessions > 0)
            .map(|account| crate::activation::GenesisAccount {
                address: account.address.clone(),
                ants_balance: account.activated_ants,
                sessions: account.sessions,
                total_activated_ants: account.total_activated_ants,
            })
            .collect::<Vec<_>>();
        accounts.sort_by(|left, right| left.address.cmp(&right.address));

        crate::activation::write_genesis(
            &self.genesis_path,
            &crate::activation::GenesisConfig {
                chain_id: self.chain_id.clone(),
                genesis_time: self.genesis_time,
                accounts,
            },
        )
    }
}

pub async fn bootstrap_chain_store(
    genesis: &GenesisConfig,
    _chain_path: &std::path::Path,
) -> Result<()> {
    let chain_db = db::connect().await?;
    db::ensure_chain_initialized(chain_db.as_ref(), &genesis.chain_id, genesis.genesis_time).await
}

fn replay_blocks(accounts: &mut HashMap<String, AccountState>, blocks: &[Block]) -> Result<()> {
    reconcile_replay_sender_balances(accounts, blocks)?;

    for block in blocks {
        apply_block(accounts, block)?;
        for (address, account) in &block.account_state_changes {
            accounts.insert(address.clone(), account.clone());
        }
    }

    Ok(())
}

/// Rebuild the EVM bridge idempotency set from durable block history. Each
/// bridge credit is recorded as a transaction whose memo is
/// `bridge:evm:<lowercase tx hash>`; scanning those once on startup restores
/// the dedup guard that previously lived only in RAM.
fn collect_processed_bridge_hashes(blocks: &[Block]) -> HashSet<String> {
    let mut hashes = HashSet::new();
    for block in blocks {
        for transaction in &block.transactions {
            if let Some(hash) = canonical_bridge_credit_hash(transaction) {
                hashes.insert(hash);
            }
        }
    }
    hashes
}

/// Rebuild the set of bridge-funded recipient addresses from durable block
/// history. Each bridge credit is a `BRIDGE_TREASURY_ADDRESS` → recipient
/// transfer whose memo is `bridge:evm:<hash>`; the recipient (`to`) of any such
/// transaction holds paid-for ANET and is therefore exempt from the
/// `MIN_SESSIONS_FOR_ANET` spend gate. Scanning once on startup restores the
/// exemption that would otherwise live only in RAM.
fn collect_bridge_funded_accounts(blocks: &[Block]) -> HashSet<String> {
    let mut funded = HashSet::new();
    for block in blocks {
        for transaction in &block.transactions {
            if canonical_bridge_credit_hash(transaction).is_some()
                || is_migration_sweep_tx(transaction)
            {
                let recipient = transaction.to.trim().to_uppercase();
                funded.insert(recipient);
            }
        }
    }
    funded
}

/// Resolve a bridge credit recipient through the completed-migration map: if
/// `requested` is an already-migrated legacy address, returns its secp wallet;
/// otherwise returns `None` (the requested address is used unchanged).
fn resolve_forwarded_recipient(
    migrated_secp: &HashMap<String, String>,
    requested: &str,
) -> Option<String> {
    migrated_secp.get(requested).cloned()
}

/// True when `transaction` is a durable legacy -> secp migration re-sweep (see
/// [`NodeState::sweep_legacy_balance_to_secp`]). The destination (`to`) of such
/// a transaction holds recovered paid-for ANET and inherits the bridge-funded
/// spend exemption, just like a direct bridge credit.
fn is_migration_sweep_tx(transaction: &Transaction) -> bool {
    transaction.tx_type == "migration_sweep"
        && transaction.nonce == 0
        && transaction.fee_ants == crate::transaction::MIN_FEE_ANTS
        && transaction.amount_ants > 0
        && transaction.is_legacy_unsigned()
        && crate::transaction::is_valid_anet_wallet(&transaction.from)
        && crate::transaction::is_valid_anet_wallet(&transaction.to)
        && transaction
            .memo
            .strip_prefix(MIGRATION_SWEEP_MEMO_PREFIX)
            .is_some()
}

fn canonical_bridge_credit_hash(transaction: &Transaction) -> Option<String> {
    if transaction.tx_type != "bridge_credit"
        || transaction.from != BRIDGE_TREASURY_ADDRESS
        || transaction.nonce != 0
        || transaction.fee_ants != crate::transaction::MIN_FEE_ANTS
        || transaction.amount_ants == 0
        || !transaction.is_legacy_unsigned()
        || !crate::transaction::is_valid_anet_wallet(&transaction.to)
    {
        return None;
    }

    let hash = transaction
        .memo
        .strip_prefix(BRIDGE_CREDIT_MEMO_PREFIX)?
        .trim()
        .to_ascii_lowercase();
    if is_valid_evm_tx_hash(&hash) {
        Some(hash)
    } else {
        None
    }
}

fn is_valid_evm_tx_hash(hash: &str) -> bool {
    hash.len() == 66
        && hash.starts_with("0x")
        && hash[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Re-verify a single proof sealed in a block's `tpow_proofs` array, returning
/// the normalized miner address only if it is a cryptographically valid,
/// self-verifying TPoW proof for this chain.
///
/// This is freshness-exempt on purpose: sealed proofs are historical, so the
/// wall-clock window in `verify_tpow_proof_submission` must not apply. Proofs
/// that fail to parse (e.g. legacy decorative proofs sealed before the
/// self-verifying format, which carry no signature) or fail cryptographic
/// verification yield `None` and are never counted.
pub(crate) fn verify_sealed_proof(
    proof_value: &serde_json::Value,
    chain_id: &str,
) -> Option<String> {
    let submission: TPoWProofSubmission = serde_json::from_value(proof_value.clone()).ok()?;
    verify_tpow_proof_crypto(&submission, chain_id).ok()
}

/// Rebuild the trustless, block-derived TPoW mining ledger from durable block
/// history. Each block seals the full, self-verifying proofs in `tpow_proofs`;
/// this re-verifies every one of them cryptographically and tallies the
/// accepted count per miner. The result is a pure function of the chain's own
/// history — no database, oracle, or admin input — so any node (or third-party
/// auditor) computes exactly the same ledger from the same blocks.
fn collect_mining_accrual_from_blocks(blocks: &[Block], chain_id: &str) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = HashMap::new();
    for block in blocks {
        for proof_value in &block.tpow_proofs {
            if let Some(miner) = verify_sealed_proof(proof_value, chain_id) {
                *counts.entry(miner).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Rebuild each wallet's first-activation vesting anchor from durable block
/// history. The anchor is the timestamp of the wallet's FIRST sealed
/// `SessionActivation` event that credited coins (`credited_ants > 0`);
/// events that carry an explicit `vesting_anchor_ms` attribute use it
/// verbatim. A pure function of the chain's own records — any node computes
/// the same schedule from the same blocks.
fn collect_activation_anchors(blocks: &[Block]) -> HashMap<String, i64> {
    let mut anchors: HashMap<String, i64> = HashMap::new();
    for block in blocks {
        for event in &block.events {
            if event.event_type != "SessionActivation" {
                continue;
            }
            let credited = event
                .attributes
                .get("credited_ants")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            if credited == 0 {
                continue;
            }
            let Some(address) = event.attributes.get("address") else {
                continue;
            };
            let anchor = event
                .attributes
                .get("vesting_anchor_ms")
                .and_then(|value| value.parse::<i64>().ok())
                .unwrap_or_else(|| event.timestamp.timestamp_millis());
            anchors
                .entry(address.trim().to_uppercase())
                .and_modify(|existing| *existing = (*existing).min(anchor))
                .or_insert(anchor);
        }
    }
    anchors
}

/// Recover the most recently sealed session-progress root from block history,
/// so a restarted node does not re-emit an identical commitment before its next
/// sync. Scans blocks newest-first for the latest `SessionProgressRoot` event.
fn collect_last_session_root(blocks: &[Block]) -> Option<String> {
    for block in blocks.iter().rev() {
        for event in block.events.iter().rev() {
            if event.event_type == "SessionProgressRoot" {
                if let Some(root) = event.attributes.get("root") {
                    return Some(root.clone());
                }
            }
        }
    }
    None
}

/// Pure milestone detection: compare a new session-progress tree against the
/// previous one and emit a bounded set of `SessionMilestone` events for miners
/// whose progress crossed a meaningful boundary — first appearance on-chain
/// (`joined`) and crossing the 1,000-session spend threshold (`eligible`).
///
/// When `previous` is `None` (cold start / first sync) no events are produced:
/// the new tree only establishes the baseline, so a restart never re-emits a
/// `joined` milestone for every existing miner. Returns the events plus a flag
/// indicating the per-commit cap was hit (events truncated).
fn detect_session_milestones(
    previous: Option<&SessionTree>,
    new_tree: &SessionTree,
    cap: usize,
) -> (Vec<ChainEvent>, bool) {
    let Some(previous) = previous else {
        return (Vec::new(), false);
    };
    let previous_map: HashMap<&str, u64> = previous
        .entries()
        .iter()
        .map(|(wallet, sessions)| (wallet.as_str(), *sessions))
        .collect();
    let threshold = crate::activation::MIN_SESSIONS_FOR_ANET;

    let mut events = Vec::new();
    let mut truncated = false;
    for (wallet, sessions) in new_tree.entries() {
        let old = previous_map.get(wallet.as_str()).copied().unwrap_or(0);
        if *sessions <= old {
            continue; // only record forward progress
        }
        if old == 0 {
            events.push(
                ChainEvent::new("SessionMilestone")
                    .attr("address", wallet)
                    .attr("milestone", "joined")
                    .attr("sessions", *sessions)
                    .attr("eligible", *sessions >= threshold),
            );
        }
        if old < threshold && *sessions >= threshold {
            events.push(
                ChainEvent::new("SessionMilestone")
                    .attr("address", wallet)
                    .attr("milestone", "eligible")
                    .attr("sessions", *sessions)
                    .attr("eligible", true),
            );
        }
        if events.len() >= cap {
            truncated = true;
            break;
        }
    }
    (events, truncated)
}

/// Build the immutable on-chain receipt for a session activation.
///
/// This is the B1 "session = on-chain coin record": every time the verified
/// Web2/oracle feed raises a wallet's completed-session count or credits its
/// activation, the chain seals a structured `SessionActivation` event into the
/// block (events are committed to the v4 block hash, so the record is
/// immutable). It is **mint-neutral** — it records the credit the activation
/// path already applies under the 21,000,000 ANET cap; it never mints anything
/// itself. `eligible` reflects the single source-of-truth spend gate
/// (`is_session_eligible`): a wallet's coins exist on-chain immediately but
/// stay unspendable until it has completed `MIN_SESSIONS_FOR_ANET` sessions.
fn session_activation_event(
    address: &str,
    sessions: u64,
    sessions_delta: u64,
    credited_ants: u64,
    total_activated_ants: u64,
    source: &str,
) -> ChainEvent {
    ChainEvent::new("SessionActivation")
        .attr("address", address)
        .attr("sessions", sessions)
        .attr("sessions_delta", sessions_delta)
        .attr("credited_ants", credited_ants)
        .attr("total_activated_ants", total_activated_ants)
        .attr("eligible", crate::activation::is_session_eligible(sessions))
        .attr("source", source)
}

fn bitcoin_merkle_root_for_serializable<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_value(value)?;
    bitcoin_merkle_root_for_json_value(&json)
}

#[cfg(feature = "abci-testnet")]
pub(crate) fn abci_testnet_state_root<T: Serialize>(value: &T) -> Result<String> {
    bitcoin_merkle_root_for_serializable(value)
}

#[cfg(feature = "abci-testnet")]
pub(crate) fn abci_testnet_proof_root(values: &[serde_json::Value]) -> Result<String> {
    bitcoin_merkle_root_for_json_value_slice(values)
}

fn bitcoin_merkle_root_for_json_value(value: &serde_json::Value) -> Result<String> {
    let canonical = canonical_json_string(value)?;
    let leaf = bitcoin::sha256d(canonical.as_bytes());
    Ok(bitcoin::display_hash(&bitcoin::merkle_root(&[leaf])))
}

fn bitcoin_merkle_root_for_json_value_slice(values: &[serde_json::Value]) -> Result<String> {
    let leaves = values
        .iter()
        .map(|value| {
            let canonical = canonical_json_string(value)?;
            Ok(bitcoin::sha256d(canonical.as_bytes()))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(bitcoin::display_hash(&bitcoin::merkle_root(&leaves)))
}

fn rebuild_account_nonces(blocks: &[Block]) -> Result<HashMap<String, u64>> {
    let mut nonces = HashMap::new();
    for block in blocks {
        for transaction in &block.transactions {
            if transaction.nonce == 0 {
                continue;
            }

            let expected = nonces
                .get(&transaction.from)
                .copied()
                .unwrap_or(0_u64)
                .checked_add(1)
                .ok_or_else(|| anyhow!("nonce overflow while rebuilding history"))?;
            if transaction.nonce != expected {
                return Err(anyhow!(
                    "invalid nonce sequence for {} in stored block {}: expected {}, found {}",
                    transaction.from,
                    block.block_height,
                    expected,
                    transaction.nonce
                ));
            }
            nonces.insert(transaction.from.clone(), transaction.nonce);
        }
    }
    Ok(nonces)
}

fn rebuild_dex_pools_from_blocks(blocks: &[Block]) -> HashMap<String, DexPool> {
    blocks
        .last()
        .map(|block| block.dex_pools.clone())
        .unwrap_or_default()
}

fn rebuild_token_registry_from_blocks(blocks: &[Block]) -> HashMap<String, Anrc20Token> {
    blocks
        .last()
        .map(|block| block.token_registry.clone())
        .unwrap_or_default()
}

fn build_dex_pool_audit(
    current_pool: &DexPool,
    token: Option<&Anrc20Token>,
    blocks: &[Block],
) -> DexPoolAuditView {
    let mut creation_index = None;
    let mut was_present = false;
    for (index, block) in blocks.iter().enumerate() {
        let is_present = block.dex_pools.contains_key(&current_pool.pair_id);
        if is_present && !was_present {
            creation_index = Some(index);
        }
        was_present = is_present;
    }
    let creation = creation_index.and_then(|index| blocks.get(index));
    let initial_pool = creation
        .and_then(|block| block.dex_pools.get(&current_pool.pair_id))
        .unwrap_or(current_pool);
    let creation_event = creation.and_then(|block| block.block_event.clone());
    let creation_source = match creation_event.as_deref() {
        Some("Genesis: Bootstrap DEX Pool") => "bootstrap_admin_generated",
        Some("DEX: Create Pool") => "wallet_debited",
        _ => "unknown",
    }
    .to_owned();

    let mut admin_top_up_detected = false;
    let mut post_creation_swap_detected = false;
    if let Some(index) = creation_index {
        for block in blocks.iter().skip(index.saturating_add(1)) {
            if !block.dex_pools.contains_key(&current_pool.pair_id) {
                continue;
            }
            match block.block_event.as_deref() {
                Some("Admin: Top Up Liquidity") => admin_top_up_detected = true,
                Some("DEX: Swap") => post_creation_swap_detected = true,
                _ => {}
            }
        }
    }

    let reserves_unchanged_since_creation = current_pool.anet_reserve_ants
        == initial_pool.anet_reserve_ants
        && current_pool.token_reserve_units == initial_pool.token_reserve_units
        && current_pool.total_lp_units == initial_pool.total_lp_units;
    let onchain_funding_auditable = creation_source == "wallet_debited" && !admin_top_up_detected;
    let external_backing_auditable = false;
    let token_pool_escrow_units = token.and_then(|item| {
        item.balances
            .get(&dex_pool_escrow_account(&current_pool.pair_id))
            .copied()
    });
    let token_pool_escrow_matches_reserve = token_pool_escrow_units
        .map(u128::from)
        .is_some_and(|units| units == current_pool.token_reserve_units);
    let suitable_for_l1_price_discovery =
        onchain_funding_auditable && token.is_some() && token_pool_escrow_matches_reserve;
    let suitable_for_external_price_discovery =
        suitable_for_l1_price_discovery && external_backing_auditable;

    let mut lp_providers = current_pool
        .lp_positions
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    lp_providers.sort();

    let mut warnings = Vec::new();
    if creation_source == "bootstrap_admin_generated" {
        warnings.push(
            "pool reserves were generated directly by an admin bootstrap and were not debited from a provider wallet"
                .to_owned(),
        );
    } else if creation_source == "unknown" {
        warnings.push("pool creation source could not be proven from block history".to_owned());
    }
    if admin_top_up_detected {
        warnings.push("an admin-generated liquidity top-up exists in pool history".to_owned());
    }
    if token.is_none() {
        warnings.push(
            "paired asset is absent from the ANRC-20 registry, so supply and ownership are not tracked"
                .to_owned(),
        );
    } else if !token_pool_escrow_matches_reserve {
        warnings.push(
            "paired asset registry does not show a pool escrow balance matching the pool reserve"
                .to_owned(),
        );
    }
    if !suitable_for_l1_price_discovery {
        warnings.push(
            "pool is excluded from native L1 price discovery until it is wallet-funded, token-registered, and free of admin liquidity history"
                .to_owned(),
        );
    }
    warnings.push(
        "external reserve backing is not part of native L1 AMM price discovery; do not present this pool as a USD redeemability guarantee without separate reserve proof"
            .to_owned(),
    );

    let status = if creation_source == "bootstrap_admin_generated" {
        "bootstrap_not_real"
    } else if admin_top_up_detected {
        "admin_liquidity_not_real"
    } else if token.is_none() {
        "wallet_funded_asset_unregistered"
    } else if !token_pool_escrow_matches_reserve {
        "pool_escrow_unverified"
    } else if suitable_for_l1_price_discovery {
        "l1_price_discovery"
    } else {
        "not_l1_price_discovery"
    }
    .to_owned();

    DexPoolAuditView {
        pair_id: current_pool.pair_id.clone(),
        token_symbol: current_pool.token_symbol.clone(),
        creation_block_height: creation.map(|block| block.block_height),
        creation_block_hash: creation.map(|block| block.hash.clone()),
        creation_event,
        creation_source,
        initial_anet_reserve_ants: initial_pool.anet_reserve_ants.to_string(),
        initial_token_reserve_units: initial_pool.token_reserve_units.to_string(),
        current_anet_reserve_ants: current_pool.anet_reserve_ants.to_string(),
        current_token_reserve_units: current_pool.token_reserve_units.to_string(),
        current_total_lp_units: current_pool.total_lp_units.to_string(),
        lp_providers,
        token_registered: token.is_some(),
        token_total_supply_units: token.map(|item| item.total_supply),
        token_pool_escrow_units,
        token_pool_escrow_matches_reserve,
        admin_top_up_detected,
        post_creation_swap_detected,
        reserves_unchanged_since_creation,
        onchain_funding_auditable,
        external_backing_auditable,
        suitable_for_l1_price_discovery,
        suitable_for_external_price_discovery,
        status,
        warnings,
    }
}

fn sort_transactions_for_block(transactions: &mut [Transaction]) {
    transactions.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then_with(|| left.nonce.cmp(&right.nonce))
            .then_with(|| left.timestamp.cmp(&right.timestamp))
            .then_with(|| left.tx_hash.cmp(&right.tx_hash))
    });
}

#[cfg(feature = "abci-testnet")]
pub(crate) fn sort_abci_testnet_transactions(transactions: &mut [Transaction]) {
    sort_transactions_for_block(transactions);
}

/// Pure, database-free replay of a verified block history: the same
/// validation and state rules `NodeState::from_genesis` applies on startup.
#[cfg(feature = "abci-testnet")]
pub(crate) struct ReplayedChain {
    pub accounts: HashMap<String, AccountState>,
    pub account_nonces: HashMap<String, u64>,
    pub dex_pools: HashMap<String, DexPool>,
    pub token_registry: HashMap<String, Anrc20Token>,
    pub tip_hash: String,
    pub tip_height: u64,
    pub block_count: u64,
}

#[cfg(feature = "abci-testnet")]
pub(crate) fn replay_verified_chain(blocks: &[Block]) -> Result<ReplayedChain> {
    validate_block_sequence(blocks)?;
    let mut accounts = HashMap::new();
    replay_blocks(&mut accounts, blocks)?;
    let account_nonces = rebuild_account_nonces(blocks)?;
    let tip = blocks
        .last()
        .ok_or_else(|| anyhow!("cannot replay an empty chain"))?;
    Ok(ReplayedChain {
        accounts,
        account_nonces,
        dex_pools: rebuild_dex_pools_from_blocks(blocks),
        token_registry: rebuild_token_registry_from_blocks(blocks),
        tip_hash: tip.hash.clone(),
        tip_height: tip.block_height,
        block_count: blocks.len() as u64,
    })
}

fn reconcile_replay_sender_balances(
    accounts: &mut HashMap<String, AccountState>,
    blocks: &[Block],
) -> Result<()> {
    let mut simulation_accounts = accounts.clone();
    let mut sender_topups: HashMap<String, u64> = HashMap::new();

    for block in blocks {
        for transaction in &block.transactions {
            let sender = simulation_accounts
                .entry(transaction.from.clone())
                .or_insert_with(|| empty_account_state(transaction.from.clone()));
            let debit = transaction.total_debit()?;

            if sender.ants_balance < debit {
                if !allows_replay_sender_topup(transaction) {
                    return Err(anyhow!(
                        "stored block {} contains transaction from {} without sufficient replay balance",
                        block.block_height,
                        transaction.from
                    ));
                }
                let deficit = debit - sender.ants_balance;
                let topup = sender_topups.entry(transaction.from.clone()).or_insert(0);
                *topup = topup
                    .checked_add(deficit)
                    .ok_or_else(|| anyhow!("replay sender topup overflowed"))?;
                sender.ants_balance = sender
                    .ants_balance
                    .checked_add(deficit)
                    .ok_or_else(|| anyhow!("replay sender balance overflowed"))?;
                sender.activated_ants = sender.activated_ants.saturating_add(deficit);
                sender.total_activated_ants = sender.total_activated_ants.saturating_add(deficit);
            }

            sender.ants_balance = sender
                .ants_balance
                .checked_sub(debit)
                .ok_or_else(|| anyhow!("sender balance underflow while reconciling replay"))?;
            sender.activated_ants = sender.activated_ants.saturating_sub(debit);

            let recipient = simulation_accounts
                .entry(transaction.to.clone())
                .or_insert_with(|| empty_account_state(transaction.to.clone()));
            recipient.ants_balance = recipient
                .ants_balance
                .checked_add(transaction.amount_ants)
                .ok_or_else(|| anyhow!("recipient balance overflow while reconciling replay"))?;
        }

        distribute_fees(&mut simulation_accounts, block)?;
    }

    for (address, amount) in sender_topups {
        let account = accounts
            .entry(address.clone())
            .or_insert_with(|| empty_account_state(address.clone()));
        account.ants_balance = account
            .ants_balance
            .checked_add(amount)
            .ok_or_else(|| anyhow!("sender replay topup overflowed"))?;
        account.activated_ants = account.activated_ants.saturating_add(amount);
        account.total_activated_ants = account.total_activated_ants.saturating_add(amount);

        tracing::warn!(
            wallet = %address,
            amount_ants = amount,
            "replay reconciliation credited sender balance to satisfy historical block debits"
        );
    }

    Ok(())
}

fn allows_replay_sender_topup(transaction: &Transaction) -> bool {
    // Legacy-unsigned transactions predate on-chain sender balances: the
    // pre-signed-payload bootstrap era (early integration-test transfers),
    // bridge-treasury credits, and Pi settlements. Their senders were funded by
    // the Web2 ledger rather than by a prior on-chain credit, so reconciling
    // replay must reconstruct that funding instead of refusing to load the
    // chain. Signed transactions, by contrast, were only ever accepted by the
    // live node after a sufficient-balance check, so a signed debit that
    // exceeds the replayed balance signals a genuinely corrupt block and must
    // still error (see `replay_rejects_insufficient_balance_for_user_transaction`).
    //
    // This cannot mint money for new activity: `queue_transaction` requires a
    // signature, and `Block::validate_structure` (run in
    // `validate_block_sequence`, before replay) rejects any unauthorized
    // unsigned transaction in a v4 block. Only immutable historical blocks and
    // already-validated system transactions can reach here unsigned.
    transaction.is_legacy_unsigned()
        || canonical_bridge_credit_hash(transaction).is_some()
        || is_canonical_pi_settlement_transaction(transaction)
}

fn is_canonical_pi_settlement_transaction(transaction: &Transaction) -> bool {
    transaction.tx_type == "pi_settlement"
        && transaction.memo.starts_with("Pi Payment Settlement: ")
        && transaction.nonce == 0
        && transaction.amount_ants == 1
        && transaction.fee_ants == crate::transaction::MIN_FEE_ANTS
        && transaction.is_legacy_unsigned()
        && crate::transaction::is_valid_anet_wallet(&transaction.from)
        && crate::transaction::is_valid_anet_wallet(&transaction.to)
}

fn empty_account_state(address: String) -> AccountState {
    AccountState {
        address,
        ants_balance: 0,
        activated_ants: 0,
        total_activated_ants: 0,
        sessions: 0,
        asset_balances: HashMap::new(),
    }
}

fn validate_block_sequence(blocks: &[Block]) -> Result<()> {
    let mut previous_hash = "GENESIS".to_owned();
    let mut previous_epoch_end = None;
    let mut label_mismatch_count = 0_usize;
    let mut first_label_mismatch: Option<(u64, usize)> = None;
    let mut last_label_mismatch: Option<(u64, usize)> = None;

    for (index, block) in blocks.iter().enumerate() {
        block.validate_structure()?;
        if !block.validate_hash()? {
            return Err(anyhow!(
                "stored block {} failed hash validation",
                block.block_height
            ));
        }
        validate_block_commitment_roots(block)?;
        // The cryptographic chain (each block's hash bound to the previous
        // block's hash via `previous_hash`) is the authoritative integrity
        // check. The `block_height` field is just a label; in early production
        // history a small number of blocks were minted with non-contiguous
        // height labels. We aggregate any mismatches into a single summary
        // line at the end so logs stay readable, but we do NOT refuse to load
        // the chain over a label mismatch — that would take a fully-intact,
        // hash-linked history offline for a cosmetic field.
        if block.block_height != index as u64 {
            label_mismatch_count += 1;
            if first_label_mismatch.is_none() {
                first_label_mismatch = Some((block.block_height, index));
            }
            last_label_mismatch = Some((block.block_height, index));
        }
        if block.previous_hash != previous_hash {
            return Err(anyhow!(
                "stored block {} has invalid previous hash linkage",
                block.block_height
            ));
        }
        if let Some(previous_epoch_end) = previous_epoch_end {
            if block.epoch_start < previous_epoch_end {
                return Err(anyhow!(
                    "stored block {} overlaps an earlier epoch",
                    block.block_height
                ));
            }
        }

        previous_hash = block.hash.clone();
        previous_epoch_end = Some(block.epoch_end);
    }

    if label_mismatch_count > 0 {
        let (first_stored, first_pos) = first_label_mismatch.unwrap_or((0, 0));
        let (last_stored, last_pos) = last_label_mismatch.unwrap_or((0, 0));
        tracing::warn!(
            count = label_mismatch_count,
            first_stored_height = first_stored,
            first_position = first_pos,
            last_stored_height = last_stored,
            last_position = last_pos,
            "block height labels diverge from linked-list position on {} legacy block(s); cryptographic chain is intact, continuing",
            label_mismatch_count
        );
    }

    Ok(())
}

fn validate_block_commitment_roots(block: &Block) -> Result<()> {
    if block.hash_version < 4 {
        return Ok(());
    }
    if is_legacy_blank_genesis_roots(block) {
        return Ok(());
    }

    // Early v4 blocks were minted during the transition before commitment-root
    // computation was wired in, so they carry EMPTY `state_root` / `proof_root`
    // strings even though they have real account-state changes. Their integrity
    // is NOT weakened by skipping the root re-derivation here: the v4 block hash
    // already commits `account_state_changes`, `tpow_proofs`, `state_root` and
    // `proof_root`, and `validate_hash` (run before this) has already confirmed
    // the stored block matches that hash, while the `previous_hash` chain
    // prevents any historical rewrite. A current producer always emits
    // non-empty roots (the Merkle root of even an empty set is a fixed non-empty
    // hash), so an empty string is an unambiguous "legacy, pre-roots" marker —
    // never a current block trying to skip validation. Validate each root only
    // when it was actually populated.
    if !block.state_root.is_empty() {
        let expected_state_root = bitcoin_merkle_root_for_serializable(&block.account_state_changes)?;
        if block.state_root != expected_state_root {
            return Err(anyhow!(
                "stored block {} has invalid state_root",
                block.block_height
            ));
        }
    }

    if !block.proof_root.is_empty() {
        let expected_proof_root = bitcoin_merkle_root_for_json_value_slice(&block.tpow_proofs)?;
        if block.proof_root != expected_proof_root {
            return Err(anyhow!(
                "stored block {} has invalid proof_root",
                block.block_height
            ));
        }
    }

    Ok(())
}

fn is_legacy_blank_genesis_roots(block: &Block) -> bool {
    block.block_height == 0
        && block.previous_hash == "GENESIS"
        && block.transactions.is_empty()
        && block.account_state_changes.is_empty()
        && block.tpow_proofs.is_empty()
        && block.state_root.is_empty()
        && block.proof_root.is_empty()
}

fn apply_block(accounts: &mut HashMap<String, AccountState>, block: &Block) -> Result<()> {
    for transaction in &block.transactions {
        let sender = accounts
            .get_mut(&transaction.from)
            .ok_or_else(|| anyhow!("sender account not found while applying block"))?;
        let debit = transaction.total_debit()?;
        sender.ants_balance = sender
            .ants_balance
            .checked_sub(debit)
            .ok_or_else(|| anyhow!("sender balance underflow while applying block"))?;
        sender.activated_ants = sender.activated_ants.saturating_sub(debit);

        let recipient = accounts
            .entry(transaction.to.clone())
            .or_insert(AccountState {
                address: transaction.to.clone(),
                ants_balance: 0,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 0,
                asset_balances: HashMap::new(),
            });
        recipient.ants_balance = recipient
            .ants_balance
            .checked_add(transaction.amount_ants)
            .ok_or_else(|| anyhow!("recipient balance overflow while applying block"))?;
    }

    distribute_fees(accounts, block)
}

#[cfg(feature = "abci-testnet")]
pub(crate) fn apply_abci_testnet_block(
    accounts: &mut HashMap<String, AccountState>,
    block: &Block,
) -> Result<()> {
    apply_block(accounts, block)
}

fn distribute_fees(accounts: &mut HashMap<String, AccountState>, block: &Block) -> Result<()> {
    if block.total_fees_ants == 0 {
        return Ok(());
    }

    if block.miners.is_empty() {
        let reserve = accounts
            .entry(SYSTEM_FEE_RESERVE_ADDRESS.to_owned())
            .or_insert(AccountState {
                address: SYSTEM_FEE_RESERVE_ADDRESS.to_owned(),
                ants_balance: 0,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 0,
                asset_balances: HashMap::new(),
            });
        reserve.ants_balance = reserve
            .ants_balance
            .checked_add(block.total_fees_ants)
            .ok_or_else(|| anyhow!("fee reserve overflowed"))?;
        return Ok(());
    }

    let remainder = block.total_fees_ants % block.miners.len() as u64;
    for miner in &block.miners {
        let account = accounts.entry(miner.clone()).or_insert(AccountState {
            address: miner.clone(),
            ants_balance: 0,
            activated_ants: 0,
            total_activated_ants: 0,
            sessions: 0,
            asset_balances: HashMap::new(),
        });
        account.ants_balance = account
            .ants_balance
            .checked_add(block.fee_per_miner)
            .ok_or_else(|| anyhow!("miner fee distribution overflowed"))?;
    }

    if remainder > 0 {
        let reserve = accounts
            .entry(SYSTEM_FEE_RESERVE_ADDRESS.to_owned())
            .or_insert(AccountState {
                address: SYSTEM_FEE_RESERVE_ADDRESS.to_owned(),
                ants_balance: 0,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 0,
                asset_balances: HashMap::new(),
            });
        reserve.ants_balance = reserve
            .ants_balance
            .checked_add(remainder)
            .ok_or_else(|| anyhow!("fee reserve overflowed"))?;
    }

    Ok(())
}

pub fn format_anet_fixed(ants: u64) -> String {
    let whole = ants / ANTS_PER_ANET;
    let fractional = ants % ANTS_PER_ANET;
    format!("{whole}.{fractional:08}")
}

fn debit_anet(account: &mut AccountState, amount: u64) -> Result<()> {
    account.ants_balance = account
        .ants_balance
        .checked_sub(amount)
        .ok_or_else(|| anyhow!("insufficient ANET balance"))?;
    account.activated_ants = account.activated_ants.saturating_sub(amount);
    Ok(())
}

fn credit_anet(account: &mut AccountState, amount: u64) -> Result<()> {
    account.ants_balance = account
        .ants_balance
        .checked_add(amount)
        .ok_or_else(|| anyhow!("ANET balance overflowed"))?;
    Ok(())
}

fn debit_asset(account: &mut AccountState, symbol: &str, amount: u64) -> Result<()> {
    let balance = account.asset_balances.get(symbol).copied().unwrap_or(0);
    if balance < amount {
        return Err(anyhow!("insufficient {symbol} balance"));
    }
    let next = balance
        .checked_sub(amount)
        .ok_or_else(|| anyhow!("asset balance underflowed"))?;
    account.asset_balances.insert(symbol.to_owned(), next);
    Ok(())
}

fn dex_pool_escrow_account(pair_id: &str) -> String {
    format!("__dex_pool_{}__", pair_id.to_ascii_uppercase())
}

fn move_token_registry_balance(
    token_registry: &mut HashMap<String, Anrc20Token>,
    symbol: &str,
    from: &str,
    to: &str,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Err(anyhow!("token movement amount must be greater than zero"));
    }
    let token = token_registry
        .get_mut(symbol)
        .ok_or_else(|| anyhow!("token must be registered before it can back a DEX pool"))?;
    let from_balance = token.balances.get(from).copied().unwrap_or(0);
    if from_balance < amount {
        return Err(anyhow!("insufficient registered {symbol} balance"));
    }
    let to_balance = token.balances.get(to).copied().unwrap_or(0);
    let next_to = to_balance
        .checked_add(amount)
        .ok_or_else(|| anyhow!("registered token balance overflowed"))?;
    token.balances.insert(from.to_owned(), from_balance - amount);
    token.balances.insert(to.to_owned(), next_to);
    Ok(())
}

fn ensure_wanet_token(token_registry: &mut HashMap<String, Anrc20Token>) -> &mut Anrc20Token {
    token_registry
        .entry(WANET_SYMBOL.to_owned())
        .or_insert_with(|| Anrc20Token {
            symbol: WANET_SYMBOL.to_owned(),
            name: "Wrapped ANET".to_owned(),
            decimals: 8,
            total_supply: 0,
            owner: BRIDGE_TREASURY_ADDRESS.to_owned(),
            mintable: false,
            balances: HashMap::new(),
        })
}

fn credit_wanet_registry_balance(
    token_registry: &mut HashMap<String, Anrc20Token>,
    to: &str,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Err(anyhow!("WANET wrap amount must be greater than zero"));
    }
    let token = ensure_wanet_token(token_registry);
    let current_balance = token.balances.get(to).copied().unwrap_or(0);
    let next_total_supply = token
        .total_supply
        .checked_add(amount)
        .ok_or_else(|| anyhow!("WANET total supply overflowed"))?;
    let next_balance = current_balance
        .checked_add(amount)
        .ok_or_else(|| anyhow!("WANET balance overflowed"))?;
    token.total_supply = next_total_supply;
    token.balances.insert(to.to_owned(), next_balance);
    Ok(())
}

fn debit_wanet_registry_balance(
    token_registry: &mut HashMap<String, Anrc20Token>,
    from: &str,
    amount: u64,
) -> Result<()> {
    if amount == 0 {
        return Err(anyhow!("WANET unwrap amount must be greater than zero"));
    }
    let token = token_registry
        .get_mut(WANET_SYMBOL)
        .ok_or_else(|| anyhow!("WANET registry is missing"))?;
    let current_balance = token.balances.get(from).copied().unwrap_or(0);
    if current_balance < amount {
        return Err(anyhow!("insufficient registered WANET balance"));
    }
    let next_total_supply = token
        .total_supply
        .checked_sub(amount)
        .ok_or_else(|| anyhow!("WANET total supply underflowed"))?;
    token.total_supply = next_total_supply;
    token.balances.insert(from.to_owned(), current_balance - amount);
    Ok(())
}

fn credit_asset(account: &mut AccountState, symbol: &str, amount: u64) -> Result<()> {
    let balance = account.asset_balances.get(symbol).copied().unwrap_or(0);
    let next = balance
        .checked_add(amount)
        .ok_or_else(|| anyhow!("asset balance overflowed"))?;
    account.asset_balances.insert(symbol.to_owned(), next);
    Ok(())
}

fn ensure_public_anrc20_symbol_allowed(symbol: &str) -> Result<()> {
    if symbol == WANET_SYMBOL {
        return Err(anyhow!(
            "token symbol WANET is reserved for internal wrap/unwrap accounting"
        ));
    }
    Ok(())
}

fn ensure_anrc20_creator_eligible(sessions: Option<u64>, is_bootstrap: bool) -> Result<()> {
    if !is_bootstrap && sessions.is_some_and(crate::activation::is_session_eligible) {
        return Ok(());
    }
    Err(anyhow!(
        "ANRC-20 creation requires at least {} completed sessions from a non-bootstrap miner",
        crate::activation::MIN_SESSIONS_FOR_ANET
    ))
}

/// One-way bridge policy tripwire. `true` means every live wANET/EVM/spoke
/// → native credit is refused at the state layer, with no env or admin
/// override. Changing this to `false` is an intentional protocol change and
/// must fail the accompanying invariant test.
fn one_way_bridge_in_active() -> bool {
    true
}

/// One-way bridge policy: native ANET may leave L1 only from an eligible
/// miner wallet (≥ MIN_SESSIONS_FOR_ANET on-chain sessions) or a historical
/// bridge-funded wallet. Returns the refusal reason, or None when allowed.
/// Pure so the attack matrix is directly unit-testable.
fn export_eligibility_error(sessions: u64, bridge_funded: bool) -> Option<String> {
    if bridge_funded {
        return None;
    }
    if sessions >= crate::activation::MIN_SESSIONS_FOR_ANET {
        return None;
    }
    Some(format!(
        "bridge export requires an eligible miner wallet: at least {} on-chain \
         sessions are needed before native ANET can leave L1 (wallet has {})",
        crate::activation::MIN_SESSIONS_FOR_ANET,
        sessions
    ))
}

/// Applies an L1 → external bridge burn to the account map: debits
/// `amount_ants + fee_ants` from `normalized`, destroys `amount_ants` from
/// L1 supply, and redistributes only the fee (validators, or the system fee
/// reserve when the validator set is empty). All-or-nothing: failures leave
/// `accounts` untouched. Free function so supply conservation is provable in
/// unit tests without a live database.
fn execute_bridge_burn(
    accounts: &mut HashMap<String, AccountState>,
    validators: &[String],
    normalized: &str,
    amount_ants: u64,
    fee_ants: u64,
) -> Result<u64> {
    let total_debit = amount_ants
        .checked_add(fee_ants)
        .ok_or_else(|| anyhow!("burn amount + validator fee overflowed u64"))?;
    let mut next_accounts = accounts.clone();

    // Build the complete next account state off to the side so any fee
    // credit overflow leaves the live state untouched.
    let new_balance = {
        let account = next_accounts
            .get_mut(normalized)
            .ok_or_else(|| anyhow!("account not found"))?;
        if account.ants_balance < total_debit {
            return Err(anyhow!(
                "insufficient ANET balance: have {} ants, need {} ants \
                 ({} bridge + {} validator fee)",
                account.ants_balance,
                total_debit,
                amount_ants,
                fee_ants
            ));
        }
        debit_anet(account, total_debit)?;
        account.ants_balance
    };

    // Distribute the validator fee. If there are no validators (genesis
    // race or post-clawback empty set), the fee goes to the system fee
    // reserve so it isn't lost.
    if validators.is_empty() {
        let reserve = next_accounts
            .entry(SYSTEM_FEE_RESERVE_ADDRESS.to_owned())
            .or_insert_with(|| empty_account_state(SYSTEM_FEE_RESERVE_ADDRESS.to_owned()));
        reserve.ants_balance = reserve
            .ants_balance
            .checked_add(fee_ants)
            .ok_or_else(|| anyhow!("fee reserve overflow"))?;
    } else {
        let n = validators.len() as u64;
        let per = fee_ants / n;
        let remainder = fee_ants % n;
        if per > 0 {
            for v in validators {
                let acc = next_accounts.entry(v.clone()).or_insert_with(|| AccountState {
                    address: v.clone(),
                    ants_balance: 0,
                    activated_ants: 0,
                    total_activated_ants: 0,
                    sessions: 0,
                    asset_balances: HashMap::new(),
                });
                acc.ants_balance = acc
                    .ants_balance
                    .checked_add(per)
                    .ok_or_else(|| anyhow!("validator fee credit overflow"))?;
            }
        }
        if remainder > 0 {
            let reserve = next_accounts
                .entry(SYSTEM_FEE_RESERVE_ADDRESS.to_owned())
                .or_insert_with(|| empty_account_state(SYSTEM_FEE_RESERVE_ADDRESS.to_owned()));
            reserve.ants_balance = reserve
                .ants_balance
                .checked_add(remainder)
                .ok_or_else(|| anyhow!("fee reserve remainder overflow"))?;
        }
    }

    *accounts = next_accounts;
    Ok(new_balance)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};
    use serde_json::Value;

    use super::{
        build_dex_pool_audit, collect_bridge_funded_accounts, collect_processed_bridge_hashes,
        credit_wanet_registry_balance, debit_wanet_registry_balance, detect_session_milestones,
        dex_pool_escrow_account, ensure_anrc20_creator_eligible, move_token_registry_balance,
        rebuild_account_nonces, replay_blocks, session_activation_event, sort_transactions_for_block,
        validate_block_sequence, AccountState, BRIDGE_CREDIT_MEMO_PREFIX,
        BRIDGE_TREASURY_ADDRESS, SYSTEM_FEE_RESERVE_ADDRESS, WANET_SYMBOL,
    };
    use crate::block::Block;
    use crate::dex::DexPool;
    use crate::session_commit::SessionTree;
    use crate::token::Anrc20Token;
    use crate::transaction::Transaction;

    fn tx(from: &str, nonce: u64, ts_seconds: i64, tx_hash: &str) -> Transaction {
        Transaction {
            tx_type: "transfer".to_owned(),
            from: from.to_owned(),
            to: "ANETFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_owned(),
            amount_ants: 1,
            fee_ants: 1_000,
            nonce,
            memo: String::new(),
            timestamp: Utc
                .timestamp_opt(ts_seconds, 0)
                .single()
                .expect("valid timestamp"),
            chain_id: "anet-mainnet".to_owned(),
            payload: Value::Object(serde_json::Map::new()),
            signature: "sig".to_owned(),
            tx_hash: tx_hash.to_owned(),
        }
    }

    fn historical_block(
        block_height: u64,
        previous_hash: &str,
        transactions: Vec<Transaction>,
    ) -> Block {
        Block {
            hash_version: 0,
            block_height,
            epoch_start: Utc
                .timestamp_opt(block_height as i64 * 60, 0)
                .single()
                .expect("valid timestamp"),
            epoch_end: Utc
                .timestamp_opt(block_height as i64 * 60 + 30, 0)
                .single()
                .expect("valid timestamp"),
            previous_hash: previous_hash.to_owned(),
            hash: format!("block-hash-{block_height}"),
            transactions,
            activated_supply_ants: 0,
            total_fees_ants: 0,
            miners: Vec::new(),
            fee_per_miner: 0,
            block_event: None,
            events: Vec::new(),
            account_state_changes: HashMap::new(),
            dex_pools: HashMap::new(),
            token_registry: HashMap::new(),
            tpow_proofs: Vec::new(),
            validator_votes: Vec::new(),
            state_root: String::new(),
            proof_root: String::new(),
        }
    }

    fn sweep_tx(legacy: &str, secp: &str, amount: u64) -> Transaction {
        Transaction {
            tx_type: "migration_sweep".to_owned(),
            from: legacy.to_owned(),
            to: secp.to_owned(),
            amount_ants: amount,
            fee_ants: crate::transaction::MIN_FEE_ANTS,
            nonce: 0,
            memo: format!("{}{}", super::MIGRATION_SWEEP_MEMO_PREFIX, legacy),
            timestamp: Utc.timestamp_opt(1_000, 0).single().expect("valid timestamp"),
            chain_id: "anet-mainnet".to_owned(),
            payload: Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        }
    }

    #[test]
    fn migration_resweep_marks_secp_bridge_funded_on_replay() {
        let legacy = "ANETE53B24FD164529753D5B2CEA1251D616C923";
        let secp = "ANET467DB4EEB1513402D5ACA10A3177FD669CAA";
        let transaction = sweep_tx(legacy, secp, 10_000);
        assert!(super::is_migration_sweep_tx(&transaction));

        let block = historical_block(1, "genesis", vec![transaction]);
        let funded = collect_bridge_funded_accounts(std::slice::from_ref(&block));
        assert!(
            funded.contains(secp),
            "swept secp must inherit the bridge-funded spend exemption on restart"
        );
        assert!(!funded.contains(legacy));
        // A re-sweep is NOT a bridge credit, so it must not pollute the bridge
        // idempotency dedup set.
        assert!(collect_processed_bridge_hashes(std::slice::from_ref(&block)).is_empty());
    }

    #[test]
    fn activation_anchors_rebuild_from_sealed_events() {
        let wallet = "ANETE53B24FD164529753D5B2CEA1251D616C923";
        let mut first = historical_block(1, "genesis", Vec::new());
        first.events.push(
            crate::events::ChainEvent::new("SessionActivation")
                .attr("address", wallet)
                .attr("credited_ants", 5_000_u64)
                .attr("vesting_anchor_ms", 111_i64),
        );
        // A later credit must NOT move the anchor.
        let mut second = historical_block(2, "block-hash-1", Vec::new());
        second.events.push(
            crate::events::ChainEvent::new("SessionActivation")
                .attr("address", wallet)
                .attr("credited_ants", 9_000_u64)
                .attr("vesting_anchor_ms", 999_999_i64),
        );
        // Session-only updates (credited_ants = 0) never seal an anchor.
        let other = "ANET467DB4EEB1513402D5ACA10A3177FD669CAA";
        second.events.push(
            crate::events::ChainEvent::new("SessionActivation")
                .attr("address", other)
                .attr("credited_ants", 0_u64),
        );

        let anchors = super::collect_activation_anchors(&[first, second]);
        assert_eq!(anchors.get(wallet).copied(), Some(111));
        assert!(!anchors.contains_key(other));
    }

    #[test]
    fn migration_resweep_recognizer_rejects_malformed() {
        let legacy = "ANETE53B24FD164529753D5B2CEA1251D616C923";
        let secp = "ANET467DB4EEB1513402D5ACA10A3177FD669CAA";

        let mut signed = sweep_tx(legacy, secp, 10_000);
        signed.signature = "deadbeef".to_owned();
        signed.tx_hash = "abc".to_owned();
        assert!(!super::is_migration_sweep_tx(&signed), "signed tx must be rejected");

        let mut wrong_type = sweep_tx(legacy, secp, 10_000);
        wrong_type.tx_type = "transfer".to_owned();
        assert!(!super::is_migration_sweep_tx(&wrong_type));

        let mut bad_memo = sweep_tx(legacy, secp, 10_000);
        bad_memo.memo = "bridge:evm:abc".to_owned();
        assert!(!super::is_migration_sweep_tx(&bad_memo));

        let mut nonced = sweep_tx(legacy, secp, 10_000);
        nonced.nonce = 5;
        assert!(!super::is_migration_sweep_tx(&nonced));
    }

    #[test]
    fn bridge_credit_forwards_to_migrated_secp() {
        let legacy = "ANETE53B24FD164529753D5B2CEA1251D616C923".to_owned();
        let secp = "ANET467DB4EEB1513402D5ACA10A3177FD669CAA".to_owned();
        let mut map = HashMap::new();
        map.insert(legacy.clone(), secp.clone());

        // A migrated legacy address forwards to its secp wallet.
        assert_eq!(super::resolve_forwarded_recipient(&map, &legacy), Some(secp));
        // A non-migrated address is left unchanged (None => caller keeps it).
        assert_eq!(
            super::resolve_forwarded_recipient(&map, "ANET1111111111111111111111111111111111AA"),
            None
        );
    }

    // ── One-way bridge policy: attack matrix ────────────────────────────

    #[test]
    fn one_way_bridge_in_policy_is_hardwired_on() {
        // Tripwire: if someone flips the policy off, this fails loudly.
        // Attacks 1/6/7/10 (buy wANET → request L1 credit, with or without
        // 1,000 sessions, with or without the admin key) all funnel through
        // queue_bridge_credit, whose first act is this refusal.
        assert!(super::one_way_bridge_in_active());
    }

    #[test]
    fn export_gate_blocks_ineligible_and_transfer_shuffled_wallets() {
        let min = crate::activation::MIN_SESSIONS_FOR_ANET;
        // Attack 2/5: buy or receive coins on a fresh wallet (or shuffle
        // through many wallets) — none of them can export without mining.
        assert!(super::export_eligibility_error(0, false).is_some());
        assert!(super::export_eligibility_error(min - 1, false).is_some());
        // Eligible miner exports (subject to vesting, tested separately).
        assert!(super::export_eligibility_error(min, false).is_none());
        // Historical bridge-funded wallets keep their export right.
        assert!(super::export_eligibility_error(0, true).is_none());
        // The refusal names the requirement so wallets can explain it.
        let msg = super::export_eligibility_error(3, false).unwrap();
        assert!(msg.contains(&min.to_string()));
        assert!(msg.contains("wallet has 3"));
    }

    #[test]
    fn bridge_burn_conserves_and_reduces_native_supply() {
        let sender = "ANET1111111111111111111111111111111111AA".to_owned();
        let v1 = "ANET2222222222222222222222222222222222BB".to_owned();
        let v2 = "ANET3333333333333333333333333333333333CC".to_owned();
        let amount = 5_0000_0000_u64; // 5 ANET
        let fee = crate::transaction::MIN_FEE_ANTS;

        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        accounts.insert(
            sender.clone(),
            AccountState {
                address: sender.clone(),
                ants_balance: amount + fee + 7,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 1_000,
                asset_balances: HashMap::new(),
            },
        );
        let total_before: u64 = accounts.values().map(|a| a.ants_balance).sum();

        let new_balance = super::execute_bridge_burn(
            &mut accounts,
            &[v1.clone(), v2.clone()],
            &sender,
            amount,
            fee,
        )
        .expect("burn ok");
        assert_eq!(new_balance, 7);

        // Attack 12: the exported value cannot stay spendable on L1. Exactly
        // `amount` left native supply; only the fee was redistributed.
        let total_after: u64 = accounts.values().map(|a| a.ants_balance).sum();
        assert_eq!(total_before - amount, total_after);
        assert_eq!(accounts.get(&v1).unwrap().ants_balance, fee / 2);
        assert_eq!(accounts.get(&v2).unwrap().ants_balance, fee / 2);

        // Insufficient balance is all-or-nothing: state stays untouched.
        let snapshot = accounts.clone();
        let err = super::execute_bridge_burn(&mut accounts, &[v1], &sender, 1_000_000, fee);
        assert!(err.is_err());
        assert_eq!(
            accounts.get(&sender).unwrap().ants_balance,
            snapshot.get(&sender).unwrap().ants_balance
        );
    }

    #[test]
    fn bridge_burn_fee_flows_to_reserve_without_validators() {
        let sender = "ANET1111111111111111111111111111111111AA".to_owned();
        let amount = 1_0000_0000_u64;
        let fee = crate::transaction::MIN_FEE_ANTS;
        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        accounts.insert(
            sender.clone(),
            AccountState {
                address: sender.clone(),
                ants_balance: amount + fee,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 1_000,
                asset_balances: HashMap::new(),
            },
        );
        let total_before: u64 = accounts.values().map(|a| a.ants_balance).sum();
        super::execute_bridge_burn(&mut accounts, &[], &sender, amount, fee).expect("burn ok");
        let total_after: u64 = accounts.values().map(|a| a.ants_balance).sum();
        assert_eq!(total_before - amount, total_after);
        assert_eq!(
            accounts.get(SYSTEM_FEE_RESERVE_ADDRESS).unwrap().ants_balance,
            fee
        );
    }

    #[test]
    fn migration_resweep_apply_conserves_supply() {
        let legacy = "ANETE53B24FD164529753D5B2CEA1251D616C923".to_owned();
        let secp = "ANET467DB4EEB1513402D5ACA10A3177FD669CAA".to_owned();
        let miner = "ANET1111111111111111111111111111111111AA".to_owned();
        let balance = 10_230_799_007_u64; // 102.30799007 ANET
        let fee = crate::transaction::MIN_FEE_ANTS;
        let amount = balance - fee;

        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        accounts.insert(
            legacy.clone(),
            AccountState {
                address: legacy.clone(),
                ants_balance: balance,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 1_000,
                asset_balances: HashMap::new(),
            },
        );

        let mut block = historical_block(1, "genesis", vec![sweep_tx(&legacy, &secp, amount)]);
        block.miners = vec![miner.clone()];
        block.total_fees_ants = fee;
        block.fee_per_miner = fee;

        let total_before: u64 = accounts.values().map(|a| a.ants_balance).sum();
        super::apply_block(&mut accounts, &block).expect("apply_block ok");
        let total_after: u64 = accounts.values().map(|a| a.ants_balance).sum();

        assert_eq!(
            accounts.get(&legacy).map(|a| a.ants_balance),
            Some(0),
            "legacy fully drained"
        );
        assert_eq!(
            accounts.get(&secp).map(|a| a.ants_balance),
            Some(amount),
            "secp credited the balance net of the producer fee"
        );
        assert_eq!(
            accounts.get(&miner).map(|a| a.ants_balance),
            Some(fee),
            "the fee is redistributed to the block producer (not burned)"
        );
        assert_eq!(total_before, total_after, "total supply is conserved");
        assert_eq!(total_after, balance);
    }

    #[test]
    fn session_activation_receipt_records_eligibility_and_is_mint_neutral() {
        // Below the threshold: coins may exist on-chain but the receipt marks
        // the wallet ineligible to spend.
        let below = session_activation_event(
            "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            999,
            10,
            4_882_812,
            4_882_812,
            "web2_sync",
        );
        assert_eq!(below.event_type, "SessionActivation");
        assert_eq!(
            below.attributes.get("eligible").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            below.attributes.get("sessions").map(String::as_str),
            Some("999")
        );
        assert_eq!(
            below.attributes.get("credited_ants").map(String::as_str),
            Some("4882812")
        );
        assert_eq!(
            below.attributes.get("source").map(String::as_str),
            Some("web2_sync")
        );

        // At the threshold: the same receipt shape now marks the wallet
        // eligible — exactly the single source-of-truth spend gate.
        let at = session_activation_event(
            "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            crate::activation::MIN_SESSIONS_FOR_ANET,
            1,
            0,
            4_882_812,
            "signed_oracle",
        );
        assert_eq!(
            at.attributes.get("eligible").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            at.attributes.get("source").map(String::as_str),
            Some("signed_oracle")
        );
    }

    #[test]
    fn session_milestones_fire_on_progress_not_on_cold_start() {
        let w_a = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
        let w_b = "ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned();

        // Cold start: a previous tree of None must yield NO milestones, even
        // though both miners exist — otherwise a restart would re-emit a
        // "joined" event for every existing miner.
        let baseline = SessionTree::build(&[(w_a.clone(), 5), (w_b.clone(), 999)]);
        let (cold, _) = detect_session_milestones(None, &baseline, 5_000);
        assert!(cold.is_empty(), "cold start must not emit milestones");

        // Next commit: C is brand-new (joined), B crosses 1,000 (eligible),
        // and an unchanged miner (A) produces nothing.
        let next = SessionTree::build(&[
            (w_a.clone(), 5),     // unchanged -> no event
            (w_b.clone(), 1_000), // 999 -> 1000 = eligible
            ("ANETCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned(), 3), // new = joined
        ]);
        let (events, truncated) = detect_session_milestones(Some(&baseline), &next, 5_000);
        assert!(!truncated);

        let kinds: Vec<(String, String)> = events
            .iter()
            .map(|e| {
                (
                    e.attributes
                        .get("address")
                        .cloned()
                        .unwrap_or_default(),
                    e.attributes
                        .get("milestone")
                        .cloned()
                        .unwrap_or_default(),
                )
            })
            .collect();
        assert!(kinds.contains(&(
            "ANETCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned(),
            "joined".to_owned()
        )));
        assert!(kinds.contains(&(w_b.clone(), "eligible".to_owned())));
        // The unchanged miner A must not appear.
        assert!(!kinds.iter().any(|(addr, _)| addr == &w_a));
        // Every event is a SessionMilestone.
        assert!(events.iter().all(|e| e.event_type == "SessionMilestone"));
    }

    #[test]
    fn session_milestones_respect_the_per_commit_cap() {
        let baseline = SessionTree::build(&[]);
        let many: Vec<(String, u64)> = (0..50)
            .map(|i| (format!("ANET{:036X}", i), 1_u64))
            .collect();
        let next = SessionTree::build(&many);
        let (events, truncated) = detect_session_milestones(Some(&baseline), &next, 10);
        assert_eq!(events.len(), 10);
        assert!(truncated);
    }

    #[test]
    fn deterministic_ordering_uses_timestamp_sender_nonce_hash() {
        let mut transactions = vec![
            tx("ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 2, 10, "bb"),
            tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 2, 10, "cc"),
            tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1, 10, "dd"),
            tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1, 9, "ee"),
            tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 2, 10, "aa"),
        ];

        sort_transactions_for_block(&mut transactions);

        let ordered = transactions
            .iter()
            .map(|item| {
                format!(
                    "{}:{}:{}:{}",
                    item.timestamp.timestamp(),
                    item.from,
                    item.nonce,
                    item.tx_hash
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ordered,
            vec![
                "9:ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1:ee",
                "10:ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1:dd",
                "10:ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2:aa",
                "10:ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:2:cc",
                "10:ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2:bb",
            ]
        );
    }

    #[test]
    fn deterministic_ordering_preserves_sender_nonce_sequence_before_timestamp() {
        let sender = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut transactions = vec![
            tx(sender, 2, 1, "nonce-2-earlier-timestamp"),
            tx(sender, 1, 9, "nonce-1-later-timestamp"),
        ];

        sort_transactions_for_block(&mut transactions);

        assert_eq!(
            transactions
                .iter()
                .map(|transaction| transaction.nonce)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn rebuild_account_nonces_from_history_tracks_latest_nonce_per_sender() {
        let blocks = vec![
            historical_block(
                0,
                "GENESIS",
                vec![
                    tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1, 1, "h1"),
                    tx("ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 1, 1, "h2"),
                ],
            ),
            historical_block(
                1,
                "block-hash-0",
                vec![
                    tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 2, 2, "h3"),
                    tx("ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", 2, 2, "h4"),
                    tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 3, 2, "h5"),
                ],
            ),
        ];

        let nonces = rebuild_account_nonces(&blocks).expect("nonce rebuild succeeds");

        assert_eq!(
            nonces
                .get("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .copied(),
            Some(3)
        );
        assert_eq!(
            nonces
                .get("ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
                .copied(),
            Some(2)
        );
    }

    #[test]
    fn rebuild_account_nonces_rejects_out_of_sequence_history() {
        let blocks = vec![historical_block(
            0,
            "GENESIS",
            vec![
                tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1, 1, "h1"),
                tx("ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 3, 1, "h2"),
            ],
        )];

        let error = rebuild_account_nonces(&blocks).expect_err("nonce gap must fail");
        assert!(error
            .to_string()
            .contains("invalid nonce sequence for ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    #[test]
    fn bridge_replay_scanner_ignores_user_memos_that_look_like_bridge_credits() {
        let evm_hash = format!("0x{}", "a".repeat(64));
        let recipient = "ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let mut spoofed = tx(
            "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            1,
            1,
            "user-transfer",
        );
        spoofed.to = recipient.to_owned();
        spoofed.memo = format!("{BRIDGE_CREDIT_MEMO_PREFIX}{evm_hash}");

        let block = historical_block(0, "GENESIS", vec![spoofed]);

        assert!(!collect_processed_bridge_hashes(std::slice::from_ref(&block))
            .contains(&evm_hash));
        assert!(!collect_bridge_funded_accounts(&[block]).contains(recipient));
    }

    #[test]
    fn bridge_replay_scanner_accepts_only_canonical_bridge_credits() {
        let evm_hash = format!("0x{}", "b".repeat(64));
        let recipient = "ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let bridge_credit = Transaction {
            tx_type: "bridge_credit".to_owned(),
            from: BRIDGE_TREASURY_ADDRESS.to_owned(),
            to: recipient.to_owned(),
            amount_ants: 42,
            fee_ants: crate::transaction::MIN_FEE_ANTS,
            nonce: 0,
            memo: format!("{BRIDGE_CREDIT_MEMO_PREFIX}{evm_hash}"),
            timestamp: Utc.timestamp_opt(1, 0).single().expect("timestamp"),
            chain_id: "anet-mainnet".to_owned(),
            payload: Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        };
        let block = historical_block(0, "GENESIS", vec![bridge_credit]);

        assert!(
            collect_processed_bridge_hashes(std::slice::from_ref(&block)).contains(&evm_hash)
        );
        assert!(collect_bridge_funded_accounts(&[block]).contains(recipient));
    }

    #[test]
    fn replay_rejects_insufficient_balance_for_user_transaction() {
        let sender = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut accounts = HashMap::from([(sender.to_owned(), account(sender, 1_000))]);
        let block = historical_block(0, "GENESIS", vec![tx(sender, 1, 1, "user-transfer")]);

        let error = replay_blocks(&mut accounts, &[block])
            .expect_err("ordinary user debits must not be synthetically funded");

        assert!(error
            .to_string()
            .contains("without sufficient replay balance"));
    }

    #[test]
    fn replay_allows_legacy_unsigned_bootstrap_transfer_topup() {
        // Reproduces the production startup failure "stored block 1 contains
        // transaction from ANETE53B... without sufficient replay balance".
        // Early bootstrap blocks contain legacy-unsigned transfers (empty
        // signature + tx_hash, e.g. a "live integration test") from senders
        // that had no prior on-chain balance. Replay must reconstruct that
        // funding rather than refuse to load the immutable historical chain.
        let sender = "ANETE53B24FD164529753D5B2CEA1251D616C923";
        let recipient = "ANETA2BF52F6B2D171B6CEEA2AF5810809FDA3FD";
        let legacy_transfer = Transaction {
            tx_type: "transfer".to_owned(),
            from: sender.to_owned(),
            to: recipient.to_owned(),
            amount_ants: 1_000,
            fee_ants: crate::transaction::MIN_FEE_ANTS,
            nonce: 0,
            memo: "live integration test".to_owned(),
            timestamp: Utc.timestamp_opt(1, 0).single().expect("timestamp"),
            chain_id: "anet-mainnet".to_owned(),
            payload: Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        };
        assert!(legacy_transfer.is_legacy_unsigned());

        let mut accounts: HashMap<String, AccountState> = HashMap::new();
        let block = historical_block(0, "GENESIS", vec![legacy_transfer]);
        replay_blocks(&mut accounts, &[block])
            .expect("legacy-unsigned bootstrap transfers must replay via sender topup");
    }

    #[test]
    fn replay_allows_canonical_bridge_credit_sender_topup() {
        let evm_hash = format!("0x{}", "c".repeat(64));
        let recipient = "ANETBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let bridge_credit = Transaction {
            tx_type: "bridge_credit".to_owned(),
            from: BRIDGE_TREASURY_ADDRESS.to_owned(),
            to: recipient.to_owned(),
            amount_ants: 42,
            fee_ants: crate::transaction::MIN_FEE_ANTS,
            nonce: 0,
            memo: format!("{BRIDGE_CREDIT_MEMO_PREFIX}{evm_hash}"),
            timestamp: Utc.timestamp_opt(1, 0).single().expect("timestamp"),
            chain_id: "anet-mainnet".to_owned(),
            payload: Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        };
        let mut block = historical_block(0, "GENESIS", vec![bridge_credit]);
        block.total_fees_ants = crate::transaction::MIN_FEE_ANTS;
        let mut accounts = HashMap::new();

        replay_blocks(&mut accounts, &[block])
            .expect("bridge credit replay should top up treasury");

        assert_eq!(accounts[recipient].ants_balance, 42);
        assert_eq!(
            accounts[SYSTEM_FEE_RESERVE_ADDRESS].ants_balance,
            crate::transaction::MIN_FEE_ANTS
        );
    }

    #[test]
    fn validate_block_sequence_rejects_v4_blocks_with_mismatched_roots() {
        let block = Block::new(
            1,
            Utc.timestamp_opt(1, 0).single().expect("timestamp"),
            Utc.timestamp_opt(2, 0).single().expect("timestamp"),
            "GENESIS".to_owned(),
            Vec::new(),
            0,
            Vec::new(),
            None,
            Vec::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
            "not-the-state-root".to_owned(),
            "not-the-proof-root".to_owned(),
        )
        .expect("block hash can commit mismatched roots before replay validation");

        assert!(block.validate_hash().expect("hash validation"));
        let error = validate_block_sequence(&[block])
            .expect_err("v4 replay must verify roots against committed payloads");

        assert!(error.to_string().contains("invalid state_root"));
    }

    #[test]
    fn validate_block_sequence_accepts_legacy_v4_blocks_with_empty_roots() {
        // Early v4 blocks were minted with EMPTY state_root/proof_root before
        // commitment-root computation was wired in, yet they carry real
        // account-state changes. Their v4 hash commits those changes, so the
        // hash check guarantees integrity; replay must NOT reject them over the
        // (redundant) root re-derivation. Regression for the production startup
        // failure "stored block 1861 has invalid state_root".
        let mut account_changes = HashMap::new();
        account_changes.insert(
            "ANETE53B24FD164529753D5B2CEA1251D616C923".to_owned(),
            AccountState {
                address: "ANETE53B24FD164529753D5B2CEA1251D616C923".to_owned(),
                ants_balance: 10_230_799_007,
                activated_ants: 0,
                total_activated_ants: 2_000,
                sessions: 1_000,
                asset_balances: HashMap::new(),
            },
        );
        let block = Block::new(
            1,
            Utc.timestamp_opt(1, 0).single().expect("timestamp"),
            Utc.timestamp_opt(2, 0).single().expect("timestamp"),
            "GENESIS".to_owned(),
            Vec::new(),
            0,
            Vec::new(),
            None,
            Vec::new(),
            account_changes,
            HashMap::new(),
            HashMap::new(),
            Vec::new(),
            Vec::new(),
            String::new(), // empty state_root (legacy transition block)
            String::new(), // empty proof_root
        )
        .expect("legacy v4 block builds");

        assert_eq!(block.hash_version, 4);
        assert!(block.validate_hash().expect("hash validation"));
        validate_block_sequence(&[block])
            .expect("legacy v4 blocks with empty roots must replay successfully");
    }

    #[test]
    fn pool_audit_identifies_unchanged_admin_bootstrap() {
        let provider = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let pool = DexPool {
            pair_id: "ANET-USDC".to_owned(),
            token_symbol: "USDC".to_owned(),
            anet_reserve_ants: 1_000_000_000,
            token_reserve_units: 10_000_000_000,
            total_lp_units: 3_162_277_660,
            fee_bps: 30,
            lp_positions: HashMap::from([(provider.to_owned(), 3_162_277_660)]),
            updated_at: Utc.timestamp_opt(100, 0).single().expect("timestamp"),
        };
        let mut old_pool_block = historical_block(0, "GENESIS", Vec::new());
        old_pool_block.block_event = Some("DEX: Create Pool".to_owned());
        old_pool_block
            .dex_pools
            .insert(pool.pair_id.clone(), pool.clone());
        let absent = historical_block(1, "block-hash-0", Vec::new());
        let mut genesis = historical_block(2, "block-hash-1", Vec::new());
        genesis.block_event = Some("Genesis: Bootstrap DEX Pool".to_owned());
        genesis.dex_pools.insert(pool.pair_id.clone(), pool.clone());
        let mut later = historical_block(3, "block-hash-2", Vec::new());
        later.dex_pools.insert(pool.pair_id.clone(), pool.clone());

        let audit = build_dex_pool_audit(&pool, None, &[old_pool_block, absent, genesis, later]);

        assert_eq!(audit.creation_source, "bootstrap_admin_generated");
        assert_eq!(audit.creation_block_height, Some(2));
        assert!(audit.reserves_unchanged_since_creation);
        assert!(!audit.onchain_funding_auditable);
        assert!(!audit.suitable_for_l1_price_discovery);
        assert!(!audit.suitable_for_external_price_discovery);
        assert_eq!(audit.status, "bootstrap_not_real");
        assert_eq!(audit.lp_providers, vec![provider.to_owned()]);
    }

    #[test]
    fn pool_audit_accepts_wallet_debited_registered_l1_market() {
        let provider = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let pool = DexPool {
            pair_id: "ANET-USDA".to_owned(),
            token_symbol: "USDA".to_owned(),
            anet_reserve_ants: 2_000_000_000,
            token_reserve_units: 200_000_000,
            total_lp_units: 632_455_532,
            fee_bps: 30,
            lp_positions: HashMap::from([(provider.to_owned(), 632_455_532)]),
            updated_at: Utc.timestamp_opt(100, 0).single().expect("timestamp"),
        };
        let token = Anrc20Token {
            symbol: "USDA".to_owned(),
            name: "User Dollar Asset".to_owned(),
            decimals: 6,
            total_supply: 200_000_000,
            owner: provider.to_owned(),
            mintable: false,
            balances: HashMap::from([(
                dex_pool_escrow_account(&pool.pair_id),
                pool.token_reserve_units as u64,
            )]),
        };
        let mut created = historical_block(0, "GENESIS", Vec::new());
        created.block_event = Some("DEX: Create Pool".to_owned());
        created.dex_pools.insert(pool.pair_id.clone(), pool.clone());
        created
            .token_registry
            .insert(token.symbol.clone(), token.clone());
        let mut later = historical_block(1, "block-hash-0", Vec::new());
        later.dex_pools.insert(pool.pair_id.clone(), pool.clone());
        later.token_registry.insert(token.symbol.clone(), token.clone());

        let audit = build_dex_pool_audit(&pool, Some(&token), &[created, later]);

        assert_eq!(audit.creation_source, "wallet_debited");
        assert!(audit.onchain_funding_auditable);
        assert!(audit.token_pool_escrow_matches_reserve);
        assert!(audit.suitable_for_l1_price_discovery);
        assert!(!audit.suitable_for_external_price_discovery);
        assert_eq!(audit.status, "l1_price_discovery");
    }

    #[test]
    fn wanet_registry_tracks_wrap_and_unwrap_supply() {
        let provider = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut registry = HashMap::new();

        credit_wanet_registry_balance(&mut registry, provider, 1_000)
            .expect("wrap should register WANET");
        credit_wanet_registry_balance(&mut registry, provider, 500)
            .expect("second wrap should add supply");

        let token = registry.get(WANET_SYMBOL).expect("WANET token exists");
        assert_eq!(token.symbol, WANET_SYMBOL);
        assert_eq!(token.decimals, 8);
        assert_eq!(token.total_supply, 1_500);
        assert_eq!(token.balances.get(provider).copied(), Some(1_500));

        debit_wanet_registry_balance(&mut registry, provider, 600)
            .expect("unwrap should burn registered WANET");
        let token = registry.get(WANET_SYMBOL).expect("WANET token remains");
        assert_eq!(token.total_supply, 900);
        assert_eq!(token.balances.get(provider).copied(), Some(900));

        let error = debit_wanet_registry_balance(&mut registry, provider, 901)
            .expect_err("cannot unwrap more registered WANET than held");
        assert!(error
            .to_string()
            .contains("insufficient registered WANET balance"));
    }

    #[test]
    fn public_anrc20_operations_cannot_use_internal_wanet_symbol() {
        let create_err = super::ensure_public_anrc20_symbol_allowed(WANET_SYMBOL)
            .expect_err("WANET must stay reserved for internal accounting");
        assert!(create_err
            .to_string()
            .contains("token symbol WANET is reserved"));

        super::ensure_public_anrc20_symbol_allowed("USDC")
            .expect("non-WANET symbols should remain available");
    }

    #[test]
    fn anrc20_creation_uses_exactly_the_1000_session_threshold() {
        assert!(ensure_anrc20_creator_eligible(None, false).is_err());
        assert!(ensure_anrc20_creator_eligible(Some(999), false).is_err());
        assert!(ensure_anrc20_creator_eligible(Some(1_000), true).is_err());
        assert!(ensure_anrc20_creator_eligible(Some(1_000), false).is_ok());
        assert!(ensure_anrc20_creator_eligible(Some(1_001), false).is_ok());
    }

    #[test]
    fn pool_audit_accepts_wallet_wrapped_wanet_l1_market() {
        let provider = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let pool = DexPool {
            pair_id: "ANET-WANET".to_owned(),
            token_symbol: WANET_SYMBOL.to_owned(),
            anet_reserve_ants: 1_000_000_000,
            token_reserve_units: 1_000_000_000,
            total_lp_units: 1_000_000_000,
            fee_bps: 30,
            lp_positions: HashMap::from([(provider.to_owned(), 1_000_000_000)]),
            updated_at: Utc.timestamp_opt(100, 0).single().expect("timestamp"),
        };
        let mut registry = HashMap::new();
        credit_wanet_registry_balance(&mut registry, provider, pool.token_reserve_units as u64)
            .expect("provider wraps ANET into WANET");
        move_token_registry_balance(
            &mut registry,
            WANET_SYMBOL,
            provider,
            &dex_pool_escrow_account(&pool.pair_id),
            pool.token_reserve_units as u64,
        )
        .expect("pool escrow receives registered WANET");

        let token = registry.get(WANET_SYMBOL).expect("WANET token exists");
        let mut created = historical_block(0, "GENESIS", Vec::new());
        created.block_event = Some("DEX: Create Pool".to_owned());
        created.dex_pools.insert(pool.pair_id.clone(), pool.clone());
        created
            .token_registry
            .insert(WANET_SYMBOL.to_owned(), token.clone());

        let audit = build_dex_pool_audit(&pool, Some(token), &[created]);

        assert_eq!(audit.creation_source, "wallet_debited");
        assert!(audit.token_registered);
        assert_eq!(
            audit.token_pool_escrow_units,
            Some(pool.token_reserve_units as u64)
        );
        assert!(audit.token_pool_escrow_matches_reserve);
        assert!(audit.suitable_for_l1_price_discovery);
        assert_eq!(audit.status, "l1_price_discovery");
    }

    #[test]
    fn replay_applies_hash_committed_account_state_changes() {
        let address = "ANETAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut accounts = HashMap::from([(address.to_owned(), account(address, 1_000))]);
        let mut block = historical_block(0, "GENESIS", Vec::new());
        let mut updated = account(address, 2_000);
        updated.ants_balance = 42;
        block
            .account_state_changes
            .insert(address.to_owned(), updated);

        replay_blocks(&mut accounts, &[block]).expect("state delta replay succeeds");
        assert_eq!(accounts[address].ants_balance, 42);
        assert_eq!(accounts[address].sessions, 2_000);
    }

    fn account(addr: &str, sessions: u64) -> super::AccountState {
        super::AccountState {
            address: addr.to_owned(),
            ants_balance: 0,
            activated_ants: 0,
            total_activated_ants: 0,
            sessions,
            asset_balances: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn validator_compute_filters_below_min_sessions() {
        let mut accounts = std::collections::HashMap::new();
        accounts.insert("A".to_owned(), account("A", 1_000));
        accounts.insert("B".to_owned(), account("B", 999));
        accounts.insert("C".to_owned(), account("C", 5_000));

        let validators = super::compute_validators_from_accounts(&accounts);
        // B excluded (< MIN_SESSIONS_FOR_ANET); C first (more sessions), then A.
        assert_eq!(validators, vec!["C".to_owned(), "A".to_owned()]);
    }

    #[test]
    fn validator_compute_ties_broken_by_address_asc() {
        let mut accounts = std::collections::HashMap::new();
        accounts.insert("Z".to_owned(), account("Z", 2_000));
        accounts.insert("A".to_owned(), account("A", 2_000));
        accounts.insert("M".to_owned(), account("M", 2_000));

        let validators = super::compute_validators_from_accounts(&accounts);
        assert_eq!(
            validators,
            vec!["A".to_owned(), "M".to_owned(), "Z".to_owned()]
        );
    }

    #[test]
    fn validator_compute_caps_at_max_validators() {
        let mut accounts = std::collections::HashMap::new();
        // Insert MAX_VALIDATORS + 50 eligible accounts.
        let total = crate::activation::MAX_VALIDATORS + 50;
        for i in 0..total {
            let addr = format!("ANET{:040}", i);
            accounts.insert(addr.clone(), account(&addr, 1_000 + i as u64));
        }
        let validators = super::compute_validators_from_accounts(&accounts);
        assert_eq!(validators.len(), crate::activation::MAX_VALIDATORS);
    }

    #[test]
    fn validator_compute_is_deterministic() {
        let mut accounts = std::collections::HashMap::new();
        accounts.insert("X".to_owned(), account("X", 1_500));
        accounts.insert("Y".to_owned(), account("Y", 1_500));
        accounts.insert("W".to_owned(), account("W", 3_000));

        let a = super::compute_validators_from_accounts(&accounts);
        let b = super::compute_validators_from_accounts(&accounts);
        assert_eq!(a, b);
        assert_eq!(a[0], "W"); // highest sessions
    }

    #[test]
    fn bootstrap_backfills_when_no_organic_validators() {
        // Only bootstrap seats are eligible — they must keep the chain live.
        let mut accounts = std::collections::HashMap::new();
        accounts.insert("BOOT1".to_owned(), account("BOOT1", 1_000));
        accounts.insert("BOOT2".to_owned(), account("BOOT2", 1_000));
        let bootstrap = vec!["BOOT1".to_owned(), "BOOT2".to_owned()];

        let validators = super::compute_active_validator_set(&accounts, &bootstrap);
        assert_eq!(validators.len(), 2);
        assert!(validators.contains(&"BOOT1".to_owned()));
        assert!(validators.contains(&"BOOT2".to_owned()));
    }

    #[test]
    fn organic_validators_outrank_bootstrap_below_quorum() {
        // One organic validator + bootstrap seats, still below the sunset
        // quorum: organic is seated first, bootstrap backfills the rest.
        let mut accounts = std::collections::HashMap::new();
        accounts.insert("ORGANIC".to_owned(), account("ORGANIC", 5_000));
        accounts.insert("BOOT1".to_owned(), account("BOOT1", 1_000));
        let bootstrap = vec!["BOOT1".to_owned()];

        let validators = super::compute_active_validator_set(&accounts, &bootstrap);
        assert_eq!(validators[0], "ORGANIC"); // organic ranked first
        assert!(validators.contains(&"BOOT1".to_owned())); // bootstrap backfills
    }

    #[test]
    fn bootstrap_fully_retires_at_organic_quorum() {
        // Exactly the quorum of organic validators exists — every bootstrap
        // seat must drop out of the active set automatically.
        let mut accounts = std::collections::HashMap::new();
        for i in 0..super::BOOTSTRAP_SUNSET_ORGANIC_QUORUM {
            let addr = format!("ORG{:040}", i);
            accounts.insert(addr.clone(), account(&addr, 2_000));
        }
        accounts.insert("BOOT1".to_owned(), account("BOOT1", 1_000));
        accounts.insert("BOOT2".to_owned(), account("BOOT2", 1_000));
        let bootstrap = vec!["BOOT1".to_owned(), "BOOT2".to_owned()];

        let validators = super::compute_active_validator_set(&accounts, &bootstrap);
        assert_eq!(validators.len(), super::BOOTSTRAP_SUNSET_ORGANIC_QUORUM);
        assert!(!validators.contains(&"BOOT1".to_owned()));
        assert!(!validators.contains(&"BOOT2".to_owned()));
    }
}
