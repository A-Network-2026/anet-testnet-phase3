use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::OnceLock,
    time::{Duration, Instant},
};

use anyhow::Result;
use axum::{
    extract::{Form, Path, Query, State as AxumState},
    http::{
        header::{HeaderName, ACCEPT, CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE, USER_AGENT},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;
use tokio::time::{sleep, timeout};
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
};

use crate::{
    bridge_vault, db,
    events::ChainEvent,
    state::{self, AccountView, SharedState},
    token::Anrc20TokenView,
    transaction::{
        verify_signed_action_authorization_for_payload, verify_tpow_proof_submission,
        wallet_seed_matches, SignedActionAuthorization, SignedTransactionRequest,
        TPoWProofSubmission, MAX_TPOW_DIFFICULTY_BITS, MIN_TPOW_DIFFICULTY_BITS,
    },
};

const EXPLORER_CSS: &str = include_str!("explorer_assets/explorer.css");
const EXPLORER_LOGO_PNG: &[u8] = include_bytes!("explorer_assets/logo.png");
const EXPLORER_JS: &str = include_str!("explorer_assets/explorer.js");
const EXPLORER_AUTH_COOKIE: &str = "anet_explorer_wallet";
const L1_RESERVE_TREASURY_EVM_ADDRESS: &str = "0x9C7C1058fdc9b710f688ECb7562924D9AE771417";

// ─────────────────────────────────────────────────────────────────────────────
// REVELATION BLOCK 0 — sealed L1 genesis assets.
//
// These bytes are embedded into the binary at compile time. They are the
// exact files used to compute the published SHA-256
// (f8719ae352bdc77b40390580ef2149f271f823635da2a928c766e639fd13d27a) and the
// matching ed25519 signature. Anyone in the world can download them from
// `/genesis/*` and locally reproduce the hash; the binary itself becomes the
// trustless distribution channel for the published commitment.
//
// Update path: when re-sealing genesis, replace the files in
// config/genesis/revelation_block_0/ and rebuild — no other code needs to
// change.
// ─────────────────────────────────────────────────────────────────────────────
const REVELATION_GENESIS_JSON: &[u8] =
    include_bytes!("../config/genesis/revelation_block_0/genesis.json");
const REVELATION_GENESIS_SHA256: &str =
    include_str!("../config/genesis/revelation_block_0/genesis.sha256");
const REVELATION_GENESIS_SIG: &str =
    include_str!("../config/genesis/revelation_block_0/genesis.sig");
const REVELATION_GENESIS_PUBKEY: &str =
    include_str!("../config/genesis/revelation_block_0/genesis.pubkey");
const REVELATION_GENESIS_MANIFEST: &str =
    include_str!("../config/genesis/revelation_block_0/manifest.txt");

/// Constant-time key comparison to prevent timing oracle attacks on admin endpoints.
/// Prevents byte-by-byte timing leaks within same-length comparisons.
fn constant_time_key_eq(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[derive(Clone)]
struct RpcContext {
    state: SharedState,
}

#[derive(Clone)]
struct CachedDashboardMetrics {
    metrics: db::DashboardMetrics,
    cached_at: Instant,
}

#[derive(Clone)]
struct CachedNetworkSummary {
    summary: state::NetworkSummary,
    cached_at: Instant,
}

#[derive(Clone)]
struct CachedNetworkStatsSnapshot {
    snapshot: db::NetworkStatsSnapshot,
    cached_at: Instant,
}

#[derive(Clone)]
struct CachedExplorerCommunitySnapshot {
    snapshot: db::ExplorerCommunitySnapshot,
    cached_at: Instant,
}

#[derive(Clone)]
struct CachedValue<T> {
    value: T,
    cached_at: Instant,
}

static DASHBOARD_METRICS_CACHE: OnceLock<RwLock<Option<CachedDashboardMetrics>>> = OnceLock::new();
static DASHBOARD_METRICS_BACKOFF_UNTIL: OnceLock<RwLock<Option<Instant>>> = OnceLock::new();
static NETWORK_SUMMARY_CACHE: OnceLock<RwLock<Option<CachedNetworkSummary>>> = OnceLock::new();
static NETWORK_STATS_SNAPSHOT_CACHE: OnceLock<RwLock<Option<CachedNetworkStatsSnapshot>>> =
    OnceLock::new();
static EXPLORER_COMMUNITY_SNAPSHOT_CACHE: OnceLock<
    RwLock<Option<CachedExplorerCommunitySnapshot>>,
> = OnceLock::new();
static TERRITORY_COLONY_USAGE_CACHE: OnceLock<
    RwLock<HashMap<String, CachedValue<Vec<db::ColonyGroupUsageRow>>>>,
> = OnceLock::new();
static TERRITORY_ROOM_PROFILES_CACHE: OnceLock<
    RwLock<HashMap<String, CachedValue<Vec<db::ColonyRoomProfileRow>>>>,
> = OnceLock::new();
static COLONY_ROOM_PROFILES_CACHE: OnceLock<
    RwLock<HashMap<String, CachedValue<Vec<db::ColonyRoomProfileRow>>>>,
> = OnceLock::new();
static ROOM_PROFILE_CACHE: OnceLock<
    RwLock<HashMap<String, CachedValue<Option<db::ColonyRoomProfileRow>>>>,
> = OnceLock::new();
static WEB2_ACCOUNT_CACHE: OnceLock<
    RwLock<HashMap<String, CachedValue<Option<db::Web2AccountRow>>>>,
> = OnceLock::new();

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

#[derive(Debug, Serialize)]
struct TransactionAccepted {
    transaction_id: String,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct Web2AccountResponse {
    address: String,
    sessions: u64,
    ants_balance: u64,
    is_eligible: bool,
    referrals: u64,
}

#[derive(Debug, Serialize)]
struct HybridOnchainView {
    ants_balance: u64,
}

#[derive(Debug, Serialize)]
struct HybridAccountResponse {
    address: String,
    onchain: HybridOnchainView,
    web2: Web2AccountResponse,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    chain_id: String,
    latest_block_height: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ReadinessResponse {
    status: &'static str,
    postgres: &'static str,
    genesis_accounts: usize,
}

#[derive(Debug, Serialize)]
struct InvestorMetricsResponse {
    chain_id: String,
    activated_supply_ants: u64,
    activated_supply_anet: String,
    latest_block_height: Option<u64>,
    current_epoch_end: String,
    seconds_until_epoch_end: i64,
    metrics: db::DashboardMetrics,
}

#[derive(Debug, Deserialize)]
struct ExplorerSearchQuery {
    q: String,
}

#[derive(Debug, Deserialize, Default)]
struct ExplorerDashboardQuery {
    view: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ExplorerLoginQuery {
    next: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ExplorerLoginForm {
    wallet: String,
    seed_phrase: String,
    next: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct BlocksQuery {
    limit: Option<usize>,
    /// Inclusive lower block height, or linked-chain position when
    /// `position=true`.
    from: Option<u64>,
    /// Inclusive upper block height/position. Ignored unless `from` is set.
    to: Option<u64>,
    #[serde(default)]
    position: bool,
}

#[derive(Debug, Deserialize, Default)]
struct AccountActivityQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

/// A wallet's activity is derived from immutable blocks plus the current
/// mempool. It is intentionally not a separate mutable ledger, so reinstalling
/// or upgrading a client can always reconstruct the same account history.
///
/// `transaction_type` / `direction` are plain `String` (not `&'static str`)
/// because DEX activity (swaps, liquidity, pool creation, app activity) is
/// merged in from `ChainEvent`s alongside plain wallet transfers; those event
/// types are read at runtime from `event.event_type`.
#[derive(Debug, Serialize)]
struct AccountActivityItem {
    transaction_type: String,
    direction: String,
    amount: u64,
    fee_ants: u64,
    total_debit_ants: u64,
    from_address: String,
    to_address: String,
    description: String,
    status: &'static str,
    tx_hash: String,
    block_number: Option<u64>,
    block_hash: Option<String>,
    confirmations: u64,
    created_at: String,
    confirmed_at: Option<String>,
    /// Raw on-chain event attributes (present only for DEX/app-activity
    /// items), exposed as-is for full transparency/verifiability.
    #[serde(skip_serializing_if = "Option::is_none")]
    event_attributes: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct AccountActivityResponse {
    address: String,
    source: &'static str,
    next_nonce: u64,
    count: usize,
    total: usize,
    history: Vec<AccountActivityItem>,
}

#[derive(Debug, Deserialize)]
struct AdminBridgeEvmCreditRequest {
    /// Must match ANET_DEX_ADMIN_KEY env var.
    admin_key: String,
    /// ANET L1 wallet address of the recipient.
    recipient: String,
    /// Amount in ANTS (smallest unit, 1 ANET = 100_000_000 ANTS).
    amount_ants: u64,
    /// Source BSC transaction hash (for dedup + explorer display).
    evm_tx_hash: String,
    /// BSC chain ID (56 = mainnet).
    evm_chain_id: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AdminBridgeEvmCreditResponse {
    ok: bool,
    recipient: String,
    amount_ants: u64,
    ants_balance: u64,
    /// Synthetic L1 tx ID: "bridge:evm:<evm_tx_hash>".
    tx_id: String,
}

/// Request body for POST /admin/evm/activity.
/// Records an EVM wallet action (send / swap) as a block event on the ANET L1 chain.
#[derive(Debug, Deserialize)]
struct AdminEvmActivityRequest {
    /// Must match ANET_DEX_ADMIN_KEY env var.
    admin_key: String,
    /// BSC transaction hash (for dedup + explorer display). Required.
    evm_tx_hash: String,
    /// Type of activity: "send", "swap", or "receive".
    activity_type: String,
    /// Token symbol involved (e.g. "BNB", "USDT", "ANET").
    token_symbol: Option<String>,
    /// Human-readable amount string (e.g. "1.5").
    amount_str: Option<String>,
    /// ANET L1 address of the user (optional, for display only).
    anet_address: Option<String>,
    /// BSC chain ID (56 = mainnet).
    evm_chain_id: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AdminEvmActivityResponse {
    ok: bool,
    activity_type: String,
    evm_tx_hash: String,
    /// L1 block event label recorded.
    block_event: String,
    /// Whether a new block was triggered (false if tx was already processed).
    new_block_triggered: bool,
}

/// Request body for POST /admin/protocol/update.
/// Seals a protocol/whitepaper update's document hash into a block event, so
/// "version X.Y was published with hash Z" becomes an independently verifiable
/// historical fact rather than only a claim on a website. Records no balance
/// change and moves no funds.
#[derive(Debug, Deserialize)]
struct AdminProtocolUpdateRequest {
    /// Must match ANET_DEX_ADMIN_KEY env var.
    admin_key: String,
    /// Human version label, e.g. "4.2".
    version: String,
    /// Short title of the update.
    title: String,
    /// SHA-256 hex digest of the published document this update refers to
    /// (e.g. the whitepaper.html source at publish time).
    document_sha256: String,
}

#[derive(Debug, Serialize)]
struct AdminProtocolUpdateResponse {
    ok: bool,
    version: String,
    document_sha256: String,
    /// L1 block event label recorded.
    block_event: String,
    /// Whether a new block was triggered (false if this document hash was
    /// already sealed this session).
    new_block_triggered: bool,
}

/// Response for GET /bridge/evm/credit/:evm_tx_hash (public lookup).
#[derive(Debug, Serialize)]
struct BridgeEvmCreditLookupResponse {
    ok: bool,
    /// Whether L1 has already credited this BSC tx hash this session.
    processed: bool,
    /// Normalized lowercase BSC tx hash that was queried.
    evm_tx_hash: String,
    /// Synthetic L1 tx ID (always returned; only meaningful when `processed=true`).
    tx_id: String,
}

// ── Bridge (L1 → BSC) burn requests/responses ──────────────────────────────

#[derive(Debug, Deserialize)]
struct BridgeBurnRequest {
    /// L1 wallet the burn is being charged to (e.g. `ANET…`).
    sender: String,
    /// BSC address (0x-prefixed, EIP-55 or all-lower) that should receive
    /// the released funds.
    bsc_recipient: String,
    /// Amount to burn, in ants. The same amount (minus relayer fees,
    /// configured on the BSC side) will be released on BSC.
    amount_ants: u64,
    /// Token symbol to release on BSC. For now: "ANET" (wrapped ANET).
    /// Future: "USDC", "USDT" if the escrow runs through the L1 AMM.
    #[serde(default = "default_bridge_token")]
    token_symbol: String,
    /// ECDSA action-auth produced by the Flutter wallet, action_type = "bridge_burn".
    auth: SignedActionAuthorization,
}

fn default_bridge_token() -> String {
    "ANET".to_owned()
}

#[derive(Debug, Serialize)]
struct BridgeBurnResponse {
    burn_id: i64,
    l1_sender: String,
    bsc_recipient: String,
    ants_burned: u64,
    anet_burned: String,
    token_symbol: String,
    new_l1_ants_balance: u64,
    new_l1_anet_balance: String,
    status: String,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct BridgeBurnListQuery {
    #[serde(default)]
    since: i64,
    #[serde(default = "default_burn_limit")]
    limit: i64,
    admin_key: String,
}

fn default_burn_limit() -> i64 {
    50
}

/// Optional long-poll for `GET /bridge/burns/:id`. When `wait_ms` is set, the
/// handler holds the connection open up to `wait_ms` milliseconds, polling the
/// DB every ~400ms, and returns as soon as the burn reaches a terminal state
/// (`released`, `failed`, or `skipped`). Lets the mobile wallet show the BSC
/// tx hash without busy-polling. Cap is 25s (under common proxy/CDN timeouts).
#[derive(Debug, Deserialize, Default)]
struct BridgeBurnByIdQuery {
    #[serde(default)]
    wait_ms: Option<u64>,
}

const BRIDGE_BURN_LONGPOLL_MAX_MS: u64 = 25_000;
const BRIDGE_BURN_LONGPOLL_TICK_MS: u64 = 400;

/// Phase 0 sync: maximum number of blocks returned by a single
/// `GET /blocks?from=&to=` range request. Followers paginate by advancing
/// `from` to `last_returned_height + 1` until they reach the peer's tip.
const BLOCK_SYNC_PAGE_MAX: usize = 256;

fn is_terminal_burn_status(status: &str) -> bool {
    matches!(status, "released" | "failed" | "skipped")
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct JsonU64Amount(serde_json::Value);

impl JsonU64Amount {
    fn as_u64(&self, field: &str) -> Result<u64> {
        match &self.0 {
            serde_json::Value::Number(number) => number
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("{field} must be an unsigned integer")),
            serde_json::Value::String(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(anyhow::anyhow!("{field} must not be empty"));
                }
                trimmed
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!("{field} must be a u64 string"))
            }
            _ => Err(anyhow::anyhow!("{field} must be a u64 or u64 string")),
        }
    }
    fn payload_value(&self) -> serde_json::Value {
        self.0.clone()
    }
}

#[cfg(test)]
mod json_u64_amount_tests {
    use super::JsonU64Amount;

    #[test]
    fn decimal_string_preserves_max_u64_and_signed_payload_type() {
        let raw = u64::MAX.to_string();
        let amount = JsonU64Amount(serde_json::Value::String(raw.clone()));

        assert_eq!(amount.as_u64("amount").expect("u64 amount"), u64::MAX);
        assert_eq!(amount.payload_value(), serde_json::Value::String(raw));
    }

    #[test]
    fn decimal_string_rejects_values_above_u64() {
        let amount = JsonU64Amount(serde_json::Value::String("18446744073709551616".to_owned()));

        assert!(amount.as_u64("amount").is_err());
    }
}

#[derive(Debug, Deserialize)]
struct BridgeBurnReleaseRequest {
    bsc_tx_hash: String,
    admin_key: String,
}

#[derive(Debug, Deserialize)]
struct BridgeBurnFailRequest {
    error: String,
    admin_key: String,
}

#[derive(Debug, Deserialize)]
struct DexCreatePoolRequest {
    provider: String,
    auth: SignedActionAuthorization,
    token_symbol: String,
    anet_amount_ants: JsonU64Amount,
    token_amount_units: JsonU64Amount,
    fee_bps: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct DexAddLiquidityRequest {
    provider: String,
    auth: SignedActionAuthorization,
    token_symbol: String,
    anet_amount_ants: JsonU64Amount,
    token_amount_units: JsonU64Amount,
}

#[derive(Debug, Deserialize)]
struct DexRemoveLiquidityRequest {
    provider: String,
    auth: SignedActionAuthorization,
    token_symbol: String,
    lp_units: String,
}

#[derive(Debug, Deserialize)]
struct DexSwapQuoteRequest {
    token_symbol: String,
    amount_in: JsonU64Amount,
    anet_to_token: bool,
}

#[derive(Debug, Deserialize)]
struct DexSwapExecuteRequest {
    trader: String,
    auth: SignedActionAuthorization,
    token_symbol: String,
    amount_in: JsonU64Amount,
    anet_to_token: bool,
    min_amount_out: Option<JsonU64Amount>,
    deadline_block: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DexWrapRequest {
    wallet: String,
    auth: SignedActionAuthorization,
    amount_ants: JsonU64Amount,
}

#[derive(Debug, Deserialize)]
struct DexUnwrapRequest {
    wallet: String,
    auth: SignedActionAuthorization,
    amount_units: JsonU64Amount,
}

#[derive(Debug, Serialize)]
struct DexWrapResponse {
    wallet: String,
    wrapped_symbol: String,
    amount_ants: u64,
    wanet_balance: u64,
    anet_balance: String,
}

#[derive(Debug, Serialize)]
struct DexUnwrapResponse {
    wallet: String,
    wrapped_symbol: String,
    amount_units: u64,
    wanet_balance: u64,
    anet_balance: String,
}

#[derive(Debug, Deserialize)]
struct PiSettlementRequest {
    pi_payment_id: String,
    pi_txid: String,
    pi_amount: String,
    from_address: String,
    to_address: String,
}

#[derive(Debug, Serialize)]
struct PiSettlementResponse {
    ok: bool,
    pi_payment_id: String,
    pi_txid: String,
    transaction_recorded: bool,
    block_event: String,
}

#[derive(Debug, Deserialize)]
struct Anrc20CreateRequest {
    auth: SignedActionAuthorization,
    symbol: String,
    name: String,
    decimals: u8,
    initial_supply: Option<JsonU64Amount>,
    mintable: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct Anrc20MintRequest {
    auth: SignedActionAuthorization,
    to: String,
    symbol: String,
    amount: JsonU64Amount,
}

#[derive(Debug, Deserialize)]
struct Anrc20TransferRequest {
    auth: SignedActionAuthorization,
    to: String,
    symbol: String,
    amount: JsonU64Amount,
}

#[derive(Debug, Serialize)]
struct Anrc20TransferResponse {
    status: &'static str,
    symbol: String,
    from: String,
    to: String,
    amount: u64,
}

#[derive(Debug, Deserialize)]
struct AppActivityRequest {
    source: String,
    action: String,
    #[serde(default)]
    wallet: Option<String>,
    #[serde(default)]
    screen: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    client_version: Option<String>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    auth: Option<SignedActionAuthorization>,
}

#[derive(Debug, Serialize)]
struct AppActivityResponse {
    status: &'static str,
    source: String,
    action: String,
}

#[derive(Debug, Serialize)]
struct SeedNodesResponse {
    chain_id: String,
    seeds: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PublicRpcEndpointsResponse {
    chain_id: String,
    endpoints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TreasuryConfigurationResponse {
    chain_id: String,
    l1_reserve_treasury_evm_address: &'static str,
    l1_reserve_chain: &'static str,
    l1_reserve_chain_id: u64,
    l1_bitcoin_reserve_treasury_address: Option<String>,
    l1_bitcoin_reserve_proof_txid: Option<String>,
    l1_bitcoin_asset_symbol: String,
    l1_bitcoin_reserve_network: &'static str,
    l1_bitcoin_market_scope: &'static str,
    bitcoin_reserve_counts_as_stablecoin_liquidity: bool,
    l1_execution_wallet: Option<String>,
    l1_market_scope: &'static str,
    l2_market_separate: bool,
    l2_balances_counted_as_l1_liquidity: bool,
    l2_pricing_shared_with_l1: bool,
}

#[derive(Debug, Serialize)]
struct SmartContractCapabilityResponse {
    status: &'static str,
    runtime: Option<&'static str>,
    operator_toggle_allowed: bool,
    requires_consensus_upgrade: bool,
    activation_height: Option<u64>,
    activation_method: &'static str,
    readiness_requirements: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct EvmBoundaryResponse {
    execution_location: &'static str,
    market_scope: &'static str,
    shares_l1_liquidity: bool,
    shares_l1_pricing: bool,
    bridge_is_smart_contract_execution: bool,
}

#[derive(Debug, Serialize)]
struct TpowCapabilityResponse {
    status: &'static str,
    hash_algorithm: &'static str,
    hash_preimage: &'static str,
    signature_preimage: &'static str,
    min_difficulty_bits: u32,
    max_difficulty_bits: u32,
    timestamp_max_age_seconds: u64,
    future_clock_skew_seconds: u64,
    /// How accepted proofs are recorded on-chain. Full, self-verifying proofs
    /// are sealed into each block's `tpow_proofs`, and every node rebuilds a
    /// block-derived mining ledger by independently re-verifying them — no
    /// database, oracle, or admin trust. Surfaced per-wallet as
    /// `mined_proofs` on the account view.
    on_chain_accrual: &'static str,
}

#[derive(Debug, Serialize)]
struct BitcoinCapabilityResponse {
    status: &'static str,
    header_hash: &'static str,
    merkle_tree: &'static str,
    compact_target: &'static str,
    target_check: &'static str,
    reference_bits: u32,
}

#[derive(Debug, Serialize)]
struct NetworkCapabilitiesResponse {
    chain_id: String,
    protocol_profile: &'static str,
    native_l1_modules: Vec<&'static str>,
    tpow: TpowCapabilityResponse,
    bitcoin: BitcoinCapabilityResponse,
    arbitrary_smart_contracts: SmartContractCapabilityResponse,
    evm: EvmBoundaryResponse,
}

/// Fixed, ungovernable issuance rules — the chain's monetary policy. Every
/// value is quoted directly from `activation.rs` constants; there is no admin
/// or governance path that can change them at runtime.
#[derive(Debug, Serialize)]
struct ConsensusIssuanceRules {
    monetary_policy: &'static str,
    max_supply_anet: u64,
    max_supply_ants: u64,
    ants_per_anet: u64,
    ants_per_session: u64,
    launch_tranche_sessions: u64,
    launch_reward_ants: u64,
    post_launch_base_reward_ants: u64,
    halving_interval_sessions: u64,
    max_halving_stage: u64,
    halving_basis: &'static str,
    issuance_sources: Vec<&'static str>,
    admin_mint_path: &'static str,
    /// How session activations are recorded on-chain. Each completed-session
    /// activation is sealed into a block as an immutable, mint-neutral
    /// `SessionActivation` event (a "session receipt"), so activation history
    /// is replayable from blocks. Spendability still requires the eligibility
    /// threshold below.
    session_activation_record: &'static str,
    /// How EVERY miner's session progress (including sub-threshold miners) is
    /// committed on-chain: a Merkle root over all miners' completed-session
    /// counts, sealed per sync as a `SessionProgressRoot` event, with per-wallet
    /// inclusion proofs served at `/sessions/proof/:wallet`. Mint-neutral.
    session_progress_commitment: &'static str,
}

/// Validator eligibility rules. Eligibility is a deterministic function of
/// on-chain session counts; no vote or admin action can alter the threshold or
/// the selection order.
#[derive(Debug, Serialize)]
struct ConsensusEligibilityRules {
    rule: &'static str,
    min_sessions_for_activation: u64,
    max_validators: usize,
    validator_selection: &'static str,
    governance: &'static str,
}

/// Time-Proof-of-Work proof rules, identical to the live submission path and to
/// the freshness-exempt re-verification used to rebuild the on-chain mining
/// ledger from block history.
#[derive(Debug, Serialize)]
struct ConsensusProofRules {
    hash_algorithm: &'static str,
    hash_preimage: &'static str,
    signature_scheme: &'static str,
    signature_preimage: &'static str,
    min_difficulty_bits: u32,
    max_difficulty_bits: u32,
    difficulty_metric: &'static str,
    on_chain_record: &'static str,
}

/// Block structure and hashing rules that make the chain independently
/// replayable and verifiable from history alone.
#[derive(Debug, Serialize)]
struct ConsensusBlockRules {
    canonical_hash_version: u32,
    hash_algorithm: &'static str,
    chaining: &'static str,
    proof_root: &'static str,
    state_root: &'static str,
    min_fee_ants: u64,
    production: &'static str,
}

/// How any third party reproduces the chain from scratch with no trust.
#[derive(Debug, Serialize)]
struct ConsensusVerification {
    independent_verifier: &'static str,
    command: &'static str,
    public_endpoints: Vec<&'static str>,
    checks: Vec<&'static str>,
}

/// `GET /network/consensus` — the chain's fixed, public, ungovernable rule set.
/// Published so any participant can read the exact monetary policy, eligibility
/// rule, proof-of-work format, and verification procedure straight from the
/// running node, and confirm they match the source and the whitepaper.
#[derive(Debug, Serialize)]
struct NetworkConsensusResponse {
    chain_id: String,
    profile: &'static str,
    rules_are_ungovernable: bool,
    issuance: ConsensusIssuanceRules,
    eligibility: ConsensusEligibilityRules,
    proof_of_work: ConsensusProofRules,
    block: ConsensusBlockRules,
    verification: ConsensusVerification,
}

#[derive(Debug, Serialize)]
struct NetworkDiscoveryResponse {
    chain_id: String,
    seed_nodes: Vec<String>,
    public_rpc_endpoints: Vec<String>,
    eligible_validators: Vec<String>,
    active_validator_heartbeats: Vec<state::ValidatorHeartbeatView>,
}

#[derive(Debug, Deserialize)]
struct ValidatorHeartbeatRequest {
    wallet: String,
    auth: SignedActionAuthorization,
    #[serde(default)]
    node_endpoint: Option<String>,
    #[serde(default)]
    client_version: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidatorHeartbeatResponse {
    status: &'static str,
    wallet: String,
    active_validator_heartbeats: usize,
}

#[derive(Debug, Serialize)]
struct MiningProofResponse {
    status: &'static str,
    miner: String,
    proof_hash: String,
    difficulty: u32,
}

pub async fn run_server(state: SharedState, bind_addr: SocketAddr) -> Result<()> {
    let context = RpcContext { state };
    let allowed_origins = {
        let mut v: Vec<HeaderValue> = vec![
            HeaderValue::from_static("https://a-network.net"),
            HeaderValue::from_static("https://www.a-network.net"),
        ];
        // Localhost origins are disabled in production by default.
        // Set CORS_ALLOW_LOCALHOST=true to re-enable (e.g. for local development).
        if std::env::var("CORS_ALLOW_LOCALHOST")
            .map(|s| s.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            v.push(HeaderValue::from_str("http://localhost:3000").expect("valid header"));
            v.push(HeaderValue::from_str("http://127.0.0.1:3000").expect("valid header"));
        }
        v
    };

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            ACCEPT,
            CONTENT_TYPE,
            COOKIE,
            SET_COOKIE,
            USER_AGENT,
            HeaderName::from_static("authorization"),
            HeaderName::from_static("x-requested-with"),
        ]);

    let router = Router::new()
        .route("/", get(root))
        .route("/robots.txt", get(robots_txt))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/blocks", get(get_blocks))
        .route("/blocks/:id", get(get_block))
        .route("/blocks/height/:height", get(get_block_by_height))
        .route("/sync/head", get(get_sync_head))
        .route("/accounts/:address", get(get_account))
        .route("/accounts/:address/activity", get(get_account_activity))
        .route(
            "/accounts/:address/unlock-status",
            get(get_account_unlock_status),
        )
        .route("/transactions", post(post_transaction))
        .route("/transaction", post(post_transaction))
        .route("/dex/pools", get(get_dex_pools))
        .route("/dex/pools/:symbol", get(get_dex_pool))
        .route("/dex/pools/:symbol/audit", get(get_dex_pool_audit))
        .route(
            "/admin/bridge/evm/credit",
            post(post_admin_bridge_evm_credit),
        )
        .route("/admin/evm/activity", post(post_admin_evm_activity))
        .route("/admin/protocol/update", post(post_admin_protocol_update))
        .route(
            "/bridge/evm/credit/:evm_tx_hash",
            get(get_bridge_evm_credit_lookup),
        )
        .route("/bridge/burn", post(post_bridge_burn))
        .route("/bridge/burns", get(get_bridge_burns_pending))
        .route(
            "/bridge/burns/by-sender/:address",
            get(get_bridge_burns_by_sender),
        )
        .route("/bridge/burns/:id", get(get_bridge_burn_by_id))
        .route(
            "/bridge/burns/:id/released",
            post(post_bridge_burn_released),
        )
        .route("/bridge/burns/:id/failed", post(post_bridge_burn_failed))
        .route("/bridge/burns/:id/digest", get(get_bridge_burn_digest))
        .route("/bridge/burns/:id/sigs", post(post_bridge_burn_sig))
        .route("/bridge/burns/:id/sigs", get(get_bridge_burn_sigs))
        .route(
            "/wallet/migrate-legacy/commit",
            post(post_wallet_migrate_commit),
        )
        .route(
            "/wallet/migrate-legacy/reveal",
            post(post_wallet_migrate_reveal),
        )
        .route(
            "/wallet/migrate-legacy/:legacy_address",
            get(get_wallet_migrate_status),
        )
        .route(
            "/wallet/migrations/stranded",
            get(get_stranded_migrations),
        )
        .route(
            "/admin/wallet/migrate-legacy/cancel",
            post(post_admin_wallet_migrate_cancel),
        )
        .route(
            "/admin/wallet/migrate-legacy/resweep",
            post(post_admin_wallet_migrate_resweep),
        )
        .route("/dex/wrap", post(post_dex_wrap))
        .route("/dex/unwrap", post(post_dex_unwrap))
        .route("/bridge/x/lock", post(post_bridge_portal_lock))
        .route("/bridge/x/pending-locks", get(get_bridge_portal_pending_locks))
        .route(
            "/bridge/x/locks/:id/attestations",
            get(get_bridge_portal_lock_attestations).post(post_bridge_portal_lock_attestation),
        )
        .route("/bridge/x/locks/:id/minted", post(post_bridge_portal_lock_minted))
        .route("/bridge/x/mint-credit", post(post_bridge_portal_mint_credit))
        .route("/bridge/x/reconciliation", get(get_bridge_portal_reconciliation))
        .route("/dex/pools/create", post(post_dex_create_pool))
        .route("/dex/pools/add-liquidity", post(post_dex_add_liquidity))
        .route(
            "/dex/pools/remove-liquidity",
            post(post_dex_remove_liquidity),
        )
        .route("/dex/swap/quote", post(post_dex_swap_quote))
        .route("/dex/swap/execute", post(post_dex_swap_execute))
        .route("/tokens/anrc20", get(get_anrc20_tokens))
        .route("/tokens/anrc20/:symbol", get(get_anrc20_token))
        .route("/tokens/anrc20/create", post(post_anrc20_create))
        .route("/tokens/anrc20/mint", post(post_anrc20_mint))
        .route("/tokens/anrc20/transfer", post(post_anrc20_transfer))
        .route("/app/activity", post(post_app_activity))
        .route("/ui/activity", post(post_app_activity))
        .route("/pi/settlement", post(post_pi_settlement))
        .route("/web2/account/:address", get(get_web2_account))
        .route("/account/full/:address", get(get_full_account))
        .route("/stats/investor", get(get_investor_metrics))
        .route("/network/seeds", get(get_network_seeds))
        .route("/network/rpc/endpoints", get(get_public_rpc_endpoints))
        .route("/network/treasury", get(get_treasury_configuration))
        .route("/network/capabilities", get(get_network_capabilities))
        .route("/network/consensus", get(get_network_consensus))
        .route("/network/discovery", get(get_network_discovery))
        .route("/sessions/root", get(get_session_root))
        .route("/sessions/proof/:wallet", get(get_session_proof))
        .route("/validators/heartbeats", get(get_validator_heartbeats))
        .route("/validators/heartbeat", post(post_validator_heartbeat))
        .route("/validators", get(get_validators))
        .route(
            "/oracle/session-snapshot",
            post(post_session_oracle_snapshot),
        )
        .route("/mining/submit-proof", post(post_mining_proof))
        .route(
            "/explorer/login",
            get(explorer_login_page).post(explorer_login_submit),
        )
        .route("/explorer/logout", post(explorer_logout))
        .route("/explorer", get(explorer_dashboard))
        .route("/explorer/assets/explorer.css", get(explorer_stylesheet))
        .route("/explorer/assets/logo.png", get(explorer_logo))
        .route("/explorer/assets/explorer.js", get(explorer_script))
        .route("/explorer/api", get(explorer_api))
        .route("/explorer/health", get(explorer_health))
        .route("/explorer/search", get(explorer_search))
        .route("/explorer/territories/:slug", get(explorer_territory))
        .route("/explorer/colonies/:slug", get(explorer_colony))
        .route("/explorer/rooms/:room_key", get(explorer_room))
        .route("/explorer/blocks", get(explorer_blocks))
        .route("/explorer/blocks/:height", get(explorer_block))
        .route("/explorer/accounts/:address", get(explorer_account))
        // Revelation Block 0 — public verification endpoints. No auth.
        // Anyone can fetch the exact bytes that produced the published hash.
        .route("/genesis", get(genesis_verification_page))
        .route("/genesis/genesis.json", get(genesis_raw_json))
        .route("/genesis/genesis.sha256", get(genesis_sha256))
        .route("/genesis/genesis.sig", get(genesis_signature))
        .route("/genesis/genesis.pubkey", get(genesis_pubkey))
        .route("/genesis/manifest.txt", get(genesis_manifest))
        .with_state(context)
        .layer(cors)
        .layer(CompressionLayer::new());

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(address = %bind_addr, "rpc server listening");
    axum::serve(listener, router).await?;
    Ok(())
}

fn parse_csv_env_list(key: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn resolved_validator_allowlist() -> Option<Vec<String>> {
    let mut wallets = parse_csv_env_list("ANET_VALIDATOR_ALLOWLIST")
        .into_iter()
        .map(|wallet| wallet.trim().to_uppercase())
        .filter(|wallet| !wallet.is_empty())
        .collect::<Vec<_>>();

    wallets.sort();
    wallets.dedup();

    if wallets.is_empty() {
        None
    } else {
        Some(wallets)
    }
}

fn is_public_rpc_endpoint(endpoint: &str) -> bool {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return false;
    }

    let lowercase = endpoint.to_ascii_lowercase();

    if lowercase.starts_with("https://0.0.0.0") || lowercase.starts_with("https://[::]") {
        return false;
    }

    if lowercase.starts_with("http://localhost") || lowercase.starts_with("http://127.0.0.1") {
        return true;
    }

    lowercase.starts_with("https://")
}

fn default_seed_nodes() -> Vec<String> {
    vec!["https://node1.a-network.net".to_owned()]
}

fn default_public_rpc_endpoints() -> Vec<String> {
    vec!["https://anet-private-mainnet.onrender.com".to_owned()]
}

fn resolved_seed_nodes() -> Vec<String> {
    let mut seeds = parse_csv_env_list("ANET_SEED_NODES");
    if seeds.is_empty() {
        seeds = default_seed_nodes();
    }
    seeds.sort();
    seeds.dedup();
    seeds
}

fn resolved_public_rpc_endpoints() -> Vec<String> {
    let mut endpoints = parse_csv_env_list("ANET_PUBLIC_RPC_ENDPOINTS")
        .into_iter()
        .filter(|endpoint| is_public_rpc_endpoint(endpoint))
        .collect::<Vec<_>>();

    if endpoints.is_empty() {
        endpoints = default_public_rpc_endpoints()
            .into_iter()
            .filter(|endpoint| is_public_rpc_endpoint(endpoint))
            .collect::<Vec<_>>();
    }

    endpoints.sort();
    endpoints.dedup();
    endpoints
}

async fn get_network_seeds(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let chain_id = context.state.read().await.chain_id.clone();
    Json(SeedNodesResponse {
        chain_id,
        seeds: resolved_seed_nodes(),
    })
}

async fn get_public_rpc_endpoints(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let chain_id = context.state.read().await.chain_id.clone();

    Json(PublicRpcEndpointsResponse {
        chain_id,
        endpoints: resolved_public_rpc_endpoints(),
    })
}

async fn get_treasury_configuration(
    AxumState(context): AxumState<RpcContext>,
) -> impl IntoResponse {
    let chain_id = context.state.read().await.chain_id.clone();
    let l1_execution_wallet = std::env::var("ANET_L1_TREASURY_ADDRESS")
        .ok()
        .map(|wallet| wallet.trim().to_uppercase())
        .filter(|wallet| crate::transaction::is_valid_anet_wallet(wallet));
    let l1_bitcoin_reserve_treasury_address = std::env::var("ANET_L1_BITCOIN_TREASURY_ADDRESS")
        .ok()
        .map(|address| address.trim().to_owned())
        .filter(|address| !address.is_empty());
    let l1_bitcoin_reserve_proof_txid = std::env::var("ANET_L1_BITCOIN_PROOF_TXID")
        .ok()
        .map(|txid| txid.trim().to_lowercase())
        .filter(|txid| txid.len() == 64 && txid.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let l1_bitcoin_asset_symbol = std::env::var("ANET_L1_BITCOIN_ASSET_SYMBOL")
        .unwrap_or_else(|_| "BTC_BTC".to_owned())
        .trim()
        .to_uppercase();

    Json(TreasuryConfigurationResponse {
        chain_id,
        l1_reserve_treasury_evm_address: L1_RESERVE_TREASURY_EVM_ADDRESS,
        l1_reserve_chain: "BNB Smart Chain",
        l1_reserve_chain_id: 56,
        l1_bitcoin_reserve_treasury_address,
        l1_bitcoin_reserve_proof_txid,
        l1_bitcoin_asset_symbol,
        l1_bitcoin_reserve_network: "bitcoin_mainnet",
        l1_bitcoin_market_scope: "anet_btc_reserve_backed_market_only",
        bitcoin_reserve_counts_as_stablecoin_liquidity: false,
        l1_execution_wallet,
        l1_market_scope: "native_anet_l1_only",
        l2_market_separate: true,
        l2_balances_counted_as_l1_liquidity: false,
        l2_pricing_shared_with_l1: false,
    })
}

async fn get_network_capabilities(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let chain_id = context.state.read().await.chain_id.clone();

    Json(NetworkCapabilitiesResponse {
        chain_id,
        protocol_profile: "bitcoin_inspired_fixed_function_l1",
        native_l1_modules: vec![
            "signed_transfers",
            "proof_of_work_mining",
            "fixed_supply_accounting",
            "anrc20_assets",
            "native_dex",
            "liquidity_withdrawal",
            "external_bridge_commitments",
        ],
        tpow: TpowCapabilityResponse {
            status: "active_for_validator_proof_inclusion",
            hash_algorithm: "sha256",
            hash_preimage: "{MINER_UPPER}|{TIMESTAMP_MS}|{NONCE}",
            signature_preimage: "proof-v1|{MINER_UPPER}|{NONCE}|{TIMESTAMP_MS}|{CHAIN_ID}|{PROOF_HASH_LOWER}|{DIFFICULTY}",
            min_difficulty_bits: MIN_TPOW_DIFFICULTY_BITS,
            max_difficulty_bits: MAX_TPOW_DIFFICULTY_BITS,
            timestamp_max_age_seconds: 600,
            future_clock_skew_seconds: 60,
            on_chain_accrual: "block_derived_self_verifying_proofs",
        },
        bitcoin: BitcoinCapabilityResponse {
            status: "bitcoin_primitives_available_for_protocol_upgrade",
            header_hash: "80_byte_header_double_sha256",
            merkle_tree: "sha256d_pair_tree_with_odd_leaf_duplication",
            compact_target: "bitcoin_nbits",
            target_check: "uint256_hash_less_than_or_equal_target",
            reference_bits: crate::bitcoin::BITCOIN_GENESIS_BITS,
        },
        arbitrary_smart_contracts: SmartContractCapabilityResponse {
            status: "disabled_not_implemented",
            runtime: None,
            operator_toggle_allowed: false,
            requires_consensus_upgrade: true,
            activation_height: None,
            activation_method: "audited_versioned_node_release_at_published_block_height",
            readiness_requirements: vec![
                "deterministic_runtime_specification_frozen",
                "consensus_test_vectors_and_replay_tests_pass",
                "independent_security_audits_complete",
                "public_testnet_activation_and_soak_complete",
                "resource_metering_and_state_growth_limits_verified",
                "validator_compatible_release_published",
                "mainnet_activation_height_announced",
            ],
        },
        evm: EvmBoundaryResponse {
            execution_location: "external_evm_network_only",
            market_scope: "separate_from_native_l1",
            shares_l1_liquidity: false,
            shares_l1_pricing: false,
            bridge_is_smart_contract_execution: false,
        },
    })
}

async fn get_network_consensus(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let chain_id = context.state.read().await.chain_id.clone();
    use crate::activation;

    Json(NetworkConsensusResponse {
        chain_id,
        profile: "bitcoin_inspired_fixed_function_l1",
        rules_are_ungovernable: true,
        issuance: ConsensusIssuanceRules {
            monetary_policy: "fixed_capped_schedule_no_admin_mint",
            max_supply_anet: activation::MAX_SUPPLY_ANET,
            max_supply_ants: activation::MAX_SUPPLY_ANTS,
            ants_per_anet: activation::ANTS_PER_ANET,
            ants_per_session: activation::ANTS_PER_SESSION,
            launch_tranche_sessions: activation::LAUNCH_TRANCHE_SESSIONS,
            launch_reward_ants: activation::LAUNCH_REWARD_ANTS,
            post_launch_base_reward_ants: activation::POST_LAUNCH_BASE_REWARD_ANTS,
            halving_interval_sessions: activation::HALVING_INTERVAL_SESSIONS,
            max_halving_stage: activation::MAX_HALVING_STAGE,
            halving_basis: "cumulative_network_sessions",
            issuance_sources: vec![
                "session_mining_activation",
            ],
            admin_mint_path: "none_removed",
            session_activation_record: "immutable_on_chain_session_receipts_mint_neutral",
            session_progress_commitment: "merkle_root_of_all_miner_sessions_per_sync_with_inclusion_proofs_and_milestone_events",
        },
        eligibility: ConsensusEligibilityRules {
            rule: "sessions >= MIN_SESSIONS_FOR_ANET",
            min_sessions_for_activation: activation::MIN_SESSIONS_FOR_ANET,
            max_validators: activation::MAX_VALIDATORS,
            validator_selection: "deterministic_sessions_desc_then_address_asc",
            governance: "ungovernable_no_vote_changes_threshold_or_selection",
        },
        proof_of_work: ConsensusProofRules {
            hash_algorithm: "sha256",
            hash_preimage: "{MINER_UPPER}|{TIMESTAMP_MS}|{NONCE}",
            signature_scheme: "secp256k1_recoverable",
            signature_preimage: "proof-v1|{MINER_UPPER}|{NONCE}|{TIMESTAMP_MS}|{CHAIN_ID}|{PROOF_HASH_LOWER}|{DIFFICULTY}",
            min_difficulty_bits: MIN_TPOW_DIFFICULTY_BITS,
            max_difficulty_bits: MAX_TPOW_DIFFICULTY_BITS,
            difficulty_metric: "leading_zero_bits_of_sha256_proof_hash",
            on_chain_record: "full_self_verifying_proof_sealed_in_block_tpow_proofs",
        },
        block: ConsensusBlockRules {
            canonical_hash_version: 4,
            hash_algorithm: "sha256_over_sorted_key_canonical_json",
            chaining: "previous_hash_linked",
            proof_root: "bitcoin_sha256d_merkle_root_over_sealed_proofs",
            state_root: "bitcoin_sha256d_merkle_root_over_account_state_changes",
            min_fee_ants: crate::transaction::MIN_FEE_ANTS,
            production: "on_demand_when_pending_work",
        },
        verification: ConsensusVerification {
            independent_verifier: "standalone_read_only_no_database",
            command: "anet-private-mainnet --verify-peer <node_url> --expect-chain-id <chain_id> --verify-once",
            public_endpoints: vec![
                "/sync/head",
                "/blocks?from=&to=",
                "/genesis/genesis.json",
                "/genesis/genesis.sha256",
                "/network/capabilities",
            ],
            checks: vec![
                "genesis_hash_matches_published",
                "every_block_hash_recomputed_and_linked",
                "every_signed_transaction_signature_recovers",
                "tpow_proofs_reverify_from_sealed_bytes",
            ],
        },
    })
}

async fn get_network_discovery(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let state = context.state.read().await;

    Json(NetworkDiscoveryResponse {
        chain_id: state.chain_id.clone(),
        seed_nodes: resolved_seed_nodes(),
        public_rpc_endpoints: resolved_public_rpc_endpoints(),
        eligible_validators: state.eligible_miners.clone(),
        active_validator_heartbeats: state.validator_heartbeat_views(120),
    })
}

async fn get_session_root(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let state = context.state.read().await;
    Json(state.session_root_view())
}

async fn get_session_proof(
    AxumState(context): AxumState<RpcContext>,
    Path(wallet): Path<String>,
) -> impl IntoResponse {
    let state = context.state.read().await;
    match state.session_inclusion_proof(&wallet) {
        Some(proof) => {
            // Defensive: the node self-verifies the proof it computed before
            // serving it, so a serving bug can never hand out a proof that does
            // not reconstruct the published root.
            if crate::session_commit::verify_inclusion(&proof) {
                Json(proof).into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ApiError {
                        error: "internal session proof failed self-verification".to_owned(),
                    }),
                )
                    .into_response()
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "wallet has no committed session progress yet".to_owned(),
            }),
        )
            .into_response(),
    }
}

async fn get_validator_heartbeats(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let state = context.state.read().await;
    Json(state.validator_heartbeat_views(120))
}

/// Read-only rich validator directory for the public explorer / scan page.
/// Surfaces the real eligible set with sessions, session-weight voting power,
/// bootstrap-vs-organic labels and live online status from heartbeats.
async fn get_validators(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let state = context.state.read().await;
    Json(state.validator_directory(120))
}

async fn post_validator_heartbeat(
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<ValidatorHeartbeatRequest>,
) -> impl IntoResponse {
    let (chain_id, chain_db) = {
        let state = context.state.read().await;
        (state.chain_id.clone(), state.chain_db.clone())
    };

    let heartbeat_payload = serde_json::json!({
        "route": "validator_heartbeat",
        "wallet": request.wallet.trim().to_uppercase(),
        "node_endpoint": request.node_endpoint.as_deref().map(str::trim),
        "client_version": request.client_version.as_deref().map(str::trim),
    });
    let auth_wallet = match verify_signed_action_authorization_for_payload(
        "validator_heartbeat",
        &request.auth,
        &chain_id,
        &heartbeat_payload,
    ) {
        Ok(wallet) => wallet,
        Err(error) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };

    if auth_wallet != request.wallet.trim().to_uppercase() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiError {
                error: "wallet does not match signed authorization".to_owned(),
            }),
        )
            .into_response();
    }

    if let Some(allowlist) = resolved_validator_allowlist() {
        if !allowlist.iter().any(|wallet| wallet == &auth_wallet) {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiError {
                    error: "validator wallet is not in ANET_VALIDATOR_ALLOWLIST".to_owned(),
                }),
            )
                .into_response();
        }
    }
    {
        let state = context.state.read().await;
        if !state
            .eligible_miners
            .iter()
            .any(|wallet| wallet == &auth_wallet)
        {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiError {
                    error: "wallet is not an active validator".to_owned(),
                }),
            )
                .into_response();
        }
    }

    let replay_recorded = match db::record_validator_heartbeat_nonce(
        chain_db.as_ref(),
        &chain_id,
        &auth_wallet,
        request.auth.nonce,
    )
    .await
    {
        Ok(recorded) => recorded,
        Err(error) => {
            tracing::warn!(?error, wallet = %auth_wallet, "failed to store validator heartbeat nonce");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "failed to persist validator heartbeat authorization".to_owned(),
                }),
            )
                .into_response();
        }
    };

    if !replay_recorded {
        return (
            StatusCode::CONFLICT,
            Json(ApiError {
                error: "replayed or stale validator heartbeat nonce".to_owned(),
            }),
        )
            .into_response();
    }

    let mut state = context.state.write().await;
    state.record_validator_heartbeat(
        auth_wallet.clone(),
        request.node_endpoint.clone(),
        request.client_version.clone(),
    );

    let active = state.validator_heartbeat_views(120).len();

    Json(ValidatorHeartbeatResponse {
        status: "ok",
        wallet: auth_wallet,
        active_validator_heartbeats: active,
    })
    .into_response()
}

/// Configured Web2 session-oracle address. When unset, the chain has no oracle
/// authority and the signed-snapshot endpoint is disabled (returns 503), so
/// operators must opt in explicitly by publishing their oracle address.
fn resolved_oracle_address() -> Option<String> {
    std::env::var("ANET_WEB2_ORACLE_ADDRESS")
        .ok()
        .map(|value| value.trim().to_uppercase())
        .filter(|value| !value.is_empty())
}

/// Maximum accepted age of a signed session snapshot, in seconds. Guards
/// against replay of an old validator set. Default 900s (15 min); set 0 to
/// disable the freshness check entirely.
fn oracle_max_age_seconds() -> i64 {
    std::env::var("ANET_ORACLE_MAX_AGE_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|seconds| *seconds >= 0)
        .unwrap_or(900)
}

#[derive(Debug, Serialize)]
struct SessionOracleResponse {
    status: &'static str,
    accounts_updated: usize,
    eligible_validators: usize,
}

/// Ingest a signed Web2 session-oracle snapshot.
///
/// The signature on the snapshot IS the authorization — no admin key required.
/// The chain verifies the snapshot recovers to the configured
/// `ANET_WEB2_ORACLE_ADDRESS`, then applies the session counts monotonically
/// and re-derives the validator set from on-chain state. This is the auditable
/// Web2→consensus boundary: any third party can replay the same verification.
async fn post_session_oracle_snapshot(
    AxumState(context): AxumState<RpcContext>,
    Json(snapshot): Json<crate::oracle::SignedSessionSnapshot>,
) -> impl IntoResponse {
    let oracle_address = match resolved_oracle_address() {
        Some(address) => address,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    error: "session oracle is not configured on this node".to_owned(),
                }),
            )
                .into_response();
        }
    };

    let chain_id = {
        let state = context.state.read().await;
        state.chain_id.clone()
    };

    let verified = match crate::oracle::verify_session_snapshot(
        &snapshot,
        &oracle_address,
        &chain_id,
        oracle_max_age_seconds(),
    ) {
        Ok(verified) => verified,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };

    let snapshot_as_of = verified.as_of;
    let entries: Vec<(String, u64)> = verified
        .entries
        .into_iter()
        .map(|entry| (entry.wallet, entry.sessions))
        .collect();

    let mut state = context.state.write().await;
    let accounts_updated = state.apply_session_oracle(&entries);
    let eligible_validators = state.eligible_miners.len();
    drop(state);

    tracing::info!(
        accounts_updated,
        eligible_validators,
        oracle = %oracle_address,
        snapshot_as_of = %snapshot_as_of,
        "applied signed session-oracle snapshot"
    );

    Json(SessionOracleResponse {
        status: "ok",
        accounts_updated,
        eligible_validators,
    })
    .into_response()
}

async fn post_mining_proof(
    AxumState(context): AxumState<RpcContext>,
    Json(proof): Json<TPoWProofSubmission>,
) -> impl IntoResponse {
    let (chain_id, chain_db) = {
        let state = context.state.read().await;
        (state.chain_id.clone(), state.chain_db.clone())
    };

    let miner_wallet = match verify_tpow_proof_submission(&proof, &chain_id) {
        Ok(wallet) => wallet,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    error: error.to_string(),
                }),
            )
                .into_response();
        }
    };
    {
        let state = context.state.read().await;
        if !state
            .eligible_miners
            .iter()
            .any(|wallet| wallet == &miner_wallet)
        {
            return (
                StatusCode::FORBIDDEN,
                Json(ApiError {
                    error: "mining proof wallet is not an active validator".to_owned(),
                }),
            )
                .into_response();
        }
        if state.pending_mining_proofs.len() >= 10_000 {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiError {
                    error: "pending mining proof queue is full".to_owned(),
                }),
            )
                .into_response();
        }
    }

    let replay_recorded = match db::record_mining_proof_nonce(
        chain_db.as_ref(),
        &chain_id,
        &miner_wallet,
        proof.nonce,
    )
    .await
    {
        Ok(recorded) => recorded,
        Err(error) => {
            tracing::warn!(?error, wallet = %miner_wallet, "failed to store mining proof nonce");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "failed to persist mining proof nonce".to_owned(),
                }),
            )
                .into_response();
        }
    };

    if !replay_recorded {
        return (
            StatusCode::CONFLICT,
            Json(ApiError {
                error: "replayed or stale mining proof nonce".to_owned(),
            }),
        )
            .into_response();
    }

    let mut state = context.state.write().await;
    let response_proof_hash = proof.proof_hash.clone();
    let response_difficulty = proof.difficulty;
    if let Err(error) = state.record_mining_proof(proof) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                error: error.to_string(),
            }),
        )
            .into_response();
    }

    Json(MiningProofResponse {
        status: "ok",
        miner: miner_wallet,
        proof_hash: response_proof_hash,
        difficulty: response_difficulty,
    })
    .into_response()
}

async fn root() -> impl IntoResponse {
    Html("<html><body><meta http-equiv=\"refresh\" content=\"0; url=/explorer\"></body></html>")
}

async fn explorer_stylesheet() -> impl IntoResponse {
    let mut headers = cache_control_header("public, max-age=3600, stale-while-revalidate=86400");
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    (headers, EXPLORER_CSS).into_response()
}

async fn explorer_logo() -> impl IntoResponse {
    let mut headers = cache_control_header("public, max-age=86400, stale-while-revalidate=604800");
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
    (headers, EXPLORER_LOGO_PNG).into_response()
}

async fn explorer_script() -> impl IntoResponse {
    let mut headers = cache_control_header("public, max-age=3600, stale-while-revalidate=86400");
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    (headers, EXPLORER_JS).into_response()
}

async fn explorer_login_page(
    Query(query): Query<ExplorerLoginQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let next = sanitize_explorer_next_path(query.next.as_deref());

    if explorer_auth_required() && authenticated_wallet_from_headers(&headers).is_some() {
        return Redirect::to(&next).into_response();
    }

    Html(render_explorer_login_page(None, &next)).into_response()
}

async fn explorer_login_submit(
    AxumState(context): AxumState<RpcContext>,
    Form(form): Form<ExplorerLoginForm>,
) -> impl IntoResponse {
    let next = sanitize_explorer_next_path(form.next.as_deref());

    if !explorer_auth_required() {
        return Redirect::to(&next).into_response();
    }

    if explorer_auth_secret().is_none() {
        record_app_activity(
            &context,
            "explorer_login_rejected_missing_secret",
            None,
            Some("ANET_EXPLORER_AUTH_SECRET_unset"),
        )
        .await;
        let body = render_explorer_login_page(
            Some("Explorer auth is enabled but ANET_EXPLORER_AUTH_SECRET is not configured."),
            &next,
        );
        return (StatusCode::SERVICE_UNAVAILABLE, Html(body)).into_response();
    }

    let wallet = form.wallet.trim().to_uppercase();
    if wallet.is_empty() || form.seed_phrase.trim().is_empty() {
        record_app_activity(
            &context,
            "explorer_login_rejected_missing_credentials",
            None,
            Some("wallet_or_seed_missing"),
        )
        .await;
        let body = render_explorer_login_page(Some("Wallet and seed phrase are required."), &next);
        return (StatusCode::BAD_REQUEST, Html(body)).into_response();
    }

    if !wallet_seed_matches(&wallet, &form.seed_phrase) {
        record_app_activity(
            &context,
            "explorer_login_rejected_seed_mismatch",
            Some(&wallet),
            None,
        )
        .await;
        let body = render_explorer_login_page(
            Some("Seed phrase does not match the provided ANET wallet."),
            &next,
        );
        return (StatusCode::UNAUTHORIZED, Html(body)).into_response();
    }

    let eligible = if allow_ineligible_wallet_test_mode() {
        true
    } else {
        match load_web2_account_fast(&wallet).await {
            Ok(Some(account)) => account.is_eligible,
            Ok(None) => false,
            Err(_) => {
                record_app_activity(
                    &context,
                    "explorer_login_rejected_eligibility_lookup_error",
                    Some(&wallet),
                    None,
                )
                .await;
                let body = render_explorer_login_page(
                    Some("Unable to verify wallet eligibility right now. Please retry."),
                    &next,
                );
                return (StatusCode::SERVICE_UNAVAILABLE, Html(body)).into_response();
            }
        }
    };

    if !eligible {
        record_app_activity(
            &context,
            "explorer_login_rejected_ineligible_wallet",
            Some(&wallet),
            None,
        )
        .await;
        let body = render_explorer_login_page(
            Some("This wallet is not eligible yet. Complete at least 1,000 sessions in-app."),
            &next,
        );
        return (StatusCode::FORBIDDEN, Html(body)).into_response();
    }

    let cookie = build_wallet_session_cookie(&wallet);
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.insert(SET_COOKIE, value);
    }

    record_app_activity(
        &context,
        "explorer_login_success",
        Some(&wallet),
        Some("session_cookie_issued"),
    )
    .await;

    (headers, Redirect::to(&next)).into_response()
}

async fn explorer_logout(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
) -> impl IntoResponse {
    let wallet = authenticated_wallet_from_headers(&headers);
    if let Some(wallet) = wallet.as_deref() {
        record_app_activity(&context, "explorer_logout", Some(wallet), None).await;
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "anet_explorer_wallet=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
        ),
    );
    (
        response_headers,
        Redirect::to("/explorer/login?next=%2Fexplorer"),
    )
        .into_response()
}

async fn robots_txt() -> impl IntoResponse {
    (
        cache_control_header("public, max-age=600"),
        "User-agent: *\nDisallow: /explorer/rooms/\n\nUser-agent: MJ12bot\nDisallow: /\n",
    )
}

async fn health(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
) -> impl IntoResponse {
    if request_prefers_html(&headers) {
        return Redirect::to("/explorer/health").into_response();
    }

    let state = context.state.read().await;
    Json(HealthResponse {
        status: "ok",
        chain_id: state.chain_id.clone(),
        latest_block_height: state.blocks.last().map(|block| block.block_height),
    })
    .into_response()
}

async fn ready(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Ok(Redirect::to("/explorer/health").into_response());
    }

    let genesis_accounts = {
        let state = context.state.read().await;
        state.accounts.len()
    };

    if !postgres_ready_fast().await {
        return Err(service_unavailable(format!(
            "service is degraded: postgres unreachable, genesis_accounts_loaded={genesis_accounts}"
        )));
    }

    Ok(Json(ReadinessResponse {
        status: "ready",
        postgres: "ok",
        genesis_accounts,
    })
    .into_response())
}

async fn get_blocks(
    headers: HeaderMap,
    Query(query): Query<BlocksQuery>,
    AxumState(context): AxumState<RpcContext>,
) -> impl IntoResponse {
    if request_prefers_html(&headers) {
        return Redirect::to("/explorer/blocks").into_response();
    }

    let state = context.state.read().await;

    // `from` switches the endpoint into range mode. Existing callers keep
    // height-label semantics; the verifier opts into linked-chain positions.
    // A single request is capped at
    // BLOCK_SYNC_PAGE_MAX so an observer paginates instead of pulling the whole
    // chain at once.
    if let Some(from) = query.from {
        let blocks = if query.position {
            let tip_position = state.blocks.len().saturating_sub(1) as u64;
            let to = query.to.unwrap_or(tip_position).min(tip_position);
            state.blocks_in_position_range(from, to, BLOCK_SYNC_PAGE_MAX)
        } else {
            let tip_height = state.sync_head().tip_height.unwrap_or(0);
            let to = query.to.unwrap_or(tip_height).min(tip_height);
            state.blocks_in_range(from, to, BLOCK_SYNC_PAGE_MAX)
        };
        return (
            cache_control_header("public, max-age=2, stale-while-revalidate=8"),
            Json(blocks),
        )
            .into_response();
    }

    let blocks = match query.limit.filter(|limit| *limit > 0) {
        Some(limit) => {
            let mut blocks = state.latest_blocks(limit.min(128));
            blocks.reverse();
            blocks
        }
        None => state.all_blocks(),
    };

    (
        cache_control_header("public, max-age=2, stale-while-revalidate=8"),
        Json(blocks),
    )
        .into_response()
}

async fn get_block(
    headers: HeaderMap,
    Path(id): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        let state = context.state.read().await;
        let explorer_target = state
            .block_by_id(&id)
            .map(|block| format!("/explorer/blocks/{}", block.block_height));
        drop(state);

        if let Some(explorer_target) = explorer_target {
            return Ok(Redirect::to(&explorer_target).into_response());
        }
    }

    let state = context.state.read().await;
    state
        .block_by_id(&id)
        .map(Json)
        .map(IntoResponse::into_response)
        .ok_or_else(|| not_found(format!("block {id} not found")))
}

async fn get_block_by_height(
    headers: HeaderMap,
    Path(height): Path<u64>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Ok(Redirect::to(&format!("/explorer/blocks/{height}")).into_response());
    }

    let state = context.state.read().await;
    state
        .blocks
        .iter()
        .find(|block| block.block_height == height)
        .cloned()
        .map(Json)
        .map(IntoResponse::into_response)
        .ok_or_else(|| not_found(format!("block {height} not found")))
}

/// Phase 0 (decentralization): chain-tip descriptor for follower nodes. A
/// follower polls this to learn (a) whether it is on the same chain
/// (`chain_id` + `genesis_hash`) and (b) how far it must sync (`tip_height`).
async fn get_sync_head(AxumState(context): AxumState<RpcContext>) -> impl IntoResponse {
    let state = context.state.read().await;
    let head = state.sync_head();
    (
        cache_control_header("public, max-age=1, stale-while-revalidate=4"),
        Json(head),
    )
        .into_response()
}

async fn get_account(
    headers: HeaderMap,
    Path(address): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Ok(Redirect::to(&format!("/explorer/accounts/{address}")).into_response());
    }

    let state = context.state.read().await;
    state
        .account_view(&address)
        .map(Json)
        .map(IntoResponse::into_response)
        .ok_or_else(|| not_found(format!("account {address} not found")))
}

/// GET /accounts/:address/unlock-status — transparent, code-enforced asset
/// lock tier (Locked / P2P-enabled / Swap-enabled / Bridge-enabled / Fully
/// unlocked). Pure reporting: mirrors `NodeState::ensure_eligible_account`
/// exactly, so this can never say "unlocked" for a wallet the chain would
/// still refuse, or vice versa. See `activation::compute_asset_unlock_status`.
async fn get_account_unlock_status(
    Path(address): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let address = address.trim().to_uppercase();
    if !crate::transaction::is_valid_anet_wallet(&address) {
        return Err(bad_request("invalid ANET wallet address"));
    }

    let state = context.state.read().await;
    let view = state
        .account_view(&address)
        .ok_or_else(|| not_found(format!("account {address} not found")))?;
    let bridge_funded = state.bridge_funded_accounts.contains(&address);
    let status = crate::activation::compute_asset_unlock_status(
        view.sessions,
        bridge_funded,
        view.ants_balance,
    );
    Ok(Json(status).into_response())
}

/// Attribute key that identifies "the wallet this event is about", per
/// `ChainEvent::event_type`. Only event types relevant to a wallet's DEX /
/// asset activity are considered here — consensus/session bookkeeping events
/// (SessionMilestone, SessionActivation, ...) are intentionally excluded from
/// wallet-facing history.
fn chain_event_wallet_match(event: &ChainEvent, address: &str) -> bool {
    match event.event_type.as_str() {
        "SwapExecuted" => event.attributes.get("trader").map(String::as_str) == Some(address),
        "LiquidityAdded" | "LiquidityRemoved" | "PoolCreated" => {
            event.attributes.get("provider").map(String::as_str) == Some(address)
        }
        "AppActivity" => event.attributes.get("wallet").map(String::as_str) == Some(address),
        "TokenTransferred" => {
            event.attributes.get("from").map(String::as_str) == Some(address)
                || event.attributes.get("to").map(String::as_str) == Some(address)
        }
        _ => false,
    }
}

/// Builds (description, direction, from_address, to_address) for a
/// wallet-relevant chain event. The raw attributes are still attached
/// separately (`event_attributes`) so anyone can verify exactly what the
/// chain recorded, independent of this description text.
fn describe_chain_event(event: &ChainEvent, address: &str) -> (String, String, String, String) {
    let get = |k: &str| event.attributes.get(k).cloned().unwrap_or_default();
    match event.event_type.as_str() {
        "SwapExecuted" => (
            format!(
                "DEX swap {} on pool {} (in {}, out {})",
                get("direction"),
                get("pair_id"),
                get("amount_in"),
                get("amount_out")
            ),
            "activity".to_owned(),
            get("trader"),
            String::new(),
        ),
        "LiquidityAdded" => (
            format!(
                "Added liquidity to {} pool (+{} LP units)",
                get("pair_id"),
                get("lp_minted")
            ),
            "activity".to_owned(),
            get("provider"),
            String::new(),
        ),
        "LiquidityRemoved" => (
            format!(
                "Removed liquidity from {} pool (-{} LP units, received {} ANTS + {} token units)",
                get("pair_id"),
                get("lp_burned"),
                get("anet_amount_ants"),
                get("token_amount_units")
            ),
            "activity".to_owned(),
            get("provider"),
            String::new(),
        ),
        "PoolCreated" => (
            format!("Created new {} pool ({})", get("pair_id"), get("token_symbol")),
            "activity".to_owned(),
            get("provider"),
            String::new(),
        ),
        "TokenTransferred" => {
            let from = get("from");
            let to = get("to");
            let outgoing = from == address;
            (
                format!("{} {} token transfer", get("amount"), get("symbol")),
                (if outgoing { "outgoing" } else { "incoming" }).to_owned(),
                from,
                to,
            )
        }
        "AppActivity" => {
            let action = get("action");
            let detail = get("detail");
            (
                if detail.is_empty() {
                    format!("App activity: {action}")
                } else {
                    format!("App activity: {action} ({detail})")
                },
                "activity".to_owned(),
                get("wallet"),
                String::new(),
            )
        }
        other => (
            format!("Chain event: {other}"),
            "activity".to_owned(),
            String::new(),
            String::new(),
        ),
    }
}

async fn get_account_activity(
    Path(address): Path<String>,
    Query(query): Query<AccountActivityQuery>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let address = address.trim().to_uppercase();
    if !crate::transaction::is_valid_anet_wallet(&address) {
        return Err(bad_request("invalid ANET wallet address"));
    }

    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let offset = query.offset.unwrap_or(0);
    let state = context.state.read().await;
    let tip_height = state.blocks.last().map(|block| block.block_height);
    let mut next_nonce = state
        .account_nonces
        .get(&address)
        .copied()
        .unwrap_or(0)
        .saturating_add(1);
    let mut pending_nonces = state
        .mempool
        .iter()
        .filter(|tx| tx.from == address)
        .map(|tx| tx.nonce)
        .collect::<Vec<_>>();
    pending_nonces.sort_unstable();
    for pending in pending_nonces {
        if pending == next_nonce {
            next_nonce = next_nonce.saturating_add(1);
        }
    }
    let mut activity = Vec::new();

    // Pending items are newest and remain visible until a validator seals them.
    for tx in state.mempool.iter().rev() {
        if tx.from != address && tx.to != address {
            continue;
        }
        let outgoing = tx.from == address;
        activity.push(AccountActivityItem {
            transaction_type: "wallet_transfer".to_owned(),
            direction: (if outgoing { "outgoing" } else { "incoming" }).to_owned(),
            amount: tx.amount_ants,
            fee_ants: tx.fee_ants,
            total_debit_ants: if outgoing {
                tx.amount_ants.saturating_add(tx.fee_ants)
            } else {
                tx.amount_ants
            },
            from_address: tx.from.clone(),
            to_address: tx.to.clone(),
            description: if tx.memo.trim().is_empty() {
                "Signed P2P transfer awaiting validator block inclusion".to_owned()
            } else {
                tx.memo.clone()
            },
            status: "queued",
            tx_hash: tx.id().unwrap_or_default(),
            block_number: None,
            block_hash: None,
            confirmations: 0,
            created_at: tx.timestamp.to_rfc3339(),
            confirmed_at: None,
            event_attributes: None,
        });
    }

    // DEX swaps / liquidity / pool-create / app activity are recorded as
    // ChainEvents rather than Transactions, so they need a separate merge.
    // Pending ones sit in `pending_events` until the next block seals them
    // (mirrors the mempool "queued" treatment above).
    for event in state.pending_events.iter().rev() {
        if !chain_event_wallet_match(event, &address) {
            continue;
        }
        let (description, direction, from_address, to_address) =
            describe_chain_event(event, &address);
        activity.push(AccountActivityItem {
            transaction_type: event.event_type.clone(),
            direction,
            amount: 0,
            fee_ants: 0,
            total_debit_ants: 0,
            from_address,
            to_address,
            description,
            status: "queued",
            tx_hash: event.tx_hash.clone().unwrap_or_default(),
            block_number: None,
            block_hash: None,
            confirmations: 0,
            created_at: event.timestamp.to_rfc3339(),
            confirmed_at: None,
            event_attributes: Some(event.attributes.clone()),
        });
    }

    // Walking the canonical chain backwards gives deterministic newest-first
    // history and retains every transfer for the lifetime of the chain.
    for block in state.blocks.iter().rev() {
        let confirmations = tip_height
            .map(|tip| tip.saturating_sub(block.block_height).saturating_add(1))
            .unwrap_or(0);

        for tx in block.transactions.iter().rev() {
            if tx.from != address && tx.to != address {
                continue;
            }
            let outgoing = tx.from == address;
            activity.push(AccountActivityItem {
                transaction_type: "wallet_transfer".to_owned(),
                direction: (if outgoing { "outgoing" } else { "incoming" }).to_owned(),
                amount: tx.amount_ants,
                fee_ants: tx.fee_ants,
                total_debit_ants: if outgoing {
                    tx.amount_ants.saturating_add(tx.fee_ants)
                } else {
                    tx.amount_ants
                },
                from_address: tx.from.clone(),
                to_address: tx.to.clone(),
                description: if tx.memo.trim().is_empty() {
                    format!(
                        "Confirmed P2P transfer sealed by validators in block #{}",
                        block.block_height
                    )
                } else {
                    tx.memo.clone()
                },
                status: "confirmed",
                tx_hash: tx.id().unwrap_or_default(),
                block_number: Some(block.block_height),
                block_hash: Some(block.hash.clone()),
                confirmations,
                created_at: tx.timestamp.to_rfc3339(),
                confirmed_at: Some(block.epoch_end.to_rfc3339()),
                event_attributes: None,
            });
        }

        for event in block.events.iter().rev() {
            if !chain_event_wallet_match(event, &address) {
                continue;
            }
            let (description, direction, from_address, to_address) =
                describe_chain_event(event, &address);
            activity.push(AccountActivityItem {
                transaction_type: event.event_type.clone(),
                direction,
                amount: 0,
                fee_ants: 0,
                total_debit_ants: 0,
                from_address,
                to_address,
                description,
                status: "confirmed",
                tx_hash: event.tx_hash.clone().unwrap_or_default(),
                block_number: Some(block.block_height),
                block_hash: Some(block.hash.clone()),
                confirmations,
                created_at: event.timestamp.to_rfc3339(),
                confirmed_at: Some(block.epoch_end.to_rfc3339()),
                event_attributes: Some(event.attributes.clone()),
            });
        }
    }

    let total = activity.len();
    let history = activity.into_iter().skip(offset).take(limit).collect::<Vec<_>>();
    Ok(Json(AccountActivityResponse {
        address,
        source: "anet_l1_blocks_and_mempool",
        next_nonce,
        count: history.len(),
        total,
        history,
    }))
}

async fn post_transaction(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<SignedTransactionRequest>,
) -> Result<(StatusCode, Json<TransactionAccepted>), (StatusCode, Json<ApiError>)> {
    if explorer_auth_required() {
        let wallet = authenticated_wallet_from_headers(&headers)
            .ok_or_else(|| unauthorized("wallet login is required".to_owned()))?;
        if request.from.trim().to_uppercase() != wallet {
            return Err(unauthorized(
                "sender wallet must match authenticated wallet session".to_owned(),
            ));
        }
    }

    let transaction = request.into_transaction().map_err(bad_request)?;
    let mut state = context.state.write().await;
    let transaction_id = state.queue_transaction(transaction).map_err(bad_request)?;

    Ok((
        StatusCode::ACCEPTED,
        Json(TransactionAccepted {
            transaction_id,
            status: "queued",
        }),
    ))
}

async fn post_app_activity(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<AppActivityRequest>,
) -> Result<(StatusCode, Json<AppActivityResponse>), (StatusCode, Json<ApiError>)> {
    let source = normalize_app_activity_source(&request.source).ok_or_else(|| {
        bad_request(anyhow::anyhow!(
            "invalid source: expected one of [web, inapp]"
        ))
    })?;
    let action = normalize_app_activity_action(&request.action)?;

    let wallet = request
        .wallet
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_uppercase());

    if let Some(wallet) = wallet.as_deref() {
        if let Some(auth) = request.auth.as_ref() {
            let auth_wallet = verify_bound_action(
                &context,
                "app_activity",
                auth,
                serde_json::json!({
                    "route": "app_activity",
                    "source": source,
                    "action": action.clone(),
                    "wallet": wallet,
                    "screen": request.screen.as_deref().map(str::trim),
                    "status": request.status.as_deref().map(str::trim),
                    "client_version": request.client_version.as_deref().map(str::trim),
                    "detail": request.detail.as_deref().map(str::trim),
                }),
            )
            .await?;
            if auth_wallet != wallet {
                return Err(unauthorized(
                    "action wallet must match app activity wallet".to_owned(),
                ));
            }
        } else {
            let session_wallet = authenticated_wallet_from_headers(&headers);
            if session_wallet.as_deref() != Some(wallet) {
                return Err(unauthorized(
                    "wallet-scoped app activity requires signed auth or matching explorer session"
                        .to_owned(),
                ));
            }
        }
    }

    let mut detail_parts = Vec::new();
    if let Some(screen) = request
        .screen
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        detail_parts.push(format!("screen={screen}"));
    }
    if let Some(status) = request
        .status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        detail_parts.push(format!("status={status}"));
    }
    if let Some(version) = request
        .client_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        detail_parts.push(format!("client_version={version}"));
    }
    if let Some(detail) = request
        .detail
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        detail_parts.push(format!("detail={detail}"));
    }

    let detail_string = if detail_parts.is_empty() {
        format!("source={source}")
    } else {
        format!("source={source};{}", detail_parts.join(";"))
    };
    let onchain_action = format!("ui_{action}");

    record_app_activity(
        &context,
        &onchain_action,
        wallet.as_deref(),
        Some(&detail_string),
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(AppActivityResponse {
            status: "accepted",
            source: source.to_owned(),
            action,
        }),
    ))
}

async fn get_dex_pools(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
) -> impl IntoResponse {
    if request_prefers_html(&headers) {
        return Redirect::to("/explorer/api").into_response();
    }

    let state = context.state.read().await;
    Json(state.dex_pool_list()).into_response()
}

async fn get_dex_pool(
    headers: HeaderMap,
    Path(symbol): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Ok(Redirect::to("/explorer/api").into_response());
    }

    let state = context.state.read().await;
    let pool = state
        .dex_pool_view(&symbol)
        .map_err(bad_request)?
        .ok_or_else(|| not_found(format!("pool for {symbol} not found")))?;
    Ok(Json(pool).into_response())
}

async fn get_dex_pool_audit(
    Path(symbol): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let state = context.state.read().await;
    let audit = state
        .dex_pool_audit_view(&symbol)
        .map_err(bad_request)?
        .ok_or_else(|| not_found(format!("pool for {symbol} not found")))?;
    Ok(Json(audit))
}

/// POST /admin/bridge/evm/credit
///
/// Credits ANET to an L1 wallet as a result of a verified EVM bridge swap.
/// Guarded by `EVM_BRIDGE_CREDITS_ENABLED=true` + `ANET_DEX_ADMIN_KEY`.
/// Does NOT require ANET_TEST_FAUCET_ENABLED — this is a production bridge path.
async fn post_admin_bridge_evm_credit(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<AdminBridgeEvmCreditRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Err(bad_request(anyhow::anyhow!(
            "HTML requests are not supported for this endpoint"
        )));
    }

    // ONE-WAY BRIDGE POLICY (2026-08-14, whitepaper v3.5): this route is
    // permanently retired. External deposits can no longer mint native ANET,
    // regardless of EVM_BRIDGE_CREDITS_ENABLED or the admin key — the refusal
    // happens before any gate so no credential combination can bypass it.
    // Historical credits remain sealed in blocks and replay normally.
    let one_way_bridge_policy = true;
    if one_way_bridge_policy {
        record_app_activity(
            &context,
            "bridge_evm_credit_rejected_one_way_policy",
            Some(&request.recipient),
            Some("/admin/bridge/evm/credit"),
        )
        .await;
        return Err((
            StatusCode::GONE,
            Json(ApiError {
                error: "one-way bridge policy: BSC/EVM deposits can no longer mint native \
                        L1 ANET. Native ANET originates only from mining. This route is \
                        permanently disabled; historical credits remain on-chain."
                    .to_owned(),
            }),
        ));
    }

    // Gate: EVM_BRIDGE_CREDITS_ENABLED must be true
    let bridge_enabled = std::env::var("EVM_BRIDGE_CREDITS_ENABLED")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if !bridge_enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                error: "EVM_BRIDGE_CREDITS_ENABLED is not set".to_owned(),
            }),
        ));
    }

    let expected_key = dex_admin_key_required()?;
    if !constant_time_key_eq(request.admin_key.trim(), &expected_key) {
        record_app_activity(
            &context,
            "bridge_evm_credit_rejected_invalid_admin_key",
            Some(&request.recipient),
            Some("/admin/bridge/evm/credit"),
        )
        .await;
        return Err(unauthorized("invalid admin key".to_owned()));
    }

    if request.amount_ants == 0 {
        return Err(bad_request(anyhow::anyhow!("amount_ants must be > 0")));
    }
    let evm_chain_id = request.evm_chain_id.unwrap_or(56);
    if evm_chain_id != 56 {
        return Err(bad_request(anyhow::anyhow!(
            "evm_chain_id must be 56 for BSC mainnet credits"
        )));
    }

    let recipient = request.recipient.trim().to_uppercase();
    let evm_tx_hash_normalized = request.evm_tx_hash.trim().to_lowercase();
    if evm_tx_hash_normalized.len() != 66
        || !evm_tx_hash_normalized.starts_with("0x")
        || !evm_tx_hash_normalized[2..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(bad_request(anyhow::anyhow!(
            "evm_tx_hash must be 0x + 64 hex characters"
        )));
    }
    let tx_id = format!("bridge:evm:{}", evm_tx_hash_normalized);

    let mut state = context.state.write().await;

    // Idempotency guard: if this BSC tx hash was already credited in this session,
    // return the cached success response rather than double-crediting.
    if state
        .processed_evm_bridge_hashes
        .contains(&evm_tx_hash_normalized)
    {
        let memo = format!(
            "{}{}",
            state::BRIDGE_CREDIT_MEMO_PREFIX,
            evm_tx_hash_normalized
        );
        let original = state
            .mempool
            .iter()
            .chain(
                state
                    .blocks
                    .iter()
                    .flat_map(|block| block.transactions.iter()),
            )
            .find(|transaction| transaction.memo == memo);
        if original.is_some_and(|transaction| {
            transaction.to != recipient || transaction.amount_ants != request.amount_ants
        }) {
            return Err((
                StatusCode::CONFLICT,
                Json(ApiError {
                    error: "evm_tx_hash was already credited with different parameters".to_owned(),
                }),
            ));
        }
        let ants_balance = state
            .accounts
            .get(&recipient)
            .map(|a| a.ants_balance)
            .unwrap_or(0);
        return Ok((
            StatusCode::OK,
            Json(AdminBridgeEvmCreditResponse {
                ok: true,
                recipient,
                amount_ants: request.amount_ants,
                ants_balance,
                tx_id,
            }),
        ));
    }

    // Credit the balance durably: queue_bridge_credit records the credit as a
    // real block transaction (persisted to Postgres and re-applied on replay),
    // so it survives node restarts/redeploys. The old in-memory test-credit
    // path mutated only in-memory state + a cosmetic block label and was lost
    // on every restart.
    let ants_balance = state
        .queue_bridge_credit(&recipient, request.amount_ants, &evm_tx_hash_normalized)
        .map_err(bad_request)?;

    // Mark this tx hash as processed to prevent double-credits within this session
    state
        .processed_evm_bridge_hashes
        .insert(evm_tx_hash_normalized);

    state.record_app_activity_event(
        "bridge_evm_credit_success",
        Some(&recipient),
        Some("/admin/bridge/evm/credit"),
    );

    Ok((
        StatusCode::OK,
        Json(AdminBridgeEvmCreditResponse {
            ok: true,
            recipient,
            amount_ants: request.amount_ants,
            ants_balance,
            tx_id,
        }),
    ))
}

/// GET /bridge/evm/credit/:evm_tx_hash — Public lookup. Returns whether a given
/// BSC transaction hash has already been credited by `/admin/bridge/evm/credit`
/// in the current chain session. Used by pi-backend to answer mobile-app
/// "is my bridge swap done?" polls without granting any admin-key access.
///
/// Backed by an in-memory HashSet (`processed_evm_bridge_hashes`) rebuilt from
/// finalized bridge-credit transaction memos on startup.
async fn get_bridge_evm_credit_lookup(
    AxumState(context): AxumState<RpcContext>,
    axum::extract::Path(evm_tx_hash): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let normalized = evm_tx_hash.trim().to_lowercase();

    // Cheap format guard: must look like 0x + 64 hex chars.
    let looks_valid = normalized.len() == 66
        && normalized.starts_with("0x")
        && normalized[2..].chars().all(|c| c.is_ascii_hexdigit());
    if !looks_valid {
        return Err(bad_request(anyhow::anyhow!(
            "evm_tx_hash must be 0x + 64 hex chars"
        )));
    }

    let state = context.state.read().await;
    let processed = state.processed_evm_bridge_hashes.contains(&normalized);
    let tx_id = format!("bridge:evm:{}", normalized);

    Ok((
        StatusCode::OK,
        Json(BridgeEvmCreditLookupResponse {
            ok: true,
            processed,
            evm_tx_hash: normalized,
            tx_id,
        }),
    ))
}

/// POST /admin/evm/activity — Records an EVM wallet activity (send/swap/receive) as a
/// block event on the ANET L1 chain. Guarded by `ANET_DEX_ADMIN_KEY`.
/// This is the lightweight counterpart to /admin/bridge/evm/credit: it triggers a block
/// event WITHOUT crediting any ANET balance. Used to prove EVM activity on L1.
async fn post_admin_evm_activity(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<AdminEvmActivityRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Err(bad_request(anyhow::anyhow!(
            "HTML requests are not supported for this endpoint"
        )));
    }

    let expected_key = dex_admin_key_required()?;
    if !constant_time_key_eq(request.admin_key.trim(), &expected_key) {
        record_app_activity(
            &context,
            "evm_activity_rejected_invalid_admin_key",
            request.anet_address.as_deref(),
            Some("/admin/evm/activity"),
        )
        .await;
        return Err(unauthorized("invalid admin key".to_owned()));
    }

    // Validate tx hash format: must be 0x + exactly 64 hex chars (66 total).
    let tx_hash_valid = request.evm_tx_hash.len() == 66
        && request.evm_tx_hash.starts_with("0x")
        && request.evm_tx_hash[2..]
            .chars()
            .all(|c| c.is_ascii_hexdigit());
    if !tx_hash_valid {
        return Err(bad_request(anyhow::anyhow!(
            "evm_tx_hash must be a valid EVM transaction hash (0x + 64 hex chars)"
        )));
    }
    let activity_type = request.activity_type.trim().to_lowercase();
    if !["send", "swap", "receive"].contains(&activity_type.as_str()) {
        return Err(bad_request(anyhow::anyhow!(
            "activity_type must be 'send', 'swap', or 'receive'"
        )));
    }

    let evm_tx_hash_normalized = request.evm_tx_hash.to_lowercase();

    let mut state = context.state.write().await;

    // Truncate user-supplied strings before using in event labels to prevent
    // unbounded data in chain state.
    let amount_display: String = request
        .amount_str
        .as_deref()
        .unwrap_or("?")
        .chars()
        .take(24)
        .collect();
    let symbol_display: String = request
        .token_symbol
        .as_deref()
        .unwrap_or("TOKEN")
        .chars()
        .take(20)
        .collect();

    // Idempotency: skip duplicate activity events in this session.
    if state
        .processed_evm_activity_hashes
        .contains(&evm_tx_hash_normalized)
    {
        let event_label = format!(
            "EVM {}: {} {} (BSC tx {})",
            activity_type.to_uppercase(),
            amount_display,
            symbol_display,
            &request.evm_tx_hash[..std::cmp::min(18, request.evm_tx_hash.len())]
        );
        return Ok((
            StatusCode::OK,
            Json(AdminEvmActivityResponse {
                ok: true,
                activity_type,
                evm_tx_hash: evm_tx_hash_normalized,
                block_event: event_label,
                new_block_triggered: false,
            }),
        ));
    }

    let event_label = format!(
        "EVM {}: {} {} on BSC (chain {} tx {})",
        activity_type.to_uppercase(),
        amount_display,
        symbol_display,
        request.evm_chain_id.unwrap_or(56),
        &request.evm_tx_hash[..std::cmp::min(18, request.evm_tx_hash.len())]
    );
    state.pending_block_event = Some(event_label.clone());
    state.pending_state_commit = true;

    state
        .processed_evm_activity_hashes
        .insert(evm_tx_hash_normalized.clone());

    state.record_app_activity_event(
        "evm_activity_block_event",
        request.anet_address.as_deref(),
        Some("/admin/evm/activity"),
    );

    Ok((
        StatusCode::OK,
        Json(AdminEvmActivityResponse {
            ok: true,
            activity_type,
            evm_tx_hash: evm_tx_hash_normalized,
            block_event: event_label,
            new_block_triggered: true,
        }),
    ))
}

/// POST /admin/protocol/update — Seals a protocol/whitepaper update's document
/// hash into a block event on the ANET L1 chain. Guarded by `ANET_DEX_ADMIN_KEY`.
/// This moves no funds and changes no balance; it is the same lightweight
/// block-event pattern as `/admin/evm/activity`, used here to make published
/// protocol/whitepaper versions independently verifiable against chain
/// history instead of only a claim on a website.
async fn post_admin_protocol_update(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<AdminProtocolUpdateRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Err(bad_request(anyhow::anyhow!(
            "HTML requests are not supported for this endpoint"
        )));
    }

    let expected_key = dex_admin_key_required()?;
    if !constant_time_key_eq(request.admin_key.trim(), &expected_key) {
        record_app_activity(
            &context,
            "protocol_update_rejected_invalid_admin_key",
            None,
            Some("/admin/protocol/update"),
        )
        .await;
        return Err(unauthorized("invalid admin key".to_owned()));
    }

    let version = request.version.trim();
    if version.is_empty() || version.chars().count() > 16 {
        return Err(bad_request(anyhow::anyhow!(
            "version must be 1-16 characters"
        )));
    }
    let title: String = request.title.trim().chars().take(120).collect();
    if title.is_empty() {
        return Err(bad_request(anyhow::anyhow!("title is required")));
    }
    let document_sha256 = request.document_sha256.trim().to_lowercase();
    let hash_valid = document_sha256.len() == 64
        && document_sha256.chars().all(|c| c.is_ascii_hexdigit());
    if !hash_valid {
        return Err(bad_request(anyhow::anyhow!(
            "document_sha256 must be a 64-character hex SHA-256 digest"
        )));
    }

    let mut state = context.state.write().await;

    // Idempotency: sealing the SAME document hash twice records only one
    // block event this session (mirrors post_admin_evm_activity's dedup).
    if state
        .processed_protocol_update_hashes
        .contains(&document_sha256)
    {
        let event_label = format!(
            "Protocol: v{version} \"{title}\" (sha256 {})",
            &document_sha256[..16]
        );
        return Ok((
            StatusCode::OK,
            Json(AdminProtocolUpdateResponse {
                ok: true,
                version: version.to_owned(),
                document_sha256,
                block_event: event_label,
                new_block_triggered: false,
            }),
        ));
    }

    let event_label = format!(
        "Protocol: v{version} \"{title}\" (sha256 {})",
        &document_sha256[..16]
    );
    state.pending_block_event = Some(event_label.clone());
    state.pending_state_commit = true;

    state
        .processed_protocol_update_hashes
        .insert(document_sha256.clone());

    state.record_app_activity_event(
        "protocol_update_block_event",
        None,
        Some(&format!("v{version}: {title}")),
    );

    Ok((
        StatusCode::OK,
        Json(AdminProtocolUpdateResponse {
            ok: true,
            version: version.to_owned(),
            document_sha256,
            block_event: event_label,
            new_block_triggered: true,
        }),
    ))
}

// ── Bridge (L1 → BSC) burn handlers ────────────────────────────────────────

/// Validate that a string looks like a BSC address (0x + 40 hex chars).
fn is_valid_bsc_address(addr: &str) -> bool {
    let s = addr.trim();
    if !s.starts_with("0x") && !s.starts_with("0X") {
        return false;
    }
    let hex = &s[2..];
    hex.len() == 40 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

/// Whether L1 → BSC bridge burn endpoints are enabled.
/// Gated by `ANET_BRIDGE_BURN_ENABLED=true` env var (default: disabled).
fn bridge_burn_enabled() -> Result<(), (StatusCode, Json<ApiError>)> {
    let enabled = std::env::var("ANET_BRIDGE_BURN_ENABLED")
        .ok()
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(false);
    if !enabled {
        return Err(not_found(
            "bridge burn endpoint is disabled on this node".to_owned(),
        ));
    }
    Ok(())
}

/// User-initiated L1 → BSC bridge burn. Burns `amount_ants` from the
/// caller's L1 balance and records a `bridge_burns` row with status
/// `pending`. The relayer polls `/bridge/burns` and releases the
/// equivalent amount on BSC, then calls `/bridge/burns/:id/released`.
async fn post_bridge_burn(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<BridgeBurnRequest>,
) -> Result<(StatusCode, Json<BridgeBurnResponse>), (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    if request_prefers_html(&headers) {
        return Err(bad_request(
            "HTML requests are not supported for this endpoint",
        ));
    }

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };

    let sender_claim = request.sender.trim().to_uppercase();
    let bsc_recipient = request.bsc_recipient.trim().to_lowercase();
    if !is_valid_bsc_address(&bsc_recipient) {
        return Err(bad_request(
            "bsc_recipient must be a 0x-prefixed 40-hex BSC address",
        ));
    }

    if request.amount_ants == 0 {
        return Err(bad_request("amount_ants must be greater than zero"));
    }

    let token_symbol = request.token_symbol.trim().to_uppercase();
    if token_symbol != "ANET" {
        return Err(bad_request(
            "token_symbol must be ANET for the current bridge vault",
        ));
    }

    // Per-tx safety cap (in ANET) — mirrors the BSC-side relayer cap so a
    // compromised wallet cannot drain the BSC escrow in a single call.
    let max_per_burn_anet: u64 = std::env::var("ANET_BRIDGE_MAX_BURN_PER_TX_ANET")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(10_000);
    let max_per_burn_ants = max_per_burn_anet.saturating_mul(crate::activation::ANTS_PER_ANET);
    if request.amount_ants > max_per_burn_ants {
        return Err(bad_request(format!(
            "burn exceeds per-tx cap of {max_per_burn_anet} ANET"
        )));
    }

    let auth_wallet = verify_bound_action(
        &context,
        "bridge_burn",
        &request.auth,
        serde_json::json!({
            "route": "bridge_burn",
            "sender": sender_claim.clone(),
            "bsc_recipient": bsc_recipient.clone(),
            "amount_ants": request.amount_ants,
            "token_symbol": token_symbol.clone(),
        }),
    )
    .await?;
    if auth_wallet != sender_claim {
        return Err(unauthorized("auth wallet does not match sender".to_owned()));
    }

    // ── 1. Debit L1 balance (atomic, in-memory) ──────────────────────────
    let (new_balance, accounts_before, block_event_before, state_commit_before) = {
        let mut state = context.state.write().await;
        let accounts_before = state.accounts.clone();
        let block_event_before = state.pending_block_event.clone();
        let state_commit_before = state.pending_state_commit;
        let new_balance = state
            .bridge_burn_anet(&sender_claim, request.amount_ants)
            .map_err(bad_request)?;
        (
            new_balance,
            accounts_before,
            block_event_before,
            state_commit_before,
        )
    };

    // ── 2. Persist the burn intent to Postgres ───────────────────────────
    // If this insert fails after the in-memory debit, we'd have an
    // inconsistency. To recover we re-credit the user and surface the
    // error.
    // Canonical EIP-712 deadline for the BSC-side release. All vault signers
    // must sign over this exact value so their sigs hash identically.
    let deadline_secs: i64 = std::env::var("BRIDGE_DEADLINE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0 && *v <= 30 * 24 * 3600)
        .unwrap_or(86_400);
    let release_deadline = chrono::Utc::now().timestamp().saturating_add(deadline_secs);

    let row = match db::insert_bridge_burn(
        chain_db.as_ref(),
        &sender_claim,
        &bsc_recipient,
        request.amount_ants,
        &token_symbol,
        release_deadline,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            let mut state = context.state.write().await;
            state.accounts = accounts_before;
            state.pending_block_event = block_event_before;
            state.pending_state_commit = state_commit_before;
            return Err(service_unavailable(format!(
                "bridge burn could not be recorded: {e}"
            )));
        }
    };

    tracing::info!(
        burn_id = row.burn_id,
        sender = %sender_claim,
        bsc_recipient = %bsc_recipient,
        ants = request.amount_ants,
        "L1 bridge burn recorded"
    );

    Ok((
        StatusCode::OK,
        Json(BridgeBurnResponse {
            burn_id: row.burn_id,
            l1_sender: row.l1_sender,
            bsc_recipient: row.bsc_recipient,
            ants_burned: request.amount_ants,
            anet_burned: state::format_anet_fixed(request.amount_ants),
            token_symbol: row.token_symbol,
            new_l1_ants_balance: new_balance,
            new_l1_anet_balance: state::format_anet_fixed(new_balance),
            status: row.status,
            created_at: row.created_at,
        }),
    ))
}

/// Relayer polling endpoint. Returns up to `limit` pending burns with
/// `burn_id > since`, oldest first. Admin-key protected.
async fn get_bridge_burns_pending(
    AxumState(context): AxumState<RpcContext>,
    Query(query): Query<BridgeBurnListQuery>,
) -> Result<Json<Vec<db::BridgeBurnRow>>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let expected_key = dex_admin_key_required()?;
    if !constant_time_key_eq(query.admin_key.trim(), &expected_key) {
        return Err(unauthorized("invalid admin key".to_owned()));
    }

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let limit = query.limit.clamp(1, 500);
    let rows = db::list_pending_bridge_burns(chain_db.as_ref(), query.since, limit)
        .await
        .map_err(service_unavailable)?;
    Ok(Json(rows))
}

/// Public read of a single burn by id. Used by the wallet UI to poll
/// status after submitting a burn.
///
/// Supports an optional `?wait_ms=N` long-poll: if the burn is not yet in a
/// terminal state, the handler waits up to `N` ms (clamped to
/// `BRIDGE_BURN_LONGPOLL_MAX_MS`) re-checking the DB roughly every
/// `BRIDGE_BURN_LONGPOLL_TICK_MS`, and returns as soon as the status flips
/// to `released`/`failed`/`skipped`. This is what powers "instant" L1→wANET
/// swap UX from the mobile app — one request, returns with the BSC tx hash.
async fn get_bridge_burn_by_id(
    AxumState(context): AxumState<RpcContext>,
    Path(id): Path<i64>,
    Query(query): Query<BridgeBurnByIdQuery>,
) -> Result<Json<db::BridgeBurnRow>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };

    // Fast path: one read.
    let initial = db::get_bridge_burn(chain_db.as_ref(), id)
        .await
        .map_err(service_unavailable)?;
    let row = match initial {
        Some(r) => r,
        None => return Err(not_found(format!("burn {id} not found"))),
    };

    // No long-poll requested, or already terminal — return immediately.
    let wait_ms = query.wait_ms.unwrap_or(0);
    if wait_ms == 0 || is_terminal_burn_status(&row.status) {
        return Ok(Json(row));
    }

    // Long-poll: re-read up to wait_ms (clamped) until terminal or timeout.
    let budget = Duration::from_millis(wait_ms.min(BRIDGE_BURN_LONGPOLL_MAX_MS));
    let tick = Duration::from_millis(BRIDGE_BURN_LONGPOLL_TICK_MS);
    let deadline = Instant::now() + budget;
    let mut latest = row;
    while Instant::now() < deadline {
        sleep(tick).await;
        let next = db::get_bridge_burn(chain_db.as_ref(), id)
            .await
            .map_err(service_unavailable)?;
        if let Some(r) = next {
            let terminal = is_terminal_burn_status(&r.status);
            latest = r;
            if terminal {
                break;
            }
        }
    }
    Ok(Json(latest))
}

/// Wallet history endpoint: most recent burns for a given L1 sender.
async fn get_bridge_burns_by_sender(
    AxumState(context): AxumState<RpcContext>,
    Path(address): Path<String>,
) -> Result<Json<Vec<db::BridgeBurnRow>>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let normalized = address.trim().to_uppercase();
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let rows = db::list_bridge_burns_for_sender(chain_db.as_ref(), &normalized, 100)
        .await
        .map_err(service_unavailable)?;
    Ok(Json(rows))
}

/// Relayer callback: marks a burn as released on BSC. Admin-key protected.
async fn post_bridge_burn_released(
    AxumState(context): AxumState<RpcContext>,
    Path(id): Path<i64>,
    Json(request): Json<BridgeBurnReleaseRequest>,
) -> Result<Json<db::BridgeBurnRow>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let expected_key = dex_admin_key_required()?;
    if !constant_time_key_eq(request.admin_key.trim(), &expected_key) {
        return Err(unauthorized("invalid admin key".to_owned()));
    }
    let bsc_tx_hash = request.bsc_tx_hash.trim().to_string();
    if bsc_tx_hash.is_empty() {
        return Err(bad_request("bsc_tx_hash is required"));
    }
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let row = db::mark_bridge_burn_released(chain_db.as_ref(), id, &bsc_tx_hash)
        .await
        .map_err(service_unavailable)?;
    match row {
        Some(r) => {
            tracing::info!(
                burn_id = r.burn_id,
                bsc_tx_hash = %bsc_tx_hash,
                "L1 bridge burn marked released"
            );
            Ok(Json(r))
        }
        None => Err(not_found(format!(
            "burn {id} not found or no longer pending"
        ))),
    }
}

/// Relayer callback: marks a burn as failed (e.g. BSC tx reverted).
/// Note: this does NOT re-credit the user. Failure recovery is a
/// manual operator action — verify on BSC what actually happened
/// first to avoid double-paying.
async fn post_bridge_burn_failed(
    AxumState(context): AxumState<RpcContext>,
    Path(id): Path<i64>,
    Json(request): Json<BridgeBurnFailRequest>,
) -> Result<Json<db::BridgeBurnRow>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let expected_key = dex_admin_key_required()?;
    if !constant_time_key_eq(request.admin_key.trim(), &expected_key) {
        return Err(unauthorized("invalid admin key".to_owned()));
    }
    let err_msg = request.error.trim().to_string();
    if err_msg.is_empty() {
        return Err(bad_request("error message is required"));
    }
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let row = db::mark_bridge_burn_failed(chain_db.as_ref(), id, &err_msg)
        .await
        .map_err(service_unavailable)?;
    match row {
        Some(r) => {
            tracing::warn!(
                burn_id = r.burn_id,
                error = %err_msg,
                "L1 bridge burn marked failed (operator action required)"
            );
            Ok(Json(r))
        }
        None => Err(not_found(format!(
            "burn {id} not found or no longer pending"
        ))),
    }
}

// ── Decentralized BSC release: out-of-band signature aggregation ───────────
//
// The vault's `releaseBurn(...)` on BSC requires M-of-N EIP-712 signatures
// over a `Release` struct. To avoid concentrating any private key on the
// L1 node or the relayer, each signer runs their own signing daemon, signs
// the digest locally, and POSTs the signature here. Anyone can read the
// collected sigs and submit `releaseBurn` on BSC.
//
//   GET  /bridge/burns/:id/digest  → metadata + EIP-712 digest (hex)
//   POST /bridge/burns/:id/sigs    → submit one signer's signature
//   GET  /bridge/burns/:id/sigs    → list collected sigs (relayer reads)

#[derive(Debug, serde::Serialize)]
struct BridgeBurnDigestResponse {
    burn_id: i64,
    l1_sender: String,
    bsc_recipient: String,
    /// Amount in wei (1e18-scaled), 0x-prefixed lowercase hex of a uint256.
    amount_wei_hex: String,
    /// Same value as decimal string for convenience.
    amount_wei_decimal: String,
    /// Canonical EIP-712 deadline. All signers MUST use this exact value.
    deadline: i64,
    /// 0x-prefixed lowercase 32-byte digest the signer should sign.
    digest: String,
    /// Allowed signer set (for the signer daemon to refuse to sign if its
    /// address is not in the set).
    signers: Vec<String>,
    threshold: u32,
    /// Vault contract address (0x-prefixed lowercase).
    vault_address: String,
    chain_id: u64,
    status: String,
}

#[derive(Debug, serde::Deserialize)]
struct BridgeBurnSigRequest {
    /// 0x-prefixed lowercase BSC address that produced `signature`.
    signer: String,
    /// 0x-prefixed 65-byte signature (r ‖ s ‖ v) hex.
    signature: String,
}

/// Helper: read vault config from env, returning a 503 if unconfigured.
fn require_vault_cfg() -> Result<bridge_vault::VaultConfig, (StatusCode, Json<ApiError>)> {
    match bridge_vault::VaultConfig::from_env() {
        Ok(Some(cfg)) => Ok(cfg),
        Ok(None) => Err(service_unavailable(
            "bridge vault config not set (BRIDGE_VAULT_ADDRESS missing)",
        )),
        Err(e) => Err(service_unavailable(format!(
            "bridge vault config invalid: {e}"
        ))),
    }
}

/// Compute the EIP-712 digest a vault signer must sign for the given burn.
/// Returns metadata + digest. Public read (no auth).
async fn get_bridge_burn_digest(
    AxumState(context): AxumState<RpcContext>,
    Path(id): Path<i64>,
) -> Result<Json<BridgeBurnDigestResponse>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let cfg = require_vault_cfg()?;

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let row = db::get_bridge_burn(chain_db.as_ref(), id)
        .await
        .map_err(service_unavailable)?
        .ok_or_else(|| not_found(format!("burn {id} not found")))?;

    if row.status != "pending" {
        return Err(bad_request(format!(
            "burn {id} status is '{}', signatures not collectable",
            row.status
        )));
    }
    let deadline = row
        .release_deadline
        .ok_or_else(|| service_unavailable("burn has no release_deadline (pre-migration row)"))?;

    let burn_id_u64 = u64::try_from(row.burn_id).map_err(|_| bad_request("burn_id negative"))?;
    let deadline_u64 = u64::try_from(deadline).map_err(|_| bad_request("deadline negative"))?;
    let ants_u64 = u64::try_from(row.ants).map_err(|_| bad_request("ants negative"))?;

    let recipient = bridge_vault::parse_bsc_recipient(&row.bsc_recipient)
        .ok_or_else(|| service_unavailable("burn has invalid bsc_recipient"))?;
    let amount_wei = bridge_vault::ants_to_wei_be(ants_u64);

    let digest = bridge_vault::release_digest(
        &cfg,
        burn_id_u64,
        &row.l1_sender,
        &recipient,
        &amount_wei,
        deadline_u64,
    );

    // Strip leading zeros for decimal display.
    let amount_wei_decimal = {
        let last16 = &amount_wei[16..];
        u128::from_be_bytes(last16.try_into().unwrap()).to_string()
    };

    Ok(Json(BridgeBurnDigestResponse {
        burn_id: row.burn_id,
        l1_sender: row.l1_sender,
        bsc_recipient: row.bsc_recipient,
        amount_wei_hex: format!("0x{}", hex::encode(amount_wei)),
        amount_wei_decimal,
        deadline,
        digest: format!("0x{}", hex::encode(digest)),
        signers: cfg.signers.clone(),
        threshold: cfg.threshold,
        vault_address: format!("0x{}", hex::encode(cfg.vault_address)),
        chain_id: cfg.chain_id,
        status: row.status,
    }))
}

/// Submit one signer's EIP-712 signature for the given burn. The handler
/// independently recomputes the digest from the stored burn row, recovers
/// the signer address via ecrecover, and verifies it matches both the
/// `signer` field in the body AND the configured signer set. Idempotent:
/// posting the same (burn_id, signer) twice overwrites the sig.
async fn post_bridge_burn_sig(
    AxumState(context): AxumState<RpcContext>,
    Path(id): Path<i64>,
    Json(request): Json<BridgeBurnSigRequest>,
) -> Result<Json<db::BridgeBurnSignatureRow>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let cfg = require_vault_cfg()?;

    let claimed_signer = request.signer.trim().to_lowercase();
    if !claimed_signer.starts_with("0x") || claimed_signer.len() != 42 {
        return Err(bad_request("signer must be a 0x-prefixed BSC address"));
    }
    if !cfg.signers.iter().any(|s| s == &claimed_signer) {
        return Err(unauthorized(format!(
            "{claimed_signer} is not in the vault signer set"
        )));
    }

    let sig_hex = request.signature.trim();
    let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| bad_request(format!("signature is not valid hex: {e}")))?;

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let row = db::get_bridge_burn(chain_db.as_ref(), id)
        .await
        .map_err(service_unavailable)?
        .ok_or_else(|| not_found(format!("burn {id} not found")))?;
    if row.status != "pending" {
        return Err(bad_request(format!(
            "burn {id} status is '{}'; signatures rejected",
            row.status
        )));
    }
    let deadline = row
        .release_deadline
        .ok_or_else(|| service_unavailable("burn has no release_deadline (pre-migration row)"))?;
    let burn_id_u64 = u64::try_from(row.burn_id).map_err(|_| bad_request("burn_id negative"))?;
    let deadline_u64 = u64::try_from(deadline).map_err(|_| bad_request("deadline negative"))?;
    let ants_u64 = u64::try_from(row.ants).map_err(|_| bad_request("ants negative"))?;
    if deadline < chrono::Utc::now().timestamp() {
        return Err(bad_request("release deadline has expired"));
    }

    let recipient = bridge_vault::parse_bsc_recipient(&row.bsc_recipient)
        .ok_or_else(|| service_unavailable("burn has invalid bsc_recipient"))?;
    let amount_wei = bridge_vault::ants_to_wei_be(ants_u64);
    let digest = bridge_vault::release_digest(
        &cfg,
        burn_id_u64,
        &row.l1_sender,
        &recipient,
        &amount_wei,
        deadline_u64,
    );

    let recovered = bridge_vault::recover_signer(&digest, &sig_bytes)
        .map_err(|e| bad_request(format!("ecrecover failed: {e}")))?;
    if recovered != claimed_signer {
        return Err(unauthorized(format!(
            "recovered signer {recovered} does not match claimed {claimed_signer}"
        )));
    }

    let saved = db::insert_bridge_burn_signature(
        chain_db.as_ref(),
        id,
        &claimed_signer,
        &format!("0x{}", hex::encode(&sig_bytes)),
    )
    .await
    .map_err(service_unavailable)?;
    tracing::info!(
        burn_id = id,
        signer = %claimed_signer,
        "bridge vault signature accepted"
    );
    Ok(Json(saved))
}

/// List collected signatures for a burn. Public read (the relayer or
/// anyone uses this to assemble the M-of-N bundle for releaseBurn()).
async fn get_bridge_burn_sigs(
    AxumState(context): AxumState<RpcContext>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<db::BridgeBurnSignatureRow>>, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let rows = db::list_bridge_burn_signatures(chain_db.as_ref(), id)
        .await
        .map_err(service_unavailable)?;
    Ok(Json(rows))
}

// ── Wallet migration: legacy-derivation → secp-derivation ──────────────────
//
// Bitcoin-aligned, permissionless sweep that lets a holder of a legacy
// address (RIPEMD160(SHA256(seed)_hex_string)) migrate their balance to a
// signing-capable secp address (RIPEMD160(compressed_pubkey)), without any
// admin involvement. Uses commit-reveal to prevent mempool front-running
// of the revealed private key.
//
// Phase 1 — commit (this endpoint just records the binding):
//   commit_hash = SHA256( hex_lower(privkey_bytes) || ":" ||
//                          secp_address_upper      || ":" ||
//                          nonce_decimal )
//   Auth: action_v1 signed by the secp privkey, action_type "migrate_commit".
//
// Phase 2 — reveal: caller posts privkey_hex + nonce. Server verifies:
//   1) auth recovers to the same secp_address that was committed,
//   2) the privkey reproduces commit_hash exactly,
//   3) RIPEMD160(SHA256(hex_lower(privkey))_hex_lower_bytes) == legacy_address,
//   4) derive_address_from_public_key(secp_pubkey_of(privkey)) == secp_address,
//   then atomically moves the legacy balance to secp and records the migration
//   in the next block as "WalletMigration: <legacy> -> <secp> ants=... sessions=...".

#[derive(Debug, Deserialize)]
struct WalletMigrateCommitRequest {
    legacy_address: String,
    secp_address: String,
    commit_hash: String,
    auth: SignedActionAuthorization,
}

#[derive(Debug, Serialize)]
struct WalletMigrateCommitResponse {
    legacy_address: String,
    secp_address: String,
    commit_hash: String,
    status: String,
    committed_at: String,
}

#[derive(Debug, Deserialize)]
struct WalletMigrateRevealRequest {
    legacy_address: String,
    secp_address: String,
    privkey_hex: String,
    nonce: u64,
    auth: SignedActionAuthorization,
}

#[derive(Debug, Serialize)]
struct WalletMigrateRevealResponse {
    legacy_address: String,
    secp_address: String,
    ants_migrated: u64,
    sessions_migrated: u64,
    new_secp_ants_balance: u64,
    status: String,
}

fn normalize_anet_addr(s: &str) -> String {
    s.trim().to_uppercase()
}

fn migration_enabled() -> Result<(), (StatusCode, Json<ApiError>)> {
    let enabled = std::env::var("ANET_WALLET_MIGRATION_ENABLED")
        .ok()
        .map(|v| v.trim().eq_ignore_ascii_case("true") || v.trim() == "1")
        .unwrap_or(false);
    if !enabled {
        return Err(not_found(
            "wallet migration endpoint is disabled; the legacy reveal flow exposes private key material and requires explicit operator opt-in".to_owned(),
        ));
    }
    Ok(())
}

async fn post_wallet_migrate_commit(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<WalletMigrateCommitRequest>,
) -> Result<(StatusCode, Json<WalletMigrateCommitResponse>), (StatusCode, Json<ApiError>)> {
    migration_enabled()?;
    if request_prefers_html(&headers) {
        return Err(bad_request(
            "HTML requests are not supported for this endpoint",
        ));
    }

    let legacy = normalize_anet_addr(&request.legacy_address);
    let secp = normalize_anet_addr(&request.secp_address);
    let commit_hash = request.commit_hash.trim().to_lowercase();

    if legacy == secp {
        return Err(bad_request(
            "legacy_address and secp_address must differ".to_owned(),
        ));
    }
    if !crate::transaction::is_valid_anet_wallet(&legacy)
        || !crate::transaction::is_valid_anet_wallet(&secp)
    {
        return Err(bad_request("invalid ANET address format".to_owned()));
    }
    if commit_hash.len() != 64 || !commit_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad_request(
            "commit_hash must be 64 lowercase hex chars (SHA-256)".to_owned(),
        ));
    }

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let auth_wallet = verify_bound_action(
        &context,
        "migrate_commit",
        &request.auth,
        serde_json::json!({
            "route": "migrate_commit",
            "legacy_address": legacy.clone(),
            "secp_address": secp.clone(),
            "commit_hash": commit_hash.clone(),
        }),
    )
    .await?;
    if auth_wallet != secp {
        return Err(unauthorized(
            "auth wallet does not match secp_address".to_owned(),
        ));
    }

    // Reject if a migration row already exists for this legacy address.
    if let Some(existing) = db::get_wallet_migration(chain_db.as_ref(), &legacy)
        .await
        .map_err(service_unavailable)?
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError {
                error: format!(
                    "legacy_address already has migration row (status={}, committed_at={})",
                    existing.status, existing.committed_at
                ),
            }),
        ));
    }

    let row = db::insert_wallet_migration_commit(chain_db.as_ref(), &legacy, &secp, &commit_hash)
        .await
        .map_err(service_unavailable)?;

    tracing::info!(
        legacy = %legacy,
        secp = %secp,
        "wallet migration commit recorded"
    );

    Ok((
        StatusCode::OK,
        Json(WalletMigrateCommitResponse {
            legacy_address: row.legacy_address,
            secp_address: row.secp_address,
            commit_hash: row.commit_hash,
            status: row.status,
            committed_at: row.committed_at,
        }),
    ))
}

async fn post_wallet_migrate_reveal(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<WalletMigrateRevealRequest>,
) -> Result<(StatusCode, Json<WalletMigrateRevealResponse>), (StatusCode, Json<ApiError>)> {
    migration_enabled()?;
    if request_prefers_html(&headers) {
        return Err(bad_request(
            "HTML requests are not supported for this endpoint",
        ));
    }

    let legacy = normalize_anet_addr(&request.legacy_address);
    let secp = normalize_anet_addr(&request.secp_address);
    let privkey_hex = request
        .privkey_hex
        .trim()
        .trim_start_matches("0x")
        .to_lowercase();
    let nonce = request.nonce;

    if privkey_hex.len() != 64 || !privkey_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad_request(
            "privkey_hex must be 64 hex chars (32 bytes)".to_owned(),
        ));
    }
    let privkey_bytes_vec = hex::decode(&privkey_hex)
        .map_err(|e| bad_request(format!("privkey_hex decode failed: {e}")))?;
    let privkey_bytes: [u8; 32] = privkey_bytes_vec
        .as_slice()
        .try_into()
        .map_err(|_| bad_request("privkey_hex must be exactly 32 bytes".to_owned()))?;

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };

    // Auth: must be signed by the secp key being claimed.
    let auth_wallet = verify_bound_action(
        &context,
        "migrate_reveal",
        &request.auth,
        serde_json::json!({
            "route": "migrate_reveal",
            "legacy_address": legacy.clone(),
            "secp_address": secp.clone(),
            "nonce": nonce,
        }),
    )
    .await?;
    if auth_wallet != secp {
        return Err(unauthorized(
            "auth wallet does not match secp_address".to_owned(),
        ));
    }

    // Look up the prior commit.
    let migration_row = db::get_wallet_migration(chain_db.as_ref(), &legacy)
        .await
        .map_err(service_unavailable)?
        .ok_or_else(|| bad_request("no prior commit found for this legacy_address".to_owned()))?;
    if migration_row.status != "committed" {
        return Err(bad_request(format!(
            "migration already in status {}",
            migration_row.status
        )));
    }
    if normalize_anet_addr(&migration_row.secp_address) != secp {
        return Err(unauthorized(
            "secp_address does not match committed secp_address (front-run attempt rejected)"
                .to_owned(),
        ));
    }

    // Recompute commit_hash and compare with stored.
    let preimage = format!("{privkey_hex}:{secp}:{nonce}");
    let mut sha = Sha256::new();
    sha.update(preimage.as_bytes());
    let computed_commit = hex::encode(sha.finalize());
    if computed_commit != migration_row.commit_hash.to_lowercase() {
        return Err(unauthorized(
            "commit hash mismatch: provided privkey/nonce do not match the recorded commitment"
                .to_owned(),
        ));
    }

    // Verify legacy derivation from privkey.
    let derived_legacy =
        crate::transaction::derive_legacy_address_from_privkey_bytes(&privkey_bytes);
    if derived_legacy != legacy {
        return Err(unauthorized(format!(
            "privkey does not control legacy_address (derived={derived_legacy})"
        )));
    }

    // Verify secp derivation from privkey.
    let secret = secp256k1::SecretKey::from_slice(&privkey_bytes)
        .map_err(|e| bad_request(format!("privkey invalid for secp256k1: {e}")))?;
    let secp_ctx = secp256k1::Secp256k1::new();
    let pubkey = secp256k1::PublicKey::from_secret_key(&secp_ctx, &secret);
    let derived_secp = crate::transaction::derive_address_from_public_key(&pubkey);
    if derived_secp != secp {
        return Err(unauthorized(format!(
            "privkey does not control secp_address (derived={derived_secp})"
        )));
    }

    // All checks passed — atomic state mutation.
    let (ants_moved, sessions_moved, _total_activated_moved) = {
        let mut state = context.state.write().await;
        let moved = state
            .migrate_legacy_to_secp(&legacy, &secp)
            .map_err(bad_request)?;
        // Forward any future credit for this legacy address to the secp wallet.
        state.register_migrated_secp(&legacy, &secp);
        moved
    };

    // Persist completion record.
    let _completed =
        db::complete_wallet_migration(chain_db.as_ref(), &legacy, ants_moved, sessions_moved)
            .await
            .map_err(service_unavailable)?;

    let new_secp_balance = {
        let state = context.state.read().await;
        state
            .account_view(&secp)
            .map(|v| v.ants_balance)
            .unwrap_or(0)
    };

    tracing::info!(
        legacy = %legacy,
        secp = %secp,
        ants_moved,
        sessions_moved,
        "wallet migration completed"
    );

    Ok((
        StatusCode::OK,
        Json(WalletMigrateRevealResponse {
            legacy_address: legacy,
            secp_address: secp,
            ants_migrated: ants_moved,
            sessions_migrated: sessions_moved,
            new_secp_ants_balance: new_secp_balance,
            status: "revealed".to_owned(),
        }),
    ))
}

async fn get_wallet_migrate_status(
    AxumState(context): AxumState<RpcContext>,
    Path(legacy_address): Path<String>,
) -> Result<Json<db::WalletMigrationRow>, (StatusCode, Json<ApiError>)> {
    migration_enabled()?;
    let legacy = normalize_anet_addr(&legacy_address);
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let row = db::get_wallet_migration(chain_db.as_ref(), &legacy)
        .await
        .map_err(service_unavailable)?
        .ok_or_else(|| not_found("no migration record for this address".to_owned()))?;
    Ok(Json(row))
}

// Admin-only: cancel a stuck (committed-but-not-revealed) migration.
//
// Required when an off-chain commit nonce is lost — without the nonce the
// reveal can never reproduce the commit_hash and the legacy balance is
// stranded forever. Deleting the row simply lets the user retry the full
// commit → reveal flow with a fresh nonce. Never operates on 'revealed'
// rows. Gated by env var ANET_MIGRATION_ADMIN_KEY (falls back to the
// DEX admin key for operational simplicity if unset).
#[derive(Debug, Deserialize)]
struct StrandedQuery {
    #[serde(default)]
    admin_key: String,
}

/// Read-only diagnostic: list every migrated (`revealed`) wallet whose LEGACY
/// address still holds an on-chain balance. These are funds credited to the
/// legacy address *after* it was migrated (e.g. a wANET bridge credit), which
/// the one-shot migration flow cannot move, so they are currently stranded.
/// Moves nothing. Admin-key gated to avoid publicly enumerating the
/// legacy-to-secp wallet mapping of every user.
async fn get_stranded_migrations(
    AxumState(context): AxumState<RpcContext>,
    Query(query): Query<StrandedQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let expected_key = migration_admin_key_required()?;
    if !constant_time_key_eq(query.admin_key.trim(), &expected_key) {
        return Err(unauthorized("invalid admin key".to_owned()));
    }

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let rows = db::list_revealed_wallet_migrations(chain_db.as_ref())
        .await
        .map_err(service_unavailable)?;

    let state = context.state.read().await;
    let mut wallets = Vec::new();
    let mut total_stranded_ants: u128 = 0;
    for row in &rows {
        let legacy = row.legacy_address.trim().to_uppercase();
        let view = state.account_view(&legacy);
        let ants = view.as_ref().map(|v| v.ants_balance).unwrap_or(0);
        if ants > 0 {
            let sessions = view.as_ref().map(|v| v.sessions).unwrap_or(0);
            total_stranded_ants += u128::from(ants);
            wallets.push(serde_json::json!({
                "legacy_address": legacy,
                "secp_address": row.secp_address,
                "stranded_ants": ants,
                "stranded_anet": state::format_anet_fixed(ants),
                "legacy_sessions": sessions,
                "ants_migrated": row.ants_migrated,
                "revealed_at": row.revealed_at,
            }));
        }
    }
    drop(state);

    let total_anet = state::format_anet_fixed(u64::try_from(total_stranded_ants).unwrap_or(u64::MAX));
    Ok(Json(serde_json::json!({
        "revealed_migrations": rows.len(),
        "stranded_wallets": wallets.len(),
        "total_stranded_ants": total_stranded_ants.to_string(),
        "total_stranded_anet": total_anet,
        "wallets": wallets,
    })))
}

#[derive(Debug, Deserialize)]
struct AdminWalletMigrateResweepRequest {
    legacy_address: String,
    admin_key: String,
}

#[derive(Debug, Serialize)]
struct AdminWalletMigrateResweepResponse {
    legacy_address: String,
    secp_address: String,
    swept_ants: u64,
    swept_anet: String,
    status: &'static str,
}

/// Admin-only recovery for funds credited to a legacy address *after* it was
/// already migrated (which the one-shot reveal flow cannot move). Moves the
/// legacy's current balance to the secp recorded in the proven `revealed`
/// migration row — the destination comes from that row, never from the
/// request, so funds can only reach the wallet that already proved ownership of
/// this legacy address. Durable: emits a real block transaction reproduced on
/// replay, and marks the secp bridge-funded so the recovered ANET is spendable.
async fn post_admin_wallet_migrate_resweep(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<AdminWalletMigrateResweepRequest>,
) -> Result<(StatusCode, Json<AdminWalletMigrateResweepResponse>), (StatusCode, Json<ApiError>)> {
    migration_enabled()?;
    if request_prefers_html(&headers) {
        return Err(bad_request(
            "HTML requests are not supported for this endpoint",
        ));
    }
    let expected_key = migration_admin_key_required()?;
    if !constant_time_key_eq(request.admin_key.trim(), &expected_key) {
        return Err(unauthorized("invalid admin key".to_owned()));
    }

    let legacy = normalize_anet_addr(&request.legacy_address);
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let row = db::get_wallet_migration(chain_db.as_ref(), &legacy)
        .await
        .map_err(service_unavailable)?
        .ok_or_else(|| bad_request("no migration row for this legacy_address".to_owned()))?;
    if row.status != "revealed" {
        return Err(bad_request(format!(
            "legacy migration is not in 'revealed' status (status={})",
            row.status
        )));
    }
    let secp = normalize_anet_addr(&row.secp_address);

    let swept_ants = {
        let mut state = context.state.write().await;
        state
            .sweep_legacy_balance_to_secp(&legacy, &secp)
            .map_err(bad_request)?
    };

    tracing::info!(legacy = %legacy, secp = %secp, swept_ants, "wallet migration re-sweep queued");

    Ok((
        StatusCode::OK,
        Json(AdminWalletMigrateResweepResponse {
            swept_anet: state::format_anet_fixed(swept_ants),
            legacy_address: legacy,
            secp_address: secp,
            swept_ants,
            status: "swept",
        }),
    ))
}

#[derive(Debug, Deserialize)]
struct AdminWalletMigrateCancelRequest {
    legacy_address: String,
    admin_key: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminWalletMigrateCancelResponse {
    legacy_address: String,
    secp_address: String,
    commit_hash: String,
    committed_at: String,
    cancelled: bool,
}

fn migration_admin_key_required() -> Result<String, (StatusCode, Json<ApiError>)> {
    let key = std::env::var("ANET_MIGRATION_ADMIN_KEY")
        .ok()
        .or_else(|| std::env::var("ANET_DEX_ADMIN_KEY").ok())
        .unwrap_or_default();
    let trimmed = key.trim().to_owned();
    if trimmed.is_empty() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                error: "migration admin key not configured".to_owned(),
            }),
        ));
    }
    Ok(trimmed)
}

async fn post_admin_wallet_migrate_cancel(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<AdminWalletMigrateCancelRequest>,
) -> Result<(StatusCode, Json<AdminWalletMigrateCancelResponse>), (StatusCode, Json<ApiError>)> {
    migration_enabled()?;
    if request_prefers_html(&headers) {
        return Err(bad_request(
            "HTML requests are not supported for this endpoint",
        ));
    }

    let expected_key = migration_admin_key_required()?;
    if !constant_time_key_eq(request.admin_key.trim(), &expected_key) {
        return Err(unauthorized("invalid admin key".to_owned()));
    }

    let legacy = normalize_anet_addr(&request.legacy_address);
    if !crate::transaction::is_valid_anet_wallet(&legacy) {
        return Err(bad_request("invalid legacy ANET address format".to_owned()));
    }

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };

    let row = db::delete_wallet_migration_committed(chain_db.as_ref(), &legacy)
        .await
        .map_err(service_unavailable)?
        .ok_or_else(|| {
            not_found("no cancellable (status=committed) migration row for this address".to_owned())
        })?;

    tracing::warn!(
        legacy = %legacy,
        secp = %row.secp_address,
        commit_hash = %row.commit_hash,
        reason = %request.reason.clone().unwrap_or_default(),
        "admin cancelled stuck wallet migration"
    );

    Ok((
        StatusCode::OK,
        Json(AdminWalletMigrateCancelResponse {
            legacy_address: row.legacy_address,
            secp_address: row.secp_address,
            commit_hash: row.commit_hash,
            committed_at: row.committed_at,
            cancelled: true,
        }),
    ))
}

fn dex_admin_key_required() -> Result<String, (StatusCode, Json<ApiError>)> {
    let expected_key = std::env::var("ANET_DEX_ADMIN_KEY").unwrap_or_default();
    if expected_key.is_empty() {
        return Err(service_unavailable(
            "ANET_DEX_ADMIN_KEY is not configured".to_owned(),
        ));
    }
    Ok(expected_key)
}

async fn post_dex_create_pool(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<DexCreatePoolRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if explorer_auth_required() {
        let wallet = authenticated_wallet_from_headers(&headers)
            .ok_or_else(|| unauthorized("wallet login is required".to_owned()))?;
        if request.provider.trim().to_uppercase() != wallet {
            return Err(unauthorized(
                "provider wallet must match authenticated wallet session".to_owned(),
            ));
        }
    }

    let token_symbol =
        crate::dex::normalize_token_symbol(&request.token_symbol).map_err(bad_request)?;
    let anet_amount_ants = request
        .anet_amount_ants
        .as_u64("anet_amount_ants")
        .map_err(bad_request)?;
    let token_amount_units = request
        .token_amount_units
        .as_u64("token_amount_units")
        .map_err(bad_request)?;
    let auth_wallet = verify_bound_action(
        &context,
        "dex_create_pool",
        &request.auth,
        serde_json::json!({
            "route": "dex_create_pool",
            "provider": request.provider.trim().to_uppercase(),
            "token_symbol": token_symbol.clone(),
            "anet_amount_ants": request.anet_amount_ants.payload_value(),
            "token_amount_units": request.token_amount_units.payload_value(),
            "fee_bps": request.fee_bps,
        }),
    )
    .await?;
    if request.provider.trim().to_uppercase() != auth_wallet {
        return Err(unauthorized(
            "action wallet must match provider wallet".to_owned(),
        ));
    }

    let mut state = context.state.write().await;
    let result = state
        .dex_create_pool(
            &request.provider,
            &token_symbol,
            anet_amount_ants,
            token_amount_units,
            request.fee_bps,
        )
        .map_err(bad_request)?;

    Ok((StatusCode::CREATED, Json(result)).into_response())
}

async fn post_dex_wrap(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<DexWrapRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if explorer_auth_required() {
        let wallet = authenticated_wallet_from_headers(&headers)
            .ok_or_else(|| unauthorized("wallet login is required".to_owned()))?;
        if request.wallet.trim().to_uppercase() != wallet {
            return Err(unauthorized(
                "wallet must match authenticated wallet session".to_owned(),
            ));
        }
    }

    let wallet = request.wallet.trim().to_uppercase();
    let amount_ants = request
        .amount_ants
        .as_u64("amount_ants")
        .map_err(bad_request)?;
    let auth_wallet = verify_bound_action(
        &context,
        "dex_wrap",
        &request.auth,
        serde_json::json!({
            "route": "dex_wrap",
            "wallet": wallet.clone(),
            "amount_ants": request.amount_ants.payload_value(),
        }),
    )
    .await?;
    if request.wallet.trim().to_uppercase() != auth_wallet {
        return Err(unauthorized(
            "action wallet must match request wallet".to_owned(),
        ));
    }

    let mut state = context.state.write().await;
    let wanet_balance = state
        .dex_wrap_anet(&wallet, amount_ants)
        .map_err(bad_request)?;
    let anet_balance = state
        .account_view(&wallet)
        .ok_or_else(|| not_found(format!("account {wallet} not found")))?
        .anet_balance;

    Ok((
        StatusCode::OK,
        Json(DexWrapResponse {
            wallet,
            wrapped_symbol: state::WANET_SYMBOL.to_owned(),
            amount_ants,
            wanet_balance,
            anet_balance,
        }),
    )
        .into_response())
}

async fn post_dex_unwrap(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<DexUnwrapRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if explorer_auth_required() {
        let wallet = authenticated_wallet_from_headers(&headers)
            .ok_or_else(|| unauthorized("wallet login is required".to_owned()))?;
        if request.wallet.trim().to_uppercase() != wallet {
            return Err(unauthorized(
                "wallet must match authenticated wallet session".to_owned(),
            ));
        }
    }

    let wallet = request.wallet.trim().to_uppercase();
    let amount_units = request
        .amount_units
        .as_u64("amount_units")
        .map_err(bad_request)?;
    let auth_wallet = verify_bound_action(
        &context,
        "dex_unwrap",
        &request.auth,
        serde_json::json!({
            "route": "dex_unwrap",
            "wallet": wallet.clone(),
            "amount_units": request.amount_units.payload_value(),
        }),
    )
    .await?;
    if request.wallet.trim().to_uppercase() != auth_wallet {
        return Err(unauthorized(
            "action wallet must match request wallet".to_owned(),
        ));
    }

    let mut state = context.state.write().await;
    let anet_raw_balance = state
        .dex_unwrap_wanet(&wallet, amount_units)
        .map_err(bad_request)?;
    let wanet_balance = state
        .accounts
        .get(&wallet)
        .and_then(|account| account.asset_balances.get(state::WANET_SYMBOL).copied())
        .unwrap_or(0);

    Ok((
        StatusCode::OK,
        Json(DexUnwrapResponse {
            wallet,
            wrapped_symbol: state::WANET_SYMBOL.to_owned(),
            amount_units,
            wanet_balance,
            anet_balance: state::format_anet_fixed(anet_raw_balance),
        }),
    )
        .into_response())
}

async fn post_dex_add_liquidity(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<DexAddLiquidityRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if explorer_auth_required() {
        let wallet = authenticated_wallet_from_headers(&headers)
            .ok_or_else(|| unauthorized("wallet login is required".to_owned()))?;
        if request.provider.trim().to_uppercase() != wallet {
            return Err(unauthorized(
                "provider wallet must match authenticated wallet session".to_owned(),
            ));
        }
    }

    let token_symbol =
        crate::dex::normalize_token_symbol(&request.token_symbol).map_err(bad_request)?;
    let anet_amount_ants = request
        .anet_amount_ants
        .as_u64("anet_amount_ants")
        .map_err(bad_request)?;
    let token_amount_units = request
        .token_amount_units
        .as_u64("token_amount_units")
        .map_err(bad_request)?;
    let auth_wallet = verify_bound_action(
        &context,
        "dex_add_liquidity",
        &request.auth,
        serde_json::json!({
            "route": "dex_add_liquidity",
            "provider": request.provider.trim().to_uppercase(),
            "token_symbol": token_symbol.clone(),
            "anet_amount_ants": request.anet_amount_ants.payload_value(),
            "token_amount_units": request.token_amount_units.payload_value(),
        }),
    )
    .await?;
    if request.provider.trim().to_uppercase() != auth_wallet {
        return Err(unauthorized(
            "action wallet must match provider wallet".to_owned(),
        ));
    }

    let mut state = context.state.write().await;
    let result = state
        .dex_add_liquidity(
            &request.provider,
            &token_symbol,
            anet_amount_ants,
            token_amount_units,
        )
        .map_err(bad_request)?;

    Ok((StatusCode::OK, Json(result)).into_response())
}

async fn post_dex_remove_liquidity(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<DexRemoveLiquidityRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if explorer_auth_required() {
        let wallet = authenticated_wallet_from_headers(&headers)
            .ok_or_else(|| unauthorized("wallet login is required".to_owned()))?;
        if request.provider.trim().to_uppercase() != wallet {
            return Err(unauthorized(
                "provider wallet must match authenticated wallet session".to_owned(),
            ));
        }
    }

    let token_symbol =
        crate::dex::normalize_token_symbol(&request.token_symbol).map_err(bad_request)?;
    let lp_units = request
        .lp_units
        .trim()
        .parse::<u128>()
        .map_err(|_| bad_request(anyhow::anyhow!("lp_units must be a u128 string")))?;
    let lp_units_for_auth = lp_units.to_string();
    let auth_wallet = verify_bound_action(
        &context,
        "dex_remove_liquidity",
        &request.auth,
        serde_json::json!({
            "route": "dex_remove_liquidity",
            "provider": request.provider.trim().to_uppercase(),
            "token_symbol": token_symbol.clone(),
            "lp_units": lp_units_for_auth,
        }),
    )
    .await?;
    if request.provider.trim().to_uppercase() != auth_wallet {
        return Err(unauthorized(
            "action wallet must match provider wallet".to_owned(),
        ));
    }

    let mut state = context.state.write().await;
    let result = state
        .dex_remove_liquidity(&request.provider, &token_symbol, lp_units)
        .map_err(bad_request)?;

    Ok((StatusCode::OK, Json(result)).into_response())
}

async fn post_dex_swap_quote(
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<DexSwapQuoteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let amount_in = request.amount_in.as_u64("amount_in").map_err(bad_request)?;
    let state = context.state.read().await;
    let quote = state
        .dex_quote(&request.token_symbol, amount_in, request.anet_to_token)
        .map_err(bad_request)?;

    Ok((StatusCode::OK, Json(quote)).into_response())
}

async fn post_dex_swap_execute(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<DexSwapExecuteRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if explorer_auth_required() {
        let wallet = authenticated_wallet_from_headers(&headers)
            .ok_or_else(|| unauthorized("wallet login is required".to_owned()))?;
        if request.trader.trim().to_uppercase() != wallet {
            return Err(unauthorized(
                "trader wallet must match authenticated wallet session".to_owned(),
            ));
        }
    }

    let token_symbol =
        crate::dex::normalize_token_symbol(&request.token_symbol).map_err(bad_request)?;
    let amount_in = request.amount_in.as_u64("amount_in").map_err(bad_request)?;
    let min_amount_out = request
        .min_amount_out
        .as_ref()
        .map(|amount| amount.as_u64("min_amount_out"))
        .transpose()
        .map_err(bad_request)?;
    let min_amount_out_payload = request
        .min_amount_out
        .as_ref()
        .map(JsonU64Amount::payload_value)
        .unwrap_or(serde_json::Value::Null);
    let auth_wallet = verify_bound_action(
        &context,
        "dex_swap",
        &request.auth,
        serde_json::json!({
            "route": "dex_swap",
            "trader": request.trader.trim().to_uppercase(),
            "token_symbol": token_symbol.clone(),
            "amount_in": request.amount_in.payload_value(),
            "anet_to_token": request.anet_to_token,
            "min_amount_out": min_amount_out_payload,
            "deadline_block": request.deadline_block,
        }),
    )
    .await?;
    if request.trader.trim().to_uppercase() != auth_wallet {
        return Err(unauthorized(
            "action wallet must match trader wallet".to_owned(),
        ));
    }

    let mut state = context.state.write().await;
    let result = state
        .dex_swap(
            &request.trader,
            &token_symbol,
            amount_in,
            request.anet_to_token,
            min_amount_out,
            request.deadline_block,
        )
        .map_err(bad_request)?;

    Ok((StatusCode::OK, Json(result)).into_response())
}

async fn get_anrc20_tokens(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
) -> impl IntoResponse {
    if request_prefers_html(&headers) {
        return Redirect::to("/explorer/api").into_response();
    }

    let state = context.state.read().await;
    Json(state.anrc20_list_tokens()).into_response()
}

async fn get_anrc20_token(
    headers: HeaderMap,
    Path(symbol): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Ok(Redirect::to("/explorer/api").into_response());
    }

    let state = context.state.read().await;
    state
        .anrc20_token_view(&symbol)
        .map(Json)
        .map(IntoResponse::into_response)
        .ok_or_else(|| not_found(format!("ANRC-20 token {symbol} not found")))
}

async fn post_anrc20_create(
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<Anrc20CreateRequest>,
) -> Result<(StatusCode, Json<Anrc20TokenView>), (StatusCode, Json<ApiError>)> {
    let symbol = crate::dex::normalize_token_symbol(&request.symbol).map_err(bad_request)?;
    let initial_supply = request
        .initial_supply
        .as_ref()
        .map(|amount| amount.as_u64("initial_supply"))
        .transpose()
        .map_err(bad_request)?
        .unwrap_or(0);
    let owner = verify_bound_action(
        &context,
        "anrc20_create",
        &request.auth,
        serde_json::json!({
            "route": "anrc20_create",
            "symbol": symbol.clone(),
            "name": request.name.trim(),
            "decimals": request.decimals,
            "initial_supply": request
                .initial_supply
                .as_ref()
                .map(JsonU64Amount::payload_value)
                .unwrap_or_else(|| serde_json::json!(0)),
            "mintable": request.mintable.unwrap_or(false),
        }),
    )
    .await?;

    let mut state = context.state.write().await;
    let token = state
        .anrc20_create_token(
            &owner,
            &symbol,
            &request.name,
            request.decimals,
            initial_supply,
            request.mintable.unwrap_or(false),
        )
        .map_err(bad_request)?;

    Ok((StatusCode::CREATED, Json(token)))
}

async fn post_anrc20_mint(
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<Anrc20MintRequest>,
) -> Result<(StatusCode, Json<Anrc20TokenView>), (StatusCode, Json<ApiError>)> {
    let symbol = crate::dex::normalize_token_symbol(&request.symbol).map_err(bad_request)?;
    let to = request.to.trim().to_uppercase();
    let amount = request.amount.as_u64("amount").map_err(bad_request)?;
    let caller = verify_bound_action(
        &context,
        "anrc20_mint",
        &request.auth,
        serde_json::json!({
            "route": "anrc20_mint",
            "to": to.clone(),
            "symbol": symbol.clone(),
            "amount": request.amount.payload_value(),
        }),
    )
    .await?;

    let mut state = context.state.write().await;
    let token = state
        .anrc20_mint(&caller, &to, &symbol, amount)
        .map_err(bad_request)?;

    Ok((StatusCode::OK, Json(token)))
}

async fn post_anrc20_transfer(
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<Anrc20TransferRequest>,
) -> Result<(StatusCode, Json<Anrc20TransferResponse>), (StatusCode, Json<ApiError>)> {
    let symbol = crate::dex::normalize_token_symbol(&request.symbol).map_err(bad_request)?;
    let to = request.to.trim().to_uppercase();
    let amount = request.amount.as_u64("amount").map_err(bad_request)?;
    let from = verify_bound_action(
        &context,
        "anrc20_transfer",
        &request.auth,
        serde_json::json!({
            "route": "anrc20_transfer",
            "to": to.clone(),
            "symbol": symbol.clone(),
            "amount": request.amount.payload_value(),
        }),
    )
    .await?;

    let mut state = context.state.write().await;
    state
        .anrc20_transfer(&from, &to, &symbol, amount)
        .map_err(bad_request)?;

    Ok((
        StatusCode::OK,
        Json(Anrc20TransferResponse {
            status: "ok",
            symbol,
            from,
            to,
            amount,
        }),
    ))
}

async fn post_pi_settlement(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<PiSettlementRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Err(bad_request(anyhow::anyhow!(
            "HTML requests are not supported for this endpoint"
        )));
    }

    let settlement_key = std::env::var("PI_SETTLEMENT_KEY").unwrap_or_default();
    if settlement_key.trim().is_empty() {
        return Err(service_unavailable(
            "PI_SETTLEMENT_KEY is not configured".to_owned(),
        ));
    }
    let provided = headers
        .get("x-pi-settlement-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_key_eq(provided.trim(), settlement_key.trim()) {
        return Err(unauthorized("invalid settlement key".to_owned()));
    }

    // Validate request fields
    let pi_payment_id = request.pi_payment_id.trim();
    let pi_txid = request.pi_txid.trim();
    let pi_amount = request.pi_amount.trim();
    let from_address = request.from_address.trim().to_uppercase();
    let to_address = request.to_address.trim().to_uppercase();

    if pi_payment_id.is_empty() {
        return Err(bad_request(anyhow::anyhow!("pi_payment_id is required")));
    }
    if pi_payment_id.len() > 32
        || !pi_payment_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(bad_request(anyhow::anyhow!(
            "pi_payment_id must be at most 32 characters using A-Z, a-z, 0-9, -, _ or ."
        )));
    }
    if pi_txid.is_empty() {
        return Err(bad_request(anyhow::anyhow!("pi_txid is required")));
    }
    if pi_txid.len() > 32
        || !pi_txid
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(bad_request(anyhow::anyhow!(
            "pi_txid must be at most 32 characters using A-Z, a-z, 0-9, -, _ or ."
        )));
    }
    if pi_amount.is_empty() {
        return Err(bad_request(anyhow::anyhow!("pi_amount is required")));
    }
    if pi_amount.len() > 32 {
        return Err(bad_request(anyhow::anyhow!(
            "pi_amount must be 32 characters or fewer"
        )));
    }
    // Validate pi_amount is a finite positive number to prevent injection of
    // non-numeric strings (e.g. "999999999999999999999" overflow, NaN, Inf).
    let pi_amount_val: f64 = pi_amount
        .parse()
        .map_err(|_| bad_request(anyhow::anyhow!("pi_amount must be a valid number")))?;
    if !pi_amount_val.is_finite() || pi_amount_val <= 0.0 {
        return Err(bad_request(anyhow::anyhow!(
            "pi_amount must be a positive finite number"
        )));
    }
    if from_address.is_empty() {
        return Err(bad_request(anyhow::anyhow!("from_address is required")));
    }
    if to_address.is_empty() {
        return Err(bad_request(anyhow::anyhow!("to_address is required")));
    }

    let mut state = context.state.write().await;
    state
        .record_pi_settlement(
            pi_payment_id,
            pi_txid,
            pi_amount,
            &from_address,
            &to_address,
        )
        .map_err(bad_request)?;

    // Get current block height (will increment when block is created)
    let current_block_height = state.blocks.last().map(|b| b.block_height).unwrap_or(0);

    drop(state); // Release lock before making external call

    // Notify Pi backend asynchronously (fire-and-forget to not block response)
    let pi_backend_url = std::env::var("PI_BACKEND_URL")
        .unwrap_or_else(|_| "https://pi-backend-q2ye.onrender.com".to_owned());
    let pi_payment_id_clone = pi_payment_id.to_string();
    let pi_txid_clone = pi_txid.to_string();
    let pi_amount_clone = pi_amount.to_string();
    let from_address_clone = from_address.clone();
    let to_address_clone = to_address.clone();

    tokio::spawn(async move {
        let settlement_payload = serde_json::json!({
            "pi_payment_id": pi_payment_id_clone,
            "pi_txid": pi_txid_clone,
            "pi_amount": pi_amount_clone,
            "from_address": from_address_clone,
            "to_address": to_address_clone,
            "l1_block_height": current_block_height,
            "l1_block_event": "Pi: Payment Settlement"
        });

        let client = reqwest::Client::new();
        let _ = client
            .post(format!("{}/api/pi/settlement/record", pi_backend_url))
            .json(&settlement_payload)
            .send()
            .await;
    });

    Ok((
        StatusCode::OK,
        Json(PiSettlementResponse {
            ok: true,
            pi_payment_id: pi_payment_id.to_owned(),
            pi_txid: pi_txid.to_owned(),
            transaction_recorded: true,
            block_event: "Pi: Payment Settlement".to_owned(),
        }),
    ))
}

async fn get_web2_account(
    Path(address): Path<String>,
) -> Result<Json<Web2AccountResponse>, (StatusCode, Json<ApiError>)> {
    let account = load_web2_account_fast(&address).await?;

    account
        .map(|account| {
            Json(Web2AccountResponse {
                address: account.address,
                sessions: account.sessions,
                ants_balance: account.ants_balance,
                is_eligible: account.is_eligible,
                referrals: account.referrals,
            })
        })
        .ok_or_else(|| not_found(format!("Ant Ledger account {address} not found")))
}

async fn get_full_account(
    Path(address): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<Json<HybridAccountResponse>, (StatusCode, Json<ApiError>)> {
    let onchain = {
        let state = context.state.read().await;
        state.account_view(&address)
    };

    let web2 = load_web2_account_fast(&address).await?;

    match (onchain, web2) {
        (Some(onchain), Some(web2)) => Ok(Json(HybridAccountResponse {
            address: address.clone(),
            onchain: HybridOnchainView {
                ants_balance: onchain.ants_balance,
            },
            web2: Web2AccountResponse {
                address: web2.address,
                sessions: web2.sessions,
                ants_balance: web2.ants_balance,
                is_eligible: web2.is_eligible,
                referrals: web2.referrals,
            },
            status: "ACTIVATED",
        })),
        (None, Some(web2)) => Ok(Json(HybridAccountResponse {
            address: address.clone(),
            onchain: HybridOnchainView { ants_balance: 0 },
            web2: Web2AccountResponse {
                address: web2.address,
                sessions: web2.sessions,
                ants_balance: web2.ants_balance,
                is_eligible: web2.is_eligible,
                referrals: web2.referrals,
            },
            status: "NOT_ACTIVATED",
        })),
        (Some(onchain), None) => Ok(Json(HybridAccountResponse {
            address: address.clone(),
            onchain: HybridOnchainView {
                ants_balance: onchain.ants_balance,
            },
            web2: Web2AccountResponse {
                address,
                sessions: 0,
                ants_balance: 0,
                is_eligible: false,
                referrals: 0,
            },
            status: "ACTIVATED",
        })),
        (None, None) => Err(not_found("account not found".to_owned())),
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Multi-chain mint/burn portal (L1 hub ⇆ EVM spokes) — P3-L1
//
// L1 → spoke: post_bridge_portal_lock burns native ANET on L1 (same debit as
//   bridge_burn) and records a lock; signer daemons attest the spoke-side
//   BridgeIn; the spoke portal verifies M-of-N on-chain and mints wANET.
// spoke → L1: post_bridge_portal_mint_credit CREDITS (mints) native ANET after
//   M-of-N native-ANET signer attestations of a spoke BridgeOut. This mints
//   real ANET, so it is GATED behind ANET_PORTAL_CREDIT_ENABLED (default OFF)
//   and reuses the audited queue_bridge_credit + per-(chain,out_id) dedup.
// ═════════════════════════════════════════════════════════════════════════

const PORTAL_ANTS_TO_WEI: u128 = 10_000_000_000; // 1 ANTS (8dp) == 1e10 wei (18dp)

fn portal_credit_enabled() -> bool {
    // ONE-WAY BRIDGE POLICY (2026-08-14, whitepaper v3.5): spoke→L1 credits
    // are permanently disabled. ANET_PORTAL_CREDIT_ENABLED is intentionally
    // ignored — wANET burned on a spoke chain no longer mints native ANET.
    // state::queue_bridge_credit refuses as a second line of defense.
    false
}

fn portal_signer_set() -> Vec<String> {
    std::env::var("ANET_PORTAL_SIGNERS")
        .ok()
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_uppercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn portal_threshold() -> i64 {
    std::env::var("ANET_PORTAL_THRESHOLD")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(2)
}

fn portal_max_per_lock_ants() -> u64 {
    let anet = std::env::var("ANET_PORTAL_MAX_PER_TX_ANET")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(10_000);
    anet.saturating_mul(crate::activation::ANTS_PER_ANET)
}

#[derive(Debug, Deserialize)]
struct PortalLockRequest {
    sender: String,
    dst_chain_id: i64,
    dst_recipient: String,
    amount_ants: u64,
    auth: SignedActionAuthorization,
}

#[derive(Debug, Serialize)]
struct PortalLockView {
    lock_id: i64,
    dst_chain_id: i64,
    dst_recipient: String,
    amount_ants: u64,
    amount_wei: String,
    l1_tx_id: String,
    deadline: i64,
    status: String,
}

fn portal_lock_view(row: &db::PortalLockRow) -> PortalLockView {
    let wei = (row.ants as u128).saturating_mul(PORTAL_ANTS_TO_WEI);
    PortalLockView {
        lock_id: row.lock_id,
        dst_chain_id: row.dst_chain_id,
        dst_recipient: row.dst_recipient.clone(),
        amount_ants: row.ants as u64,
        amount_wei: wei.to_string(),
        l1_tx_id: format!("portal-lock-{}", row.lock_id),
        deadline: row.deadline,
        status: row.status.clone(),
    }
}

async fn post_bridge_portal_lock(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<PortalLockRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    bridge_burn_enabled()?;
    if request_prefers_html(&headers) {
        return Err(bad_request("HTML requests are not supported for this endpoint"));
    }

    let sender = request.sender.trim().to_uppercase();
    let dst_recipient = request.dst_recipient.trim().to_lowercase();
    if !is_valid_bsc_address(&dst_recipient) {
        return Err(bad_request(
            "dst_recipient must be a 0x-prefixed 40-hex EVM address",
        ));
    }
    if request.dst_chain_id <= 0 {
        return Err(bad_request("dst_chain_id must be positive"));
    }
    if request.amount_ants == 0 {
        return Err(bad_request("amount_ants must be greater than zero"));
    }
    if request.amount_ants > portal_max_per_lock_ants() {
        return Err(bad_request("lock exceeds per-tx cap"));
    }

    let auth_wallet = verify_bound_action(
        &context,
        "portal_lock",
        &request.auth,
        serde_json::json!({
            "route": "portal_lock",
            "sender": sender.clone(),
            "dst_chain_id": request.dst_chain_id,
            "dst_recipient": dst_recipient.clone(),
            "amount_ants": request.amount_ants,
        }),
    )
    .await?;
    if auth_wallet != sender {
        return Err(unauthorized("auth wallet does not match sender".to_owned()));
    }

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };

    // Burn native ANET on L1 (atomic in-memory), with rollback if the durable
    // insert fails so the debit is never orphaned.
    let (accounts_before, block_event_before, state_commit_before) = {
        let mut state = context.state.write().await;
        let ab = state.accounts.clone();
        let be = state.pending_block_event.clone();
        let sc = state.pending_state_commit;
        state
            .bridge_burn_anet(&sender, request.amount_ants)
            .map_err(bad_request)?;
        (ab, be, sc)
    };

    let deadline_secs: i64 = std::env::var("BRIDGE_DEADLINE_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0 && *v <= 30 * 24 * 3600)
        .unwrap_or(86_400);
    let deadline = chrono::Utc::now().timestamp().saturating_add(deadline_secs);

    let row = match db::insert_portal_lock(
        chain_db.as_ref(),
        &sender,
        request.dst_chain_id,
        &dst_recipient,
        request.amount_ants,
        deadline,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            let mut state = context.state.write().await;
            state.accounts = accounts_before;
            state.pending_block_event = block_event_before;
            state.pending_state_commit = state_commit_before;
            return Err(service_unavailable(format!(
                "portal lock could not be recorded: {e}"
            )));
        }
    };

    Ok((StatusCode::OK, Json(portal_lock_view(&row))))
}

async fn get_bridge_portal_pending_locks(
    AxumState(context): AxumState<RpcContext>,
) -> Result<Json<Vec<PortalLockView>>, (StatusCode, Json<ApiError>)> {
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let rows = db::list_pending_portal_locks(chain_db.as_ref(), 0, 200)
        .await
        .map_err(service_unavailable)?;
    Ok(Json(rows.iter().map(portal_lock_view).collect()))
}

#[derive(Debug, Deserialize)]
struct PortalAttestationRequest {
    signer: String,
    sig: String,
}

async fn post_bridge_portal_lock_attestation(
    AxumState(context): AxumState<RpcContext>,
    Path(lock_id): Path<i64>,
    Json(req): Json<PortalAttestationRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    if db::get_portal_lock(chain_db.as_ref(), lock_id)
        .await
        .map_err(service_unavailable)?
        .is_none()
    {
        return Err(not_found(format!("lock {lock_id} not found")));
    }
    let signer = req.signer.trim().to_string();
    let sig = req.sig.trim().to_string();
    if signer.is_empty() || sig.is_empty() {
        return Err(bad_request("signer and sig are required"));
    }
    db::insert_portal_lock_signature(chain_db.as_ref(), lock_id, &signer, &sig)
        .await
        .map_err(service_unavailable)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "ok": true }))))
}

async fn get_bridge_portal_lock_attestations(
    AxumState(context): AxumState<RpcContext>,
    Path(lock_id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let sigs = db::list_portal_lock_signatures(chain_db.as_ref(), lock_id)
        .await
        .map_err(service_unavailable)?;
    Ok(Json(serde_json::json!({ "signatures": sigs })))
}

#[derive(Debug, Deserialize)]
struct PortalMintedRequest {
    spoke_tx_hash: String,
    message_id: String,
}

async fn post_bridge_portal_lock_minted(
    AxumState(context): AxumState<RpcContext>,
    Path(lock_id): Path<i64>,
    Json(req): Json<PortalMintedRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };
    let updated = db::mark_portal_lock_minted(
        chain_db.as_ref(),
        lock_id,
        req.spoke_tx_hash.trim(),
        req.message_id.trim(),
    )
    .await
    .map_err(service_unavailable)?;
    match updated {
        Some(row) => Ok(Json(portal_lock_view(&row))),
        None => Err(not_found(format!("lock {lock_id} not pending"))),
    }
}

#[derive(Debug, Deserialize)]
struct PortalMintCreditRequest {
    spoke_chain_id: i64,
    spoke_tx_hash: String,
    out_id: String,
    l1_recipient: String,
    amount_ants: u64,
    auth: SignedActionAuthorization,
}

async fn post_bridge_portal_mint_credit(
    AxumState(context): AxumState<RpcContext>,
    Json(request): Json<PortalMintCreditRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if !portal_credit_enabled() {
        return Err(service_unavailable(
            "ANET_PORTAL_CREDIT_ENABLED is not set",
        ));
    }
    if request.amount_ants == 0 {
        return Err(bad_request("amount_ants must be greater than zero"));
    }
    let l1_recipient = request.l1_recipient.trim().to_uppercase();
    if !crate::transaction::is_valid_anet_wallet(&l1_recipient) {
        return Err(bad_request("l1_recipient must be a valid ANET wallet"));
    }
    let out_id = request.out_id.trim().to_string();
    if out_id.is_empty() || out_id.len() > 128 {
        return Err(bad_request("out_id is required (<=128 chars)"));
    }
    let spoke_tx_hash = request.spoke_tx_hash.trim().to_lowercase();

    // Authenticate the attesting signer via native ANET action signature.
    let signer = verify_bound_action(
        &context,
        "portal_mint_credit",
        &request.auth,
        serde_json::json!({
            "route": "portal_mint_credit",
            "spoke_chain_id": request.spoke_chain_id,
            "spoke_tx_hash": spoke_tx_hash.clone(),
            "out_id": out_id.clone(),
            "l1_recipient": l1_recipient.clone(),
            "amount_ants": request.amount_ants,
        }),
    )
    .await?;
    if !portal_signer_set().iter().any(|s| s == &signer) {
        return Err(unauthorized(
            "signer is not in the configured portal signer set".to_owned(),
        ));
    }

    let chain_db = {
        let state = context.state.read().await;
        state.chain_db.clone()
    };

    if db::portal_credit_exists(chain_db.as_ref(), request.spoke_chain_id, &out_id)
        .await
        .map_err(service_unavailable)?
    {
        return Ok(Json(serde_json::json!({ "status": "credited", "already": true })));
    }

    let count = db::record_portal_credit_signature(
        chain_db.as_ref(),
        request.spoke_chain_id,
        &out_id,
        &signer,
        request.amount_ants,
        &l1_recipient,
    )
    .await
    .map_err(service_unavailable)?;

    let threshold = portal_threshold();
    if count < threshold {
        return Ok(Json(serde_json::json!({
            "status": "pending",
            "signatures": count,
            "threshold": threshold,
        })));
    }

    // Threshold reached — perform the credit exactly once. The portal_credits
    // UNIQUE(spoke_chain_id, out_id) plus queue_bridge_credit's own dedup make
    // double-credit impossible even under concurrency.
    let credit_ref = format!("portal:{}:{}", request.spoke_chain_id, out_id);
    let inserted = db::insert_portal_credit(
        chain_db.as_ref(),
        request.spoke_chain_id,
        &spoke_tx_hash,
        &out_id,
        &l1_recipient,
        request.amount_ants,
        &credit_ref,
    )
    .await
    .map_err(service_unavailable)?;
    if !inserted {
        return Ok(Json(serde_json::json!({ "status": "credited", "already": true })));
    }

    let ants_balance = {
        let mut state = context.state.write().await;
        let bal = state
            .queue_bridge_credit(&l1_recipient, request.amount_ants, &credit_ref)
            .map_err(bad_request)?;
        state.processed_evm_bridge_hashes.insert(credit_ref.clone());
        bal
    };

    Ok(Json(serde_json::json!({
        "status": "credited",
        "l1_recipient": l1_recipient,
        "amount_ants": request.amount_ants,
        "ants_balance": ants_balance,
    })))
}

async fn get_bridge_portal_reconciliation(
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let (chain_id, chain_db) = {
        let state = context.state.read().await;
        (state.chain_id.clone(), state.chain_db.clone())
    };
    let locked = db::portal_locked_net_ants(chain_db.as_ref())
        .await
        .map_err(service_unavailable)?;
    let max_supply_ants: u64 = 21_000_000u64.saturating_mul(crate::activation::ANTS_PER_ANET);
    Ok(Json(serde_json::json!({
        "chain_id": chain_id,
        "locked_ants": locked,
        "max_supply_ants": max_supply_ants,
        "portal_credit_enabled": portal_credit_enabled(),
    })))
}

async fn get_investor_metrics(
    headers: HeaderMap,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    if request_prefers_html(&headers) {
        return Ok(Redirect::to("/explorer/api").into_response());
    }

    let summary = load_network_summary_cached(&context).await;

    let metrics = load_dashboard_metrics_fast().await?;

    Ok((
        cache_control_header("public, max-age=5, stale-while-revalidate=15"),
        Json(InvestorMetricsResponse {
            chain_id: summary.chain_id,
            activated_supply_ants: summary.total_ants,
            activated_supply_anet: summary.total_anet,
            latest_block_height: summary.latest_block_height,
            current_epoch_end: summary.current_epoch_end.to_rfc3339(),
            seconds_until_epoch_end: summary.seconds_until_epoch_end,
            metrics,
        }),
    )
        .into_response())
}

async fn explorer_dashboard(
    headers: HeaderMap,
    Query(query): Query<ExplorerDashboardQuery>,
    AxumState(context): AxumState<RpcContext>,
) -> impl IntoResponse {
    let _ = headers;

    let (summary, latest_blocks) = {
        let state = context.state.read().await;
        (state.network_summary(), state.latest_blocks(8))
    };

    let session_committed_count = {
        let state = context.state.read().await;
        state.session_root_view().leaf_count
    };

    let transfer_only = query.view.as_deref() == Some("transfer");
    if transfer_only {
        return Redirect::to("/explorer").into_response();
    }

    let (dashboard_metrics, fallback_network_stats, fallback_community_snapshot) = if transfer_only
    {
        (None, None, None)
    } else {
        let (metrics, snapshot, community) = tokio::join!(
            try_load_dashboard_metrics_fast(),
            try_load_network_stats_snapshot_fast(),
            try_load_explorer_community_snapshot_fast()
        );
        let snapshot = if metrics.is_some() { None } else { snapshot };
        let community = if metrics.is_some() { None } else { community };
        (metrics, snapshot, community)
    };

    let blocks_html = if latest_blocks.is_empty() {
        "<p class=\"muted\">No blocks have been created yet.</p>".to_owned()
    } else {
        latest_blocks
            .iter()
            .map(|block| {
                format!(
                    "<a class=\"list-row\" href=\"/explorer/blocks/{height}\"><span>Block #{height}</span><span>{tx_count} tx</span><span>{fees} ANTS fees</span></a>",
                    height = block.block_height,
                    tx_count = format_integer(block.transactions.len() as u64),
                    fees = format_integer(block.total_fees_ants),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let hero_metrics_html = if let Some(metrics) = dashboard_metrics.as_ref() {
        let worldwide_workers = format!(
            "{} real miners in {} countries",
            format_integer(metrics.total_real_miners),
            format_integer(metrics.country_count)
        );
        // On-chain committed miners can be slightly fewer than total real
        // miners: only miners who have an on-chain wallet address can be sealed
        // into the session-progress commitment (no address = no Merkle leaf).
        // Surface both so the two numbers tell one consistent story instead of
        // looking contradictory.
        let on_chain_committed = match session_committed_count {
            Some(count) => {
                let awaiting = metrics.total_real_miners.saturating_sub(count as u64);
                if awaiting > 0 {
                    format!(
                        "{} committed · {} awaiting wallet",
                        format_integer(count as u64),
                        format_integer(awaiting)
                    )
                } else {
                    format!("{} committed", format_integer(count as u64))
                }
            }
            None => "committing…".to_owned(),
        };
        format!(
            r#"
        <div>
            <span>Accumulated Work</span>
            <strong>{accumulated_anet} ANET</strong>
        </div>
        <div>
            <span>Worldwide Workers</span>
            <strong>{worldwide_workers}</strong>
        </div>
        <div>
            <span>On-Chain Miners</span>
            <strong>{on_chain_committed}</strong>
        </div>
        <div>
            <span>Sessions To Halving</span>
            <strong>{sessions_left}</strong>
        </div>
        <div>
            <span>Colony Groups In Use</span>
            <strong>{group_participants} ants across {group_rooms} rooms</strong>
        </div>
"#,
            accumulated_anet = state::format_anet_fixed(metrics.total_accumulated_ants),
            worldwide_workers = worldwide_workers,
            on_chain_committed = on_chain_committed,
            sessions_left = format_integer(metrics.remaining_sessions_to_halving),
            group_participants = format_integer(metrics.total_group_participants),
            group_rooms = format_integer(metrics.total_colony_rooms),
        )
    } else {
        format!(
            r#"
        <div>
            <span>Transfer Cadence</span>
            <strong>{epoch_label}</strong>
        </div>
        <div>
            <span>Activated Supply</span>
            <strong>{total_anet} ANET</strong>
        </div>
        <div>
            <span>Current Window</span>
            <strong>{countdown}</strong>
        </div>
        <div>
            <span>Epoch End</span>
            <strong class=\"break-anywhere\">{epoch_end}</strong>
        </div>
"#,
            epoch_label = format_transfer_epoch_label(summary.epoch_seconds),
            total_anet = summary.total_anet,
            countdown = seconds_to_countdown(summary.seconds_until_epoch_end),
            epoch_end = summary.current_epoch_end.to_rfc3339(),
        )
    };

    let investor_cards_html = if let Some(metrics) = dashboard_metrics.as_ref() {
        let supply_delta_ants = summary.total_ants.abs_diff(metrics.total_accumulated_ants);

        format!(
            r#"
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Production Accumulated Output</div>
        <p class="metric metric-finance"><span class="metric-amount">{accumulated_anet}</span><span class="metric-unit">ANET</span></p>
        <p class="metric-sub mono">{accumulated_ants} ANTS</p>
        <p class="metric-note">Production-database total mined or worked output across the colony economy.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Confirmed Layer 1 Supply</div>
        <p class="metric metric-finance"><span class="metric-amount">{activated_anet}</span><span class="metric-unit">ANET</span></p>
        <p class="metric-sub mono">{activated_ants} ANTS</p>
        <p class="metric-note">Already settled into the live Layer 1 ledger and reflected in wallet balances.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Source Reconciliation Delta</div>
        <p class="metric metric-finance"><span class="metric-amount">{delta_anet}</span><span class="metric-unit">ANET</span></p>
        <p class="metric-sub mono">{delta_ants} ANTS</p>
        <p class="metric-note">Current difference between production accumulated output and confirmed Layer 1 supply.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Worldwide Worker Base</div>
        <p class="metric mono">{real_miners}</p>
        <p class="metric-note">Real miners with completed sessions. {verified_workers} verified workers across {countries} countries.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Live Mining Activity</div>
        <p class="metric mono">{active_miners}</p>
        <p class="metric-note">Workers mining now. {online_users} ants online and {eligible_users} workers already halving-eligible.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Sessions To Next Halving</div>
        <p class="metric mono">{sessions_left}</p>
        <p class="metric-note">Stage {stage}/{max_stage}. {progress}% through the current {halving_interval}-session interval.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Colony Group Adoption</div>
        <p class="metric mono">{group_participants}</p>
        <p class="metric-note">Ants active in colony group chat. {group_rooms} rooms and {group_messages} messages tracked live.</p>
    </article>
"#,
            accumulated_anet = format_anet_display(metrics.total_accumulated_ants),
            accumulated_ants = format_integer(metrics.total_accumulated_ants),
            activated_anet = format_anet_display(summary.total_ants),
            activated_ants = format_integer(summary.total_ants),
            delta_anet = format_anet_display(supply_delta_ants),
            delta_ants = format_integer(supply_delta_ants),
            real_miners = format_integer(metrics.total_real_miners),
            verified_workers = format_integer(metrics.total_workers),
            countries = format_integer(metrics.country_count),
            active_miners = format_integer(metrics.total_active_miners),
            online_users = format_integer(metrics.users_online),
            eligible_users = format_integer(metrics.total_eligible_users),
            sessions_left = format_integer(metrics.remaining_sessions_to_halving),
            stage = format_integer(metrics.halving_stage),
            max_stage = format_integer(metrics.max_halving_stage),
            progress = format_percent(metrics.next_halving_progress),
            halving_interval = format_integer(metrics.halving_interval),
            group_participants = format_integer(metrics.total_group_participants),
            group_rooms = format_integer(metrics.total_colony_rooms),
            group_messages = format_integer(metrics.total_group_messages),
        )
    } else {
        let supply_note = if summary.used_supply_history_fallback {
            "Already settled into the Layer 1 activated ledger. Source: chain-history fallback while live account sync is rebuilding."
        } else {
            "Already settled into the Layer 1 activated ledger."
        };

        let validator_note = if summary.used_validator_history_fallback {
            "Validator count is currently shown from the latest finalized block miner set while live validator sync is unavailable."
        } else {
            "Eligible worker validators currently recognized by the colony state."
        };

        let latest_block_card = summary
            .latest_block_height
            .map(|height| {
                format!(
                    r#"<a class="card stat-card-pro spotlight-card card-link" href="/explorer/blocks/{height}">
        <div class="detail-kicker">Latest Block</div>
        <p class="metric mono">#{height}</p>
        <p class="metric-note">Most recent finalized settlement block on the activated ledger.</p>
    </a>"#,
                )
            })
            .unwrap_or_else(|| {
                r#"<article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Latest Block</div>
        <p class="metric mono">Pending</p>
        <p class="metric-note">No settlement block has been finalized yet.</p>
    </article>"#
                    .to_owned()
            });

        format!(
            r#"
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Activated On-Chain Supply</div>
        <p class="metric metric-finance"><span class="metric-amount">{activated_anet}</span><span class="metric-unit">ANET</span></p>
        <p class="metric-sub mono">{activated_ants} ANTS</p>
        <p class="metric-note">{supply_note}</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Active Validators</div>
        <p class="metric mono">{active_miners}</p>
        <p class="metric-note">{validator_note}</p>
    </article>
    {latest_block_card}
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Current Window Ends</div>
        <p class="metric mono" id="countdown" data-seconds="{seconds}">{countdown}</p>
        <p class="metric-note break-anywhere">This settlement window closes at {epoch_end}. A block is created only when transfers or newly synchronized ANTS supply exist.</p>
    </article>
"#,
            activated_anet = format_anet_display(summary.total_ants),
            activated_ants = format_integer(summary.total_ants),
            supply_note = supply_note,
            active_miners = format_integer(summary.active_miners as u64),
            validator_note = validator_note,
            latest_block_card = latest_block_card,
            seconds = summary.seconds_until_epoch_end,
            countdown = seconds_to_countdown(summary.seconds_until_epoch_end),
            epoch_end = summary.current_epoch_end.to_rfc3339(),
        )
    };

    let executive_panel_html = if let Some(metrics) = dashboard_metrics.as_ref() {
        let supply_delta_ants = summary.total_ants.abs_diff(metrics.total_accumulated_ants);
        let supply_delta_anet = format_anet_display(supply_delta_ants);
        let supply_delta_direction = if summary.total_ants >= metrics.total_accumulated_ants {
            "Layer 1 is ahead of the production accumulation feed"
        } else {
            "Production accumulation feed is ahead of Layer 1"
        };
        let activated_share = percentage(summary.total_ants, metrics.total_accumulated_ants.max(1));
        let claimed_share = percentage(
            metrics.total_anet_claimed_ants,
            metrics.total_accumulated_ants.max(1),
        );
        let worker_activity_share =
            percentage(metrics.total_active_miners, metrics.total_workers.max(1));

        format!(
            r#"
<section class="executive-band">
    <article class="card executive-card">
        <p class="eyebrow">Executive Supply View</p>
        <h2>Capital Visibility</h2>
        <p class="muted">A fast reading layer for investors covering production-db accumulation, confirmed Layer 1 supply, claimed value, and the live worker engine behind the colony.</p>
        <div class="executive-grid">
            <div><span>Source Delta</span><strong class="mono">{supply_delta_anet} ANET</strong></div>
            <div><span>Delta Direction</span><strong>{supply_delta_direction}</strong></div>
        </div>
        <div class="executive-stack">
            <div class="executive-meter">
                <div class="executive-head"><strong>Confirmed Layer 1 vs production accumulation</strong><span>{activated_share}</span></div>
                <div class="progress-track executive-track"><span style="width: {activated_share};"></span></div>
            </div>
            <div class="executive-meter">
                <div class="executive-head"><strong>Claimed vs accumulated output</strong><span>{claimed_share}</span></div>
                <div class="progress-track executive-track"><span style="width: {claimed_share};"></span></div>
            </div>
            <div class="executive-meter">
                <div class="executive-head"><strong>Live worker activity</strong><span>{worker_activity_share}</span></div>
                <div class="progress-track executive-track"><span style="width: {worker_activity_share};"></span></div>
            </div>
        </div>
    </article>
    <article class="card executive-card executive-chart-card">
        <p class="eyebrow">Colony Engine</p>
        <h2>Executive Signal Board</h2>
        <div class="executive-grid">
            <div><span>Real Miners</span><strong class="mono">{real_miners}</strong></div>
            <div><span>Online Now</span><strong class="mono">{users_online}</strong></div>
            <div><span>Countries</span><strong class="mono">{countries}</strong></div>
            <div><span>Colony Groups</span><strong class="mono">{group_rooms}</strong></div>
        </div>
        <div class="hero-tags executive-tags">
            <a class="pill pill-link" href="/stats/investor">Investor Metrics API</a>
            <a class="pill pill-link" href="/explorer/colonies/{worker_slug}">Worker Colony Drilldown</a>
        </div>
    </article>
</section>
"#,
            supply_delta_anet = supply_delta_anet,
            supply_delta_direction = supply_delta_direction,
            activated_share = format_percent(activated_share),
            claimed_share = format_percent(claimed_share),
            worker_activity_share = format_percent(worker_activity_share),
            real_miners = format_integer(metrics.total_real_miners),
            users_online = format_integer(metrics.users_online),
            countries = format_integer(metrics.country_count),
            group_rooms = format_integer(metrics.total_colony_rooms),
            worker_slug = colony_slug("Worker Ants"),
        )
    } else {
        String::new()
    };

    let render_country_rows_html = |top_countries: &[db::DashboardCountryRow]| {
        if top_countries.is_empty() {
            return "<p class=\"muted\">Worldwide worker distribution is not available yet.</p>"
                .to_owned();
        }

        let max_workers = top_countries
            .iter()
            .map(|row| row.workers)
            .max()
            .unwrap_or(1);

        top_countries
            .iter()
            .map(|row| {
                let width = if max_workers == 0 {
                    0.0
                } else {
                    ((row.workers as f64 / max_workers as f64) * 100.0).max(8.0)
                };

                format!(
                    r#"
        <a class="country-row link-card" href="/explorer/territories/{slug}">
            <div class="country-meta">
                <strong>{country}</strong>
                <span>{workers} workers</span>
            </div>
            <div class="country-bar"><span style="width: {width:.2}%;"></span></div>
        </a>
"#,
                    slug = territory_slug(&row.country),
                    country = row.country,
                    workers = format_integer(row.workers),
                    width = width,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let render_group_cards_html = |group_usage: &[db::ColonyGroupUsageRow]| {
        let preferred_groups = [
            "Worker Ants",
            "Queen Ant",
            "Nurse Ants",
            "Farmer Ants",
            "Builder Ants",
            "Scout Ants",
            "Soldier Ants",
        ];

        let mut group_cards = preferred_groups
            .iter()
            .map(|label| {
                let usage = group_usage.iter().find(|row| row.room_name == *label);
                let room_count = usage.map(|row| row.room_count).unwrap_or(0);
                let active_chat_ants = usage.map(|row| row.active_chat_ants).unwrap_or(0);
                let message_count = usage.map(|row| row.message_count).unwrap_or(0);
                let top_owner_label = usage
                    .map(|row| row.top_owner_label.as_str())
                    .filter(|label| !label.trim().is_empty())
                    .unwrap_or("No owner yet");

                format!(
                    r#"
        <a class="group-card link-card" href="/explorer/colonies/{slug}">
            <p class="eyebrow">Colony Label</p>
            <h3>{label}</h3>
            <div class="group-meta">
                <div><span>Rooms</span><strong class="mono">{room_count}</strong></div>
                <div><span>Active Ants</span><strong class="mono">{active_chat_ants}</strong></div>
                <div><span>Messages</span><strong class="mono">{message_count}</strong></div>
                <div><span>Top Owner</span><strong>{top_owner_label}</strong></div>
            </div>
        </a>
"#,
                    slug = colony_slug(label),
                    label = label,
                    room_count = format_integer(room_count),
                    active_chat_ants = format_integer(active_chat_ants),
                    message_count = format_integer(message_count),
                    top_owner_label = escape_html(top_owner_label),
                )
            })
            .collect::<Vec<_>>();

        group_cards.extend(
            group_usage
                .iter()
                .filter(|row| !preferred_groups.contains(&row.room_name.as_str()))
                .map(|row| {
                    format!(
                        r#"
        <a class="group-card link-card" href="/explorer/colonies/{slug}">
            <p class="eyebrow">Colony Label</p>
            <h3>{label}</h3>
            <div class="group-meta">
                <div><span>Rooms</span><strong class="mono">{room_count}</strong></div>
                <div><span>Active Ants</span><strong class="mono">{active_chat_ants}</strong></div>
                <div><span>Messages</span><strong class="mono">{message_count}</strong></div>
                <div><span>Top Owner</span><strong>{top_owner_label}</strong></div>
            </div>
        </a>
"#,
                        slug = colony_slug(&row.room_name),
                        label = row.room_name,
                        room_count = format_integer(row.room_count),
                        active_chat_ants = format_integer(row.active_chat_ants),
                        message_count = format_integer(row.message_count),
                        top_owner_label = escape_html(&row.top_owner_label),
                    )
                }),
        );

        group_cards.join("")
    };

    let strategic_sections_html = if let Some(metrics) = dashboard_metrics.as_ref() {
        let country_rows_html = render_country_rows_html(&metrics.top_countries);
        let group_cards_html = render_group_cards_html(&metrics.group_usage);

        format!(
            r#"
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Investor Snapshot</p>
            <h2>Supply, Halving, and Worker Economics</h2>
        </div>
        <span class="muted">Live production metrics tied to accumulated ANTS, verified worker activity, and the total-session halving schedule.</span>
    </div>
    <div class="progress-shell">
        <div class="progress-head">
            <strong>Next halving readiness</strong>
            <span>{progress}% of the active interval completed</span>
        </div>
        <div class="progress-track"><span style="width: {progress_width};"></span></div>
    </div>
    <div class="details details-strong signal-grid">
        <div>
            <span>Total ANET Claimed</span>
            <strong class="mono">{claimed_anet} ANET</strong>
        </div>
        <div>
            <span>Current Reward / Session</span>
            <strong class="mono">{current_reward} ANET</strong>
        </div>
        <div>
            <span>Next Reward / Session</span>
            <strong class="mono">{next_reward} ANET</strong>
        </div>
        <div>
            <span>Registered Accounts</span>
            <strong class="mono">{registered_accounts}</strong>
        </div>
        <div>
            <span>Total Work Sessions</span>
            <strong class="mono">{total_sessions}</strong>
        </div>
        <div>
            <span>Converted Workers</span>
            <strong class="mono">{converted_workers}</strong>
        </div>
        <div>
            <span>Mining Status</span>
            <strong>{mining_status}</strong>
        </div>
    </div>
</section>
<section class="grid grid-two">
    <article class="card section-surface">
        <div class="section-head">
            <div>
                <p class="eyebrow">ANT Territories</p>
                <h2>All ANT Territories</h2>
            </div>
            <span class="muted">Verified worker ants grouped across every active ANT Territory in the network.</span>
        </div>
        <div class="country-list">{country_rows_html}</div>
    </article>
    <article class="card section-surface">
        <div class="section-head">
            <div>
                <p class="eyebrow">Colony Chat</p>
                <h2>Group Label Adoption</h2>
            </div>
            <span class="muted">Live count of how many ants are using each in-app colony group label. Click a colony card for its dedicated drilldown.</span>
        </div>
        <div class="group-grid">{group_cards_html}</div>
    </article>
</section>
"#,
            progress = format_percent(metrics.next_halving_progress),
            progress_width = format_percent(metrics.next_halving_progress),
            claimed_anet = state::format_anet_fixed(metrics.total_anet_claimed_ants),
            current_reward = state::format_anet_fixed(metrics.current_reward_per_session_ants),
            next_reward = state::format_anet_fixed(metrics.next_reward_per_session_ants),
            registered_accounts = format_integer(metrics.total_registered_accounts),
            total_sessions = format_integer(metrics.total_sessions),
            converted_workers = format_integer(metrics.total_converted_users),
            mining_status = if metrics.is_mining_active {
                "Mining Active"
            } else {
                "Mining Paused"
            },
            country_rows_html = country_rows_html,
            group_cards_html = group_cards_html,
        )
    } else if let Some(snapshot) = fallback_community_snapshot.as_ref() {
        let country_rows_html = render_country_rows_html(&snapshot.top_countries);
        let group_cards_html = render_group_cards_html(&snapshot.group_usage);

        format!(
            r#"
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Investor Snapshot</p>
            <h2>Extended production metrics are temporarily unavailable</h2>
        </div>
        <span class="muted">The explorer is live, but heavy Web2 analytics timed out. Territory and colony views below are served from a lightweight snapshot.</span>
    </div>
</section>
<section class="grid grid-two">
    <article class="card section-surface">
        <div class="section-head">
            <div>
                <p class="eyebrow">ANT Territories</p>
                <h2>All ANT Territories</h2>
            </div>
            <span class="muted">{countries} indexed territories from lightweight worker-distribution reads.</span>
        </div>
        <div class="country-list">{country_rows_html}</div>
    </article>
    <article class="card section-surface">
        <div class="section-head">
            <div>
                <p class="eyebrow">Colony Chat</p>
                <h2>Group Label Adoption</h2>
            </div>
            <span class="muted">{rooms} colony rooms, {participants} active ants, and {messages} tracked messages from lightweight chat aggregation.</span>
        </div>
        <div class="group-grid">{group_cards_html}</div>
    </article>
</section>
"#,
            countries = format_integer(snapshot.country_count),
            rooms = format_integer(snapshot.total_colony_rooms),
            participants = format_integer(snapshot.total_group_participants),
            messages = format_integer(snapshot.total_group_messages),
            country_rows_html = country_rows_html,
            group_cards_html = group_cards_html,
        )
    } else {
        r#"
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Investor Snapshot</p>
            <h2>Extended production metrics are temporarily unavailable</h2>
        </div>
        <span class="muted">The explorer is live, but the additional Web2 worker analytics source is not currently reachable from this node.</span>
    </div>
</section>
<section class="grid grid-two">
    <article class="card section-surface">
        <div class="section-head">
            <div>
                <p class="eyebrow">ANT Territories</p>
                <h2>All ANT Territories</h2>
            </div>
            <span class="muted">Territory analytics are warming up. Reload in a moment or increase dashboard timeout settings.</span>
        </div>
        <div class="country-list"><p class="muted">No territory snapshot available yet.</p></div>
    </article>
    <article class="card section-surface">
        <div class="section-head">
            <div>
                <p class="eyebrow">Colony Chat</p>
                <h2>Group Label Adoption</h2>
            </div>
            <span class="muted">Colony analytics are warming up. Reload in a moment or increase community snapshot timeout.</span>
        </div>
        <div class="group-grid"><p class="muted">No colony snapshot available yet.</p></div>
    </article>
</section>
"#
        .to_owned()
    };

    let block_trigger_reason = if summary.mempool_depth > 0 {
        format!(
            "Mempool has {} queued transfer(s)",
            format_integer(summary.mempool_depth)
        )
    } else if summary.pending_activated_supply_ants > 0 {
        format!(
            "Pending activated Web2 supply delta: {} ANTS",
            format_integer(summary.pending_activated_supply_ants)
        )
    } else {
        "No pending transfer or activation delta; next block waits for fresh work".to_owned()
    };

    let last_sync_label = summary
        .last_web2_sync_at
        .map(|timestamp| timestamp.to_rfc3339())
        .unwrap_or_else(|| "No successful Web2 sync recorded yet".to_owned());

    let sync_health_label = match summary.last_web2_sync_error.as_ref() {
        Some(error) => format!("Degraded: {}", escape_html(error)),
        None => "Healthy".to_owned(),
    };

    let global_user_mined_label = dashboard_metrics
        .as_ref()
        .map(|metrics| {
            format!(
                "{} ANET ({} ANTS)",
                format_anet_display(metrics.total_accumulated_ants),
                format_integer(metrics.total_accumulated_ants)
            )
        })
        .or_else(|| {
            fallback_network_stats.as_ref().map(|snapshot| {
                format!(
                    "{} ANET ({} ANTS) [lightweight fallback]",
                    format_anet_display(snapshot.total_accumulated_ants),
                    format_integer(snapshot.total_accumulated_ants)
                )
            })
        })
        .unwrap_or_else(|| {
            format!(
                "At least {} ANET ({} ANTS) [on-chain confirmed floor; Web2 metrics offline]",
                format_anet_display(summary.total_ants),
                format_integer(summary.total_ants)
            )
        });

    let activated_on_chain_label = format!(
        "{} ANET ({} ANTS)",
        format_anet_display(summary.total_ants),
        format_integer(summary.total_ants)
    );

    let pending_activation_delta_label = format!(
        "{} ANET ({} ANTS)",
        format_anet_display(summary.pending_activated_supply_ants),
        format_integer(summary.pending_activated_supply_ants)
    );

    let block_diagnostics_html = format!(
        r#"
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Block Trigger Diagnostics</p>
            <h2>Why the next block will or will not be created</h2>
        </div>
        <span class="muted">This panel explains live consensus trigger state so operators can distinguish idle epochs from sync-related degradation.</span>
    </div>
    <div class="details details-strong" style="margin-bottom: 16px;">
        <div>
            <span>Global User Mined</span>
            <strong class="mono break-anywhere">{global_user_mined}</strong>
        </div>
        <div>
            <span>Activated On-Chain</span>
            <strong class="mono break-anywhere">{activated_on_chain}</strong>
        </div>
        <div>
            <span>Pending Activation Delta</span>
            <strong class="mono break-anywhere">{pending_activation_delta}</strong>
        </div>
    </div>
    <div class="details details-strong signal-grid">
        <div>
            <span>Pending Block Work</span>
            <strong>{pending_work}</strong>
        </div>
        <div>
            <span>Trigger Reason</span>
            <strong>{trigger_reason}</strong>
        </div>
        <div>
            <span>Mempool Transfers</span>
            <strong class="mono">{mempool_depth}</strong>
        </div>
        <div>
            <span>Pending Activated Supply</span>
            <strong class="mono">{pending_activation} ANTS</strong>
        </div>
        <div>
            <span>Last Successful Web2 Sync</span>
            <strong class="mono break-anywhere">{last_sync}</strong>
        </div>
        <div>
            <span>Web2 Sync Health</span>
            <strong class="break-anywhere">{sync_health}</strong>
        </div>
    </div>
</section>
"#,
        global_user_mined = escape_html(&global_user_mined_label),
        activated_on_chain = activated_on_chain_label,
        pending_activation_delta = pending_activation_delta_label,
        pending_work = yes_no(summary.has_pending_block_work),
        trigger_reason = escape_html(&block_trigger_reason),
        mempool_depth = format_integer(summary.mempool_depth),
        pending_activation = format_integer(summary.pending_activated_supply_ants),
        last_sync = escape_html(&last_sync_label),
        sync_health = sync_health_label,
    );

    let transfer_panel_html = String::new();

    let body = format!(
        r#"
<section class="hero hero-grid">
    <div class="hero-copy">
        <p class="eyebrow">ANET Ant Colony</p>
        <h1>Colony Intelligence Dashboard</h1>
        <p class="hero-sub muted">A detailed production view for investors and operators, combining activated Layer 1 supply, accumulated worker output, halving readiness, global worker reach, and live colony-group adoption.</p>
        <div class="hero-tags">
            <span class="pill">Genesis Activation</span>
            <span class="pill">TPoW Consensus</span>
            <span class="pill">Investor Metrics</span>
            <span class="pill">Colony Chat Signals</span>
        </div>
        <form class="search-form" action="/explorer/search" method="get">
            <input name="q" type="text" placeholder="Search block height, hash, or ANET wallet" required />
            <button type="submit">Search</button>
        </form>
    </div>
    <div class="hero-panel card">
        <div class="detail-kicker">Network</div>
        <div class="hero-stat">ANET Mainnet</div>
        <div class="mono break-anywhere" style="font-size:0.72rem;margin-top:6px;opacity:0.65">{chain_id}</div>
        <div class="hero-meta-grid">
            {hero_metrics_html}
        </div>
    </div>
</section>
<section class="grid grid-metrics">
    {investor_cards_html}
</section>
{executive_panel_html}
{strategic_sections_html}
{block_diagnostics_html}
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Ant Ledger</p><h2>Latest Blocks</h2></div><a class="action-ghost" href="/explorer/blocks">View all</a></div>
    <div class="list">{blocks_html}</div>
</section>
{transfer_panel_html}
"#,
        chain_id = summary.chain_id,
        hero_metrics_html = hero_metrics_html,
        investor_cards_html = investor_cards_html,
        executive_panel_html = executive_panel_html,
        strategic_sections_html = strategic_sections_html,
        block_diagnostics_html = block_diagnostics_html,
        blocks_html = blocks_html,
        transfer_panel_html = transfer_panel_html,
    );

    Html(layout("Explorer Dashboard", &body)).into_response()
}

async fn explorer_territory(
    Path(slug): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<Html<String>, (StatusCode, Json<ApiError>)> {
    let summary = {
        let state = context.state.read().await;
        state.network_summary()
    };

    let metrics = load_dashboard_metrics_fast().await?;

    let territory = metrics
        .top_countries
        .iter()
        .find(|row| territory_slug(&row.country) == slug)
        .cloned()
        .ok_or_else(|| not_found(format!("territory {slug} not found")))?;

    let territory_colonies = load_territory_colony_usage_fast(&territory.country).await?;
    let territory_rooms = load_territory_room_profiles_fast(&territory.country).await?;

    let territory_room_count = territory_colonies
        .iter()
        .map(|row| row.room_count)
        .sum::<u64>();
    let territory_active_ants = territory_colonies
        .iter()
        .map(|row| row.active_chat_ants)
        .sum::<u64>();
    let territory_message_count = territory_colonies
        .iter()
        .map(|row| row.message_count)
        .sum::<u64>();

    let worker_share = percentage(territory.workers, metrics.total_real_miners.max(1));
    let room_share = percentage(territory_room_count, metrics.total_colony_rooms.max(1));
    let participant_share = percentage(
        territory_active_ants,
        metrics.total_group_participants.max(1),
    );
    let message_share = percentage(territory_message_count, metrics.total_group_messages.max(1));

    let territory_colonies_html = if territory_colonies.is_empty() {
        "<p class=\"muted\">No ANT Colonies are indexed for this territory yet.</p>".to_owned()
    } else {
        format!(
            "<div class=\"list\">{}</div>",
            territory_colonies
                .iter()
                .map(|row| {
                    format!(
                        "<a class=\"list-row\" href=\"/explorer/colonies/{slug}\"><span>{label}</span><span>{rooms} rooms</span><span>{ants} ants</span><span>{messages} messages</span></a>",
                        slug = colony_slug(&row.room_name),
                        label = escape_html(&row.room_name),
                        rooms = format_integer(row.room_count),
                        ants = format_integer(row.active_chat_ants),
                        messages = format_integer(row.message_count),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        )
    };

    let territory_rooms_html = if territory_rooms.is_empty() {
        "<p class=\"muted\">No owner rooms were found for this territory yet.</p>".to_owned()
    } else {
        format!(
            "<div class=\"list\">{}</div>",
            territory_rooms
                .iter()
                .map(|room| {
                    format!(
                        "<a class=\"list-row\" href=\"/explorer/rooms/{room_key}\"><span>{owner_label}</span><span>{colony}</span><span>{ants} ants</span><span>{messages_30d} msgs / 30d</span></a>",
                        room_key = escape_html(&room.room_key),
                        owner_label = escape_html(&room.owner_label),
                        colony = escape_html(&room.room_name),
                        ants = format_integer(room.ants_count),
                        messages_30d = format_integer(room.messages_30d),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        )
    };

    let top_colony_label = territory_colonies
        .first()
        .map(|row| escape_html(&row.room_name))
        .unwrap_or_else(|| "No colony yet".to_owned());

    let body = format!(
        r#"
<section class="hero compact-hero colony-hero">
    <p class="eyebrow">ANT Territory Drilldown</p>
    <h1>{territory}</h1>
    <p class="hero-sub muted">A focused territory view showing the worker footprint in this ANT Territory and the ANT Colony labels currently active inside it.</p>
    <div class="hero-tags">
        <a class="pill pill-link" href="/explorer">Back To Overview</a>
        <a class="pill pill-link" href="/stats/investor">Investor Metrics API</a>
    </div>
</section>
<section class="grid grid-metrics colony-metrics-grid">
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Verified Workers</div>
        <p class="metric mono">{workers}</p>
        <p class="metric-note">This territory represents {worker_share} of all verified workers currently indexed by the network.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">ANT Colonies</div>
        <p class="metric mono">{colony_count}</p>
        <p class="metric-note">Distinct colony labels currently visible inside this territory.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Territory Rooms</div>
        <p class="metric mono">{rooms}</p>
        <p class="metric-note">These rooms account for {room_share} of all tracked colony rooms.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Active Chat Ants</div>
        <p class="metric mono">{ants}</p>
        <p class="metric-note">This territory represents {participant_share} of all ants participating in tracked group chat.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Message Flow</div>
        <p class="metric mono">{messages}</p>
        <p class="metric-note">This territory produced {message_share} of all tracked group messages.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Top Colony</div>
        <p class="metric break-anywhere">{top_colony_label}</p>
        <p class="metric-note">Leading ANT Colony label currently indexed inside this territory.</p>
    </article>
</section>
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Territory Position</p>
            <h2>Share Of Global Community Activity</h2>
        </div>
        <span class="muted">These progress lanes compare this ANT Territory against the currently indexed global worker and colony footprint.</span>
    </div>
    <div class="executive-stack">
        <div class="executive-meter">
            <div class="executive-head"><strong>Worker Share</strong><span>{worker_share}</span></div>
            <div class="progress-track executive-track"><span style="width: {worker_share};"></span></div>
        </div>
        <div class="executive-meter">
            <div class="executive-head"><strong>Room Share</strong><span>{room_share}</span></div>
            <div class="progress-track executive-track"><span style="width: {room_share};"></span></div>
        </div>
        <div class="executive-meter">
            <div class="executive-head"><strong>Participant Share</strong><span>{participant_share}</span></div>
            <div class="progress-track executive-track"><span style="width: {participant_share};"></span></div>
        </div>
        <div class="executive-meter">
            <div class="executive-head"><strong>Message Share</strong><span>{message_share}</span></div>
            <div class="progress-track executive-track"><span style="width: {message_share};"></span></div>
        </div>
    </div>
    <div class="details details-strong signal-grid">
        <div><span>Global Countries</span><strong class="mono">{countries}</strong></div>
        <div><span>Active Workers Now</span><strong class="mono">{active_miners}</strong></div>
        <div><span>Latest Block</span><strong class="mono">{latest_block}</strong></div>
        <div><span>Epoch Ends</span><strong class="mono break-anywhere">{epoch_end}</strong></div>
    </div>
</section>
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">ANT Colony</p>
            <h2>Colonies In This Territory</h2>
        </div>
        <span class="muted">Click a colony to open its dedicated drilldown page.</span>
    </div>
    {territory_colonies_html}
</section>
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Owner Rooms</p>
            <h2>Rooms In This Territory</h2>
        </div>
        <span class="muted">Click a room owner row to inspect the underlying colony room profile.</span>
    </div>
    {territory_rooms_html}
</section>
"#,
        territory = escape_html(&territory.country),
        workers = format_integer(territory.workers),
        worker_share = format_percent(worker_share),
        colony_count = format_integer(territory_colonies.len() as u64),
        rooms = format_integer(territory_room_count),
        room_share = format_percent(room_share),
        ants = format_integer(territory_active_ants),
        participant_share = format_percent(participant_share),
        messages = format_integer(territory_message_count),
        message_share = format_percent(message_share),
        top_colony_label = top_colony_label,
        countries = format_integer(metrics.country_count),
        active_miners = format_integer(metrics.total_active_miners),
        latest_block = summary
            .latest_block_height
            .map(|height| format!("#{height}"))
            .unwrap_or_else(|| "Pending".to_owned()),
        epoch_end = summary.current_epoch_end.to_rfc3339(),
        territory_colonies_html = territory_colonies_html,
        territory_rooms_html = territory_rooms_html,
    );

    Ok(Html(layout(
        &format!("Territory {}", territory.country),
        &body,
    )))
}

async fn explorer_colony(
    Path(slug): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<Html<String>, (StatusCode, Json<ApiError>)> {
    let summary = {
        let state = context.state.read().await;
        state.network_summary()
    };

    let metrics = load_dashboard_metrics_fast().await?;

    let selected_label = metrics
        .group_usage
        .iter()
        .find(|row| colony_slug(&row.room_name) == slug)
        .map(|row| row.room_name.clone())
        .or_else(|| {
            preferred_colony_labels()
                .iter()
                .find(|label| colony_slug(label) == slug)
                .map(|label| (*label).to_owned())
        })
        .ok_or_else(|| not_found(format!("colony {slug} not found")))?;

    let room_profiles = load_colony_room_profiles_fast(&selected_label).await?;

    let selected_usage = metrics
        .group_usage
        .iter()
        .find(|row| row.room_name == selected_label)
        .cloned()
        .unwrap_or(db::ColonyGroupUsageRow {
            room_name: selected_label.clone(),
            room_count: 0,
            active_chat_ants: 0,
            message_count: 0,
            top_owner_label: "No owner yet".to_owned(),
        });

    let room_share = percentage(selected_usage.room_count, metrics.total_colony_rooms.max(1));
    let participant_share = percentage(
        selected_usage.active_chat_ants,
        metrics.total_group_participants.max(1),
    );
    let message_share = percentage(
        selected_usage.message_count,
        metrics.total_group_messages.max(1),
    );

    let mut leaderboard_rows = metrics.group_usage.clone();
    for label in preferred_colony_labels() {
        if !leaderboard_rows.iter().any(|row| row.room_name == label) {
            leaderboard_rows.push(db::ColonyGroupUsageRow {
                room_name: label.to_owned(),
                room_count: 0,
                active_chat_ants: 0,
                message_count: 0,
                top_owner_label: "No owner yet".to_owned(),
            });
        }
    }
    leaderboard_rows.sort_by(|left, right| {
        right
            .room_count
            .cmp(&left.room_count)
            .then(right.active_chat_ants.cmp(&left.active_chat_ants))
            .then(left.room_name.cmp(&right.room_name))
    });

    let leaderboard_html = leaderboard_rows
        .iter()
        .map(|row| {
            format!(
                r#"
        <a class="list-row" href="/explorer/colonies/{slug}"><span>{label}</span><span>{rooms} rooms</span><span>{ants} ants</span><span>{messages} messages</span></a>
"#,
                slug = colony_slug(&row.room_name),
                label = row.room_name,
                rooms = format_integer(row.room_count),
                ants = format_integer(row.active_chat_ants),
                messages = format_integer(row.message_count),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let room_profiles_html = if room_profiles.is_empty() {
        "<p class=\"muted\">No owner rooms were found for this colony label yet.</p>".to_owned()
    } else {
        format!(
            "<div class=\"list\">{}</div>",
            room_profiles
                .iter()
                .map(|room| {
                    format!(
                        "<a class=\"list-row\" href=\"/explorer/rooms/{room_key}\"><span>{owner_label}</span><span>{ants} ants</span><span>{status}</span><span>{messages_30d} msgs / 30d</span></a>",
                        room_key = escape_html(&room.room_key),
                        owner_label = escape_html(&room.owner_label),
                        ants = format_integer(room.ants_count),
                        status = escape_html(&room.status),
                        messages_30d = format_integer(room.messages_30d),
                    )
                })
                .collect::<Vec<_>>()
                .join("")
        )
    };

    let body = format!(
        r#"
<section class="hero compact-hero colony-hero">
    <p class="eyebrow">Colony Drilldown</p>
    <h1>{label}</h1>
    <p class="hero-sub muted">A focused analytics view for this colony label, covering room adoption, active chat participation, message flow, and its relative share of the global community layer.</p>
    <div class="hero-tags">
        <a class="pill pill-link" href="/explorer">Back To Overview</a>
        <a class="pill pill-link" href="/stats/investor">Investor Metrics API</a>
    </div>
</section>
<section class="grid grid-metrics colony-metrics-grid">
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Colony Rooms</div>
        <p class="metric mono">{rooms}</p>
        <p class="metric-note">This label accounts for {room_share} of all tracked colony rooms.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Active Chat Ants</div>
        <p class="metric mono">{ants}</p>
        <p class="metric-note">This colony represents {participant_share} of all ants participating in tracked group chat.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Message Flow</div>
        <p class="metric mono">{messages}</p>
        <p class="metric-note">This colony produced {message_share} of all tracked group messages.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Network Context</div>
        <p class="metric mono">{countries}</p>
        <p class="metric-note">Global worker reach spans {countries} countries, while the colony engine is currently on block {latest_block}.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Top Owner</div>
        <p class="metric break-anywhere">{top_owner_label}</p>
        <p class="metric-note">Live owner label currently leading this colony group by chat participation and message flow.</p>
    </article>
</section>
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Colony Position</p>
            <h2>Share Of Global Community Activity</h2>
        </div>
        <span class="muted">These progress lanes compare this colony label against the total community footprint currently indexed by the investor dashboard.</span>
    </div>
    <div class="executive-stack">
        <div class="executive-meter">
            <div class="executive-head"><strong>Room Share</strong><span>{room_share}</span></div>
            <div class="progress-track executive-track"><span style="width: {room_share};"></span></div>
        </div>
        <div class="executive-meter">
            <div class="executive-head"><strong>Participant Share</strong><span>{participant_share}</span></div>
            <div class="progress-track executive-track"><span style="width: {participant_share};"></span></div>
        </div>
        <div class="executive-meter">
            <div class="executive-head"><strong>Message Share</strong><span>{message_share}</span></div>
            <div class="progress-track executive-track"><span style="width: {message_share};"></span></div>
        </div>
    </div>
    <div class="details details-strong signal-grid">
        <div><span>Accumulated Colony Work</span><strong class="mono">{accumulated_anet} ANET</strong></div>
        <div><span>Sessions To Halving</span><strong class="mono">{sessions_left}</strong></div>
        <div><span>Active Workers Now</span><strong class="mono">{active_miners}</strong></div>
        <div><span>Epoch Ends</span><strong class="mono break-anywhere">{epoch_end}</strong></div>
    </div>
</section>
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Colony Rankboard</p>
            <h2>All Colony Labels</h2>
        </div>
        <span class="muted">Jump between labels to inspect their current community footprint.</span>
    </div>
    <div class="list">{leaderboard_html}</div>
</section>
<section class="card section-surface">
    <div class="section-head">
        <div>
            <p class="eyebrow">Owner Rooms</p>
            <h2>Rooms In This Colony</h2>
        </div>
        <span class="muted">Click a room owner row to open the room profile with live ants and daily-to-monthly activity windows.</span>
    </div>
    {room_profiles_html}
</section>
"#,
        label = selected_label,
        rooms = format_integer(selected_usage.room_count),
        room_share = format_percent(room_share),
        ants = format_integer(selected_usage.active_chat_ants),
        participant_share = format_percent(participant_share),
        messages = format_integer(selected_usage.message_count),
        message_share = format_percent(message_share),
        countries = format_integer(metrics.country_count),
        latest_block = summary
            .latest_block_height
            .map(|height| format!("#{height}"))
            .unwrap_or_else(|| "Pending".to_owned()),
        accumulated_anet = state::format_anet_fixed(metrics.total_accumulated_ants),
        sessions_left = format_integer(metrics.remaining_sessions_to_halving),
        active_miners = format_integer(metrics.total_active_miners),
        epoch_end = summary.current_epoch_end.to_rfc3339(),
        top_owner_label = escape_html(&selected_usage.top_owner_label),
        leaderboard_html = leaderboard_html,
        room_profiles_html = room_profiles_html,
    );

    Ok(Html(layout(&format!("Colony {}", selected_label), &body)))
}

async fn explorer_room(
    Path(room_key): Path<String>,
    headers: HeaderMap,
) -> Result<Html<String>, (StatusCode, Json<ApiError>)> {
    if should_short_circuit_room_bot_scan(&headers, &room_key) {
        return Err(not_found(format!("room {room_key} not found")));
    }

    let room = load_colony_room_profile_fast(&room_key)
        .await?
        .ok_or_else(|| not_found(format!("room {room_key} not found")))?;

    let activity_note = match room.status.as_str() {
        "Active" => "This room had message activity within the last 24 hours.",
        "Warm" => "This room was active within the last 7 days.",
        "Quiet" => "This room had activity in the last 30 days but not in the last week.",
        _ => "This room has no tracked message activity in the last 30 days.",
    };

    let body = format!(
        r#"
<section class="hero compact-hero colony-hero">
    <p class="eyebrow">Owner Room Profile</p>
    <h1>{owner_label}</h1>
    <p class="hero-sub muted">A focused room profile for this colony owner, including live ant participation, message totals, and recent activity windows.</p>
    <div class="hero-tags">
        <a class="pill pill-link" href="/explorer/colonies/{colony_slug}">Back To Colony</a>
        <span class="pill">{status}</span>
        <span class="pill mono">Room {room_key}</span>
    </div>
</section>
<section class="grid grid-metrics colony-metrics-grid">
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Owner</div>
        <p class="metric break-anywhere">{owner_label}</p>
        <p class="metric-note">Owner profile label for this room inside the colony group.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Ants In Room</div>
        <p class="metric mono">{ants_count}</p>
        <p class="metric-note">Distinct ants who posted in this room.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Total Messages</div>
        <p class="metric mono">{total_messages}</p>
        <p class="metric-note">All tracked messages recorded for this room.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Room Status</div>
        <p class="metric">{status}</p>
        <p class="metric-note">{activity_note}</p>
    </article>
</section>
<section class="card section-surface">
    <div class="section-head">
        <div><p class="eyebrow">Recent Activity</p><h2>Daily To Monthly Windows</h2></div>
        <span class="muted">Short-range visibility for this owner room.</span>
    </div>
    <div class="details details-strong signal-grid">
        <div><span>Messages 24h</span><strong class="mono">{messages_24h}</strong></div>
        <div><span>Messages 7d</span><strong class="mono">{messages_7d}</strong></div>
        <div><span>Messages 30d</span><strong class="mono">{messages_30d}</strong></div>
        <div><span>Last Activity</span><strong class="mono break-anywhere">{last_activity_at}</strong></div>
        <div><span>Room Created</span><strong class="mono break-anywhere">{room_created_at}</strong></div>
        <div><span>Room Updated</span><strong class="mono break-anywhere">{room_updated_at}</strong></div>
        <div><span>Owner User ID</span><strong class="mono">{owner_user_id}</strong></div>
        <div><span>Colony Label</span><strong>{room_name}</strong></div>
    </div>
</section>
"#,
        owner_label = escape_html(&room.owner_label),
        colony_slug = colony_slug(&room.room_name),
        status = escape_html(&room.status),
        room_key = escape_html(&room.room_key),
        ants_count = format_integer(room.ants_count),
        total_messages = format_integer(room.total_messages),
        activity_note = activity_note,
        messages_24h = format_integer(room.messages_24h),
        messages_7d = format_integer(room.messages_7d),
        messages_30d = format_integer(room.messages_30d),
        last_activity_at = escape_html(
            room.last_activity_at
                .as_deref()
                .unwrap_or("No activity yet")
        ),
        room_created_at = escape_html(room.room_created_at.as_deref().unwrap_or("Unknown")),
        room_updated_at = escape_html(room.room_updated_at.as_deref().unwrap_or("Unknown")),
        owner_user_id = format_integer(room.owner_user_id),
        room_name = escape_html(&room.room_name),
    );

    Ok(Html(layout(&format!("Room {}", room.owner_label), &body)))
}

async fn explorer_blocks(AxumState(context): AxumState<RpcContext>) -> Html<String> {
    let state = context.state.read().await;
    let blocks = state.all_blocks();

    let rows = if blocks.is_empty() {
        "<p class=\"muted\">No blocks yet.</p>".to_owned()
    } else {
        blocks
            .iter()
            .rev()
            .map(|block| {
                let block_kind = if let Some(ref event) = block.block_event {
                    event.clone()
                } else if block.transactions.is_empty() {
                    if block.activated_supply_ants > 0 {
                        "Settlement".to_string()
                    } else {
                        "Anchor".to_string()
                    }
                } else if block.activated_supply_ants > 0 {
                    "Transfer + Settlement".to_string()
                } else {
                    "Transfer".to_string()
                };
                format!(
                    "<a class=\"list-row\" href=\"/explorer/blocks/{height}\"><span>Block #{height}</span><span>{start}</span><span>{tx_count} tx</span><span>{activated_supply_anet} ANET ({activated_supply} ANTS) activated</span><span>{block_kind}</span></a>",
                    height = block.block_height,
                    start = block.epoch_start.to_rfc3339(),
                    tx_count = block.transactions.len(),
                    activated_supply = format_integer(block.activated_supply_ants),
                    activated_supply_anet = state::format_anet_fixed(block.activated_supply_ants),
                    block_kind = block_kind,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    Html(layout(
        "Explorer Blocks",
        &format!(
            r#"
<section class="hero compact-hero">
    <p class="eyebrow">Ant Ledger</p>
    <h1>Block Ledger</h1>
    <p class="hero-sub muted">A complete colony ledger view with block timestamps, ant-fee totals, and worker settlement activity.</p>
</section>
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Ledger</p><h2>All Blocks</h2></div><a class="action-ghost" href="/explorer">Colony overview</a></div>
    <div class="list">{rows}</div>
</section>
"#,
            rows = rows,
        ),
    ))
}

async fn explorer_api(AxumState(context): AxumState<RpcContext>) -> Html<String> {
    let (summary, latest_block, sample_account) = {
        let state = context.state.read().await;
        (
            state.network_summary(),
            state.blocks.last().cloned(),
            state.accounts.keys().next().cloned(),
        )
    };

    let account_endpoint = sample_account
        .as_ref()
        .map(|address| format!("/accounts/{address}"))
        .unwrap_or_else(|| "/accounts/ANET...".to_owned());

    let health_preview = pretty_json(&HealthResponse {
        status: "ok",
        chain_id: summary.chain_id.clone(),
        latest_block_height: summary.latest_block_height,
    });
    let block_preview = latest_block
        .as_ref()
        .map(pretty_json)
        .unwrap_or_else(|| "{\n  \"message\": \"No blocks yet\"\n}".to_owned());
    let account_preview = sample_account
        .as_ref()
        .map(|address| {
            pretty_json(&AccountView {
                address: address.clone(),
                ants_balance: 0,
                anet_balance: state::format_anet_fixed(0),
                asset_balances: std::collections::HashMap::new(),
                sessions: 0,
                mined_proofs: 0,
                is_validator: false,
                total_activated_ants: 0,
                vesting_anchor_ms: None,
                swap_vested_bps: 0,
                swap_locked_ants: 0,
            })
        })
        .unwrap_or_else(|| {
            "{\n  \"address\": \"ANET...\",\n  \"ants_balance\": 0,\n  \"anet_balance\": \"0.00000000\",\n  \"sessions\": 0,\n  \"mined_proofs\": 0,\n  \"is_validator\": false\n}"
                .to_owned()
        });
    let latest_validator_links = latest_block
        .as_ref()
        .map(|block| {
            if block.miners.is_empty() {
                "<p class=\"muted\">No validator wallets were recorded for the latest block.</p>"
                    .to_owned()
            } else {
                format!(
                    "<div class=\"wallet-list\">{}</div>",
                    block
                        .miners
                        .iter()
                        .map(|address| wallet_pill(address))
                        .collect::<Vec<_>>()
                        .join("")
                )
            }
        })
        .unwrap_or_else(|| {
            "<p class=\"muted\">No block validators are available yet.</p>".to_owned()
        });
    let sample_account_link = sample_account
        .as_ref()
        .map(|address| wallet_pill(address))
        .unwrap_or_else(|| "<span class=\"pill\">No activated wallet yet</span>".to_owned());

    let body = format!(
        r#"
<section class="hero compact-hero">
    <p class="eyebrow">ANET RPC</p>
    <h1>Explorer API Portal</h1>
    <p class="hero-sub muted">Machine-readable endpoints are still available, but this page presents them in an ANET explorer style instead of raw responses by default.</p>
    <div class="hero-tags">
        <a class="pill pill-link" href="/blocks">Raw Blocks JSON</a>
        <a class="pill pill-link" href="/stats/investor">Investor Metrics JSON</a>
        <a class="pill pill-link" href="/health">Health JSON</a>
    </div>
</section>
<section class="grid grid-two">
    <article class="card section-surface">
        <div class="section-head">
            <div><p class="eyebrow">Chain Data</p><h2>Explorer Endpoints</h2></div>
            <span class="muted">Ethereum-style endpoint index, adapted to worker epochs and ANTS accounting.</span>
        </div>
        <div class="list">
            <a class="list-row" href="/blocks"><span>GET /blocks</span><span>All blocks</span><span>Raw JSON</span><span>Ledger feed</span></a>
            <a class="list-row" href="/explorer/blocks"><span>/explorer/blocks</span><span>Human view</span><span>Styled</span><span>Ledger explorer</span></a>
            <a class="list-row" href="/stats/investor"><span>GET /stats/investor</span><span>Metrics</span><span>Raw JSON</span><span>Investor data</span></a>
            <a class="list-row" href="{account_endpoint}"><span>{account_endpoint}</span><span>Wallet state</span><span>Raw JSON</span><span>Account endpoint</span></a>
        </div>
    </article>
    <article class="card section-surface">
        <div class="section-head">
            <div><p class="eyebrow">Network State</p><h2>Runtime Snapshot</h2></div>
            <span class="muted">Current chain identity and fast transfer-block status.</span>
        </div>
        <div class="details details-strong">
            <div><span>Chain ID</span><strong class="mono break-anywhere">{chain_id}</strong></div>
            <div><span>Latest Block</span><strong class="mono">{latest_block}</strong></div>
            <div><span>Transfer Block End</span><strong class="mono break-anywhere">{epoch_end}</strong></div>
            <div><span>Transfer Cadence</span><strong class="mono">{epoch_label}</strong></div>
            <div><span>Activated Supply</span><strong class="mono">{activated_supply}</strong></div>
        </div>
        <div class="account-actions">
            <a class="action-link" href="/explorer/health">Open Health Dashboard</a>
            <a class="action-ghost" href="/ready">Raw Ready JSON</a>
        </div>
    </article>
</section>
<section class="grid grid-two">
    <article class="card section-surface">
        <div class="section-head"><div><p class="eyebrow">Sample</p><h2>Health Payload</h2></div><a class="action-ghost" href="/health">Open Raw</a></div>
        <div class="tx-result"><pre class="mono break-anywhere">{health_preview}</pre></div>
        <div class="section-head" style="margin-top: 18px;"><div><p class="eyebrow">Linked Wallets</p><h2>Latest Validator Wallets</h2></div></div>
        {latest_validator_links}
    </article>
    <article class="card section-surface">
        <div class="section-head"><div><p class="eyebrow">Sample</p><h2>Latest Block Payload</h2></div><a class="action-ghost" href="/blocks">Open Raw</a></div>
        <div class="tx-result"><pre class="mono break-anywhere">{block_preview}</pre></div>
    </article>
</section>
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Sample</p><h2>Account Payload</h2></div><a class="action-ghost" href="{account_endpoint}">Open Raw</a></div>
    <div class="tx-result"><pre class="mono break-anywhere">{account_preview}</pre></div>
    <div class="section-head" style="margin-top: 18px;"><div><p class="eyebrow">Wallet Link</p><h2>Sample Activated Wallet</h2></div></div>
    <div class="wallet-list">{sample_account_link}</div>
</section>
"#,
        account_endpoint = account_endpoint,
        chain_id = summary.chain_id,
        latest_block = summary
            .latest_block_height
            .map(|height| format!("#{height}"))
            .unwrap_or_else(|| "Pending".to_owned()),
        epoch_end = summary.current_epoch_end.to_rfc3339(),
        epoch_label = format_transfer_epoch_label(summary.epoch_seconds),
        activated_supply = summary.total_anet,
        health_preview = health_preview,
        block_preview = block_preview,
        account_preview = account_preview,
        latest_validator_links = latest_validator_links,
        sample_account_link = sample_account_link,
    );

    Html(layout("Explorer API", &body))
}

async fn explorer_health(AxumState(context): AxumState<RpcContext>) -> Html<String> {
    let summary = {
        let state = context.state.read().await;
        state.network_summary()
    };

    let postgres_ready = postgres_ready_fast().await;
    let health_preview = pretty_json(&HealthResponse {
        status: "ok",
        chain_id: summary.chain_id.clone(),
        latest_block_height: summary.latest_block_height,
    });
    let readiness_preview = if postgres_ready {
        pretty_json(&ReadinessResponse {
            status: "ready",
            postgres: "ok",
            genesis_accounts: 0,
        })
    } else {
        "{\n  \"status\": \"degraded\",\n  \"postgres\": \"unreachable\"\n}".to_owned()
    };

    let latest_block_card = summary
        .latest_block_height
        .map(|height| {
            format!(
                r#"<a class="card stat-card-pro spotlight-card card-link" href="/explorer/blocks/{height}">
        <div class="detail-kicker">Latest Block</div>
        <p class="metric mono">#{height}</p>
        <p class="metric-note">Most recent finalized settlement block.</p>
    </a>"#,
            )
        })
        .unwrap_or_else(|| {
            r#"<article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Latest Block</div>
        <p class="metric mono">Pending</p>
        <p class="metric-note">No settlement block has been finalized yet.</p>
    </article>"#
                .to_owned()
        });

    let body = format!(
        r#"
<section class="hero compact-hero">
    <p class="eyebrow">Node Monitor</p>
    <h1>Colony Health Dashboard</h1>
    <p class="hero-sub muted">A branded health and readiness screen for the ANET node. Layer 1 opens 2-second settlement windows while Web2 mining sessions remain on the separate 6-hour model.</p>
</section>
<section class="grid grid-metrics">
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Chain ID</div>
        <p class="metric metric-chain mono break-anywhere">{chain_id}</p>
        <p class="metric-note">Current Layer 1 ledger identity.</p>
    </article>
    {latest_block_card}
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Postgres Link</div>
        <p class="metric mono">{postgres_state}</p>
        <p class="metric-note">Database reachability for validator refresh and Web2 visibility.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Current Window Ends</div>
        <p class="metric mono">{countdown}</p>
        <p class="metric-note break-anywhere">This settlement window closes at {epoch_end}. A block is created only when transfers or newly synchronized ANTS supply exist.</p>
    </article>
    <article class="card stat-card-pro spotlight-card">
        <div class="detail-kicker">Settlement Window</div>
        <p class="metric metric-compact mono">{epoch_label}</p>
        <p class="metric-note">Current Layer 1 settlement cadence for transfers and synchronized supply.</p>
    </article>
</section>
<section class="grid grid-two">
    <article class="card section-surface">
        <div class="section-head"><div><p class="eyebrow">Liveness</p><h2>Health Payload</h2></div><a class="action-ghost" href="/health">Open Raw</a></div>
        <div class="tx-result"><pre class="mono break-anywhere">{health_preview}</pre></div>
    </article>
    <article class="card section-surface">
        <div class="section-head"><div><p class="eyebrow">Dependencies</p><h2>Readiness Payload</h2></div><a class="action-ghost" href="/ready">Open Raw</a></div>
        <div class="tx-result"><pre class="mono break-anywhere">{readiness_preview}</pre></div>
    </article>
</section>
"#,
        chain_id = summary.chain_id,
        latest_block_card = latest_block_card,
        postgres_state = if postgres_ready { "ONLINE" } else { "DEGRADED" },
        countdown = seconds_to_countdown(summary.seconds_until_epoch_end),
        epoch_end = summary.current_epoch_end.to_rfc3339(),
        epoch_label = format_transfer_epoch_label(summary.epoch_seconds),
        health_preview = health_preview,
        readiness_preview = readiness_preview,
    );

    Html(layout("Explorer Health", &body))
}

async fn explorer_search(
    Query(query): Query<ExplorerSearchQuery>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let needle = query.q.trim();
    if needle.is_empty() {
        return Ok(Redirect::to("/explorer").into_response());
    }

    let state = context.state.read().await;

    if needle.chars().all(|ch| ch.is_ascii_digit()) {
        if let Ok(height) = needle.parse::<u64>() {
            if state
                .blocks
                .iter()
                .any(|block| block.block_height == height)
            {
                return Ok(Redirect::to(&format!("/explorer/blocks/{height}")).into_response());
            }
        }
    }

    let wallet = needle.to_uppercase();
    if wallet.starts_with("ANET") && state.accounts.contains_key(&wallet) {
        return Ok(Redirect::to(&format!("/explorer/accounts/{wallet}")).into_response());
    }

    if let Some(block) = state.block_by_id(needle) {
        return Ok(
            Redirect::to(&format!("/explorer/blocks/{}", block.block_height)).into_response(),
        );
    }

    let summary = state.network_summary();
    drop(state);

    let body = format!(
        r#"
<section class="hero compact-hero">
    <p class="eyebrow">Explorer Search</p>
    <h1>No Match Found</h1>
    <p class="hero-sub muted">The search term <strong>{needle}</strong> did not match a block height, block hash, or activated ANET wallet in the current node state.</p>
    <div class="hero-tags">
        <a class="pill pill-link" href="/explorer">Back To Dashboard</a>
        <a class="pill pill-link" href="/explorer/blocks">Open Ledger</a>
        <a class="pill pill-link" href="/explorer/api">Open API Portal</a>
    </div>
</section>
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Try Again</p><h2>Search The Colony</h2></div><span class="muted">Use a block height, full block hash, or ANET wallet address.</span></div>
    <form class="search-form" action="/explorer/search" method="get">
        <input name="q" type="text" value="{needle}" placeholder="Search block height, hash, or ANET wallet" required />
        <button type="submit">Search</button>
    </form>
    <div class="details details-strong" style="margin-top: 18px;">
        <div><span>Chain ID</span><strong class="mono break-anywhere">{chain_id}</strong></div>
        <div><span>Latest Block</span><strong class="mono">{latest_block}</strong></div>
        <div><span>Epoch End</span><strong class="mono break-anywhere">{epoch_end}</strong></div>
    </div>
</section>
"#,
        needle = needle,
        chain_id = summary.chain_id,
        latest_block = summary
            .latest_block_height
            .map(|height| format!("#{height}"))
            .unwrap_or_else(|| "Pending".to_owned()),
        epoch_end = summary.current_epoch_end.to_rfc3339(),
    );

    Ok(Html(layout("Explorer Search", &body)).into_response())
}

async fn explorer_block(
    Path(height): Path<u64>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<Html<String>, (StatusCode, Json<ApiError>)> {
    let state = context.state.read().await;
    let block = state
        .blocks
        .iter()
        .find(|block| block.block_height == height)
        .cloned()
        .ok_or_else(|| not_found(format!("block {height} not found")))?;

    let transactions = if block.transactions.is_empty() {
        "<p class=\"muted\">No transactions were included in this epoch.</p>".to_owned()
    } else {
        block
            .transactions
            .iter()
            .map(|tx| {
                let memo_html = if tx.memo.trim().is_empty() {
                    "<span class=\"muted\">No memo</span>".to_owned()
                } else {
                    format!(
                        "<span class=\"tx-memo\">Memo: {}</span>",
                        escape_html(&tx.memo)
                    )
                };
                format!(
                    "<div class=\"tx-row\"><strong>{from}</strong><span>{amount} ANTS</span><strong>{to}</strong><span>Fee {fee} ANTS</span><span class=\"tx-status confirmed\">Confirmed in Block #{height}</span>{memo}</div>",
                    from = wallet_link(&tx.from),
                    amount = format_integer(tx.amount_ants),
                    to = wallet_link(&tx.to),
                    fee = tx.fee_ants,
                    height = block.block_height,
                    memo = memo_html,
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };
    let miner_wallets = if block.miners.is_empty() {
        "<p class=\"muted\">No validator wallets were recorded for this block.</p>".to_owned()
    } else {
        format!(
            "<div class=\"wallet-list\">{}</div>",
            block
                .miners
                .iter()
                .map(|address| wallet_pill(address))
                .collect::<Vec<_>>()
                .join("")
        )
    };

    Ok(Html(layout(
        &format!("Block #{}", block.block_height),
        &format!(
            r#"
<section class="hero compact-hero">
    <p class="eyebrow">Worker Block</p>
    <h1>Block #{height}</h1>
    <p class="hero-sub muted">This block records worker settlement, validator participation, and all confirmed ANT-denominated transfers included at this height.</p>
    <div class="hero-tags">
        <span class="pill">{block_kind}</span>
        <span class="pill">{activated_supply_anet} ANET ({activated_supply} ANTS) Activated</span>
        <span class="pill">{tx_count} Confirmed Transfers</span>
    </div>
</section>
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Block Header</p><h2>Overview</h2></div><a class="action-ghost" href="/explorer/blocks">Back to ledger</a></div>
    <div class="details details-strong">
        <div><span>Hash</span><strong class="mono break-anywhere">{hash}</strong></div>
        <div><span>Previous Hash</span><strong class="mono break-anywhere">{previous}</strong></div>
        <div><span>Epoch Start</span><strong class="break-anywhere">{start}</strong></div>
        <div><span>Epoch End</span><strong class="break-anywhere">{end}</strong></div>
        <div><span>Activated Supply</span><strong class="mono break-anywhere">{activated_supply_anet} ANET ({activated_supply} ANTS)</strong></div>
        <div><span>Total Fees</span><strong class="mono break-anywhere">{fees_anet} ANET ({fees} ANTS)</strong></div>
        <div><span>Fee Per Miner</span><strong class="mono break-anywhere">{fee_per_miner_anet} ANET ({fee_per_miner} ANTS)</strong></div>
        <div><span>Worker Validators</span><strong class="mono">{miner_count}</strong></div>
    </div>
</section>
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Validators</p><h2>Validator Wallets</h2></div><span class="muted">Every validator wallet is linked to its account profile.</span></div>
    {miner_wallets}
</section>
<section class="card section-surface"><div class="section-head"><div><p class="eyebrow">Transfers</p><h2>Worker Transactions</h2></div></div>{transactions}</section>
"#,
            height = block.block_height,
            block_kind = if let Some(ref event) = block.block_event {
                format!("{} Block", event)
            } else if block.transactions.is_empty() {
                if block.activated_supply_ants > 0 {
                    "Settlement Block".to_string()
                } else {
                    "Anchor Block".to_string()
                }
            } else if block.activated_supply_ants > 0 {
                "Transfer + Settlement Block".to_string()
            } else {
                "Transfer Block".to_string()
            },
            activated_supply = format_integer(block.activated_supply_ants),
            activated_supply_anet = state::format_anet_fixed(block.activated_supply_ants),
            tx_count = format_integer(block.transactions.len() as u64),
            hash = block.hash,
            previous = block.previous_hash,
            start = block.epoch_start.to_rfc3339(),
            end = block.epoch_end.to_rfc3339(),
            fees = format_integer(block.total_fees_ants),
            fees_anet = state::format_anet_fixed(block.total_fees_ants),
            fee_per_miner = format_integer(block.fee_per_miner),
            fee_per_miner_anet = state::format_anet_fixed(block.fee_per_miner),
            miner_count = format_integer(block.miners.len() as u64),
            miner_wallets = miner_wallets,
            transactions = transactions,
        ),
    )))
}

async fn explorer_account(
    Path(address): Path<String>,
    AxumState(context): AxumState<RpcContext>,
) -> Result<Html<String>, (StatusCode, Json<ApiError>)> {
    let (onchain, blocks, mempool, summary) = {
        let state = context.state.read().await;
        (
            state.account_view(&address),
            state.all_blocks(),
            state.mempool.clone(),
            state.network_summary(),
        )
    };

    let web2 = try_load_web2_account_fast(&address).await;

    if onchain.is_none() && web2.is_none() {
        return Err(not_found(format!("account {address} not found")));
    }

    let onchain_ants = onchain
        .as_ref()
        .map(|account| account.ants_balance)
        .unwrap_or(0);
    let web2_ants = web2
        .as_ref()
        .map(|account| account.ants_balance)
        .unwrap_or(0);
    let sessions = web2.as_ref().map(|account| account.sessions).unwrap_or(0);
    let status = if onchain.is_some() {
        "ACTIVATED"
    } else {
        "NOT_ACTIVATED"
    };
    let phase = if onchain.is_some() {
        "Activated"
    } else {
        "Colony Phase"
    };
    let pending_label = if onchain.is_some() {
        "Activated"
    } else {
        "Pending Genesis"
    };
    let eligible = web2
        .as_ref()
        .map(|account| yes_no(account.is_eligible))
        .unwrap_or("No");
    let combined_ants = onchain_ants.max(web2_ants);
    let session_ants = sessions.saturating_mul(crate::activation::ANTS_PER_SESSION);
    let mut incoming_transfers = 0_u64;
    let mut outgoing_transfers = 0_u64;
    let mut pending_incoming_transfers = 0_u64;
    let mut pending_outgoing_transfers = 0_u64;
    let mut total_received_ants = 0_u64;
    let mut total_sent_ants = 0_u64;
    let mut total_fees_paid_ants = 0_u64;
    let mut validated_blocks = 0_u64;
    let mut last_activity_at = None;
    let mut incoming_history = Vec::new();
    let mut outgoing_history = Vec::new();
    let mut pending_incoming_history = Vec::new();
    let mut pending_outgoing_history = Vec::new();

    for block in &blocks {
        let mut touched = false;

        if block.miners.iter().any(|miner| miner == &address) {
            validated_blocks = validated_blocks.saturating_add(1);
            touched = true;
        }

        for tx in &block.transactions {
            if tx.from == address {
                outgoing_transfers = outgoing_transfers.saturating_add(1);
                total_sent_ants = total_sent_ants.saturating_add(tx.amount_ants);
                total_fees_paid_ants = total_fees_paid_ants.saturating_add(tx.fee_ants);
                outgoing_history.push(render_transfer_row(
                    tx,
                    block.block_height,
                    &block.epoch_end.to_rfc3339(),
                    false,
                ));
                touched = true;
            }
            if tx.to == address {
                incoming_transfers = incoming_transfers.saturating_add(1);
                total_received_ants = total_received_ants.saturating_add(tx.amount_ants);
                incoming_history.push(render_transfer_row(
                    tx,
                    block.block_height,
                    &block.epoch_end.to_rfc3339(),
                    true,
                ));
                touched = true;
            }
        }

        if touched {
            last_activity_at = Some(block.epoch_end.to_rfc3339());
        }
    }

    for tx in &mempool {
        if tx.from == address {
            pending_outgoing_transfers = pending_outgoing_transfers.saturating_add(1);
            pending_outgoing_history.push(render_pending_transfer_row(tx, false));
        }
        if tx.to == address {
            pending_incoming_transfers = pending_incoming_transfers.saturating_add(1);
            pending_incoming_history.push(render_pending_transfer_row(tx, true));
        }
    }

    let current_role = if onchain
        .as_ref()
        .map(|account| account.is_validator)
        .unwrap_or(false)
    {
        "ACTIVE VALIDATOR"
    } else if web2
        .as_ref()
        .map(|account| account.is_eligible)
        .unwrap_or(false)
    {
        "ELIGIBLE WORKER"
    } else {
        "STANDARD WORKER"
    };
    let last_activity_label =
        last_activity_at.unwrap_or_else(|| "No on-chain activity yet".to_owned());
    let settlement_note = format!(
        "Confirmed transfers appear below only after they are included in a TPoW block. Once a transfer is listed here, it is already credited or debited on-chain. New mempool transfers normally reflect after the next {} block closes at {}.",
        format_transfer_epoch_label(summary.epoch_seconds),
        summary.current_epoch_end.to_rfc3339(),
    );
    let incoming_anchor = if incoming_transfers > 0 {
        "#incoming-transfers"
    } else {
        "#incoming-pending"
    };
    let outgoing_anchor = if outgoing_transfers > 0 {
        "#outgoing-transfers"
    } else {
        "#outgoing-pending"
    };
    let incoming_history_html = render_transfer_history(
        "incoming-transfers",
        "Confirmed Incoming Transfers",
        "Every transfer in this list is already credited to this wallet because it was sealed into a confirmed block.",
        &incoming_history,
        "No confirmed incoming transfers yet.",
    );
    let outgoing_history_html = render_transfer_history(
        "outgoing-transfers",
        "Confirmed Outgoing Transfers",
        "Every transfer in this list is already debited from this wallet because it was sealed into a confirmed block.",
        &outgoing_history,
        "No confirmed outgoing transfers yet.",
    );
    let pending_incoming_html = render_transfer_history(
        "incoming-pending",
        "Pending Incoming Transfers",
        "These transfers are still waiting in the mempool. They are not credited until they appear in a confirmed block.",
        &pending_incoming_history,
        "No pending incoming transfers.",
    );
    let pending_outgoing_html = render_transfer_history(
        "outgoing-pending",
        "Pending Outgoing Transfers",
        "These transfers are still waiting in the mempool. They are not debited until they appear in a confirmed block.",
        &pending_outgoing_history,
        "No pending outgoing transfers.",
    );

    Ok(Html(layout(
        &format!("Account {}", address),
        &format!(
            r#"
<section class="hero compact-hero">
    <p class="eyebrow">Worker Account</p>
    <h1>Account Overview</h1>
    <p class="hero-sub muted break-anywhere">{address}</p>
</section>
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Worker State</p><h2>Wallet: {address}</h2></div><span class="pill">{status}</span></div>
    <div class="account-actions">
        <a class="action-link" href="/explorer?from={address}">Send From Worker Wallet</a>
        <a class="action-ghost" href="/account/full/{address}">Worker JSON View</a>
    </div>
    <div class="balance-stack">
        <div class="balance-card">
            <span>On-Chain Balance</span>
            <strong class="mono break-anywhere">{onchain_anet} ANET</strong>
        </div>
        <div class="balance-card highlight">
            <span>Session-Based Balance</span>
            <strong class="mono break-anywhere">{web2_anet} ANET ({pending_label})</strong>
        </div>
        <div class="balance-card">
            <span>Combined Footprint</span>
            <strong class="mono break-anywhere">{combined_anet} ANET</strong>
        </div>
    </div>
    <div class="details details-strong">
        <div><span>Work Sessions</span><strong class="mono">{sessions}</strong></div>
        <div><span>Session Reward Base</span><strong class="mono">{session_reward} ANTS</strong></div>
        <div><span>Session-Derived Work</span><strong class="mono">{session_anet} ANET</strong></div>
        <div><span>Phase</span><strong>{phase}</strong></div>
        <div><span>Ledger State</span><strong>{status}</strong></div>
        <div><span>Validator Eligible</span><strong>{eligible}</strong></div>
        <div><span>Current Role</span><strong>{current_role}</strong></div>
    </div>
</section>
<section class="card section-surface">
    <div class="section-head"><div><p class="eyebrow">Chain Activity</p><h2>Wallet Activity Detail</h2></div><span class="muted">Session-derived work, transfer flow, and validator participation for this wallet.</span></div>
    <p class="muted section-note">{settlement_note}</p>
    <div class="details details-strong">
        <div><span>Incoming Transfers</span><strong class="mono"><a class="stat-link" href="{incoming_anchor}">{incoming_transfers}</a></strong></div>
        <div><span>Outgoing Transfers</span><strong class="mono"><a class="stat-link" href="{outgoing_anchor}">{outgoing_transfers}</a></strong></div>
        <div><span>Pending Incoming</span><strong class="mono"><a class="stat-link" href='#incoming-pending'>{pending_incoming_transfers}</a></strong></div>
        <div><span>Pending Outgoing</span><strong class="mono"><a class="stat-link" href='#outgoing-pending'>{pending_outgoing_transfers}</a></strong></div>
        <div><span>Total Received</span><strong class="mono break-anywhere">{received_anet} ANET</strong></div>
        <div><span>Total Sent</span><strong class="mono break-anywhere">{sent_anet} ANET</strong></div>
        <div><span>Total Fees Paid</span><strong class="mono break-anywhere">{fees_anet} ANET</strong></div>
        <div><span>Validated Blocks</span><strong class="mono">{validated_blocks}</strong></div>
        <div><span>Last Chain Activity</span><strong class="mono break-anywhere">{last_activity}</strong></div>
    </div>
</section>
{incoming_history_html}
{outgoing_history_html}
{pending_incoming_html}
{pending_outgoing_html}
"#,
            address = address,
            onchain_anet = state::format_anet_fixed(onchain_ants),
            web2_anet = state::format_anet_fixed(web2_ants),
            combined_anet = state::format_anet_fixed(combined_ants),
            pending_label = pending_label,
            sessions = sessions,
            session_reward = format_integer(crate::activation::ANTS_PER_SESSION),
            session_anet = state::format_anet_fixed(session_ants),
            phase = phase,
            status = status,
            eligible = eligible,
            current_role = current_role,
            settlement_note = settlement_note,
            incoming_anchor = incoming_anchor,
            outgoing_anchor = outgoing_anchor,
            incoming_transfers = format_integer(incoming_transfers),
            outgoing_transfers = format_integer(outgoing_transfers),
            pending_incoming_transfers = format_integer(pending_incoming_transfers),
            pending_outgoing_transfers = format_integer(pending_outgoing_transfers),
            received_anet = state::format_anet_fixed(total_received_ants),
            sent_anet = state::format_anet_fixed(total_sent_ants),
            fees_anet = state::format_anet_fixed(total_fees_paid_ants),
            validated_blocks = format_integer(validated_blocks),
            last_activity = last_activity_label,
            incoming_history_html = incoming_history_html,
            outgoing_history_html = outgoing_history_html,
            pending_incoming_html = pending_incoming_html,
            pending_outgoing_html = pending_outgoing_html,
        ),
    )))
}

fn bad_request(error: impl ToString) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            error: error.to_string(),
        }),
    )
}

async fn verify_bound_action(
    context: &RpcContext,
    action_type: &str,
    auth: &SignedActionAuthorization,
    expected_payload: serde_json::Value,
) -> Result<String, (StatusCode, Json<ApiError>)> {
    let (chain_id, chain_db) = {
        let state = context.state.read().await;
        (state.chain_id.clone(), state.chain_db.clone())
    };
    let wallet = verify_signed_action_authorization_for_payload(
        action_type,
        auth,
        &chain_id,
        &expected_payload,
    )
    .map_err(|error| unauthorized(error.to_string()))?;

    let recorded = db::record_action_authorization_nonce(
        chain_db.as_ref(),
        &chain_id,
        &wallet,
        action_type,
        auth.nonce,
    )
    .await
    .map_err(service_unavailable)?;
    if !recorded {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError {
                error: "replayed or stale signed action nonce".to_owned(),
            }),
        ));
    }

    Ok(wallet)
}

fn normalize_app_activity_source(source: &str) -> Option<&'static str> {
    match source.trim().to_ascii_lowercase().as_str() {
        "web" => Some("web"),
        "inapp" => Some("inapp"),
        _ => None,
    }
}

fn normalize_app_activity_action(action: &str) -> Result<String, (StatusCode, Json<ApiError>)> {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 64 {
        return Err(bad_request(anyhow::anyhow!(
            "action must be between 1 and 64 characters"
        )));
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(bad_request(anyhow::anyhow!(
            "action must contain only [a-z0-9_]"
        )));
    }

    Ok(normalized)
}

async fn record_app_activity(
    context: &RpcContext,
    action: &str,
    wallet: Option<&str>,
    detail: Option<&str>,
) {
    let mut state = context.state.write().await;
    state.record_app_activity_event(action, wallet, detail);
}

fn unauthorized(message: String) -> (StatusCode, Json<ApiError>) {
    (StatusCode::UNAUTHORIZED, Json(ApiError { error: message }))
}

fn not_found(message: String) -> (StatusCode, Json<ApiError>) {
    (StatusCode::NOT_FOUND, Json(ApiError { error: message }))
}

fn service_unavailable(error: impl ToString) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiError {
            error: error.to_string(),
        }),
    )
}

fn explorer_db_timeout() -> Duration {
    std::env::var("ANET_EXPLORER_DB_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(1500))
}

/// Floor of 8000 ms for explorer detail-page loaders (per-colony /
/// per-territory room profiles). These queries are heavier than the
/// generic list queries the 1.5 s default was sized for; without a floor
/// a misconfigured `ANET_EXPLORER_DB_TIMEOUT_MS` (e.g. 1500) causes
/// /explorer/colonies/<slug> to return 503
/// "failed to load room profiles for colony <name>".
/// Mirrors the same pattern already used by `explorer_dashboard_db_timeout`.
fn explorer_detail_db_timeout() -> Duration {
    explorer_db_timeout().max(Duration::from_millis(8000))
}

fn explorer_dashboard_db_timeout() -> Duration {
    std::env::var("ANET_EXPLORER_DASHBOARD_DB_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| explorer_db_timeout().max(Duration::from_millis(8000)))
}

fn explorer_dashboard_soft_timeout() -> Duration {
    // The dashboard metrics aggregation is intrinsically multi-second (full
    // user base + mining_sessions). The generic 1.5s read timeout was sized for
    // light list queries and is far below this query's real cost, so it fired
    // on every cache miss and produced the "metrics skipped after soft timeout"
    // flood while never letting the 30s cache warm. Default the soft timeout to
    // the dashboard DB timeout (>=8s) so a cache-miss request can actually
    // complete and refresh the cache; subsequent reads are served instantly.
    std::env::var("ANET_EXPLORER_DASHBOARD_SOFT_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(explorer_dashboard_db_timeout)
        // Floor at the dashboard DB budget (>=8s) so a stale/low env override
        // (e.g. a 2500ms value left over from a past incident) cannot force the
        // soft timeout below the metrics query's real multi-second cost, which
        // would cancel every cache-miss query before it completes and prevent
        // the 30s cache from ever warming (the "metrics skipped after soft
        // timeout" flood). The env var can still raise it for very large networks.
        .max(explorer_dashboard_db_timeout())
}

fn explorer_dashboard_backoff_duration() -> Duration {
    std::env::var("ANET_EXPLORER_DASHBOARD_BACKOFF_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(10))
}

async fn postgres_ready_fast() -> bool {
    matches!(
        timeout(explorer_db_timeout(), db::connect()).await,
        Ok(Ok(_))
    )
}

/// Returns a cached `NetworkSummary` to avoid re-iterating all accounts and
/// blocks (and contending on the state `RwLock` against block-processing
/// writers) on every Explorer poll. TTL reuses `ANET_EXPLORER_DASHBOARD_CACHE_MS`
/// (default 5 s). Cached fields like `seconds_until_epoch_end` can be up to
/// that many seconds stale, which clients can compensate for client-side.
async fn load_network_summary_cached(context: &RpcContext) -> state::NetworkSummary {
    let cache_ttl = dashboard_metrics_cache_ttl();
    let cache = network_summary_cache();
    {
        let cached = cache.read().await;
        if let Some(cached) = cached.as_ref() {
            if cached.cached_at.elapsed() < cache_ttl {
                return cached.summary.clone();
            }
        }
    }

    let summary = {
        let state = context.state.read().await;
        state.network_summary()
    };

    let mut cached = cache.write().await;
    *cached = Some(CachedNetworkSummary {
        summary: summary.clone(),
        cached_at: Instant::now(),
    });

    summary
}

async fn load_dashboard_metrics_fast() -> Result<db::DashboardMetrics, (StatusCode, Json<ApiError>)>
{
    let cache_ttl = dashboard_metrics_cache_ttl();
    let cache = dashboard_metrics_cache();
    {
        let cached = cache.read().await;
        if let Some(cached) = cached.as_ref() {
            if cached.cached_at.elapsed() < cache_ttl {
                return Ok(cached.metrics.clone());
            }
        }
    }

    let timeout_window = explorer_dashboard_db_timeout();
    let fresh_metrics = async {
        let client = timeout(timeout_window, db::connect())
            .await
            .map_err(|_| {
                service_unavailable(format!(
                    "postgres connect timed out after {} ms",
                    timeout_window.as_millis()
                ))
            })?
            .map_err(service_unavailable)?;

        timeout(timeout_window, db::load_dashboard_metrics(&client))
            .await
            .map_err(|_| {
                service_unavailable(format!(
                    "postgres metrics query timed out after {} ms",
                    timeout_window.as_millis()
                ))
            })?
            .map_err(service_unavailable)
    }
    .await;

    let metrics = match fresh_metrics {
        Ok(metrics) => metrics,
        Err((status, error)) => {
            let cached = cache.read().await;
            if let Some(cached) = cached.as_ref() {
                tracing::warn!(
                    status = %status,
                    message = %error.error,
                    age_ms = cached.cached_at.elapsed().as_millis(),
                    "serving stale dashboard metrics cache"
                );
                return Ok(cached.metrics.clone());
            }

            return Err((status, error));
        }
    };

    let mut cached = cache.write().await;
    *cached = Some(CachedDashboardMetrics {
        metrics: metrics.clone(),
        cached_at: Instant::now(),
    });

    Ok(metrics)
}

async fn try_load_dashboard_metrics_fast() -> Option<db::DashboardMetrics> {
    if let Some(backoff_until) = dashboard_metrics_backoff_remaining().await {
        if let Some(cached) = read_dashboard_metrics_cache_any_age().await {
            return Some(cached);
        }

        tracing::debug!(
            backoff_remaining_ms = backoff_until.as_millis(),
            "explorer dashboard metrics request skipped during backoff window"
        );
        return None;
    }

    let soft_timeout = explorer_dashboard_soft_timeout();

    match timeout(soft_timeout, load_dashboard_metrics_fast()).await {
        Ok(Ok(metrics)) => {
            clear_dashboard_metrics_backoff().await;
            Some(metrics)
        }
        Ok(Err((status, error))) => {
            activate_dashboard_metrics_backoff().await;
            tracing::warn!(
                status = %status,
                message = %error.error,
                timeout_ms = soft_timeout.as_millis(),
                "explorer dashboard metrics unavailable"
            );
            read_dashboard_metrics_cache_any_age().await
        }
        Err(_) => {
            activate_dashboard_metrics_backoff().await;
            tracing::warn!(
                timeout_ms = soft_timeout.as_millis(),
                "explorer dashboard metrics skipped after soft timeout"
            );
            read_dashboard_metrics_cache_any_age().await
        }
    }
}

async fn read_dashboard_metrics_cache_any_age() -> Option<db::DashboardMetrics> {
    let cache = dashboard_metrics_cache();
    let cached = cache.read().await;
    cached.as_ref().map(|entry| entry.metrics.clone())
}

async fn dashboard_metrics_backoff_remaining() -> Option<Duration> {
    let backoff = dashboard_metrics_backoff();
    let guard = backoff.read().await;
    guard
        .as_ref()
        .and_then(|deadline| deadline.checked_duration_since(Instant::now()))
}

async fn activate_dashboard_metrics_backoff() {
    let mut backoff = dashboard_metrics_backoff().write().await;
    *backoff = Some(Instant::now() + explorer_dashboard_backoff_duration());
}

async fn clear_dashboard_metrics_backoff() {
    let mut backoff = dashboard_metrics_backoff().write().await;
    *backoff = None;
}

async fn load_territory_colony_usage_fast(
    territory: &str,
) -> Result<Vec<db::ColonyGroupUsageRow>, (StatusCode, Json<ApiError>)> {
    let cache_ttl = detail_query_cache_ttl();
    if let Some(cached) =
        read_cached_key(territory_colony_usage_cache(), territory, cache_ttl).await
    {
        return Ok(cached);
    }

    let timeout_window = explorer_db_timeout();
    let client = timeout(timeout_window, db::connect())
        .await
        .map_err(|_| {
            service_unavailable(format!(
                "postgres connect timed out after {} ms",
                timeout_window.as_millis()
            ))
        })?
        .map_err(service_unavailable)?;

    let rows = timeout(
        timeout_window,
        db::load_territory_colony_usage(&client, territory),
    )
    .await
    .map_err(|_| {
        service_unavailable(format!(
            "postgres territory colony query timed out after {} ms",
            timeout_window.as_millis()
        ))
    })?
    .map_err(service_unavailable)?;

    write_cached_key(territory_colony_usage_cache(), territory, rows.clone()).await;
    Ok(rows)
}

async fn load_territory_room_profiles_fast(
    territory: &str,
) -> Result<Vec<db::ColonyRoomProfileRow>, (StatusCode, Json<ApiError>)> {
    let cache_ttl = detail_query_cache_ttl();
    if let Some(cached) =
        read_cached_key(territory_room_profiles_cache(), territory, cache_ttl).await
    {
        return Ok(cached);
    }

    let timeout_window = explorer_detail_db_timeout();
    let client = timeout(timeout_window, db::connect())
        .await
        .map_err(|_| {
            service_unavailable(format!(
                "postgres connect timed out after {} ms",
                timeout_window.as_millis()
            ))
        })?
        .map_err(service_unavailable)?;

    let rows = timeout(
        timeout_window,
        db::load_territory_room_profiles(&client, territory),
    )
    .await
    .map_err(|_| {
        service_unavailable(format!(
            "postgres territory room query timed out after {} ms",
            timeout_window.as_millis()
        ))
    })?
    .map_err(service_unavailable)?;

    write_cached_key(territory_room_profiles_cache(), territory, rows.clone()).await;
    Ok(rows)
}

async fn load_colony_room_profiles_fast(
    colony_label: &str,
) -> Result<Vec<db::ColonyRoomProfileRow>, (StatusCode, Json<ApiError>)> {
    let cache_ttl = detail_query_cache_ttl();
    if let Some(cached) =
        read_cached_key(colony_room_profiles_cache(), colony_label, cache_ttl).await
    {
        return Ok(cached);
    }

    let timeout_window = explorer_detail_db_timeout();
    let client = timeout(timeout_window, db::connect())
        .await
        .map_err(|_| {
            service_unavailable(format!(
                "postgres connect timed out after {} ms",
                timeout_window.as_millis()
            ))
        })?
        .map_err(service_unavailable)?;

    let rows = timeout(
        timeout_window,
        db::load_colony_room_profiles(&client, colony_label),
    )
    .await
    .map_err(|_| {
        service_unavailable(format!(
            "postgres room query timed out after {} ms",
            timeout_window.as_millis()
        ))
    })?
    .map_err(service_unavailable)?;

    write_cached_key(colony_room_profiles_cache(), colony_label, rows.clone()).await;
    Ok(rows)
}

async fn load_colony_room_profile_fast(
    room_key: &str,
) -> Result<Option<db::ColonyRoomProfileRow>, (StatusCode, Json<ApiError>)> {
    let cache_ttl = detail_query_cache_ttl();
    if let Some(cached) = read_cached_key(room_profile_cache(), room_key, cache_ttl).await {
        return Ok(cached);
    }

    let timeout_window = explorer_db_timeout();
    let client = timeout(timeout_window, db::connect())
        .await
        .map_err(|_| {
            service_unavailable(format!(
                "postgres connect timed out after {} ms",
                timeout_window.as_millis()
            ))
        })?
        .map_err(service_unavailable)?;

    let row = timeout(
        timeout_window,
        db::load_colony_room_profile(&client, room_key),
    )
    .await
    .map_err(|_| {
        service_unavailable(format!(
            "postgres room profile query timed out after {} ms",
            timeout_window.as_millis()
        ))
    })?
    .map_err(service_unavailable)?;

    write_cached_key(room_profile_cache(), room_key, row.clone()).await;
    Ok(row)
}

async fn load_web2_account_fast(
    address: &str,
) -> Result<Option<db::Web2AccountRow>, (StatusCode, Json<ApiError>)> {
    let cache_ttl = detail_query_cache_ttl();
    if let Some(cached) = read_cached_key(web2_account_cache(), address, cache_ttl).await {
        return Ok(cached);
    }

    let timeout_window = explorer_db_timeout();
    let client = timeout(timeout_window, db::connect())
        .await
        .map_err(|_| {
            service_unavailable(format!(
                "postgres connect timed out after {} ms",
                timeout_window.as_millis()
            ))
        })?
        .map_err(service_unavailable)?;

    let account = timeout(timeout_window, db::load_web2_account(&client, address))
        .await
        .map_err(|_| {
            service_unavailable(format!(
                "postgres account query timed out after {} ms",
                timeout_window.as_millis()
            ))
        })?
        .map_err(service_unavailable)?;

    write_cached_key(web2_account_cache(), address, account.clone()).await;
    Ok(account)
}

async fn try_load_web2_account_fast(address: &str) -> Option<db::Web2AccountRow> {
    load_web2_account_fast(address).await.ok().flatten()
}

fn dashboard_metrics_cache() -> &'static RwLock<Option<CachedDashboardMetrics>> {
    DASHBOARD_METRICS_CACHE.get_or_init(|| RwLock::new(None))
}

fn network_summary_cache() -> &'static RwLock<Option<CachedNetworkSummary>> {
    NETWORK_SUMMARY_CACHE.get_or_init(|| RwLock::new(None))
}

fn dashboard_metrics_backoff() -> &'static RwLock<Option<Instant>> {
    DASHBOARD_METRICS_BACKOFF_UNTIL.get_or_init(|| RwLock::new(None))
}

fn network_stats_snapshot_cache() -> &'static RwLock<Option<CachedNetworkStatsSnapshot>> {
    NETWORK_STATS_SNAPSHOT_CACHE.get_or_init(|| RwLock::new(None))
}

fn explorer_community_snapshot_cache() -> &'static RwLock<Option<CachedExplorerCommunitySnapshot>> {
    EXPLORER_COMMUNITY_SNAPSHOT_CACHE.get_or_init(|| RwLock::new(None))
}

fn dashboard_metrics_cache_ttl() -> Duration {
    // The investor/dashboard metrics query aggregates across the full user base
    // and mining_sessions table, so it is intrinsically heavy (multiple seconds)
    // and grows with the network. A short TTL makes refreshes overlap the query
    // itself, guaranteeing churn. Default to 30 s — dashboard counters change on
    // the order of minutes, so this is imperceptible to users while drastically
    // cutting PostgreSQL load. Override with `ANET_EXPLORER_DASHBOARD_CACHE_MS`.
    std::env::var("ANET_EXPLORER_DASHBOARD_CACHE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30))
}

fn detail_query_cache_ttl() -> Duration {
    std::env::var("ANET_EXPLORER_DETAIL_CACHE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(10))
}

fn network_stats_snapshot_cache_ttl() -> Duration {
    Duration::from_secs(30)
}

fn explorer_community_snapshot_cache_ttl() -> Duration {
    std::env::var("ANET_EXPLORER_COMMUNITY_CACHE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(30))
}

/// Minimum soft timeout for the explorer community + network-stats snapshot
/// aggregates. In production these queries cost a few seconds under DB load, so
/// a soft timeout below that cancels every cache-miss query before it can
/// finish — the snapshot caches then never warm and each refresh re-emits a
/// "... snapshot timed out" WARN. Flooring here makes them robust to a stale or
/// too-low env override. The snapshots are fetched in parallel (tokio::join!)
/// with — and dominated by — the dashboard-metrics query, and are cached, so the
/// floor adds no critical-path latency.
const EXPLORER_SNAPSHOT_SOFT_TIMEOUT_FLOOR_MS: u64 = 5000;

fn explorer_network_stats_soft_timeout() -> Duration {
    std::env::var("ANET_EXPLORER_NETWORK_STATS_SOFT_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(EXPLORER_SNAPSHOT_SOFT_TIMEOUT_FLOOR_MS))
        .max(Duration::from_millis(EXPLORER_SNAPSHOT_SOFT_TIMEOUT_FLOOR_MS))
}

fn explorer_community_soft_timeout() -> Duration {
    std::env::var("ANET_EXPLORER_COMMUNITY_SOFT_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(explorer_db_timeout)
        .max(Duration::from_millis(EXPLORER_SNAPSHOT_SOFT_TIMEOUT_FLOOR_MS))
}

async fn try_load_network_stats_snapshot_fast() -> Option<db::NetworkStatsSnapshot> {
    let cache_ttl = network_stats_snapshot_cache_ttl();
    {
        let cache = network_stats_snapshot_cache().read().await;
        if let Some(cached) = cache.as_ref() {
            if cached.cached_at.elapsed() < cache_ttl {
                return Some(cached.snapshot.clone());
            }
        }
    }

    let timeout_window = explorer_network_stats_soft_timeout();
    let snapshot = timeout(timeout_window, async {
        let client = db::connect().await.map_err(service_unavailable)?;
        db::load_network_stats_snapshot(client.as_ref())
            .await
            .map_err(service_unavailable)
    })
    .await;

    match snapshot {
        Ok(Ok(snapshot)) => {
            let mut cache = network_stats_snapshot_cache().write().await;
            *cache = Some(CachedNetworkStatsSnapshot {
                snapshot: snapshot.clone(),
                cached_at: Instant::now(),
            });
            Some(snapshot)
        }
        Ok(Err((status, error))) => {
            tracing::warn!(
                status = %status,
                message = %error.error,
                "lightweight network stats snapshot unavailable"
            );
            let cache = network_stats_snapshot_cache().read().await;
            cache.as_ref().map(|cached| cached.snapshot.clone())
        }
        Err(_) => {
            tracing::warn!(
                timeout_ms = timeout_window.as_millis(),
                "lightweight network stats snapshot timed out"
            );
            let cache = network_stats_snapshot_cache().read().await;
            cache.as_ref().map(|cached| cached.snapshot.clone())
        }
    }
}

async fn try_load_explorer_community_snapshot_fast() -> Option<db::ExplorerCommunitySnapshot> {
    let cache_ttl = explorer_community_snapshot_cache_ttl();
    {
        let cache = explorer_community_snapshot_cache().read().await;
        if let Some(cached) = cache.as_ref() {
            if cached.cached_at.elapsed() < cache_ttl {
                return Some(cached.snapshot.clone());
            }
        }
    }

    let timeout_window = explorer_community_soft_timeout();
    let snapshot = timeout(timeout_window, async {
        let client = db::connect().await.map_err(service_unavailable)?;
        db::load_explorer_community_snapshot(client.as_ref())
            .await
            .map_err(service_unavailable)
    })
    .await;

    match snapshot {
        Ok(Ok(snapshot)) => {
            let mut cache = explorer_community_snapshot_cache().write().await;
            *cache = Some(CachedExplorerCommunitySnapshot {
                snapshot: snapshot.clone(),
                cached_at: Instant::now(),
            });
            Some(snapshot)
        }
        Ok(Err((status, error))) => {
            tracing::warn!(
                status = %status,
                message = %error.error,
                "lightweight explorer community snapshot unavailable"
            );
            let cache = explorer_community_snapshot_cache().read().await;
            cache.as_ref().map(|cached| cached.snapshot.clone())
        }
        Err(_) => {
            tracing::warn!(
                timeout_ms = timeout_window.as_millis(),
                "lightweight explorer community snapshot timed out"
            );
            let cache = explorer_community_snapshot_cache().read().await;
            cache.as_ref().map(|cached| cached.snapshot.clone())
        }
    }
}

fn territory_colony_usage_cache(
) -> &'static RwLock<HashMap<String, CachedValue<Vec<db::ColonyGroupUsageRow>>>> {
    TERRITORY_COLONY_USAGE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn territory_room_profiles_cache(
) -> &'static RwLock<HashMap<String, CachedValue<Vec<db::ColonyRoomProfileRow>>>> {
    TERRITORY_ROOM_PROFILES_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn colony_room_profiles_cache(
) -> &'static RwLock<HashMap<String, CachedValue<Vec<db::ColonyRoomProfileRow>>>> {
    COLONY_ROOM_PROFILES_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn room_profile_cache(
) -> &'static RwLock<HashMap<String, CachedValue<Option<db::ColonyRoomProfileRow>>>> {
    ROOM_PROFILE_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn web2_account_cache() -> &'static RwLock<HashMap<String, CachedValue<Option<db::Web2AccountRow>>>>
{
    WEB2_ACCOUNT_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

async fn read_cached_key<T: Clone>(
    cache: &'static RwLock<HashMap<String, CachedValue<T>>>,
    key: &str,
    ttl: Duration,
) -> Option<T> {
    let cache = cache.read().await;
    cache.get(key).and_then(|cached| {
        if cached.cached_at.elapsed() < ttl {
            Some(cached.value.clone())
        } else {
            None
        }
    })
}

async fn write_cached_key<T: Clone>(
    cache: &'static RwLock<HashMap<String, CachedValue<T>>>,
    key: &str,
    value: T,
) {
    let mut cache = cache.write().await;
    cache.insert(
        key.to_owned(),
        CachedValue {
            value,
            cached_at: Instant::now(),
        },
    );
}

fn cache_control_header(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(value));
    headers
}

fn layout(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>{title}</title>
    <meta name=\"theme-color\" content=\"#ffffff\" />
    <link rel=\"icon\" type=\"image/png\" href=\"/explorer/assets/logo.png\" />
    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />
    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />
    <link href=\"https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Roboto+Mono:wght@400;500&display=swap\" rel=\"stylesheet\" />
    <link rel=\"stylesheet\" href=\"/explorer/assets/explorer.css\" />
</head>
<body>
    <div class=\"bg-orb\"></div>
    <div class=\"bg-orb-two\"></div>
    <div class=\"bg-grid\"></div>
    <div class=\"viewport\">
        <aside class=\"sidebar\">
            <div class=\"brand-stack\">
                <img class=\"brand-mark\" src=\"/explorer/assets/logo.png\" alt=\"A Network\" width=\"54\" height=\"54\" />
                <div class=\"brand-copy\">
                    <strong>A-Network</strong>
                    <span>Ant colony explorer</span>
                </div>
            </div>
            <div class=\"sidebar-section\">
                <p class=\"sidebar-label\">Navigation</p>
                <div class=\"sidebar-nav\">
                    <a class=\"sidebar-link {dashboard_sidebar_class}\" href=\"/explorer\"><span>Colony Overview</span><span>Live</span></a>
                    <a class=\"sidebar-link {blocks_sidebar_class}\" href=\"/explorer/blocks\"><span>Ant Ledger</span><span>Chain</span></a>
                    <a class=\"sidebar-link {api_sidebar_class}\" href=\"/explorer/api\"><span>Ledger API</span><span>Portal</span></a>
                    <a class=\"sidebar-link {health_sidebar_class}\" href=\"/explorer/health\"><span>Colony Health</span><span>Monitor</span></a>
                </div>
            </div>
            <div class=\"sidebar-section\">
                <p class=\"sidebar-label\">Overview</p>
                <div class=\"sidebar-note\">
                    <strong>ANTS Mainnet</strong>
                    This explorer tracks the ANTS Mainnet Ant Ledger in real time, including worker balances, block formation, validator readiness, and ANT-denominated transaction fees.
                </div>
            </div>
        </aside>
        <main class=\"shell\">
            <nav class=\"nav\">
                <a class=\"{dashboard_nav_class}\" href=\"/explorer\">Overview</a>
                <a class=\"{blocks_nav_class}\" href=\"/explorer/blocks\">Ant Ledger</a>
                <a class=\"{api_nav_class}\" href=\"/explorer/api\">API</a>
                <a class=\"{health_nav_class}\" href=\"/explorer/health\">Health</a>
                <a href=\"/explorer/search?q=1\">Search</a>
            </nav>
            {body}
        </main>
    </div>
</body>
</html>",
        title = title,
        body = body,
        dashboard_sidebar_class = nav_class(title == "Explorer Dashboard"),
        blocks_sidebar_class = nav_class(title == "Explorer Blocks" || title.starts_with("Block #")),
        api_sidebar_class = nav_class(title == "Explorer API"),
        health_sidebar_class = nav_class(title == "Explorer Health"),
        dashboard_nav_class = nav_class(title == "Explorer Dashboard"),
        blocks_nav_class = nav_class(title == "Explorer Blocks" || title.starts_with("Block #")),
        api_nav_class = nav_class(title == "Explorer API"),
        health_nav_class = nav_class(title == "Explorer Health"),
    )
}

fn pretty_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned())
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn block_link(height: u64) -> String {
    format!(
        "<a class=\"address-link mono\" href=\"/explorer/blocks/{height}\">Block #{height}</a>",
        height = height,
    )
}

fn render_transfer_row(
    tx: &crate::transaction::Transaction,
    block_height: u64,
    settled_at: &str,
    incoming: bool,
) -> String {
    let counterparty = if incoming { &tx.from } else { &tx.to };
    let direction = if incoming { "Credited" } else { "Debited" };
    let fee_label = if incoming {
        "Fee paid by sender".to_owned()
    } else {
        format!("Fee {} ANTS", tx.fee_ants)
    };
    let memo_html = if tx.memo.trim().is_empty() {
        "<span class=\"muted\">No memo</span>".to_owned()
    } else {
        format!(
            "<span class=\"tx-memo\">Memo: {}</span>",
            escape_html(&tx.memo)
        )
    };

    format!(
        "<div class=\"tx-row\"><strong>{direction}</strong><span>{amount} ANTS</span><strong>{counterparty}</strong><span>{fee}</span><span class=\"tx-status confirmed\">{block}</span><span class=\"mono\">{settled_at}</span>{memo}</div>",
        direction = direction,
        amount = format_integer(tx.amount_ants),
        counterparty = wallet_link(counterparty),
        fee = fee_label,
        block = block_link(block_height),
        settled_at = escape_html(settled_at),
        memo = memo_html,
    )
}

fn render_pending_transfer_row(tx: &crate::transaction::Transaction, incoming: bool) -> String {
    let counterparty = if incoming { &tx.from } else { &tx.to };
    let direction = if incoming {
        "Awaiting Credit"
    } else {
        "Awaiting Debit"
    };
    let fee_label = if incoming {
        "Fee paid by sender".to_owned()
    } else {
        format!("Fee {} ANTS", tx.fee_ants)
    };
    let memo_html = if tx.memo.trim().is_empty() {
        "<span class=\"muted\">No memo</span>".to_owned()
    } else {
        format!(
            "<span class=\"tx-memo\">Memo: {}</span>",
            escape_html(&tx.memo)
        )
    };

    format!(
        "<div class=\"tx-row\"><strong>{direction}</strong><span>{amount} ANTS</span><strong>{counterparty}</strong><span>{fee}</span><span class=\"tx-status pending\">Pending in mempool</span><span class=\"mono\">Queued {queued_at}</span>{memo}</div>",
        direction = direction,
        amount = format_integer(tx.amount_ants),
        counterparty = wallet_link(counterparty),
        fee = fee_label,
        queued_at = escape_html(&tx.timestamp.to_rfc3339()),
        memo = memo_html,
    )
}

fn render_transfer_history(
    section_id: &str,
    title: &str,
    note: &str,
    rows: &[String],
    empty_message: &str,
) -> String {
    let content = if rows.is_empty() {
        format!("<p class=\"muted\">{}</p>", empty_message)
    } else {
        format!("<div class=\"list\">{}</div>", rows.join(""))
    };

    format!(
        "<section id=\"{section_id}\" class=\"card section-surface\"><div class=\"section-head\"><div><p class=\"eyebrow\">Transfer History</p><h2>{title}</h2></div></div><p class=\"muted section-note\">{note}</p>{content}</section>",
        section_id = section_id,
        title = title,
        note = note,
        content = content,
    )
}

fn wallet_link(address: &str) -> String {
    format!(
        "<a class=\"address-link mono break-anywhere\" href=\"/explorer/accounts/{address}\">{address}</a>",
        address = address,
    )
}

fn wallet_pill(address: &str) -> String {
    format!(
        "<a class=\"wallet-pill mono break-anywhere\" href=\"/explorer/accounts/{address}\">{address}</a>",
        address = address,
    )
}

fn request_prefers_html(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.contains("text/html"))
        .unwrap_or(false)
}

fn explorer_auth_required() -> bool {
    std::env::var("ANET_EXPLORER_AUTH_REQUIRED")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| !matches!(value.as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(false)
}

fn allow_ineligible_wallet_test_mode() -> bool {
    std::env::var("ANET_ALLOW_INELIGIBLE_WALLET_TEST")
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on"
        })
        .unwrap_or(false)
}

fn explorer_auth_secret() -> Option<String> {
    std::env::var("ANET_EXPLORER_AUTH_SECRET")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn explorer_wallet_session_ttl_seconds() -> u64 {
    std::env::var("ANET_EXPLORER_AUTH_TTL_SECONDS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(43_200)
}

fn unix_now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sign_wallet_session(wallet: &str, expires_at: u64, secret: &str) -> String {
    let payload = format!("{wallet}:{expires_at}:{secret}");
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

fn build_wallet_session_cookie(wallet: &str) -> String {
    let secret = explorer_auth_secret().unwrap_or_default();
    let expires_at = unix_now_seconds().saturating_add(explorer_wallet_session_ttl_seconds());
    let signature = sign_wallet_session(wallet, expires_at, &secret);
    let value = format!("{wallet}.{expires_at}.{signature}");
    format!(
        "{cookie_name}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax",
        cookie_name = EXPLORER_AUTH_COOKIE,
        value = value,
        max_age = explorer_wallet_session_ttl_seconds(),
    )
}

fn extract_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie_header| {
            cookie_header.split(';').map(str::trim).find_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                let key = parts.next()?.trim();
                let value = parts.next()?.trim();
                if key == name {
                    Some(value.to_owned())
                } else {
                    None
                }
            })
        })
}

fn authenticated_wallet_from_headers(headers: &HeaderMap) -> Option<String> {
    if !explorer_auth_required() {
        return None;
    }

    let secret = explorer_auth_secret()?;
    let raw = extract_cookie_value(headers, EXPLORER_AUTH_COOKIE)?;
    let mut parts = raw.splitn(3, '.');
    let wallet = parts.next()?.trim().to_uppercase();
    let expires_at = parts.next()?.trim().parse::<u64>().ok()?;
    let signature = parts.next()?.trim().to_owned();

    if wallet.is_empty() || expires_at <= unix_now_seconds() {
        return None;
    }

    let expected = sign_wallet_session(&wallet, expires_at, &secret);
    if expected != signature {
        return None;
    }

    Some(wallet)
}

fn sanitize_explorer_next_path(next: Option<&str>) -> String {
    let next = next.unwrap_or("/explorer").trim();
    if next.starts_with("/explorer") {
        next.to_owned()
    } else {
        "/explorer".to_owned()
    }
}

fn render_explorer_login_page(error: Option<&str>, next: &str) -> String {
    let error_html = error
        .map(|message| {
            format!(
                "<div class=\"tx-result error\" style=\"margin-top:0;\">{}</div>",
                escape_html(message)
            )
        })
        .unwrap_or_default();

    let body = format!(
        r#"
<section class="hero compact-hero">
    <p class="eyebrow">Wallet Access</p>
    <h1>Explorer Is Read-Only</h1>
    <p class="hero-sub muted">Wallet actions are now handled inside the authenticated A Network mobile app. Public explorer remains read-only for blocks, validators, and settlement visibility.</p>
</section>
<section class="card section-surface">
    {error_html}
    <div class="details details-strong">
        <div><span>Wallet Actions</span><strong>App Only</strong></div>
        <div><span>Explorer Mode</span><strong>Read-Only</strong></div>
        <div><span>Unlock Rule</span><strong>1,000 sessions for protected actions</strong></div>
    </div>
    <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
        <a class="action-ghost" href="anetwork://invite?action=connect">Open Wallet App</a>
        <a class="action-ghost" href="{next}">Back To Explorer</a>
    </div>
</section>
"#,
        error_html = error_html,
        next = escape_html(next),
    );

    layout("Explorer Wallet Login", &body)
}

fn explorer_room_bot_guard_enabled() -> bool {
    std::env::var("ANET_EXPLORER_ROOM_BOT_GUARD")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| !matches!(value.as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(true)
}

fn is_probable_room_scan_key(room_key: &str) -> bool {
    room_key
        .strip_prefix("referral-room-")
        .map(|suffix| suffix.len() >= 3 && suffix.chars().all(|ch| ch.is_ascii_digit()))
        .unwrap_or(false)
}

fn is_known_aggressive_crawler(user_agent: &str) -> bool {
    let ua = user_agent.to_ascii_lowercase();
    ua.contains("mj12bot")
        || ua.contains("ahrefsbot")
        || ua.contains("semrushbot")
        || ua.contains("dotbot")
        || ua.contains("bytespider")
        || ua.contains("petalbot")
}

fn should_short_circuit_room_bot_scan(headers: &HeaderMap, room_key: &str) -> bool {
    if !explorer_room_bot_guard_enabled() || !is_probable_room_scan_key(room_key) {
        return false;
    }

    headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(is_known_aggressive_crawler)
        .unwrap_or(false)
}

fn nav_class(active: bool) -> &'static str {
    if active {
        "active"
    } else {
        ""
    }
}

fn seconds_to_countdown(seconds: i64) -> String {
    let safe = seconds.max(0);
    let hours = safe / 3600;
    let minutes = (safe % 3600) / 60;
    let seconds = safe % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn format_transfer_epoch_label(epoch_seconds: u64) -> String {
    if epoch_seconds == 1 {
        return "1s Settlement Window".to_owned();
    }

    if epoch_seconds < 60 {
        return format!("{epoch_seconds}s Settlement Window");
    }

    if epoch_seconds == 60 {
        return "1m Settlement Window".to_owned();
    }

    if epoch_seconds < 3600 {
        return format!("{}m Settlement Window", epoch_seconds / 60);
    }

    if epoch_seconds == crate::consensus::DEFAULT_WORKER_SESSION_SECONDS {
        return "6h Settlement Window".to_owned();
    }

    format!("{}h Settlement Window", epoch_seconds / 3600)
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}

fn format_integer(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);

    for (index, ch) in digits.chars().rev().enumerate() {
        if index != 0 && index % 3 == 0 {
            formatted.push(',');
        }
        formatted.push(ch);
    }

    formatted.chars().rev().collect()
}

fn format_anet_display(ants: u64) -> String {
    const ANTS_PER_ANET: u64 = 100_000_000;

    let whole = ants / ANTS_PER_ANET;
    let fraction = ants % ANTS_PER_ANET;

    if fraction == 0 {
        return format_integer(whole);
    }

    let mut fraction_text = format!("{fraction:08}");
    while fraction_text.ends_with('0') {
        fraction_text.pop();
    }

    format!("{}.{}", format_integer(whole), fraction_text)
}

fn format_percent(value: f64) -> String {
    format!("{:.2}%", value.clamp(0.0, 100.0))
}

fn percentage(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (value as f64 / total as f64) * 100.0
    }
}

fn colony_slug(label: &str) -> String {
    let mut slug = String::new();
    let mut previous_was_dash = false;

    for ch in label.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_was_dash = false;
        } else if !previous_was_dash {
            slug.push('-');
            previous_was_dash = true;
        }
    }

    slug.trim_matches('-').to_owned()
}

fn territory_slug(label: &str) -> String {
    colony_slug(label)
}

fn preferred_colony_labels() -> [&'static str; 7] {
    [
        "Worker Ants",
        "Queen Ant",
        "Nurse Ants",
        "Farmer Ants",
        "Builder Ants",
        "Scout Ants",
        "Soldier Ants",
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Revelation Block 0 — public verification handlers.
//
// Goal: anyone in the world can independently reproduce the published
// SHA-256 (f8719ae3…d27a) by downloading these exact bytes from a running
// node. No trust, no API key, no JavaScript required.
// ─────────────────────────────────────────────────────────────────────────────

fn plain_text_response(body: &'static str, content_type: &'static str) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300, immutable"),
    );
    (StatusCode::OK, headers, body)
}

async fn genesis_raw_json() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300, immutable"),
    );
    headers.insert(
        HeaderName::from_static("content-disposition"),
        HeaderValue::from_static("inline; filename=\"genesis.json\""),
    );
    (StatusCode::OK, headers, REVELATION_GENESIS_JSON)
}

async fn genesis_sha256() -> impl IntoResponse {
    plain_text_response(REVELATION_GENESIS_SHA256, "text/plain; charset=utf-8")
}

async fn genesis_signature() -> impl IntoResponse {
    plain_text_response(REVELATION_GENESIS_SIG, "text/plain; charset=utf-8")
}

async fn genesis_pubkey() -> impl IntoResponse {
    plain_text_response(REVELATION_GENESIS_PUBKEY, "text/plain; charset=utf-8")
}

async fn genesis_manifest() -> impl IntoResponse {
    plain_text_response(REVELATION_GENESIS_MANIFEST, "text/plain; charset=utf-8")
}

async fn genesis_verification_page() -> impl IntoResponse {
    let sha256 = REVELATION_GENESIS_SHA256
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim();
    let pubkey = REVELATION_GENESIS_PUBKEY.trim();
    let signature = REVELATION_GENESIS_SIG.trim();
    let body = format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Revelation Block 0 — A-Network Mainnet</title>
<meta name="description" content="Public verification of the A-Network mainnet genesis. SHA-256 root, ed25519 signature, and downloadable artifacts.">
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#f4f7fb; color:#1d2939; margin:0; padding:32px 20px 80px; }}
  .wrap {{ max-width: 880px; margin: 0 auto; }}
  h1 {{ font-size: 26px; margin:0 0 6px; letter-spacing:.5px; color:#12263f; }}
  h2 {{ font-size: 16px; margin:32px 0 10px; color:#12263f; border-bottom:1px solid #dce3eb; padding-bottom:6px; }}
  .sub {{ color:#5d6b7c; margin:0 0 20px; }}
  .box {{ background:#fff; border:1px solid #dce3eb; border-radius:8px; padding:14px 16px; margin:10px 0; overflow-x:auto; }}
  .k {{ color:#5d6b7c; }}
  .v {{ color:#17674a; word-break:break-all; }}
  a {{ color:#1769aa; }}
  code {{ color:#17674a; }}
  pre {{ background:#f7f9fc; border:1px solid #dce3eb; border-radius:6px; padding:12px 14px; overflow-x:auto; color:#29435e; }}
  ul {{ padding-left: 20px; }}
  li {{ margin: 4px 0; }}
  .files a {{ display:inline-block; margin-right:14px; }}
  .warn {{ color:#8a5a0a; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>REVELATION BLOCK 0</h1>
  <p class="sub">A-Network Mainnet — sealed 2026-05-26T19:14:23Z. No authority. No reversal. No governance. Truth revealed by computation.</p>

  <h2>Cryptographic commitment</h2>
  <div class="box"><span class="k">SHA-256 root</span><br><span class="v">{sha256}</span></div>
  <div class="box"><span class="k">Ed25519 public key</span><br><span class="v">{pubkey}</span></div>
  <div class="box"><span class="k">Ed25519 signature (over the SHA-256 bytes)</span><br><span class="v">{signature}</span></div>

  <h2>External anchors</h2>
  <ul>
    <li>Bitcoin head at sealing: <a href="https://mempool.space/block/951158" rel="noopener">block #951158</a></li>
    <li>BSC head at sealing: <a href="https://bscscan.com/block/100593590" rel="noopener">block #100593590</a></li>
    <li>BSC commitment tx (SHA-256 in <code>Input Data</code>): <a href="https://bscscan.com/tx/0xffade6523ab9c6a8efee858fe5c244e4be5f45f154fa90026d84892a75ddcec2" rel="noopener">0xffade652…ddcec2</a> in <a href="https://bscscan.com/block/100602262" rel="noopener">block #100602262</a></li>
  </ul>

  <h2>Aggregate state at seal</h2>
  <ul>
    <li>Unique wallets: <code>81,763</code></li>
    <li>Total sessions: <code>2,446,072</code></li>
    <li>Total ledger balance: <code>31,990.68690775 ANET</code> (<code>3,199,068,690,775</code> ANTS)</li>
    <li>Hard cap headroom: <code>20,968,009.31309225 ANET</code></li>
  </ul>

  <h2>Files</h2>
  <p class="files">
    <a href="/genesis/genesis.json">genesis.json</a>
    <a href="/genesis/genesis.sha256">genesis.sha256</a>
    <a href="/genesis/genesis.sig">genesis.sig</a>
    <a href="/genesis/genesis.pubkey">genesis.pubkey</a>
    <a href="/genesis/manifest.txt">manifest.txt</a>
  </p>

  <h2>Verify the hash (any machine, no dependencies)</h2>
<pre>curl -sO https://mainnet.explorer.a-network.net/genesis/genesis.json
shasum -a 256 genesis.json
# expected: {sha256}  genesis.json</pre>

  <h2>Verify the signature (Python 3 + PyNaCl)</h2>
<pre>pip install pynacl
python3 - &lt;&lt;'PY'
from nacl.signing import VerifyKey
import hashlib, binascii
pub = binascii.unhexlify("{pubkey}")
sig = binascii.unhexlify("{signature}")
with open("genesis.json","rb") as f:
    digest = hashlib.sha256(f.read()).digest()
VerifyKey(pub).verify(digest, sig)
print("OK — signature valid for SHA-256 of genesis.json")
PY</pre>

  <p class="warn">If your hash or signature check fails, the bytes were tampered with in transit or this node is not the genuine A-Network mainnet node. Reject and report.</p>

  <p style="margin-top:40px;color:#5d6b7c;font-size:12px;">
    Explorer: <a href="/explorer">/explorer</a> · Network: ANET Mainnet
  </p>
</div>
</body>
</html>"##,
        sha256 = sha256,
        pubkey = pubkey,
        signature = signature,
    );
    Html(body)
}

#[cfg(test)]
mod bridge_policy_tests {
    #[test]
    fn portal_spoke_to_l1_credit_is_permanently_disabled() {
        // Attack 8/10: even with the legacy env flag set, the spoke → L1
        // credit gate must stay closed. The env var is intentionally ignored.
        std::env::set_var("ANET_PORTAL_CREDIT_ENABLED", "true");
        assert!(!super::portal_credit_enabled());
        std::env::remove_var("ANET_PORTAL_CREDIT_ENABLED");
        assert!(!super::portal_credit_enabled());
    }
}

#[cfg(test)]
mod account_activity_tests {
    use super::{chain_event_wallet_match, describe_chain_event, ChainEvent};

    fn event(event_type: &str, attrs: &[(&str, &str)]) -> ChainEvent {
        let mut e = ChainEvent::new(event_type);
        for (k, v) in attrs {
            e = e.attr(k, v.to_string());
        }
        e
    }

    #[test]
    fn swap_executed_matches_only_the_trader() {
        let e = event("SwapExecuted", &[("trader", "ANETAAAA"), ("pair_id", "ANET/USDT")]);
        assert!(chain_event_wallet_match(&e, "ANETAAAA"));
        assert!(!chain_event_wallet_match(&e, "ANETBBBB"));
    }

    #[test]
    fn liquidity_and_pool_events_match_provider() {
        for kind in ["LiquidityAdded", "LiquidityRemoved", "PoolCreated"] {
            let e = event(kind, &[("provider", "ANETPROVIDER"), ("pair_id", "ANET/USDC")]);
            assert!(chain_event_wallet_match(&e, "ANETPROVIDER"), "{kind} should match provider");
            assert!(!chain_event_wallet_match(&e, "ANETOTHER"), "{kind} should not match unrelated wallet");
        }
    }

    #[test]
    fn app_activity_matches_wallet_attribute() {
        let e = event("AppActivity", &[("action", "web_dex_swap"), ("wallet", "ANETUSER")]);
        assert!(chain_event_wallet_match(&e, "ANETUSER"));
        assert!(!chain_event_wallet_match(&e, "ANETSOMEONEELSE"));
    }

    #[test]
    fn token_transferred_matches_either_side() {
        let e = event("TokenTransferred", &[("symbol", "USDT"), ("from", "ANETSENDER"), ("to", "ANETRECEIVER"), ("amount", "500")]);
        assert!(chain_event_wallet_match(&e, "ANETSENDER"));
        assert!(chain_event_wallet_match(&e, "ANETRECEIVER"));
        assert!(!chain_event_wallet_match(&e, "ANETBYSTANDER"));
    }

    #[test]
    fn unrelated_event_types_never_match() {
        let e = event("SessionMilestone", &[("wallet", "ANETUSER")]);
        assert!(!chain_event_wallet_match(&e, "ANETUSER"));
    }

    #[test]
    fn describe_swap_executed_reads_direction_and_amounts() {
        let e = event(
            "SwapExecuted",
            &[
                ("trader", "ANETTRADER"),
                ("pair_id", "ANET/USDT"),
                ("direction", "ANET->USDT"),
                ("amount_in", "100000000"),
                ("amount_out", "99000000"),
            ],
        );
        let (description, direction, from, to) = describe_chain_event(&e, "ANETTRADER");
        assert!(description.contains("ANET/USDT"));
        assert!(description.contains("ANET->USDT"));
        assert_eq!(direction, "activity");
        assert_eq!(from, "ANETTRADER");
        assert_eq!(to, "");
    }

    #[test]
    fn describe_token_transferred_sets_outgoing_incoming_by_perspective() {
        let e = event(
            "TokenTransferred",
            &[("symbol", "USDC"), ("from", "ANETSENDER"), ("to", "ANETRECEIVER"), ("amount", "42")],
        );
        let (_desc, direction_as_sender, from, to) = describe_chain_event(&e, "ANETSENDER");
        assert_eq!(direction_as_sender, "outgoing");
        assert_eq!(from, "ANETSENDER");
        assert_eq!(to, "ANETRECEIVER");

        let (_desc, direction_as_receiver, _, _) = describe_chain_event(&e, "ANETRECEIVER");
        assert_eq!(direction_as_receiver, "incoming");
    }
}
