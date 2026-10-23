use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::db;

pub const CHAIN_ID: &str = "anet-private-mainnet-1";
pub const ANTS_PER_SESSION: u64 = 4_882_812;
pub const ANTS_PER_ANET: u64 = 100_000_000;
pub const MIN_SESSIONS_FOR_ANET: u64 = 1_000;

/// THE single source-of-truth eligibility predicate.
///
/// "A wallet is eligible once it has completed at least
/// `MIN_SESSIONS_FOR_ANET` sessions." This rule is referenced by the chain's
/// validator selection (`state::compute_validators_from_accounts`) AND must be
/// mirrored *byte-for-byte* by the Web2 backend's `is_eligible` computation and
/// by the signed session-oracle (`oracle::SignedSessionSnapshot`). Defining it
/// in one place is what keeps Web2 logic and on-chain consensus consistent:
/// neither side may invent its own threshold.
#[inline]
pub fn is_session_eligible(sessions: u64) -> bool {
    sessions >= MIN_SESSIONS_FOR_ANET
}

/// Hard cap on the size of the active validator set.
///
/// Bitcoin-aligned design choice: small, deterministic, ungovernable.
/// 2,100 is chosen as a nod to Bitcoin's "21" magic number (21M supply
/// cap; 210,000 blocks per halving era). It is large enough for global
/// geographic decentralization while keeping per-block fee distribution
/// economically meaningful for each seated validator.
///
/// Selection when more than `MAX_VALIDATORS` accounts are eligible is
/// deterministic: sessions DESC, then address ASC (see
/// `state::compute_validators_from_accounts`).
pub const MAX_VALIDATORS: usize = 2_100;

// ─────────────────────────────────────────────────────────────────────────────
// Bitcoin-style capped emission schedule
// ─────────────────────────────────────────────────────────────────────────────
//
// ANET issuance mirrors Bitcoin's monetary policy: a fixed, ungovernable
// schedule with a hard supply ceiling that any node can verify independently.
// Unlike Bitcoin — whose subsidy halves on BLOCK HEIGHT — ANET halves on
// CUMULATIVE NETWORK SESSIONS, because a session is this chain's unit of
// proof-of-work and blocks here are produced on-demand (an idle network mints
// no blocks, so height is not a usable clock).
//
// The schedule is defined ONCE here and MUST be mirrored byte-for-byte by the
// Web2 backend (`rmp-site/backend/services/miningEngine.js`). Neither side may
// invent its own numbers — that is what keeps Web2-credited balances and
// on-chain supply consistent.
//
// Two eras:
//   1. Launch tranche — the first `LAUNCH_TRANCHE_SESSIONS` sessions pay the
//      generous bootstrap reward `LAUNCH_REWARD_ANTS` (the rate every existing
//      wallet was already credited at). This is the high-subsidy early era.
//   2. Post-launch — the reward resets to `POST_LAUNCH_BASE_REWARD_ANTS` and
//      halves every `HALVING_INTERVAL_SESSIONS` sessions, tapering to exactly 0
//      (the base is a power of two, so integer halving reaches 0 at stage 19).
//
// The geometric series is bounded, so total issuance converges to a finite cap
// at or below `MAX_SUPPLY_ANTS` (21,000,000 ANET); `capped_session_reward_ants`
// additionally enforces that ceiling as a hard invariant.

/// Permanent hard supply ceiling, in whole ANET. Bitcoin's "21 million".
pub const MAX_SUPPLY_ANET: u64 = 21_000_000;

/// Permanent hard supply ceiling, in ANTS (`MAX_SUPPLY_ANET * ANTS_PER_ANET`).
/// No schedule or admin path may ever mint ANET beyond this total.
pub const MAX_SUPPLY_ANTS: u64 = MAX_SUPPLY_ANET * ANTS_PER_ANET;

/// Length of the launch tranche (high-subsidy bootstrap era), in cumulative
/// network sessions. While `total_sessions < LAUNCH_TRANCHE_SESSIONS`, every
/// session pays `LAUNCH_REWARD_ANTS`.
pub const LAUNCH_TRANCHE_SESSIONS: u64 = 500_000;

/// Per-session reward during the launch tranche, in ANTS. Identical to the
/// historical `ANTS_PER_SESSION`, so existing balances are unaffected.
pub const LAUNCH_REWARD_ANTS: u64 = ANTS_PER_SESSION;

/// First post-launch per-session reward, in ANTS. A power of two (2^18) so the
/// halving series reaches exactly 0.
pub const POST_LAUNCH_BASE_REWARD_ANTS: u64 = 262_144;

/// Sessions between post-launch halvings. Chosen so the bounded geometric
/// series (launch tranche + post-launch halvings) converges just under the
/// 21,000,000 ANET ceiling.
pub const HALVING_INTERVAL_SESSIONS: u64 = 4_000_000_000;

/// Final halving stage. `POST_LAUNCH_BASE_REWARD_ANTS >> 19 == 0`, so issuance
/// has fully tapered to zero by this stage. The stage is clamped here so the
/// bit-shift in `session_reward_ants` can never overflow.
pub const MAX_HALVING_STAGE: u64 = 19;

/// Cumulative sessions elapsed since the end of the launch tranche.
#[inline]
pub fn post_launch_sessions(total_sessions: u64) -> u64 {
    total_sessions.saturating_sub(LAUNCH_TRANCHE_SESSIONS)
}

/// Current halving stage for a given cumulative network session count. Stage 0
/// covers the launch tranche and the first post-launch interval; each further
/// `HALVING_INTERVAL_SESSIONS` advances the stage by one, clamped at
/// `MAX_HALVING_STAGE` (where the reward is already 0).
pub fn halving_stage(total_sessions: u64) -> u64 {
    if total_sessions < LAUNCH_TRANCHE_SESSIONS {
        return 0;
    }
    (post_launch_sessions(total_sessions) / HALVING_INTERVAL_SESSIONS).min(MAX_HALVING_STAGE)
}

/// Per-session reward (ANTS) for the NEXT session, given how many sessions the
/// network has already completed — the pure schedule, before the global supply
/// clamp. Flat `LAUNCH_REWARD_ANTS` during the launch tranche; afterwards it
/// halves geometrically to 0.
pub fn session_reward_ants(total_sessions_completed: u64) -> u64 {
    if total_sessions_completed < LAUNCH_TRANCHE_SESSIONS {
        return LAUNCH_REWARD_ANTS;
    }
    // `stage` is clamped to `MAX_HALVING_STAGE` (19), so the shift never
    // overflows and the reward floors at 0.
    let stage = halving_stage(total_sessions_completed);
    POST_LAUNCH_BASE_REWARD_ANTS >> stage
}

/// Per-session reward (ANTS) clamped by the hard supply ceiling. Returns 0 once
/// `MAX_SUPPLY_ANTS` has been minted, and trims the final reward so cumulative
/// issuance lands exactly on the cap — the same rule the Web2 crediting path
/// enforces. This is the Bitcoin invariant: no node mints past 21,000,000 ANET.
///
/// Reserved canonical API: the live L1 issuance path (`state::sync_activated_accounts`)
/// currently enforces the same ceiling on activation *deltas*, but this
/// per-session form is verified by tests and mirrored by the Web2 backend.
#[allow(dead_code)]
pub fn capped_session_reward_ants(total_sessions_completed: u64, total_minted_ants: u64) -> u64 {
    if total_minted_ants >= MAX_SUPPLY_ANTS {
        return 0;
    }
    let remaining = MAX_SUPPLY_ANTS - total_minted_ants;
    session_reward_ants(total_sessions_completed).min(remaining)
}

/// Total ANTS the schedule will ever emit if run to exhaustion (reward 0). This
/// is the emergent cap — analogous to Bitcoin's 20,999,999.97 BTC — and is
/// guaranteed `<= MAX_SUPPLY_ANTS`.
///
/// Reserved canonical API: verified by tests as a hard invariant on the tuned
/// schedule constants; not called on a hot path.
#[allow(dead_code)]
pub fn lifetime_emission_ants() -> u64 {
    let launch = LAUNCH_TRANCHE_SESSIONS.saturating_mul(LAUNCH_REWARD_ANTS);
    let mut post = 0_u64;
    let mut stage = 0_u64;
    while stage < MAX_HALVING_STAGE {
        let reward = POST_LAUNCH_BASE_REWARD_ANTS >> stage;
        post = post.saturating_add(HALVING_INTERVAL_SESSIONS.saturating_mul(reward));
        stage += 1;
    }
    launch.saturating_add(post)
}

// ─────────────────────────────────────────────────────────────────────────────
// Mined-coin vesting schedule (value-protection for wANET swaps)
// ─────────────────────────────────────────────────────────────────────────────
//
// Mined (activated) ANET becomes P2P-transferable as soon as the wallet is
// eligible, but swapping it OUT of the L1 economy (bridge burn to wANET on
// BSC, or wrapping to WANET on the native DEX) unlocks gradually:
//
//   - 6-month cliff from the wallet's FIRST on-chain activation, then
//   - 25% of the wallet's total activated coins per 3 months:
//     6mo → 25%, 9mo → 50%, 12mo → 75%, 15mo → 100%.
//
// The anchor is the timestamp of the wallet's first sealed `SessionActivation`
// credit event — an immutable on-chain record — so any node derives the same
// unlock state from block history alone. Bridge-purchased coins (paid-for,
// not mined) are never vested; only the mined `total_activated_ants` are.

/// Milliseconds in one 30-day month (the schedule's fixed unit).
const VESTING_MONTH_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Cliff before the first tranche unlocks: 6 months from first activation.
pub const VESTING_CLIFF_MS: i64 = 6 * VESTING_MONTH_MS;

/// Interval between tranches after the cliff: 3 months each.
pub const VESTING_TRANCHE_MS: i64 = 3 * VESTING_MONTH_MS;

/// Fraction unlocked per tranche, in basis points (25%).
pub const VESTING_TRANCHE_BPS: u64 = 2_500;

/// Fraction (basis points, 0..=10_000) of a wallet's mined coins that may be
/// swapped to wANET, given its first-activation anchor and the current time.
pub fn vested_fraction_bps(anchor_ms: i64, now_ms: i64) -> u64 {
    let elapsed = now_ms.saturating_sub(anchor_ms);
    if elapsed < VESTING_CLIFF_MS {
        return 0;
    }
    let tranches = 1 + ((elapsed - VESTING_CLIFF_MS) / VESTING_TRANCHE_MS) as u64;
    (tranches.saturating_mul(VESTING_TRANCHE_BPS)).min(10_000)
}

/// ANTS still locked for wANET swaps: the unvested share of the wallet's
/// mined (activated) total. `None` anchor means the wallet was activated
/// before any anchor was sealed on-chain — treated as fully unvested until
/// its first post-upgrade activation event seals an anchor, EXCEPT when it
/// has no mined coins at all (bridge-only wallets are never locked).
pub fn unvested_activated_ants(
    total_activated_ants: u64,
    anchor_ms: Option<i64>,
    now_ms: i64,
) -> u64 {
    if total_activated_ants == 0 {
        return 0;
    }
    let vested_bps = match anchor_ms {
        Some(anchor) => vested_fraction_bps(anchor, now_ms),
        None => 0,
    };
    let vested = ((total_activated_ants as u128) * (vested_bps as u128) / 10_000) as u64;
    total_activated_ants.saturating_sub(vested)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: String,
    pub ants_balance: u64,
    pub sessions: u64,
    #[serde(default)]
    pub total_activated_ants: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: String,
    pub genesis_time: DateTime<Utc>,
    pub accounts: Vec<GenesisAccount>,
}

pub async fn activate_genesis(path: &Path) -> Result<GenesisConfig> {
    let client = db::connect().await?;
    let ant_ledger_accounts = db::load_genesis_accounts(&client).await?;

    let accounts = ant_ledger_accounts
        .into_iter()
        .map(|row| GenesisAccount {
            address: row.wallet_address,
            ants_balance: row
                .ants_balance
                .max(row.sessions.saturating_mul(ANTS_PER_SESSION)),
            sessions: row.sessions,
            total_activated_ants: row
                .ants_balance
                .max(row.sessions.saturating_mul(ANTS_PER_SESSION)),
        })
        .collect();

    let genesis = GenesisConfig {
        chain_id: CHAIN_ID.to_owned(),
        genesis_time: Utc::now(),
        accounts,
    };

    write_genesis(path, &genesis)?;
    Ok(genesis)
}

pub fn load_genesis(path: &Path) -> Result<GenesisConfig> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read genesis file at {}", path.display()))?;
    let genesis = serde_json::from_str(&contents)
        .with_context(|| format!("failed to parse genesis file at {}", path.display()))?;
    Ok(genesis)
}

pub fn write_genesis(path: &Path, genesis: &GenesisConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    }

    let encoded = serde_json::to_string_pretty(genesis)?;
    fs::write(path, encoded)
        .with_context(|| format!("failed to write genesis file at {}", path.display()))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Asset unlock tiers — transparent, code-enforced status (read-only reporting)
// ─────────────────────────────────────────────────────────────────────────────
//
// Purpose: give users (and the app UI) a clear, honest answer to "what can I
// do with my ANET right now, and why" WITHOUT changing any existing spend
// enforcement. The actual gate that blocks P2P transfers and native-DEX swaps
// today is `NodeState::ensure_eligible_account` (sessions >= MIN_SESSIONS_FOR_ANET,
// or bridge-funded). This module is a pure, side-effect-free function that
// mirrors that SAME rule for P2P/Swap (so reported status can never drift
// from real enforcement), and adds a SEPARATE, independently-tunable Bridge
// tier because bridging out to an external network is a network-readiness
// decision, not a per-wallet session count — the live node already disables
// the L1 burn/bridge-out endpoint network-wide (`BRIDGE_BURN_ENABLED`), so
// defaulting the Bridge tier to "not yet announced" matches current reality
// exactly. Every threshold defaults to today's existing behavior; operators
// can raise `ANET_SWAP_MIN_SESSIONS` above the P2P threshold, or flip
// `ANET_BRIDGE_UNLOCK_ANNOUNCED=true`, later WITHOUT a code change — a
// transparent config knob, not a manual per-user approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetLockTier {
    /// Mining balance is visible on-chain but cannot be transferred, swapped,
    /// or bridged. Reached below `MIN_SESSIONS_FOR_ANET` and not bridge-funded.
    Locked,
    /// Eligible for internal Layer 1 peer-to-peer transfers only.
    P2pEnabled,
    /// Eligible for P2P transfers AND the internal native-DEX.
    SwapEnabled,
    /// Eligible for P2P, swap, AND bridging to a supported external network.
    BridgeEnabled,
    /// All currently-defined utility functions are available.
    FullyUnlocked,
}

impl AssetLockTier {
    /// Reserved canonical API: a stable string form for callers that want the
    /// tier outside of JSON (e.g. logging). The JSON wire format already gets
    /// the same string via `#[serde(rename_all = "snake_case")]`.
    #[allow(dead_code)]
    pub fn label(self) -> &'static str {
        match self {
            AssetLockTier::Locked => "locked",
            AssetLockTier::P2pEnabled => "p2p_enabled",
            AssetLockTier::SwapEnabled => "swap_enabled",
            AssetLockTier::BridgeEnabled => "bridge_enabled",
            AssetLockTier::FullyUnlocked => "fully_unlocked",
        }
    }
}

/// Minimum completed sessions required for the Swap tier. Defaults to the
/// SAME value as `MIN_SESSIONS_FOR_ANET` (today's actual DEX gate), so this is
/// a reporting-only knob until an operator deliberately raises it above the
/// P2P threshold via env — no existing behavior changes by default.
pub fn swap_min_sessions() -> u64 {
    std::env::var("ANET_SWAP_MIN_SESSIONS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.max(MIN_SESSIONS_FOR_ANET))
        .unwrap_or(MIN_SESSIONS_FOR_ANET)
}

/// Whether official Bridge-tier unlock conditions have been announced. Off by
/// default — matches the live node, which already disables the bridge-out
/// endpoint network-wide regardless of any individual wallet's session count.
pub fn bridge_unlock_announced() -> bool {
    matches!(
        std::env::var("ANET_BRIDGE_UNLOCK_ANNOUNCED")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Human-readable description of what still gates the Bridge tier. Purely
/// informational — shown to users so "why is this locked" is never a mystery.
pub fn bridge_unlock_condition_label() -> String {
    std::env::var("ANET_BRIDGE_UNLOCK_CONDITION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            "Bridging to external networks awaits an official mainnet unlock announcement."
                .to_string()
        })
}

/// Transparent, per-wallet unlock status. Every field is derived from
/// already-enforced chain rules (see module docs) — nothing here can grant an
/// action the real gates would refuse, and nothing here can refuse an action
/// the real gates would allow.
#[derive(Debug, Clone, Serialize)]
pub struct AssetUnlockStatus {
    pub tier: AssetLockTier,
    pub sessions: u64,
    pub sessions_required_for_p2p: u64,
    pub sessions_required_for_swap: u64,
    pub bridge_funded: bool,
    pub p2p_enabled: bool,
    pub swap_enabled: bool,
    pub bridge_enabled: bool,
    pub bridge_unlock_condition: String,
    pub reason: String,
    pub sessions_remaining_for_p2p: u64,
    pub sessions_remaining_for_swap: u64,
    pub available_actions: Vec<&'static str>,
    pub unavailable_actions: Vec<&'static str>,
}

/// Computes the transparent unlock status for a wallet. `ants_balance` is
/// accepted (rather than derived here) so the caller can pass the SAME value
/// already returned by `/accounts/:address`, keeping the two responses
/// consistent by construction.
pub fn compute_asset_unlock_status(
    sessions: u64,
    bridge_funded: bool,
    ants_balance: u64,
) -> AssetUnlockStatus {
    let p2p_required = MIN_SESSIONS_FOR_ANET;
    let swap_required = swap_min_sessions();
    // Mirrors `NodeState::ensure_eligible_account` exactly: bridge-funded
    // wallets paid real value and are exempt from the mined-ANTS session gate.
    let p2p_enabled = bridge_funded || sessions >= p2p_required;
    let swap_enabled = bridge_funded || sessions >= swap_required;
    let bridge_enabled = swap_enabled && bridge_unlock_announced();

    let tier = if bridge_enabled {
        // Reserved for when a distinct "fully unlocked" milestone (beyond
        // bridge access) is defined; today Bridge implies Fully Unlocked.
        AssetLockTier::FullyUnlocked
    } else if swap_enabled {
        AssetLockTier::SwapEnabled
    } else if p2p_enabled {
        AssetLockTier::P2pEnabled
    } else {
        AssetLockTier::Locked
    };

    let mut available = Vec::new();
    let mut unavailable = Vec::new();
    available.push("view_balance");
    if p2p_enabled {
        available.push("p2p_transfer");
    } else {
        unavailable.push("p2p_transfer");
    }
    if swap_enabled {
        available.push("native_dex_swap");
    } else {
        unavailable.push("native_dex_swap");
    }
    if bridge_enabled {
        available.push("bridge_to_external_network");
    } else {
        unavailable.push("bridge_to_external_network");
    }

    let reason = if bridge_funded {
        "Wallet received a backed bridge credit and is exempt from the mining session gate."
            .to_string()
    } else if tier == AssetLockTier::Locked {
        format!(
            "This wallet has completed {sessions} of the {p2p_required} sessions required to unlock transfers. \
             Mined ANTS remain visible but cannot be transferred, swapped, or bridged until then."
        )
    } else if tier == AssetLockTier::P2pEnabled {
        format!(
            "P2P transfers are unlocked ({sessions} sessions completed). \
             {} more session(s) are required to unlock the native DEX.",
            swap_required.saturating_sub(sessions)
        )
    } else {
        "P2P transfers and the native DEX are unlocked. Bridging to external networks awaits an official unlock."
            .to_string()
    };

    let _ = ants_balance; // reserved for a future "locked balance visibility" nuance

    AssetUnlockStatus {
        tier,
        sessions,
        sessions_required_for_p2p: p2p_required,
        sessions_required_for_swap: swap_required,
        bridge_funded,
        p2p_enabled,
        swap_enabled,
        bridge_enabled,
        bridge_unlock_condition: bridge_unlock_condition_label(),
        reason,
        sessions_remaining_for_p2p: p2p_required.saturating_sub(sessions),
        sessions_remaining_for_swap: swap_required.saturating_sub(sessions),
        available_actions: available,
        unavailable_actions: unavailable,
    }
}

#[cfg(test)]
mod emission_tests {
    use super::*;

    #[test]
    fn max_supply_is_21_million_anet() {
        assert_eq!(MAX_SUPPLY_ANTS, 2_100_000_000_000_000);
        assert_eq!(MAX_SUPPLY_ANTS, MAX_SUPPLY_ANET * ANTS_PER_ANET);
    }

    #[test]
    fn launch_tranche_pays_legacy_reward() {
        assert_eq!(session_reward_ants(0), LAUNCH_REWARD_ANTS);
        assert_eq!(session_reward_ants(1), LAUNCH_REWARD_ANTS);
        assert_eq!(
            session_reward_ants(LAUNCH_TRANCHE_SESSIONS - 1),
            LAUNCH_REWARD_ANTS
        );
        assert_eq!(halving_stage(LAUNCH_TRANCHE_SESSIONS - 1), 0);
        // The launch reward must equal the historical flat rate so no existing
        // balance changes.
        assert_eq!(LAUNCH_REWARD_ANTS, ANTS_PER_SESSION);
    }

    #[test]
    fn post_launch_starts_at_base_then_halves() {
        // First post-launch session pays the post-launch base.
        assert_eq!(
            session_reward_ants(LAUNCH_TRANCHE_SESSIONS),
            POST_LAUNCH_BASE_REWARD_ANTS
        );
        // One full interval in -> stage 1 -> base / 2.
        let one_interval = LAUNCH_TRANCHE_SESSIONS + HALVING_INTERVAL_SESSIONS;
        assert_eq!(halving_stage(one_interval), 1);
        assert_eq!(
            session_reward_ants(one_interval),
            POST_LAUNCH_BASE_REWARD_ANTS / 2
        );
        // Two intervals -> stage 2 -> base / 4.
        let two_intervals = LAUNCH_TRANCHE_SESSIONS + 2 * HALVING_INTERVAL_SESSIONS;
        assert_eq!(halving_stage(two_intervals), 2);
        assert_eq!(
            session_reward_ants(two_intervals),
            POST_LAUNCH_BASE_REWARD_ANTS / 4
        );
    }

    #[test]
    fn reward_tapers_to_exactly_zero() {
        // Base is 2^18, so the reward is 1 at stage 18 and 0 from stage 19 on.
        let at_stage_18 = LAUNCH_TRANCHE_SESSIONS + 18 * HALVING_INTERVAL_SESSIONS;
        assert_eq!(session_reward_ants(at_stage_18), 1);
        let at_stage_19 = LAUNCH_TRANCHE_SESSIONS + 19 * HALVING_INTERVAL_SESSIONS;
        assert_eq!(session_reward_ants(at_stage_19), 0);
        // Stays 0 far past the final stage (clamped, no shift overflow / panic).
        let far_future = LAUNCH_TRANCHE_SESSIONS + 1_000 * HALVING_INTERVAL_SESSIONS;
        assert_eq!(session_reward_ants(far_future), 0);
        assert_eq!(session_reward_ants(u64::MAX), 0);
    }

    #[test]
    fn reward_is_monotonically_non_increasing() {
        let mut prev = session_reward_ants(LAUNCH_TRANCHE_SESSIONS);
        for stage in 1..=MAX_HALVING_STAGE {
            let reward =
                session_reward_ants(LAUNCH_TRANCHE_SESSIONS + stage * HALVING_INTERVAL_SESSIONS);
            assert!(
                reward <= prev,
                "reward increased at stage {stage}: {reward} > {prev}"
            );
            prev = reward;
        }
    }

    #[test]
    fn lifetime_emission_within_hard_cap() {
        let total = lifetime_emission_ants();
        assert!(
            total <= MAX_SUPPLY_ANTS,
            "lifetime emission {total} exceeds cap {MAX_SUPPLY_ANTS}"
        );
        // Sanity: the series converges close to 21M (within 0.1% of the cap),
        // like Bitcoin's 20,999,999.97 BTC.
        let floor = MAX_SUPPLY_ANTS - MAX_SUPPLY_ANTS / 1000;
        assert!(
            total >= floor,
            "lifetime emission {total} is unexpectedly far below cap {MAX_SUPPLY_ANTS}"
        );
    }

    #[test]
    fn cap_clamp_trims_final_reward_then_stops() {
        // One reward short of the cap -> reward trimmed to exactly the remainder.
        let near = MAX_SUPPLY_ANTS - 10;
        assert_eq!(capped_session_reward_ants(0, near), 10);
        // At/over the cap -> issuance has ended.
        assert_eq!(capped_session_reward_ants(0, MAX_SUPPLY_ANTS), 0);
        assert_eq!(capped_session_reward_ants(0, MAX_SUPPLY_ANTS + 1), 0);
        // Below the cap, the clamp is a no-op on the normal schedule.
        assert_eq!(capped_session_reward_ants(0, 0), LAUNCH_REWARD_ANTS);
    }
}

#[cfg(test)]
mod asset_unlock_status_tests {
    use super::*;

    // NOTE: intentionally does not set ANET_SWAP_MIN_SESSIONS /
    // ANET_BRIDGE_UNLOCK_ANNOUNCED — cargo test runs in one process, so
    // mutating shared env vars would be flaky under parallel tests. These
    // tests exercise the documented DEFAULTS only.

    #[test]
    fn below_threshold_is_locked_with_no_actions() {
        let status = compute_asset_unlock_status(999, false, 0);
        assert_eq!(status.tier, AssetLockTier::Locked);
        assert!(!status.p2p_enabled);
        assert!(!status.swap_enabled);
        assert!(!status.bridge_enabled);
        assert_eq!(status.sessions_remaining_for_p2p, 1);
        assert!(status.available_actions.contains(&"view_balance"));
        assert!(!status.available_actions.contains(&"p2p_transfer"));
        assert!(status.unavailable_actions.contains(&"p2p_transfer"));
        assert!(status.unavailable_actions.contains(&"native_dex_swap"));
        assert!(status.unavailable_actions.contains(&"bridge_to_external_network"));
    }

    #[test]
    fn min_sessions_unlocks_p2p_and_swap_by_default() {
        // Default swap threshold == MIN_SESSIONS_FOR_ANET, matching today's
        // single `ensure_eligible_account` gate exactly (no behavior change).
        let status = compute_asset_unlock_status(MIN_SESSIONS_FOR_ANET, false, 0);
        assert_eq!(status.tier, AssetLockTier::SwapEnabled);
        assert!(status.p2p_enabled);
        assert!(status.swap_enabled);
        // Bridge stays locked by default even once P2P/Swap unlock — matches
        // the live node's network-wide bridge-out disable.
        assert!(!status.bridge_enabled);
        assert!(status.available_actions.contains(&"native_dex_swap"));
        assert!(status.unavailable_actions.contains(&"bridge_to_external_network"));
    }

    #[test]
    fn bridge_funded_wallet_is_exempt_from_session_gate() {
        let status = compute_asset_unlock_status(0, true, 500_000);
        assert!(status.bridge_funded);
        assert!(status.p2p_enabled);
        assert!(status.swap_enabled);
        assert_eq!(status.tier, AssetLockTier::SwapEnabled);
    }

    #[test]
    fn tier_labels_are_stable_strings() {
        assert_eq!(AssetLockTier::Locked.label(), "locked");
        assert_eq!(AssetLockTier::P2pEnabled.label(), "p2p_enabled");
        assert_eq!(AssetLockTier::SwapEnabled.label(), "swap_enabled");
        assert_eq!(AssetLockTier::BridgeEnabled.label(), "bridge_enabled");
        assert_eq!(AssetLockTier::FullyUnlocked.label(), "fully_unlocked");
    }
}

#[cfg(test)]
mod vesting_tests {
    use super::*;

    const DAY_MS: i64 = 24 * 60 * 60 * 1000;

    #[test]
    fn nothing_vests_before_the_six_month_cliff() {
        assert_eq!(vested_fraction_bps(0, 0), 0);
        assert_eq!(vested_fraction_bps(0, VESTING_CLIFF_MS - 1), 0);
        assert_eq!(vested_fraction_bps(0, 179 * DAY_MS), 0);
    }

    #[test]
    fn tranches_unlock_25_percent_every_three_months() {
        assert_eq!(vested_fraction_bps(0, VESTING_CLIFF_MS), 2_500);
        assert_eq!(
            vested_fraction_bps(0, VESTING_CLIFF_MS + VESTING_TRANCHE_MS - 1),
            2_500
        );
        assert_eq!(
            vested_fraction_bps(0, VESTING_CLIFF_MS + VESTING_TRANCHE_MS),
            5_000
        );
        assert_eq!(
            vested_fraction_bps(0, VESTING_CLIFF_MS + 2 * VESTING_TRANCHE_MS),
            7_500
        );
        assert_eq!(
            vested_fraction_bps(0, VESTING_CLIFF_MS + 3 * VESTING_TRANCHE_MS),
            10_000
        );
        // Never exceeds 100%, even years later.
        assert_eq!(vested_fraction_bps(0, 10 * 365 * DAY_MS), 10_000);
    }

    #[test]
    fn clock_skew_before_the_anchor_stays_fully_locked() {
        assert_eq!(vested_fraction_bps(1_000_000, 500_000), 0);
    }

    #[test]
    fn unvested_amount_follows_the_schedule() {
        let total = 1_000_000_u64;
        // During the cliff: everything locked.
        assert_eq!(unvested_activated_ants(total, Some(0), 100), total);
        // First tranche: 75% locked.
        assert_eq!(
            unvested_activated_ants(total, Some(0), VESTING_CLIFF_MS),
            750_000
        );
        // Fully vested after the final tranche.
        assert_eq!(
            unvested_activated_ants(
                total,
                Some(0),
                VESTING_CLIFF_MS + 3 * VESTING_TRANCHE_MS
            ),
            0
        );
    }

    #[test]
    fn wallets_without_an_anchor_stay_locked_but_bridge_only_wallets_do_not() {
        // Mined coins with no sealed anchor: fully locked until one seals.
        assert_eq!(unvested_activated_ants(500, None, i64::MAX), 500);
        // No mined coins at all (bridge-only wallet): never locked.
        assert_eq!(unvested_activated_ants(0, None, 0), 0);
    }
}

