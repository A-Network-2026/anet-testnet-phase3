use std::{env, sync::Arc};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use native_tls::{Certificate, TlsConnector};
use postgres_native_tls::MakeTlsConnector;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::OnceCell;
use tokio_postgres::{Client, NoTls};

use crate::{
    activation::MIN_SESSIONS_FOR_ANET,
    block::Block,
};

#[derive(Debug, Clone)]
pub struct MiningAccountRow {
    pub wallet_address: String,
    pub sessions: u64,
    pub ants_balance: u64,
}

#[derive(Debug, Clone)]
pub struct Web2AccountRow {
    pub address: String,
    pub sessions: u64,
    pub ants_balance: u64,
    pub is_eligible: bool,
    /// Direct referrals: how many other accounts list this wallet's user id as
    /// their `referred_by`. 0 when the schema has no `referred_by` column.
    pub referrals: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardCountryRow {
    pub country: String,
    pub workers: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColonyGroupUsageRow {
    pub room_name: String,
    pub room_count: u64,
    pub active_chat_ants: u64,
    pub message_count: u64,
    pub top_owner_label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ColonyRoomProfileRow {
    pub room_key: String,
    pub room_name: String,
    pub owner_user_id: u64,
    pub owner_label: String,
    pub ants_count: u64,
    pub total_messages: u64,
    pub messages_24h: u64,
    pub messages_7d: u64,
    pub messages_30d: u64,
    pub last_activity_at: Option<String>,
    pub room_created_at: Option<String>,
    pub room_updated_at: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardMetrics {
    pub total_accumulated_ants: u64,
    pub total_anet_claimed_ants: u64,
    pub total_registered_accounts: u64,
    pub total_real_miners: u64,
    pub total_workers: u64,
    pub users_online: u64,
    pub total_active_miners: u64,
    pub total_eligible_users: u64,
    pub total_converted_users: u64,
    pub total_sessions: u64,
    pub is_mining_active: bool,
    pub halving_stage: u64,
    pub max_halving_stage: u64,
    pub halving_interval: u64,
    pub remaining_sessions_to_halving: u64,
    pub next_halving_progress: f64,
    pub current_reward_per_session_ants: u64,
    pub next_reward_per_session_ants: u64,
    pub country_count: u64,
    pub top_countries: Vec<DashboardCountryRow>,
    pub total_colony_rooms: u64,
    pub total_group_participants: u64,
    pub total_group_messages: u64,
    pub group_usage: Vec<ColonyGroupUsageRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkStatsSnapshot {
    pub total_accumulated_ants: u64,
    pub total_anet_claimed_ants: u64,
    pub is_mining_active: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExplorerCommunitySnapshot {
    pub country_count: u64,
    pub top_countries: Vec<DashboardCountryRow>,
    pub total_colony_rooms: u64,
    pub total_group_participants: u64,
    pub total_group_messages: u64,
    pub group_usage: Vec<ColonyGroupUsageRow>,
}

static SHARED_DB_CLIENT: OnceCell<Arc<Client>> = OnceCell::const_new();
static LEDGER_CAPABILITIES_CACHE: OnceCell<LedgerCapabilities> = OnceCell::const_new();
static EXPLORER_SCHEMA_CACHE: OnceCell<ExplorerSchemaCapabilities> = OnceCell::const_new();

#[derive(Debug, Clone, Copy)]
struct LedgerCapabilities {
    has_ant_balance: bool,
    has_ants_balance: bool,
    has_is_banned: bool,
    has_is_deleted: bool,
    has_is_flagged: bool,
    has_migration_wallet_address: bool,
    has_ms_is_flagged: bool,
    has_successful_sessions: bool,
    has_total_sessions: bool,
    has_referred_by: bool,
}

#[derive(Debug, Clone, Copy)]
struct ExplorerSchemaCapabilities {
    has_referral_chat_rooms: bool,
    has_referral_group_messages: bool,
}

const LAST_HASH_META_KEY: &str = "LAST_HASH";

pub async fn connect() -> Result<Arc<Client>> {
    let client = SHARED_DB_CLIENT
        .get_or_try_init(|| async { connect_fresh().await.map(Arc::new) })
        .await?;

    Ok(Arc::clone(client))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PgSslMode {
    Disable,
    Require,
    VerifyCa,
    VerifyFull,
}

/// Resolve the PostgreSQL `sslmode` from `PGSSLMODE`, following libpq
/// semantics. Unknown or empty values default to `require` (encrypt without
/// certificate verification), matching libpq's behavior when TLS is available.
fn pg_ssl_mode() -> PgSslMode {
    match env::var("PGSSLMODE")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "disable" => PgSslMode::Disable,
        "verify-ca" => PgSslMode::VerifyCa,
        "verify-full" => PgSslMode::VerifyFull,
        // "require" | "prefer" | "allow" | "" | unknown
        _ => PgSslMode::Require,
    }
}

/// Load a pinned CA certificate (PEM) for verifying a private PostgreSQL TLS
/// endpoint such as Render's managed Postgres. `PGSSLROOTCERT_PEM` carries the
/// PEM inline (newlines may be escaped as `\n`); `PGSSLROOTCERT` is a path to a
/// PEM file. Returns `None` when neither is configured.
fn load_pg_root_cert_pem() -> Result<Option<String>> {
    if let Ok(pem) = env::var("PGSSLROOTCERT_PEM") {
        let trimmed = pem.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.replace("\\n", "\n")));
        }
    }

    if let Ok(path) = env::var("PGSSLROOTCERT") {
        let path = path.trim();
        if !path.is_empty() {
            let pem = std::fs::read_to_string(path).with_context(|| {
                format!("failed to read PostgreSQL root certificate file at {path}")
            })?;
            return Ok(Some(pem));
        }
    }

    Ok(None)
}

async fn connect_fresh() -> Result<Client> {
    let connection_string = database_connection_string()?;
    let ssl_mode = pg_ssl_mode();

    if ssl_mode == PgSslMode::Disable {
        let (client, connection) = tokio_postgres::connect(&connection_string, NoTls)
            .await
            .context("failed to connect to PostgreSQL without TLS")?;

        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!(?error, "postgres connection task exited");
            }
        });

        return Ok(client);
    }

    // `PGSSL_ACCEPT_INVALID_CERTS` is a development-only escape hatch. The
    // production guard in `main.rs` refuses to boot when it is set, so it can
    // never silently disable verification in production.
    let accept_invalid_certs = env::var("PGSSL_ACCEPT_INVALID_CERTS")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if accept_invalid_certs {
        tracing::warn!(
            "PGSSL_ACCEPT_INVALID_CERTS is enabled; PostgreSQL TLS certificates will not be verified"
        );
    }

    let mut tls_builder = TlsConnector::builder();

    // Pin a private CA (e.g. Render's managed-Postgres CA) so `verify-full`
    // and `verify-ca` can succeed against a certificate that is not in the
    // container's system trust store. `PGSSLROOTCERT_PEM` carries the PEM
    // inline (handy for secret env vars); `PGSSLROOTCERT` is a file path.
    if let Some(ca_pem) = load_pg_root_cert_pem()? {
        let cert = Certificate::from_pem(ca_pem.as_bytes())
            .context("failed to parse PostgreSQL root certificate (PGSSLROOTCERT/_PEM)")?;
        tls_builder.add_root_certificate(cert);
    }

    match ssl_mode {
        // `disable` is handled above.
        PgSslMode::Disable => unreachable!(),
        // libpq semantics: `require`/`prefer`/`allow` encrypt but do not
        // verify the server certificate or hostname.
        PgSslMode::Require => {
            tls_builder.danger_accept_invalid_certs(true);
        }
        // `verify-ca` validates the certificate chain but not the hostname.
        PgSslMode::VerifyCa => {
            tls_builder.danger_accept_invalid_certs(accept_invalid_certs);
            tls_builder.danger_accept_invalid_hostnames(true);
        }
        // `verify-full` validates both the chain and the hostname.
        PgSslMode::VerifyFull => {
            tls_builder.danger_accept_invalid_certs(accept_invalid_certs);
        }
    }

    let tls = tls_builder
        .build()
        .context("failed to create TLS connector")?;
    let tls = MakeTlsConnector::new(tls);
    let (client, connection) = tokio_postgres::connect(&connection_string, tls)
        .await
        .context("failed to connect to PostgreSQL with TLS")?;

    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::error!(?error, "postgres connection task exited");
        }
    });

    Ok(client)
}

pub async fn load_genesis_accounts(client: &Client) -> Result<Vec<MiningAccountRow>> {
    let capabilities = ledger_capabilities(client).await?;
    let query = build_ledger_query(
        &capabilities,
        &format!(
            r#"
        SELECT
            wallet_address,
                        effective_sessions AS sessions,
                        GREATEST(stored_ants_balance, effective_sessions * 4882812::bigint) AS ants_balance
        FROM ledger
        WHERE wallet_address IS NOT NULL
          AND is_deleted = false
                    AND effective_sessions >= {min_sessions}::bigint
        ORDER BY wallet_address ASC
                "#,
            min_sessions = MIN_SESSIONS_FOR_ANET,
        ),
    );

    let rows = client
        .query(&query, &[])
        .await
        .context("failed to load Ant Ledger accounts for Genesis Activation")?;

    Ok(rows
        .into_iter()
        .map(|row| MiningAccountRow {
            wallet_address: row.get::<_, String>(0),
            sessions: row.get::<_, i64>(1).max(0) as u64,
            ants_balance: row.get::<_, i64>(2).max(0) as u64,
        })
        .collect())
}

pub async fn load_eligible_validators(client: &Client) -> Result<Vec<String>> {
    let capabilities = ledger_capabilities(client).await?;
    let query = build_ledger_query(
        &capabilities,
        &format!(
            r#"
        SELECT wallet_address
        FROM ledger
        WHERE wallet_address IS NOT NULL
          AND is_deleted = false
          AND is_banned = false
          AND is_flagged = false
                    AND effective_sessions >= {min_sessions}::bigint
        ORDER BY wallet_address ASC
                "#,
            min_sessions = MIN_SESSIONS_FOR_ANET,
        ),
    );

    let rows = client
        .query(&query, &[])
        .await
        .context("failed to load eligible validators")?;

    Ok(rows
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect())
}

/// Load **every** miner's wallet and cumulative completed-session count for the
/// on-chain session-progress commitment — including miners below the
/// 1,000-session spend threshold. Returns only the two columns the Merkle
/// commitment needs (wallet + sessions), not balances, so the read stays light
/// even across the full user base. Wallets with zero completed sessions are
/// excluded (nothing to commit yet).
pub async fn load_all_session_progress(client: &Client) -> Result<Vec<(String, u64)>> {
    let capabilities = ledger_capabilities(client).await?;
    let query = build_ledger_query(
        &capabilities,
        r#"
        SELECT
            wallet_address,
            effective_sessions AS sessions
        FROM ledger
        WHERE wallet_address IS NOT NULL
          AND is_deleted = false
          AND effective_sessions >= 1::bigint
        ORDER BY wallet_address ASC
        "#,
    );

    let rows = client
        .query(&query, &[])
        .await
        .context("failed to load session progress for on-chain commitment")?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let wallet = row.get::<_, String>(0);
            let sessions = row.get::<_, i64>(1).max(0) as u64;
            (wallet, sessions)
        })
        .collect())
}

pub async fn load_web2_account(client: &Client, address: &str) -> Result<Option<Web2AccountRow>> {
    let capabilities = ledger_capabilities(client).await?;
    // Count direct referrals (other users whose `referred_by` points at this
    // wallet's user id). Scoped to the single matched ledger row by the
    // `WHERE wallet_address = $1` filter, so the correlated subquery runs once
    // per lookup, not across the whole user base. Falls back to 0 on schemas
    // without a `referred_by` column.
    let referrals_expr = if capabilities.has_referred_by {
        "(SELECT COUNT(*) FROM users r WHERE r.referred_by = ledger.id)::bigint"
    } else {
        "0::bigint"
    };
    let query = build_ledger_query(
        &capabilities,
        &format!(
            r#"
        SELECT
            wallet_address,
            effective_sessions AS sessions,
            GREATEST(stored_ants_balance, effective_sessions * {ants_per_session}::bigint) AS ants_balance,
            (is_deleted = false AND is_banned = false AND is_flagged = false AND effective_sessions >= {min_sessions}::bigint) AS is_eligible,
            {referrals_expr} AS referrals
        FROM ledger
        WHERE wallet_address = $1
        "#,
            ants_per_session = crate::activation::ANTS_PER_SESSION,
            min_sessions = MIN_SESSIONS_FOR_ANET,
            referrals_expr = referrals_expr,
        ),
    );

    let row = client
        .query_opt(&query, &[&address])
        .await
        .with_context(|| format!("failed to load Ant Ledger account for {address}"))?;

    Ok(row.map(|row| {
        let sessions = row.get::<_, i64>(1).max(0) as u64;
        let ants_balance = row.get::<_, i64>(2).max(0) as u64;
        let referrals = row.get::<_, i64>(4).max(0) as u64;
        Web2AccountRow {
            address: row.get::<_, String>(0),
            sessions,
            ants_balance,
            is_eligible: row.get::<_, bool>(3),
            referrals,
        }
    }))
}

pub async fn load_dashboard_metrics(client: &Client) -> Result<DashboardMetrics> {
    let user_stats = client
        .query_one(
            r#"
            SELECT
                COUNT(*) FILTER (
                    WHERE COALESCE(email_verified, FALSE) = TRUE
                      AND COALESCE(successful_sessions, 0) > 0
                )::bigint AS total_workers,
                COUNT(*) FILTER (
                    WHERE COALESCE(email_verified, FALSE) = TRUE
                      AND COALESCE(successful_sessions, 0) > 0
                      AND COALESCE(last_seen_at, NOW() - INTERVAL '100 years') > NOW() - INTERVAL '5 minutes'
                )::bigint AS users_online,
                COUNT(*) FILTER (
                    WHERE COALESCE(email_verified, FALSE) = TRUE
                      AND COALESCE(is_mining, FALSE) = TRUE
                      AND COALESCE(session_end_time, NOW() - INTERVAL '1 second') > NOW()
                      AND COALESCE(last_mining_start, NOW() - INTERVAL '100 years') > NOW() - INTERVAL '8 hours'
                )::bigint AS total_active_miners,
                COUNT(*) FILTER (
                    WHERE COALESCE(email_verified, FALSE) = TRUE
                      AND COALESCE(successful_sessions, 0) >= 1000
                )::bigint AS total_eligible_users,
                COUNT(*) FILTER (
                    WHERE COALESCE(email_verified, FALSE) = TRUE
                      AND COALESCE(claimed_anet, 0) > 0
                )::bigint AS total_converted_users,
                COALESCE(
                    SUM(
                        CASE
                            WHEN COALESCE(email_verified, FALSE) = TRUE THEN GREATEST(COALESCE(successful_sessions, 0), COALESCE(total_sessions, 0))
                            ELSE 0
                        END
                    ),
                    0
                )::bigint AS total_sessions
            FROM users
            WHERE COALESCE(is_deleted, FALSE) = FALSE
            "#,
            &[],
        )
        .await
        .context("failed to load worker dashboard totals")?;

    let registered = client
        .query_one(
            "SELECT COUNT(*)::bigint AS total_registered FROM users",
            &[],
        )
        .await
        .context("failed to load registered worker account total")?;

    let real_miners = client
        .query_one(
            r#"
            SELECT COUNT(DISTINCT user_id)::bigint AS total_real_miners
            FROM mining_sessions
            WHERE is_completed = TRUE
              AND COALESCE(status, '') = 'completed'
            "#,
            &[],
        )
        .await
        .context("failed to load real miner total")?;

    let network_stats = client
        .query_opt(
            &format!(
                r#"
                SELECT
                    COALESCE(total_mined_ants, 0)::bigint AS total_mined_ants,
                    ROUND(COALESCE(total_anet_distributed, 0) * {ants_per_anet})::bigint AS total_anet_claimed_ants,
                    COALESCE(is_mining_active, FALSE) AS is_mining_active
                FROM network_stats
                LIMIT 1
                "#,
                ants_per_anet = crate::activation::ANTS_PER_ANET,
            ),
            &[],
        )
        .await
        .context("failed to load network stats")?;

    let community = load_explorer_community_snapshot(client)
        .await
        .context("failed to load explorer community snapshot")?;

    let total_sessions = user_stats.get::<_, i64>(5).max(0) as u64;

    // Bitcoin-style emission display, sourced from the single canonical schedule
    // in `activation` (mirrored byte-for-byte by the Web2 backend). Launch-tranche
    // aware: stage 0 spans the whole bootstrap era, then the reward halves every
    // `HALVING_INTERVAL_SESSIONS` cumulative sessions and tapers to 0.
    let halving_stage = crate::activation::halving_stage(total_sessions);
    let in_launch_phase = total_sessions < crate::activation::LAUNCH_TRANCHE_SESSIONS;
    let active_interval = if in_launch_phase {
        crate::activation::LAUNCH_TRANCHE_SESSIONS
    } else {
        crate::activation::HALVING_INTERVAL_SESSIONS
    };
    let at_final_stage =
        !in_launch_phase && halving_stage >= crate::activation::MAX_HALVING_STAGE;
    let progress_sessions = if in_launch_phase {
        total_sessions
    } else if at_final_stage {
        crate::activation::HALVING_INTERVAL_SESSIONS
    } else {
        crate::activation::post_launch_sessions(total_sessions)
            % crate::activation::HALVING_INTERVAL_SESSIONS
    };
    let remaining_sessions_to_halving = if at_final_stage {
        0
    } else {
        active_interval.saturating_sub(progress_sessions)
    };
    let next_halving_progress = if at_final_stage {
        100.0
    } else {
        ((progress_sessions as f64 / active_interval as f64) * 100.0 * 100.0).round() / 100.0
    };
    let current_reward_per_session_ants = crate::activation::session_reward_ants(total_sessions);
    let next_reward_per_session_ants = if in_launch_phase {
        crate::activation::POST_LAUNCH_BASE_REWARD_ANTS
    } else {
        let next_stage = (halving_stage + 1).min(crate::activation::MAX_HALVING_STAGE);
        crate::activation::POST_LAUNCH_BASE_REWARD_ANTS >> next_stage
    };

    let total_accumulated_ants = network_stats
        .as_ref()
        .map(|row| row.get::<_, i64>(0).max(0) as u64)
        .unwrap_or(0);
    let total_anet_claimed_ants = network_stats
        .as_ref()
        .map(|row| row.get::<_, i64>(1).max(0) as u64)
        .unwrap_or(0);
    let is_mining_active = network_stats
        .as_ref()
        .map(|row| row.get::<_, bool>(2))
        .unwrap_or(false);

    let total_real_miners = real_miners.get::<_, i64>(0).max(0) as u64;
    let active_miners_strict = user_stats.get::<_, i64>(2).max(0) as u64;
    let total_active_miners = if active_miners_strict == 0 && total_real_miners > 0 {
        total_real_miners
    } else {
        active_miners_strict
    };

    Ok(DashboardMetrics {
        total_accumulated_ants,
        total_anet_claimed_ants,
        total_registered_accounts: registered.get::<_, i64>(0).max(0) as u64,
        total_real_miners,
        total_workers: user_stats.get::<_, i64>(0).max(0) as u64,
        users_online: user_stats.get::<_, i64>(1).max(0) as u64,
        total_active_miners,
        total_eligible_users: user_stats.get::<_, i64>(3).max(0) as u64,
        total_converted_users: user_stats.get::<_, i64>(4).max(0) as u64,
        total_sessions,
        is_mining_active,
        halving_stage,
        max_halving_stage: crate::activation::MAX_HALVING_STAGE,
        halving_interval: active_interval,
        remaining_sessions_to_halving,
        next_halving_progress,
        current_reward_per_session_ants,
        next_reward_per_session_ants,
        country_count: community.country_count,
        top_countries: community.top_countries,
        total_colony_rooms: community.total_colony_rooms,
        total_group_participants: community.total_group_participants,
        total_group_messages: community.total_group_messages,
        group_usage: community.group_usage,
    })
}

pub async fn load_explorer_community_snapshot(
    client: &Client,
) -> Result<ExplorerCommunitySnapshot> {
    let country_rows = client
        .query(
            r#"
            SELECT
                COALESCE(NULLIF(TRIM(country), ''), 'Unknown') AS country,
                COUNT(*)::bigint AS workers
            FROM users
            WHERE COALESCE(is_deleted, FALSE) = FALSE
              AND COALESCE(email_verified, FALSE) = TRUE
              AND COALESCE(successful_sessions, 0) > 0
            GROUP BY 1
            ORDER BY workers DESC, country ASC
                        LIMIT 64
            "#,
            &[],
        )
        .await
        .context("failed to load country distribution")?;

    let mut top_countries = country_rows
        .iter()
        .map(|row| DashboardCountryRow {
            country: row.get::<_, String>(0),
            workers: row.get::<_, i64>(1).max(0) as u64,
        })
        .collect::<Vec<_>>();
    top_countries.shrink_to_fit();

    let explorer_schema = explorer_schema_capabilities(client).await?;
    let (total_colony_rooms, total_group_participants, total_group_messages, group_usage) =
        if explorer_schema.has_referral_chat_rooms && explorer_schema.has_referral_group_messages {
            let overview = client
                .query_one(
                    r#"
                    SELECT
                        COUNT(DISTINCT r.room_key)::bigint AS total_colony_rooms,
                        COUNT(DISTINCT m.user_id)::bigint AS total_group_participants,
                        COUNT(m.id)::bigint AS total_group_messages
                    FROM referral_chat_rooms r
                    LEFT JOIN referral_group_messages m
                        ON m.room_key = r.room_key
                    "#,
                    &[],
                )
                .await
                .context("failed to load colony group overview")?;

            let usage = client
                .query(
                    r#"
                    SELECT
                        COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants') AS room_name,
                        COUNT(DISTINCT r.room_key)::bigint AS room_count,
                        COUNT(DISTINCT m.user_id)::bigint AS active_chat_ants,
                        COUNT(m.id)::bigint AS message_count,
                        'Open colony details'::text AS top_owner_label
                    FROM referral_chat_rooms r
                    LEFT JOIN referral_group_messages m
                        ON m.room_key = r.room_key
                    GROUP BY 1
                    ORDER BY room_count DESC, active_chat_ants DESC, room_name ASC
                    LIMIT 64
                    "#,
                    &[],
                )
                .await
                .context("failed to load colony group usage")?;

            (
                overview.get::<_, i64>(0).max(0) as u64,
                overview.get::<_, i64>(1).max(0) as u64,
                overview.get::<_, i64>(2).max(0) as u64,
                usage
                    .into_iter()
                    .map(|row| ColonyGroupUsageRow {
                        room_name: row.get::<_, String>(0),
                        room_count: row.get::<_, i64>(1).max(0) as u64,
                        active_chat_ants: row.get::<_, i64>(2).max(0) as u64,
                        message_count: row.get::<_, i64>(3).max(0) as u64,
                        top_owner_label: row.get::<_, String>(4),
                    })
                    .collect::<Vec<_>>(),
            )
        } else {
            (0, 0, 0, Vec::new())
        };

    Ok(ExplorerCommunitySnapshot {
        country_count: country_rows.len() as u64,
        top_countries,
        total_colony_rooms,
        total_group_participants,
        total_group_messages,
        group_usage,
    })
}

pub async fn load_colony_room_profiles(
    client: &Client,
    colony_label: &str,
) -> Result<Vec<ColonyRoomProfileRow>> {
    let rows = client
        .query(
            r#"
            SELECT
                r.room_key,
                COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants') AS room_name,
                r.owner_user_id,
                COALESCE(NULLIF(TRIM(u.referral_code), ''), SPLIT_PART(u.email, '@', 1), 'User ' || r.owner_user_id::text) AS owner_label,
                COUNT(DISTINCT m.user_id)::bigint AS ants_count,
                COUNT(m.id)::bigint AS total_messages,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '1 day')::bigint AS messages_24h,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '7 days')::bigint AS messages_7d,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '30 days')::bigint AS messages_30d,
                MAX(m.created_at)::text AS last_activity_at,
                r.created_at::text AS room_created_at,
                r.updated_at::text AS room_updated_at
            FROM referral_chat_rooms r
            LEFT JOIN referral_group_messages m
                ON m.room_key = r.room_key
            LEFT JOIN users u
                ON u.id = r.owner_user_id
            WHERE COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants') = $1
            GROUP BY r.room_key, room_name, r.owner_user_id, owner_label, r.created_at, r.updated_at
            ORDER BY ants_count DESC, total_messages DESC, r.owner_user_id ASC
            "#,
            &[&colony_label],
        )
        .await
        .with_context(|| format!("failed to load room profiles for colony {colony_label}"))?;

    Ok(rows.into_iter().map(map_colony_room_profile_row).collect())
}

pub async fn load_territory_colony_usage(
    client: &Client,
    territory: &str,
) -> Result<Vec<ColonyGroupUsageRow>> {
    let rows = client
        .query(
            r#"
            WITH owner_room_stats AS (
                SELECT
                    COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants') AS room_name,
                    r.owner_user_id,
                    COALESCE(NULLIF(TRIM(u.referral_code), ''), SPLIT_PART(u.email, '@', 1), 'User ' || r.owner_user_id::text) AS owner_label,
                    COUNT(DISTINCT m.user_id)::bigint AS active_chat_ants,
                    COUNT(m.id)::bigint AS message_count
                FROM referral_chat_rooms r
                LEFT JOIN referral_group_messages m
                    ON m.room_key = r.room_key
                LEFT JOIN users u
                    ON u.id = r.owner_user_id
                WHERE COALESCE(NULLIF(TRIM(u.country), ''), 'Unknown') = $1
                GROUP BY 1, 2, 3
            ),
            top_owners AS (
                SELECT
                    room_name,
                    owner_label,
                    ROW_NUMBER() OVER (
                        PARTITION BY room_name
                        ORDER BY active_chat_ants DESC, message_count DESC, owner_user_id ASC
                    ) AS owner_rank
                FROM owner_room_stats
            )
            SELECT
                COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants') AS room_name,
                COUNT(DISTINCT r.room_key)::bigint AS room_count,
                COUNT(DISTINCT m.user_id)::bigint AS active_chat_ants,
                COUNT(m.id)::bigint AS message_count,
                COALESCE(MAX(t.owner_label) FILTER (WHERE t.owner_rank = 1), 'No owner yet') AS top_owner_label
            FROM referral_chat_rooms r
            LEFT JOIN referral_group_messages m
                ON m.room_key = r.room_key
            LEFT JOIN users u
                ON u.id = r.owner_user_id
            LEFT JOIN top_owners t
                ON t.room_name = COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants')
            WHERE COALESCE(NULLIF(TRIM(u.country), ''), 'Unknown') = $1
            GROUP BY 1
            ORDER BY room_count DESC, active_chat_ants DESC, room_name ASC
            "#,
            &[&territory],
        )
        .await
        .with_context(|| format!("failed to load colony usage for territory {territory}"))?;

    Ok(rows
        .into_iter()
        .map(|row| ColonyGroupUsageRow {
            room_name: row.get::<_, String>(0),
            room_count: row.get::<_, i64>(1).max(0) as u64,
            active_chat_ants: row.get::<_, i64>(2).max(0) as u64,
            message_count: row.get::<_, i64>(3).max(0) as u64,
            top_owner_label: row.get::<_, String>(4),
        })
        .collect())
}

pub async fn load_territory_room_profiles(
    client: &Client,
    territory: &str,
) -> Result<Vec<ColonyRoomProfileRow>> {
    let rows = client
        .query(
            r#"
            SELECT
                r.room_key,
                COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants') AS room_name,
                r.owner_user_id,
                COALESCE(NULLIF(TRIM(u.referral_code), ''), SPLIT_PART(u.email, '@', 1), 'User ' || r.owner_user_id::text) AS owner_label,
                COUNT(DISTINCT m.user_id)::bigint AS ants_count,
                COUNT(m.id)::bigint AS total_messages,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '1 day')::bigint AS messages_24h,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '7 days')::bigint AS messages_7d,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '30 days')::bigint AS messages_30d,
                MAX(m.created_at)::text AS last_activity_at,
                r.created_at::text AS room_created_at,
                r.updated_at::text AS room_updated_at
            FROM referral_chat_rooms r
            LEFT JOIN referral_group_messages m
                ON m.room_key = r.room_key
            LEFT JOIN users u
                ON u.id = r.owner_user_id
            WHERE COALESCE(NULLIF(TRIM(u.country), ''), 'Unknown') = $1
            GROUP BY r.room_key, room_name, r.owner_user_id, owner_label, r.created_at, r.updated_at
            ORDER BY ants_count DESC, total_messages DESC, r.owner_user_id ASC
            "#,
            &[&territory],
        )
        .await
        .with_context(|| format!("failed to load room profiles for territory {territory}"))?;

    Ok(rows.into_iter().map(map_colony_room_profile_row).collect())
}

pub async fn load_colony_room_profile(
    client: &Client,
    room_key: &str,
) -> Result<Option<ColonyRoomProfileRow>> {
    let row = client
        .query_opt(
            r#"
            SELECT
                r.room_key,
                COALESCE(NULLIF(TRIM(r.room_name), ''), 'Worker Ants') AS room_name,
                r.owner_user_id,
                COALESCE(NULLIF(TRIM(u.referral_code), ''), SPLIT_PART(u.email, '@', 1), 'User ' || r.owner_user_id::text) AS owner_label,
                COUNT(DISTINCT m.user_id)::bigint AS ants_count,
                COUNT(m.id)::bigint AS total_messages,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '1 day')::bigint AS messages_24h,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '7 days')::bigint AS messages_7d,
                COUNT(m.id) FILTER (WHERE m.created_at >= NOW() - INTERVAL '30 days')::bigint AS messages_30d,
                MAX(m.created_at)::text AS last_activity_at,
                r.created_at::text AS room_created_at,
                r.updated_at::text AS room_updated_at
            FROM referral_chat_rooms r
            LEFT JOIN referral_group_messages m
                ON m.room_key = r.room_key
            LEFT JOIN users u
                ON u.id = r.owner_user_id
            WHERE r.room_key = $1
            GROUP BY r.room_key, room_name, r.owner_user_id, owner_label, r.created_at, r.updated_at
            LIMIT 1
            "#,
            &[&room_key],
        )
        .await
        .with_context(|| format!("failed to load room profile {room_key}"))?;

    Ok(row.map(map_colony_room_profile_row))
}

fn map_colony_room_profile_row(row: tokio_postgres::Row) -> ColonyRoomProfileRow {
    let messages_24h = row.get::<_, i64>(6).max(0) as u64;
    let messages_7d = row.get::<_, i64>(7).max(0) as u64;
    let messages_30d = row.get::<_, i64>(8).max(0) as u64;
    let status = if messages_24h > 0 {
        "Active"
    } else if messages_7d > 0 {
        "Warm"
    } else if messages_30d > 0 {
        "Quiet"
    } else {
        "Dormant"
    };

    ColonyRoomProfileRow {
        room_key: row.get::<_, String>(0),
        room_name: row.get::<_, String>(1),
        owner_user_id: row.get::<_, i64>(2).max(0) as u64,
        owner_label: row.get::<_, String>(3),
        ants_count: row.get::<_, i64>(4).max(0) as u64,
        total_messages: row.get::<_, i64>(5).max(0) as u64,
        messages_24h,
        messages_7d,
        messages_30d,
        last_activity_at: row.get::<_, Option<String>>(9),
        room_created_at: row.get::<_, Option<String>>(10),
        room_updated_at: row.get::<_, Option<String>>(11),
        status: status.to_owned(),
    }
}

async fn ledger_capabilities(client: &Client) -> Result<LedgerCapabilities> {
    let capabilities = LEDGER_CAPABILITIES_CACHE
        .get_or_try_init(|| async {
            Ok::<LedgerCapabilities, anyhow::Error>(LedgerCapabilities {
                has_ant_balance: table_has_column(client, "users", "ant_balance").await?,
                has_ants_balance: table_has_column(client, "users", "ants_balance").await?,
                has_is_banned: table_has_column(client, "users", "is_banned").await?,
                has_is_deleted: table_has_column(client, "users", "is_deleted").await?,
                has_is_flagged: table_has_column(client, "users", "is_flagged").await?,
                has_migration_wallet_address: table_has_column(
                    client,
                    "users",
                    "migration_wallet_address",
                )
                .await?,
                has_ms_is_flagged: table_has_column(client, "mining_sessions", "is_flagged")
                    .await?,
                has_successful_sessions: table_has_column(client, "users", "successful_sessions")
                    .await?,
                has_total_sessions: table_has_column(client, "users", "total_sessions").await?,
                has_referred_by: table_has_column(client, "users", "referred_by").await?,
            })
        })
        .await?;

    Ok(*capabilities)
}

async fn explorer_schema_capabilities(client: &Client) -> Result<ExplorerSchemaCapabilities> {
    let capabilities = EXPLORER_SCHEMA_CACHE
        .get_or_try_init(|| async {
            Ok::<ExplorerSchemaCapabilities, anyhow::Error>(ExplorerSchemaCapabilities {
                has_referral_chat_rooms: table_exists(client, "referral_chat_rooms").await?,
                has_referral_group_messages: table_exists(client, "referral_group_messages")
                    .await?,
            })
        })
        .await?;

    Ok(*capabilities)
}

async fn table_has_column(client: &Client, table_name: &str, column_name: &str) -> Result<bool> {
    const QUERY: &str = r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = $1
              AND column_name = $2
        )
    "#;

    let row = client
        .query_one(QUERY, &[&table_name, &column_name])
        .await
        .with_context(|| format!("failed to inspect {table_name}.{column_name} schema"))?;
    Ok(row.get::<_, bool>(0))
}

async fn table_exists(client: &Client, table_name: &str) -> Result<bool> {
    const QUERY: &str = r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name = $1
        )
    "#;

    let row = client
        .query_one(QUERY, &[&table_name])
        .await
        .with_context(|| format!("failed to inspect table {table_name}"))?;
    Ok(row.get::<_, bool>(0))
}

fn build_ledger_query(capabilities: &LedgerCapabilities, selection_sql: &str) -> String {
    let wallet_address_expr = if capabilities.has_migration_wallet_address {
        "COALESCE(NULLIF(BTRIM(u.wallet_address), ''), NULLIF(BTRIM(u.migration_wallet_address), ''))"
    } else {
        "NULLIF(BTRIM(u.wallet_address), '')"
    };
    let total_sessions_expr = if capabilities.has_total_sessions {
        "COALESCE(u.total_sessions, 0)::bigint"
    } else {
        "0::bigint"
    };
    let successful_sessions_expr = if capabilities.has_successful_sessions {
        "COALESCE(u.successful_sessions, 0)::bigint"
    } else {
        "0::bigint"
    };
    let stored_ants_balance_expr =
        match (capabilities.has_ants_balance, capabilities.has_ant_balance) {
            (true, true) => {
                "GREATEST(COALESCE(u.ants_balance, 0)::bigint, COALESCE(u.ant_balance, 0)::bigint)"
            }
            (true, false) => "COALESCE(u.ants_balance, 0)::bigint",
            (false, true) => "COALESCE(u.ant_balance, 0)::bigint",
            (false, false) => "0::bigint",
        };
    let is_banned_expr = if capabilities.has_is_banned {
        "COALESCE(u.is_banned, false)"
    } else {
        "false"
    };
    let is_deleted_expr = if capabilities.has_is_deleted {
        "COALESCE(u.is_deleted, false)"
    } else {
        "false"
    };
    let is_flagged_expr = if capabilities.has_is_flagged {
        "COALESCE(u.is_flagged, false)"
    } else {
        "false"
    };
    let completed_sessions_filter = if capabilities.has_ms_is_flagged {
        "WHERE ms.is_completed = true AND COALESCE(ms.is_flagged, false) = false"
    } else {
        "WHERE ms.is_completed = true"
    };

    format!(
        r#"
        WITH session_counts AS (
            SELECT
                ms.user_id,
                COUNT(ms.id) FILTER ({completed_sessions_filter})::bigint AS completed_sessions
            FROM mining_sessions ms
            GROUP BY ms.user_id
        ),
        ledger AS (
            SELECT
                u.id,
                {wallet_address_expr} AS wallet_address,
                {total_sessions_expr} AS total_sessions,
                {successful_sessions_expr} AS successful_sessions,
                COALESCE(sc.completed_sessions, 0)::bigint AS completed_sessions,
                {stored_ants_balance_expr} AS stored_ants_balance,
                {is_banned_expr} AS is_banned,
                {is_deleted_expr} AS is_deleted,
                {is_flagged_expr} AS is_flagged,
                GREATEST(
                    {total_sessions_expr},
                    {successful_sessions_expr},
                    COALESCE(sc.completed_sessions, 0)::bigint
                ) AS effective_sessions
            FROM users u
            LEFT JOIN session_counts sc
                ON u.id = sc.user_id
        )
        {selection_sql}
        "#,
        wallet_address_expr = wallet_address_expr,
        total_sessions_expr = total_sessions_expr,
        successful_sessions_expr = successful_sessions_expr,
        completed_sessions_filter = completed_sessions_filter,
        stored_ants_balance_expr = stored_ants_balance_expr,
        is_banned_expr = is_banned_expr,
        is_deleted_expr = is_deleted_expr,
        is_flagged_expr = is_flagged_expr,
        selection_sql = selection_sql,
    )
}

fn database_connection_string() -> Result<String> {
    if let Ok(url) = env::var("DATABASE_URL") {
        return Ok(url);
    }

    let host = env::var("DB_HOST").context("DB_HOST is required when DATABASE_URL is not set")?;
    let user = env::var("DB_USER").context("DB_USER is required when DATABASE_URL is not set")?;
    let password =
        env::var("DB_PASS").context("DB_PASS is required when DATABASE_URL is not set")?;
    let dbname = env::var("DB_NAME").context("DB_NAME is required when DATABASE_URL is not set")?;
    let port = env::var("DB_PORT").unwrap_or_else(|_| "5432".to_owned());

    if host.trim().is_empty() || user.trim().is_empty() || dbname.trim().is_empty() {
        return Err(anyhow!("database connection settings are incomplete"));
    }

    Ok(format!(
        "host={host} user={user} password={password} dbname={dbname} port={port}"
    ))
}

pub async fn load_network_stats_snapshot(client: &Client) -> Result<NetworkStatsSnapshot> {
    let network_stats = client
        .query_opt(
            &format!(
                r#"
                SELECT
                    COALESCE(total_mined_ants, 0)::bigint AS total_mined_ants,
                    ROUND(COALESCE(total_anet_distributed, 0) * {ants_per_anet})::bigint AS total_anet_claimed_ants,
                    COALESCE(is_mining_active, FALSE) AS is_mining_active
                FROM network_stats
                LIMIT 1
                "#,
                ants_per_anet = crate::activation::ANTS_PER_ANET,
            ),
            &[],
        )
        .await
        .context("failed to load lightweight network stats snapshot")?;

    Ok(NetworkStatsSnapshot {
        total_accumulated_ants: network_stats
            .as_ref()
            .map(|row| row.get::<_, i64>(0).max(0) as u64)
            .unwrap_or(0),
        total_anet_claimed_ants: network_stats
            .as_ref()
            .map(|row| row.get::<_, i64>(1).max(0) as u64)
            .unwrap_or(0),
        is_mining_active: network_stats
            .as_ref()
            .map(|row| row.get::<_, bool>(2))
            .unwrap_or(false),
    })
}

pub async fn ensure_blockchain_tables(client: &Client) -> Result<()> {
    client
        .batch_execute(
            r#"
            CREATE TABLE IF NOT EXISTS blocks (
                hash TEXT PRIMARY KEY,
                previous_hash TEXT,
                height BIGINT,
                data JSONB,
                timestamp BIGINT
            );

            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS validator_heartbeat_nonces (
                chain_id TEXT NOT NULL,
                wallet TEXT NOT NULL,
                last_nonce BIGINT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (chain_id, wallet)
            );

            CREATE TABLE IF NOT EXISTS mining_proof_nonces (
                chain_id TEXT NOT NULL,
                wallet TEXT NOT NULL,
                last_nonce BIGINT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (chain_id, wallet)
            );

            CREATE TABLE IF NOT EXISTS action_authorization_nonces (
                chain_id TEXT NOT NULL,
                wallet TEXT NOT NULL,
                action_type TEXT NOT NULL,
                last_nonce BIGINT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (chain_id, wallet, action_type)
            );

            -- L1 → BSC bridge: irreversible burns of ANET on the L1
            -- chain that the relayer mirrors with a release of wANET
            -- (or USDC/USDT) on BSC. Each row represents one outbound
            -- bridge intent. The L1 supply has already been decreased
            -- by the time this row exists (debit happens atomically
            -- with the insert in `state::bridge_burn_anet`).
            CREATE TABLE IF NOT EXISTS bridge_burns (
                burn_id        BIGSERIAL PRIMARY KEY,
                l1_sender      TEXT        NOT NULL,
                bsc_recipient  TEXT        NOT NULL,
                ants           BIGINT      NOT NULL CHECK (ants > 0),
                token_symbol   TEXT        NOT NULL,
                status         TEXT        NOT NULL DEFAULT 'pending',
                bsc_tx_hash    TEXT,
                error          TEXT,
                created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                released_at    TIMESTAMPTZ
            );

            CREATE INDEX IF NOT EXISTS bridge_burns_status_idx
                ON bridge_burns (status, burn_id);
            CREATE INDEX IF NOT EXISTS bridge_burns_sender_idx
                ON bridge_burns (l1_sender, burn_id);

            -- Canonical EIP-712 deadline for the wANET release, computed at
            -- burn-insert time as created_at_unix + BRIDGE_DEADLINE_SECS.
            -- All signers must sign with this exact deadline so their
            -- sigs hash identically and combine on-chain.
            ALTER TABLE bridge_burns
                ADD COLUMN IF NOT EXISTS release_deadline BIGINT;

            -- Decentralized signature collection for AnetBridgeVault
            -- releases. Each row is one signer's EIP-712 signature over
            -- the canonical Release struct for a given burn.
            -- The relayer (or anyone) reads M sigs and submits releaseBurn
            -- on BSC. L1 has no signing power and never sees a private key.
            CREATE TABLE IF NOT EXISTS bridge_burn_signatures (
                burn_id     BIGINT      NOT NULL REFERENCES bridge_burns(burn_id),
                signer      TEXT        NOT NULL,
                signature   TEXT        NOT NULL,
                created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (burn_id, signer)
            );

            CREATE INDEX IF NOT EXISTS bridge_burn_signatures_burn_idx
                ON bridge_burn_signatures (burn_id);

            -- Permissionless legacy → secp wallet migration. Implements a
            -- commit-reveal scheme that lets a user sweep an old legacy-
            -- derivation wallet (RIPEMD160(SHA256(seed)_hex)) into a new
            -- signing-capable secp-derivation wallet, atomically and
            -- on-chain, without any admin involvement. Each legacy_address
            -- can only be migrated once (PRIMARY KEY).
            CREATE TABLE IF NOT EXISTS wallet_migrations (
                legacy_address   TEXT        NOT NULL PRIMARY KEY,
                secp_address     TEXT        NOT NULL,
                commit_hash      TEXT        NOT NULL,
                status           TEXT        NOT NULL DEFAULT 'committed',
                ants_migrated    BIGINT,
                sessions_migrated BIGINT,
                committed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                revealed_at      TIMESTAMPTZ
            );
            CREATE INDEX IF NOT EXISTS wallet_migrations_secp_idx
                ON wallet_migrations (secp_address);

            -- ── Multi-chain mint/burn portal (L1 hub ⇆ EVM spokes) ──────────
            -- DISTINCT from bridge_burns (legacy BSC-vault flow) so cross-chain
            -- supply reconciliation stays unambiguous.
            --
            -- portal_locks: L1 → spoke. Native ANET is BURNED on L1 (debit is
            -- atomic with the insert, same as bridge_burns) and the relayer
            -- mints the SAME value of wANET on the destination spoke. Backing
            -- for spoke wANET = Σ(portal_locks) − Σ(portal_credits).
            CREATE TABLE IF NOT EXISTS portal_locks (
                lock_id       BIGSERIAL   PRIMARY KEY,
                l1_sender     TEXT        NOT NULL,
                dst_chain_id  BIGINT      NOT NULL,
                dst_recipient TEXT        NOT NULL,
                ants          BIGINT      NOT NULL CHECK (ants > 0),
                status        TEXT        NOT NULL DEFAULT 'pending',
                message_id    TEXT,
                spoke_tx_hash TEXT,
                deadline      BIGINT      NOT NULL,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                minted_at     TIMESTAMPTZ
            );
            CREATE INDEX IF NOT EXISTS portal_locks_status_idx
                ON portal_locks (status, lock_id);

            -- Off-chain M-of-N signer attestations of a lock's spoke-side
            -- BridgeIn (EIP-712). L1 only stores them; the spoke portal does
            -- the cryptographic verification on-chain.
            CREATE TABLE IF NOT EXISTS portal_lock_signatures (
                lock_id    BIGINT      NOT NULL REFERENCES portal_locks(lock_id),
                signer     TEXT        NOT NULL,
                signature  TEXT        NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (lock_id, signer)
            );

            -- portal_credits: spoke → L1. A spoke BridgeOut burned wANET; L1
            -- credits (unlocks) the same value of native ANET. UNIQUE
            -- (spoke_chain_id, out_id) is the dedup ledger that makes
            -- double-credit impossible.
            CREATE TABLE IF NOT EXISTS portal_credits (
                id             BIGSERIAL   PRIMARY KEY,
                spoke_chain_id BIGINT      NOT NULL,
                spoke_tx_hash  TEXT        NOT NULL,
                out_id         TEXT        NOT NULL,
                l1_recipient   TEXT        NOT NULL,
                ants           BIGINT      NOT NULL CHECK (ants > 0),
                l1_tx_id       TEXT,
                created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (spoke_chain_id, out_id)
            );

            -- M-of-N native-ANET signer attestations for a spoke→L1 credit.
            -- The credit executes once threshold distinct configured signers
            -- have attested the exact same (chain, tx, out_id, recipient, amt).
            CREATE TABLE IF NOT EXISTS portal_credit_signatures (
                spoke_chain_id BIGINT      NOT NULL,
                out_id         TEXT        NOT NULL,
                signer         TEXT        NOT NULL,
                ants           BIGINT      NOT NULL,
                l1_recipient   TEXT        NOT NULL,
                created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (spoke_chain_id, out_id, signer)
            );
            "#,
        )
        .await
        .context("failed to ensure blockchain tables")?;

    Ok(())
}

// ── Bridge burn helpers (L1 → BSC) ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct BridgeBurnRow {
    pub burn_id: i64,
    pub l1_sender: String,
    pub bsc_recipient: String,
    pub ants: i64,
    pub token_symbol: String,
    pub status: String,
    pub bsc_tx_hash: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub released_at: Option<String>,
    /// EIP-712 deadline (unix seconds) that every vault signer must use
    /// when signing the Release struct for this burn. Set once at insert.
    /// Optional for backward compatibility with rows inserted pre-migration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_deadline: Option<i64>,
}

fn row_to_bridge_burn(row: &tokio_postgres::Row) -> BridgeBurnRow {
    BridgeBurnRow {
        burn_id: row.get::<_, i64>(0),
        l1_sender: row.get::<_, String>(1),
        bsc_recipient: row.get::<_, String>(2),
        ants: row.get::<_, i64>(3),
        token_symbol: row.get::<_, String>(4),
        status: row.get::<_, String>(5),
        bsc_tx_hash: row.get::<_, Option<String>>(6),
        error: row.get::<_, Option<String>>(7),
        created_at: row.get::<_, DateTime<Utc>>(8).to_rfc3339(),
        released_at: row
            .get::<_, Option<DateTime<Utc>>>(9)
            .map(|t| t.to_rfc3339()),
        release_deadline: row.get::<_, Option<i64>>(10),
    }
}

pub async fn insert_bridge_burn(
    client: &Client,
    l1_sender: &str,
    bsc_recipient: &str,
    ants: u64,
    token_symbol: &str,
    release_deadline_unix: i64,
) -> Result<BridgeBurnRow> {
    let ants_i64 =
        i64::try_from(ants).with_context(|| format!("burn amount {ants} does not fit BIGINT"))?;
    let row = client
        .query_one(
            r#"
            INSERT INTO bridge_burns (l1_sender, bsc_recipient, ants, token_symbol, release_deadline)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING burn_id, l1_sender, bsc_recipient, ants, token_symbol,
                      status, bsc_tx_hash, error, created_at, released_at, release_deadline
            "#,
            &[&l1_sender, &bsc_recipient, &ants_i64, &token_symbol, &release_deadline_unix],
        )
        .await
        .context("failed to insert bridge_burns row")?;
    Ok(row_to_bridge_burn(&row))
}

pub async fn list_pending_bridge_burns(
    client: &Client,
    since: i64,
    limit: i64,
) -> Result<Vec<BridgeBurnRow>> {
    let rows = client
        .query(
            r#"
            SELECT burn_id, l1_sender, bsc_recipient, ants, token_symbol,
                   status, bsc_tx_hash, error, created_at, released_at, release_deadline
            FROM bridge_burns
            WHERE burn_id > $1 AND status = 'pending'
            ORDER BY burn_id ASC
            LIMIT $2
            "#,
            &[&since, &limit],
        )
        .await
        .context("failed to query pending bridge_burns")?;
    Ok(rows.iter().map(row_to_bridge_burn).collect())
}

pub async fn get_bridge_burn(client: &Client, burn_id: i64) -> Result<Option<BridgeBurnRow>> {
    let row = client
        .query_opt(
            r#"
            SELECT burn_id, l1_sender, bsc_recipient, ants, token_symbol,
                   status, bsc_tx_hash, error, created_at, released_at, release_deadline
            FROM bridge_burns
            WHERE burn_id = $1
            "#,
            &[&burn_id],
        )
        .await
        .context("failed to query bridge_burn by id")?;
    Ok(row.map(|r| row_to_bridge_burn(&r)))
}

pub async fn list_bridge_burns_for_sender(
    client: &Client,
    sender: &str,
    limit: i64,
) -> Result<Vec<BridgeBurnRow>> {
    let rows = client
        .query(
            r#"
            SELECT burn_id, l1_sender, bsc_recipient, ants, token_symbol,
                   status, bsc_tx_hash, error, created_at, released_at, release_deadline
            FROM bridge_burns
            WHERE l1_sender = $1
            ORDER BY burn_id DESC
            LIMIT $2
            "#,
            &[&sender, &limit],
        )
        .await
        .context("failed to query bridge_burns by sender")?;
    Ok(rows.iter().map(row_to_bridge_burn).collect())
}

pub async fn mark_bridge_burn_released(
    client: &Client,
    burn_id: i64,
    bsc_tx_hash: &str,
) -> Result<Option<BridgeBurnRow>> {
    let row = client
        .query_opt(
            r#"
            UPDATE bridge_burns
            SET status = 'released',
                bsc_tx_hash = $2,
                released_at = NOW(),
                error = NULL
            WHERE burn_id = $1 AND status = 'pending'
            RETURNING burn_id, l1_sender, bsc_recipient, ants, token_symbol,
                      status, bsc_tx_hash, error, created_at, released_at, release_deadline
            "#,
            &[&burn_id, &bsc_tx_hash],
        )
        .await
        .context("failed to mark bridge_burn released")?;
    Ok(row.map(|r| row_to_bridge_burn(&r)))
}

pub async fn mark_bridge_burn_failed(
    client: &Client,
    burn_id: i64,
    error_msg: &str,
) -> Result<Option<BridgeBurnRow>> {
    let row = client
        .query_opt(
            r#"
            UPDATE bridge_burns
            SET status = 'failed',
                error = $2
            WHERE burn_id = $1 AND status = 'pending'
            RETURNING burn_id, l1_sender, bsc_recipient, ants, token_symbol,
                      status, bsc_tx_hash, error, created_at, released_at, release_deadline
            "#,
            &[&burn_id, &error_msg],
        )
        .await
        .context("failed to mark bridge_burn failed")?;
    Ok(row.map(|r| row_to_bridge_burn(&r)))
}

// ── Decentralized signature collection for AnetBridgeVault ─────────────────
//
// Each vault signer (identified by a BSC address that appears in the vault's
// on-chain signer set) submits an EIP-712 signature over the canonical
// Release struct for a pending burn. The L1 chain stores these sigs but does
// NOT hold any private keys and cannot itself sign. Once ≥ threshold sigs
// are collected, the relayer (or anyone) reads them via GET /bridge/burns/:id/sigs
// and submits releaseBurn() on BSC.
//
// Invariants enforced at the rpc layer (NOT here) before insert:
//   1. ecrecover(signature, digest) ∈ configured signer set
//   2. burn_id exists and is still 'pending'
//   3. signer is the same as the recovered address (case-insensitive)

#[derive(Debug, Clone, Serialize)]
pub struct BridgeBurnSignatureRow {
    pub burn_id: i64,
    pub signer: String,
    pub signature: String,
    pub created_at: String,
}

fn row_to_bridge_sig(row: &tokio_postgres::Row) -> BridgeBurnSignatureRow {
    BridgeBurnSignatureRow {
        burn_id: row.get::<_, i64>(0),
        signer: row.get::<_, String>(1),
        signature: row.get::<_, String>(2),
        created_at: row.get::<_, DateTime<Utc>>(3).to_rfc3339(),
    }
}

pub async fn insert_bridge_burn_signature(
    client: &Client,
    burn_id: i64,
    signer: &str,
    signature: &str,
) -> Result<BridgeBurnSignatureRow> {
    let row = client
        .query_one(
            r#"
            INSERT INTO bridge_burn_signatures (burn_id, signer, signature)
            VALUES ($1, $2, $3)
            ON CONFLICT (burn_id, signer) DO UPDATE
                SET signature  = EXCLUDED.signature,
                    created_at = NOW()
            RETURNING burn_id, signer, signature, created_at
            "#,
            &[&burn_id, &signer, &signature],
        )
        .await
        .context("failed to insert bridge_burn_signatures row")?;
    Ok(row_to_bridge_sig(&row))
}

pub async fn list_bridge_burn_signatures(
    client: &Client,
    burn_id: i64,
) -> Result<Vec<BridgeBurnSignatureRow>> {
    let rows = client
        .query(
            r#"
            SELECT burn_id, signer, signature, created_at
            FROM bridge_burn_signatures
            WHERE burn_id = $1
            ORDER BY signer ASC
            "#,
            &[&burn_id],
        )
        .await
        .context("failed to query bridge_burn_signatures")?;
    Ok(rows.iter().map(row_to_bridge_sig).collect())
}

// ── Multi-chain mint/burn portal helpers ───────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct PortalLockRow {
    pub lock_id: i64,
    pub l1_sender: String,
    pub dst_chain_id: i64,
    pub dst_recipient: String,
    pub ants: i64,
    pub status: String,
    pub message_id: Option<String>,
    pub spoke_tx_hash: Option<String>,
    pub deadline: i64,
    pub created_at: String,
    pub minted_at: Option<String>,
}

fn row_to_portal_lock(row: &tokio_postgres::Row) -> PortalLockRow {
    PortalLockRow {
        lock_id: row.get::<_, i64>(0),
        l1_sender: row.get::<_, String>(1),
        dst_chain_id: row.get::<_, i64>(2),
        dst_recipient: row.get::<_, String>(3),
        ants: row.get::<_, i64>(4),
        status: row.get::<_, String>(5),
        message_id: row.get::<_, Option<String>>(6),
        spoke_tx_hash: row.get::<_, Option<String>>(7),
        deadline: row.get::<_, i64>(8),
        created_at: row.get::<_, DateTime<Utc>>(9).to_rfc3339(),
        minted_at: row.get::<_, Option<DateTime<Utc>>>(10).map(|t| t.to_rfc3339()),
    }
}

const PORTAL_LOCK_COLS: &str =
    "lock_id, l1_sender, dst_chain_id, dst_recipient, ants, status, message_id, spoke_tx_hash, deadline, created_at, minted_at";

pub async fn insert_portal_lock(
    client: &Client,
    l1_sender: &str,
    dst_chain_id: i64,
    dst_recipient: &str,
    ants: u64,
    deadline_unix: i64,
) -> Result<PortalLockRow> {
    let ants_i64 =
        i64::try_from(ants).with_context(|| format!("lock amount {ants} does not fit BIGINT"))?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO portal_locks (l1_sender, dst_chain_id, dst_recipient, ants, deadline) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING {PORTAL_LOCK_COLS}"
            ),
            &[&l1_sender, &dst_chain_id, &dst_recipient, &ants_i64, &deadline_unix],
        )
        .await
        .context("failed to insert portal_locks row")?;
    Ok(row_to_portal_lock(&row))
}

pub async fn list_pending_portal_locks(
    client: &Client,
    since: i64,
    limit: i64,
) -> Result<Vec<PortalLockRow>> {
    let rows = client
        .query(
            &format!(
                "SELECT {PORTAL_LOCK_COLS} FROM portal_locks \
                 WHERE lock_id > $1 AND status = 'pending' ORDER BY lock_id ASC LIMIT $2"
            ),
            &[&since, &limit],
        )
        .await
        .context("failed to query pending portal_locks")?;
    Ok(rows.iter().map(row_to_portal_lock).collect())
}

pub async fn get_portal_lock(client: &Client, lock_id: i64) -> Result<Option<PortalLockRow>> {
    let row = client
        .query_opt(
            &format!("SELECT {PORTAL_LOCK_COLS} FROM portal_locks WHERE lock_id = $1"),
            &[&lock_id],
        )
        .await
        .context("failed to query portal_lock by id")?;
    Ok(row.map(|r| row_to_portal_lock(&r)))
}

pub async fn mark_portal_lock_minted(
    client: &Client,
    lock_id: i64,
    spoke_tx_hash: &str,
    message_id: &str,
) -> Result<Option<PortalLockRow>> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE portal_locks SET status = 'minted', spoke_tx_hash = $2, \
                 message_id = $3, minted_at = NOW() WHERE lock_id = $1 AND status = 'pending' \
                 RETURNING {PORTAL_LOCK_COLS}"
            ),
            &[&lock_id, &spoke_tx_hash, &message_id],
        )
        .await
        .context("failed to mark portal_lock minted")?;
    Ok(row.map(|r| row_to_portal_lock(&r)))
}

#[derive(Debug, Clone, Serialize)]
pub struct PortalSigRow {
    pub signer: String,
    #[serde(rename = "sig")]
    pub signature: String,
}

pub async fn insert_portal_lock_signature(
    client: &Client,
    lock_id: i64,
    signer: &str,
    signature: &str,
) -> Result<()> {
    client
        .execute(
            r#"
            INSERT INTO portal_lock_signatures (lock_id, signer, signature)
            VALUES ($1, $2, $3)
            ON CONFLICT (lock_id, signer) DO UPDATE
                SET signature = EXCLUDED.signature, created_at = NOW()
            "#,
            &[&lock_id, &signer, &signature],
        )
        .await
        .context("failed to insert portal_lock_signatures row")?;
    Ok(())
}

pub async fn list_portal_lock_signatures(
    client: &Client,
    lock_id: i64,
) -> Result<Vec<PortalSigRow>> {
    let rows = client
        .query(
            "SELECT signer, signature FROM portal_lock_signatures WHERE lock_id = $1 ORDER BY signer ASC",
            &[&lock_id],
        )
        .await
        .context("failed to query portal_lock_signatures")?;
    Ok(rows
        .iter()
        .map(|r| PortalSigRow {
            signer: r.get::<_, String>(0),
            signature: r.get::<_, String>(1),
        })
        .collect())
}

/// True if a credit for this spoke BridgeOut has already been recorded.
pub async fn portal_credit_exists(
    client: &Client,
    spoke_chain_id: i64,
    out_id: &str,
) -> Result<bool> {
    let row = client
        .query_opt(
            "SELECT 1 FROM portal_credits WHERE spoke_chain_id = $1 AND out_id = $2",
            &[&spoke_chain_id, &out_id],
        )
        .await
        .context("failed to check portal_credit existence")?;
    Ok(row.is_some())
}

/// Record a credit. Returns false if it already existed (dedup — no double credit).
pub async fn insert_portal_credit(
    client: &Client,
    spoke_chain_id: i64,
    spoke_tx_hash: &str,
    out_id: &str,
    l1_recipient: &str,
    ants: u64,
    l1_tx_id: &str,
) -> Result<bool> {
    let ants_i64 =
        i64::try_from(ants).with_context(|| format!("credit amount {ants} does not fit BIGINT"))?;
    let n = client
        .execute(
            r#"
            INSERT INTO portal_credits (spoke_chain_id, spoke_tx_hash, out_id, l1_recipient, ants, l1_tx_id)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (spoke_chain_id, out_id) DO NOTHING
            "#,
            &[&spoke_chain_id, &spoke_tx_hash, &out_id, &l1_recipient, &ants_i64, &l1_tx_id],
        )
        .await
        .context("failed to insert portal_credit")?;
    Ok(n == 1)
}

/// Record a distinct signer attestation for a spoke→L1 credit, bound to the
/// exact (ants, l1_recipient). Returns the count of DISTINCT signers that
/// attested this SAME (chain, out_id, ants, recipient) — so signers who
/// disagree on the amount/recipient never combine toward the threshold.
pub async fn record_portal_credit_signature(
    client: &Client,
    spoke_chain_id: i64,
    out_id: &str,
    signer: &str,
    ants: u64,
    l1_recipient: &str,
) -> Result<i64> {
    let ants_i64 = i64::try_from(ants)
        .with_context(|| format!("credit amount {ants} does not fit BIGINT"))?;
    client
        .execute(
            r#"
            INSERT INTO portal_credit_signatures (spoke_chain_id, out_id, signer, ants, l1_recipient)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (spoke_chain_id, out_id, signer) DO NOTHING
            "#,
            &[&spoke_chain_id, &out_id, &signer, &ants_i64, &l1_recipient],
        )
        .await
        .context("failed to insert portal_credit_signature")?;
    let row = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM portal_credit_signatures \
             WHERE spoke_chain_id = $1 AND out_id = $2 AND ants = $3 AND l1_recipient = $4",
            &[&spoke_chain_id, &out_id, &ants_i64, &l1_recipient],
        )
        .await
        .context("failed to count portal_credit_signatures")?;
    Ok(row.get::<_, i64>(0))
}

/// Σ(portal_locks.ants) − Σ(portal_credits.ants) = native ANET currently
/// backing spoke wANET. The core reconciliation figure.
pub async fn portal_locked_net_ants(client: &Client) -> Result<i64> {
    let locked = client
        .query_one("SELECT COALESCE(SUM(ants),0)::BIGINT FROM portal_locks", &[])
        .await
        .context("failed to sum portal_locks")?
        .get::<_, i64>(0);
    let credited = client
        .query_one("SELECT COALESCE(SUM(ants),0)::BIGINT FROM portal_credits", &[])
        .await
        .context("failed to sum portal_credits")?
        .get::<_, i64>(0);
    Ok(locked.saturating_sub(credited))
}

// ── Wallet migration helpers (legacy → secp) ───────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct WalletMigrationRow {
    pub legacy_address: String,
    pub secp_address: String,
    pub commit_hash: String,
    pub status: String,
    pub ants_migrated: Option<i64>,
    pub sessions_migrated: Option<i64>,
    pub committed_at: String,
    pub revealed_at: Option<String>,
}

fn row_to_wallet_migration(row: &tokio_postgres::Row) -> WalletMigrationRow {
    WalletMigrationRow {
        legacy_address: row.get::<_, String>(0),
        secp_address: row.get::<_, String>(1),
        commit_hash: row.get::<_, String>(2),
        status: row.get::<_, String>(3),
        ants_migrated: row.get::<_, Option<i64>>(4),
        sessions_migrated: row.get::<_, Option<i64>>(5),
        committed_at: row.get::<_, DateTime<Utc>>(6).to_rfc3339(),
        revealed_at: row
            .get::<_, Option<DateTime<Utc>>>(7)
            .map(|t| t.to_rfc3339()),
    }
}

pub async fn get_wallet_migration(
    client: &Client,
    legacy_address: &str,
) -> Result<Option<WalletMigrationRow>> {
    let row = client
        .query_opt(
            r#"
            SELECT legacy_address, secp_address, commit_hash, status,
                   ants_migrated, sessions_migrated, committed_at, revealed_at
              FROM wallet_migrations
             WHERE legacy_address = $1
            "#,
            &[&legacy_address],
        )
        .await
        .context("failed to query wallet_migrations")?;
    Ok(row.as_ref().map(row_to_wallet_migration))
}

/// Read-only: list every migration that has completed (`revealed`). Used by the
/// stranded-funds diagnostic to find wallets whose legacy address was credited
/// again after migration (those funds cannot be re-migrated and need a sweep).
pub async fn list_revealed_wallet_migrations(client: &Client) -> Result<Vec<WalletMigrationRow>> {
    let rows = client
        .query(
            r#"
            SELECT legacy_address, secp_address, commit_hash, status,
                   ants_migrated, sessions_migrated, committed_at, revealed_at
              FROM wallet_migrations
             WHERE status = 'revealed'
             ORDER BY revealed_at
            "#,
            &[],
        )
        .await
        .context("failed to list revealed wallet_migrations")?;
    Ok(rows.iter().map(row_to_wallet_migration).collect())
}

pub async fn insert_wallet_migration_commit(
    client: &Client,
    legacy_address: &str,
    secp_address: &str,
    commit_hash: &str,
) -> Result<WalletMigrationRow> {
    let row = client
        .query_one(
            r#"
            INSERT INTO wallet_migrations (legacy_address, secp_address, commit_hash, status)
            VALUES ($1, $2, $3, 'committed')
            RETURNING legacy_address, secp_address, commit_hash, status,
                      ants_migrated, sessions_migrated, committed_at, revealed_at
            "#,
            &[&legacy_address, &secp_address, &commit_hash],
        )
        .await
        .context("failed to insert wallet_migrations commit")?;
    Ok(row_to_wallet_migration(&row))
}

/// Admin-only: delete a `wallet_migrations` row outright.
///
/// Used to recover from a stuck commit (the off-chain nonce was lost so
/// reveal can never complete). Only safe to call when status='committed'
/// — never delete a 'revealed' row.
pub async fn delete_wallet_migration_committed(
    client: &Client,
    legacy_address: &str,
) -> Result<Option<WalletMigrationRow>> {
    let row = client
        .query_opt(
            r#"
            DELETE FROM wallet_migrations
             WHERE legacy_address = $1 AND status = 'committed'
            RETURNING legacy_address, secp_address, commit_hash, status,
                      ants_migrated, sessions_migrated, committed_at, revealed_at
            "#,
            &[&legacy_address],
        )
        .await
        .context("failed to delete wallet_migrations committed row")?;
    Ok(row.as_ref().map(row_to_wallet_migration))
}

pub async fn complete_wallet_migration(
    client: &Client,
    legacy_address: &str,
    ants_migrated: u64,
    sessions_migrated: u64,
) -> Result<WalletMigrationRow> {
    let ants_i64 = i64::try_from(ants_migrated)
        .with_context(|| format!("ants_migrated {ants_migrated} does not fit BIGINT"))?;
    let sessions_i64 = i64::try_from(sessions_migrated)
        .with_context(|| format!("sessions_migrated {sessions_migrated} does not fit BIGINT"))?;
    let row = client
        .query_one(
            r#"
            UPDATE wallet_migrations
               SET status            = 'revealed',
                   ants_migrated     = $2,
                   sessions_migrated = $3,
                   revealed_at       = NOW()
             WHERE legacy_address = $1
             RETURNING legacy_address, secp_address, commit_hash, status,
                       ants_migrated, sessions_migrated, committed_at, revealed_at
            "#,
            &[&legacy_address, &ants_i64, &sessions_i64],
        )
        .await
        .context("failed to complete wallet_migrations row")?;
    Ok(row_to_wallet_migration(&row))
}

pub async fn record_validator_heartbeat_nonce(
    client: &Client,
    chain_id: &str,
    wallet: &str,
    nonce: u64,
) -> Result<bool> {
    let nonce_i64 = i64::try_from(nonce).context("heartbeat nonce exceeds BIGINT range")?;
    let rows_affected = client
        .execute(
            r#"
            INSERT INTO validator_heartbeat_nonces (chain_id, wallet, last_nonce, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (chain_id, wallet) DO UPDATE
            SET
                last_nonce = EXCLUDED.last_nonce,
                updated_at = NOW()
            WHERE validator_heartbeat_nonces.last_nonce < EXCLUDED.last_nonce
            "#,
            &[&chain_id, &wallet, &nonce_i64],
        )
        .await
        .context("failed to persist validator heartbeat nonce")?;

    Ok(rows_affected > 0)
}

pub async fn record_mining_proof_nonce(
    client: &Client,
    chain_id: &str,
    wallet: &str,
    nonce: u64,
) -> Result<bool> {
    let nonce_i64 = i64::try_from(nonce).context("mining proof nonce exceeds BIGINT range")?;
    let rows_affected = client
        .execute(
            r#"
            INSERT INTO mining_proof_nonces (chain_id, wallet, last_nonce, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (chain_id, wallet) DO UPDATE
            SET
                last_nonce = EXCLUDED.last_nonce,
                updated_at = NOW()
            WHERE mining_proof_nonces.last_nonce < EXCLUDED.last_nonce
            "#,
            &[&chain_id, &wallet, &nonce_i64],
        )
        .await
        .context("failed to persist mining proof nonce")?;

    Ok(rows_affected > 0)
}

pub async fn record_action_authorization_nonce(
    client: &Client,
    chain_id: &str,
    wallet: &str,
    action_type: &str,
    nonce: u64,
) -> Result<bool> {
    let nonce_i64 = i64::try_from(nonce).context("action nonce exceeds BIGINT range")?;
    let rows_affected = client
        .execute(
            r#"
            INSERT INTO action_authorization_nonces
                (chain_id, wallet, action_type, last_nonce, updated_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (chain_id, wallet, action_type) DO UPDATE
            SET
                last_nonce = EXCLUDED.last_nonce,
                updated_at = NOW()
            WHERE action_authorization_nonces.last_nonce < EXCLUDED.last_nonce
            "#,
            &[&chain_id, &wallet, &action_type, &nonce_i64],
        )
        .await
        .context("failed to persist signed action nonce")?;

    Ok(rows_affected > 0)
}

pub async fn get_last_hash(client: &Client) -> Result<Option<String>> {
    let row = client
        .query_opt(
            "SELECT value FROM meta WHERE key = $1",
            &[&LAST_HASH_META_KEY],
        )
        .await
        .context("failed to read LAST_HASH from meta table")?;

    Ok(row.map(|row| row.get::<_, String>(0)))
}

pub async fn load_chain_blocks(client: &Client) -> Result<Vec<Block>> {
    let mut blocks = Vec::new();
    let mut visited_hashes = std::collections::HashSet::new();
    let mut current_hash = match get_last_hash(client).await? {
        Some(hash) => hash,
        None => return Ok(blocks),
    };

    loop {
        if !visited_hashes.insert(current_hash.clone()) {
            return Err(anyhow!(
                "cycle detected while loading chain at hash {current_hash}"
            ));
        }
        let row = client
            .query_opt(
                "SELECT data FROM blocks WHERE hash = $1 LIMIT 1",
                &[&current_hash],
            )
            .await
            .with_context(|| format!("failed to load block by hash {current_hash}"))?
            .ok_or_else(|| anyhow!("chain tip references missing block hash {current_hash}"))?;

        let payload = row.get::<_, Value>(0);
        let block: Block = serde_json::from_value(payload)
            .with_context(|| format!("failed to decode block JSON for hash {current_hash}"))?;
        if block.hash != current_hash {
            return Err(anyhow!(
                "block row key {current_hash} does not match embedded hash {}",
                block.hash
            ));
        }

        blocks.push(block.clone());
        if block.previous_hash == "GENESIS" {
            break;
        }

        current_hash = block.previous_hash;
    }

    blocks.reverse();
    Ok(blocks)
}

pub async fn store_block_and_update_tip(client: &Client, block: &Block) -> Result<()> {
    let data = serde_json::to_value(block)
        .with_context(|| format!("failed to serialize block {}", block.block_height))?;
    let timestamp = block.epoch_end.timestamp();
    let height = i64::try_from(block.block_height)
        .with_context(|| format!("block height {} does not fit BIGINT", block.block_height))?;

    let rows_affected = client
        .execute(
            r#"
            WITH tip_lock AS MATERIALIZED (
                SELECT pg_advisory_xact_lock(hashtext($6))
            ),
            current_tip AS (
                SELECT value
                FROM meta, tip_lock
                WHERE key = $6
                FOR UPDATE
            ),
            inserted AS (
                INSERT INTO blocks (hash, previous_hash, height, data, timestamp)
                SELECT $1, $2, $3, $4, $5
                WHERE
                    EXISTS (SELECT 1 FROM tip_lock)
                    AND (
                        (SELECT value FROM current_tip) = $2
                        OR ($2 = 'GENESIS' AND NOT EXISTS (SELECT 1 FROM current_tip))
                    )
                RETURNING hash
            )
            INSERT INTO meta (key, value)
            SELECT $6, hash FROM inserted
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
            "#,
            &[
                &block.hash,
                &block.previous_hash,
                &height,
                &data,
                &timestamp,
                &LAST_HASH_META_KEY,
            ],
        )
        .await
        .with_context(|| {
            format!(
                "failed to atomically store block {} and advance LAST_HASH",
                block.block_height
            )
        })?;
    if rows_affected != 1 {
        return Err(anyhow!(
            "chain tip changed before block {} could be stored",
            block.block_height
        ));
    }

    Ok(())
}

pub async fn ensure_chain_initialized(
    client: &Client,
    chain_id: &str,
    genesis_time: DateTime<Utc>,
) -> Result<()> {
    ensure_blockchain_tables(client).await?;

    if let Some(last_hash) = get_last_hash(client).await? {
        let row = client
            .query_opt(
                "SELECT height FROM blocks WHERE hash = $1 LIMIT 1",
                &[&last_hash],
            )
            .await
            .context("failed to load latest block metadata")?
            .ok_or_else(|| anyhow!("meta LAST_HASH points to missing block hash {last_hash}"))?;
        let height = row.get::<_, i64>(0).max(0) as u64;

        client
            .execute(
                "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
                &[&"CHAIN_ID", &chain_id],
            )
            .await
            .context("failed to refresh CHAIN_ID metadata")?;

        tracing::info!(height, "Loaded existing chain at height {}", height);
        return Ok(());
    }

    let genesis_block = Block::new(
        0,
        genesis_time,
        genesis_time + ChronoDuration::seconds(1),
        "GENESIS".to_owned(),
        Vec::new(),
        0,
        Vec::new(),
        None,
        Vec::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        Vec::new(),
        Vec::new(),
        String::new(),
        String::new(),
    )?;

    store_block_and_update_tip(client, &genesis_block).await?;

    client
        .execute(
            "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[&"CHAIN_ID", &chain_id],
        )
        .await
        .context("failed to persist CHAIN_ID metadata")?;

    client
        .execute(
            "INSERT INTO meta (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            &[&"GENESIS_TIME", &genesis_time.to_rfc3339()],
        )
        .await
        .context("failed to persist GENESIS_TIME metadata")?;

    tracing::info!("Created genesis block");
    Ok(())
}
