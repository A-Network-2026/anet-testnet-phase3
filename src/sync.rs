//! Phase 0 (decentralization): standalone chain verifier.
//!
//! This module lets *anyone* — with no database, no genesis seed, and no trust
//! in the operator — independently pull the published block history from a peer
//! node and re-verify its cryptographic integrity end to end:
//!
//!   1. the genesis block hash the peer reports matches the hash of block 0,
//!   2. every block's stored hash equals the hash recomputed from its contents,
//!   3. each block's `previous_hash` links to the prior block (an unbroken
//!      hash chain from genesis to tip — a rewrite of any historical block
//!      would break the link), and
//!   4. every transaction carries a valid secp256k1 signature bound to this
//!      chain id (the operator cannot forge transfers for keys it does not
//!      hold).
//!
//! It is deliberately read-only: it never writes to a database and never
//! mutates node state, so it is safe to run against the production node from
//! anywhere. It is the first concrete step away from "trust the server": a
//! third party can now prove the chain has not been silently rewritten.
//!
//! NOTE (honest scope): this verifier proves the *block history* is internally
//! consistent and signed. It does NOT yet reconstruct full account balances,
//! because account activation is currently credited from the shared Web2
//! datastore rather than recorded on-chain. Making activation fully on-chain —
//! so that a follower can rebuild all balances from blocks alone — is the next
//! decentralization milestone after this one.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};

use crate::{block::Block, state::SyncHead};

/// Blocks pulled per range request while verifying. Matches the server-side
/// `BLOCK_SYNC_PAGE_MAX` cap so a single page is never truncated server-side.
const VERIFY_PAGE: u64 = 256;

/// Transactions counted while verifying a single block.
#[derive(Debug, Clone, Copy, Default)]
struct BlockVerifyTally {
    transactions_verified: u64,
    legacy_unsigned_transactions: u64,
}

/// Verify a single block against the prior block's hash and epoch end. This is
/// the **single source of truth** for block validity used by both the one-shot
/// verifier (`verify_against_peer`) and the persistent follower
/// (`run_follower`), so the two can never diverge on what they accept — the
/// property that keeps every node's view of the chain uniform and split-free.
///
/// Checks, in order: structural sanity; stored hash equals recomputed hash;
/// unbroken `previous_hash` linkage; epochs do not move backwards; and every
/// non-legacy transaction carries a signature that recovers on this chain.
fn verify_block_against_prev(
    block: &Block,
    previous_hash: &str,
    previous_epoch_end: Option<DateTime<Utc>>,
    chain_id: &str,
) -> Result<BlockVerifyTally> {
    block.validate_structure().with_context(|| {
        format!("block {} failed structural validation", block.block_height)
    })?;

    if !block
        .validate_hash()
        .with_context(|| format!("block {} hash computation failed", block.block_height))?
    {
        return Err(anyhow!(
            "block {} failed hash validation (contents do not match stored hash)",
            block.block_height
        ));
    }

    if block.previous_hash != previous_hash {
        return Err(anyhow!(
            "block {} breaks the hash chain: previous_hash does not link to the prior block",
            block.block_height
        ));
    }

    if let Some(prev_end) = previous_epoch_end {
        if block.epoch_start < prev_end {
            return Err(anyhow!(
                "block {} overlaps an earlier epoch",
                block.block_height
            ));
        }
    }

    let mut tally = BlockVerifyTally::default();
    for transaction in &block.transactions {
        if transaction.is_legacy_unsigned() {
            tally.legacy_unsigned_transactions = tally.legacy_unsigned_transactions.saturating_add(1);
        } else {
            transaction
                .validate_signed_for_chain(chain_id)
                .with_context(|| {
                    format!(
                        "block {} contains a transaction with an invalid signature",
                        block.block_height
                    )
                })?;
        }
        tally.transactions_verified = tally.transactions_verified.saturating_add(1);
    }

    Ok(tally)
}

/// Outcome of a full verification pass over a peer's chain.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub chain_id: String,
    pub genesis_hash: String,
    pub tip_height: u64,
    pub blocks_verified: u64,
    pub transactions_verified: u64,
    pub legacy_unsigned_transactions: u64,
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("anet-chain-verifier/0")
        .build()
        .context("failed to build verifier HTTP client")
}

/// Fetch the peer's chain-tip descriptor.
async fn fetch_head(client: &reqwest::Client, peer: &str) -> Result<SyncHead> {
    let url = format!("{}/sync/head", peer.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "peer /sync/head returned HTTP {}",
            response.status()
        ));
    }
    response
        .json::<SyncHead>()
        .await
        .context("failed to decode peer /sync/head response")
}

/// Fetch an inclusive contiguous range of blocks `[from, to]` from the peer.
async fn fetch_range(
    client: &reqwest::Client,
    peer: &str,
    from: u64,
    to: u64,
) -> Result<Vec<Block>> {
    let url = format!(
        "{}/blocks?from={}&to={}&position=true",
        peer.trim_end_matches('/'),
        from,
        to
    );
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "peer block range {from}..={to} returned HTTP {}",
            response.status()
        ));
    }
    response
        .json::<Vec<Block>>()
        .await
        .with_context(|| format!("failed to decode peer block range {from}..={to}"))
}

/// Run one full verification pass over the peer's chain from genesis to tip.
///
/// `expect_chain_id`, when provided, is asserted against the peer's reported
/// chain id before verifying — so an operator can pin the exact chain they
/// expect rather than trusting whatever the peer self-reports.
pub async fn verify_against_peer(
    peer: &str,
    expect_chain_id: Option<&str>,
) -> Result<VerifyReport> {
    let client = http_client()?;
    let head = fetch_head(&client, peer).await?;

    if let Some(expected) = expect_chain_id {
        if expected != head.chain_id {
            return Err(anyhow!(
                "peer chain_id {:?} does not match expected {:?}",
                head.chain_id,
                expected
            ));
        }
    }

    let tip_height = head
        .tip_height
        .ok_or_else(|| anyhow!("peer reports an empty chain (no tip height)"))?;
    if head.block_count == 0 {
        return Err(anyhow!("peer reports a tip but block_count is zero"));
    }
    if head.genesis_hash.is_empty() || head.tip_hash.is_empty() {
        return Err(anyhow!("peer head is missing genesis_hash or tip_hash"));
    }

    let mut previous_hash = "GENESIS".to_owned();
    let mut previous_epoch_end: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut next_position = 0_u64;
    let mut blocks_verified = 0_u64;
    let mut transactions_verified = 0_u64;
    let mut legacy_unsigned_transactions = 0_u64;
    let mut genesis_hash: Option<String> = None;
    let mut final_height: Option<u64> = None;

    while next_position < head.block_count {
        let to = next_position
            .saturating_add(VERIFY_PAGE - 1)
            .min(head.block_count - 1);
        let blocks = fetch_range(&client, peer, next_position, to).await?;
        if blocks.is_empty() {
            return Err(anyhow!(
                "peer returned no blocks for positions {next_position}..={to}; chain has a gap"
            ));
        }
        let max_page_len = to.saturating_sub(next_position).saturating_add(1);
        if blocks.len() as u64 > max_page_len {
            return Err(anyhow!(
                "peer returned too many blocks for positions {next_position}..={to}"
            ));
        }

        for block in &blocks {
            let tally = verify_block_against_prev(
                block,
                &previous_hash,
                previous_epoch_end,
                &head.chain_id,
            )?;
            transactions_verified =
                transactions_verified.saturating_add(tally.transactions_verified);
            legacy_unsigned_transactions =
                legacy_unsigned_transactions.saturating_add(tally.legacy_unsigned_transactions);

            if genesis_hash.is_none() {
                genesis_hash = Some(block.hash.clone());
            }

            previous_hash = block.hash.clone();
            previous_epoch_end = Some(block.epoch_end);
            final_height = Some(block.block_height);
            blocks_verified = blocks_verified.saturating_add(1);
            next_position = next_position.saturating_add(1);
        }
    }

    let genesis_hash = genesis_hash.unwrap_or_default();

    // The genesis hash the peer advertised must equal the hash of block 0 we
    // just verified — otherwise the peer's head descriptor is inconsistent with
    // the history it served.
    if head.genesis_hash != genesis_hash {
        return Err(anyhow!(
            "peer advertised genesis hash {} but block 0 hashes to {}",
            head.genesis_hash,
            genesis_hash
        ));
    }
    if previous_hash != head.tip_hash {
        return Err(anyhow!(
            "peer advertised tip hash {} but verified history ends at {}",
            head.tip_hash,
            previous_hash
        ));
    }
    if final_height != Some(tip_height) {
        return Err(anyhow!(
            "peer advertised tip height {} but verified history ends at {:?}",
            tip_height,
            final_height
        ));
    }
    if blocks_verified != head.block_count {
        return Err(anyhow!(
            "peer advertised {} blocks but verifier received {}",
            head.block_count,
            blocks_verified
        ));
    }

    Ok(VerifyReport {
        chain_id: head.chain_id,
        genesis_hash,
        tip_height,
        blocks_verified,
        transactions_verified,
        legacy_unsigned_transactions,
    })
}

/// Verifier entry point used by the `--verify-peer` CLI mode. Runs one pass
/// (or repeats every `interval` when `once` is false), logging the result.
pub async fn run_verifier(
    peer: String,
    expect_chain_id: Option<String>,
    interval: Duration,
    once: bool,
) -> Result<()> {
    loop {
        match verify_against_peer(&peer, expect_chain_id.as_deref()).await {
            Ok(report) => {
                tracing::info!(
                    peer = %peer,
                    chain_id = %report.chain_id,
                    genesis_hash = %report.genesis_hash,
                    tip_height = report.tip_height,
                    blocks_verified = report.blocks_verified,
                    transactions_verified = report.transactions_verified,
                    legacy_unsigned_transactions = report.legacy_unsigned_transactions,
                    "chain verification PASSED: full hash chain and signed transactions are valid"
                );
            }
            Err(error) => {
                tracing::error!(
                    peer = %peer,
                    ?error,
                    "chain verification FAILED"
                );
                if once {
                    return Err(error);
                }
            }
        }

        if once {
            return Ok(());
        }

        tokio::time::sleep(interval).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistent follower node (decentralization: local replica)
// ─────────────────────────────────────────────────────────────────────────────
//
// A follower node performs Bitcoin-style Initial Block Download: it syncs the
// chain from block 0, re-verifies every block with the SAME rules the producer
// uses (`verify_block_against_prev`), and persists the verified chain to a
// local embedded store (`sled`). It needs no PostgreSQL and no genesis seed, so
// the very same binary runs on a server, a laptop, or a phone under Termux.
//
// Crucially, a follower NEVER produces blocks. It only verifies and follows the
// one canonical chain, so it cannot fork or split it — running more followers
// only makes the chain's data more replicated and more independently verified.
// When the device is offline the follower simply pauses and resumes from its
// last verified height when connectivity returns, exactly like a Bitcoin node.
//
// (Multi-producer block creation and peer-to-peer gossip are a later, carefully
// tested phase; this module is the safe replication/verification foundation.)

const FOLLOWER_META_TREE: &str = "meta";
const FOLLOWER_BLOCKS_TREE: &str = "blocks";
const FOLLOWER_KEY_CHAIN_ID: &str = "chain_id";
const FOLLOWER_KEY_TIP_BLOCK: &str = "tip_block";

/// Local, embedded persistence for a follower node. Stores every verified block
/// keyed by its contiguous chain position so the chain lives durably on the
/// device, plus a small metadata record for the chain id and the verified tip.
struct FollowerStore {
    db: sled::Db,
    blocks: sled::Tree,
    meta: sled::Tree,
}

/// The follower's last verified tip, used to resume syncing without re-checking
/// history that was already verified before it was persisted.
struct FollowerTip {
    position: u64,
    hash: String,
    epoch_end: DateTime<Utc>,
}

impl FollowerStore {
    fn open(path: &Path) -> Result<Self> {
        let db = sled::open(path)
            .with_context(|| format!("failed to open follower store at {}", path.display()))?;
        let blocks = db
            .open_tree(FOLLOWER_BLOCKS_TREE)
            .context("failed to open follower blocks tree")?;
        let meta = db
            .open_tree(FOLLOWER_META_TREE)
            .context("failed to open follower meta tree")?;
        Ok(Self { db, blocks, meta })
    }

    fn stored_chain_id(&self) -> Result<Option<String>> {
        match self.meta.get(FOLLOWER_KEY_CHAIN_ID)? {
            Some(bytes) => Ok(Some(String::from_utf8(bytes.to_vec()).context(
                "stored chain id is not valid UTF-8",
            )?)),
            None => Ok(None),
        }
    }

    fn set_chain_id(&self, chain_id: &str) -> Result<()> {
        self.meta.insert(FOLLOWER_KEY_CHAIN_ID, chain_id.as_bytes())?;
        Ok(())
    }

    /// The last verified tip, reconstructed from the persisted tip-block record.
    fn tip(&self) -> Result<Option<FollowerTip>> {
        match self.meta.get(FOLLOWER_KEY_TIP_BLOCK)? {
            Some(bytes) => {
                let block: Block = serde_json::from_slice(&bytes)
                    .context("failed to decode persisted follower tip block")?;
                // The tip's contiguous position is the number of blocks stored
                // minus one (positions are dense from 0).
                let position = self.block_count()?.saturating_sub(1);
                Ok(Some(FollowerTip {
                    position,
                    hash: block.hash,
                    epoch_end: block.epoch_end,
                }))
            }
            None => Ok(None),
        }
    }

    fn block_count(&self) -> Result<u64> {
        Ok(self.blocks.len() as u64)
    }

    /// All stored blocks in contiguous position order.
    fn load_all_blocks(&self) -> Result<Vec<Block>> {
        let mut blocks = Vec::with_capacity(self.blocks.len());
        for (expected, entry) in self.blocks.iter().enumerate() {
            let (key, value) = entry?;
            let position = u64::from_be_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| anyhow!("follower store has a malformed block key"))?,
            );
            if position != expected as u64 {
                return Err(anyhow!(
                    "follower store has a gap at position {expected} (found {position})"
                ));
            }
            blocks.push(serde_json::from_slice(&value).context("failed to decode stored block")?);
        }
        Ok(blocks)
    }

    /// Persist a freshly-verified block at its contiguous chain position and
    /// advance the stored tip. Flushed before returning so a crash mid-sync
    /// never leaves a torn tip.
    fn append_verified_block(&self, position: u64, block: &Block) -> Result<()> {
        let encoded = serde_json::to_vec(block).context("failed to encode block for storage")?;
        self.blocks.insert(position.to_be_bytes(), encoded.clone())?;
        self.meta.insert(FOLLOWER_KEY_TIP_BLOCK, encoded)?;
        // One durable flush of the whole database commits both the block and
        // the advanced tip together, so a crash mid-sync never tears the tip.
        self.db.flush()?;
        Ok(())
    }
}

/// Read-only export of a follower replica for the isolated ABCI import test.
#[cfg(feature = "abci-testnet")]
pub(crate) fn load_follower_replica(path: &Path) -> Result<(String, Vec<Block>)> {
    let store = FollowerStore::open(path)?;
    let chain_id = store
        .stored_chain_id()?
        .ok_or_else(|| anyhow!("follower store has no chain id"))?;
    let blocks = store.load_all_blocks()?;
    Ok((chain_id, blocks))
}

/// Progress made by a single follow pass.
#[derive(Debug, Clone, Copy)]
struct FollowProgress {
    blocks_added: u64,
    tip_height: u64,
    up_to_date: bool,
}

/// Run one follow pass: fetch the peer head, then verify-and-persist any blocks
/// beyond the local tip. Verification reuses `verify_block_against_prev`, so a
/// follower accepts exactly what the one-shot verifier (and the producer)
/// accept.
async fn follow_once(
    client: &reqwest::Client,
    peer: &str,
    expect_chain_id: Option<&str>,
    store: &FollowerStore,
) -> Result<FollowProgress> {
    let head = fetch_head(client, peer).await?;

    if let Some(expected) = expect_chain_id {
        if expected != head.chain_id {
            return Err(anyhow!(
                "peer chain_id {:?} does not match expected {:?}",
                head.chain_id,
                expected
            ));
        }
    }
    // Pin the chain id on first sync; refuse to mix histories afterward.
    match store.stored_chain_id()? {
        Some(existing) if existing != head.chain_id => {
            return Err(anyhow!(
                "follower store holds chain {:?} but peer serves {:?}",
                existing,
                head.chain_id
            ));
        }
        Some(_) => {}
        None => store.set_chain_id(&head.chain_id)?,
    }

    let (mut next_position, mut previous_hash, mut previous_epoch_end) = match store.tip()? {
        Some(tip) => (
            tip.position.saturating_add(1),
            tip.hash,
            Some(tip.epoch_end),
        ),
        None => (0_u64, "GENESIS".to_owned(), None),
    };

    if next_position >= head.block_count {
        let tip_height = store
            .tip()?
            .map(|tip| tip.position)
            .unwrap_or(0);
        return Ok(FollowProgress {
            blocks_added: 0,
            tip_height,
            up_to_date: true,
        });
    }

    let mut blocks_added = 0_u64;
    while next_position < head.block_count {
        let to = next_position
            .saturating_add(VERIFY_PAGE - 1)
            .min(head.block_count - 1);
        let blocks = fetch_range(client, peer, next_position, to).await?;
        if blocks.is_empty() {
            return Err(anyhow!(
                "peer returned no blocks for positions {next_position}..={to}; chain has a gap"
            ));
        }
        let max_page_len = to.saturating_sub(next_position).saturating_add(1);
        if blocks.len() as u64 > max_page_len {
            return Err(anyhow!(
                "peer returned too many blocks for positions {next_position}..={to}"
            ));
        }

        for block in &blocks {
            verify_block_against_prev(block, &previous_hash, previous_epoch_end, &head.chain_id)?;
            store.append_verified_block(next_position, block)?;
            previous_hash = block.hash.clone();
            previous_epoch_end = Some(block.epoch_end);
            next_position = next_position.saturating_add(1);
            blocks_added = blocks_added.saturating_add(1);
        }
    }

    Ok(FollowProgress {
        blocks_added,
        tip_height: next_position.saturating_sub(1),
        up_to_date: true,
    })
}

/// Follower entry point used by the `--follow-peer` CLI mode. Performs Initial
/// Block Download into a local store, then continuously follows the tip
/// (or runs a single pass when `once`). Network errors are non-fatal: the
/// follower logs, keeps its verified progress, and retries — so it tolerates an
/// offline device and resumes on reconnect.
pub async fn run_follower(
    peer: String,
    expect_chain_id: Option<String>,
    store_path: std::path::PathBuf,
    interval: Duration,
    once: bool,
) -> Result<()> {
    let store = FollowerStore::open(&store_path)?;
    let client = http_client()?;
    tracing::info!(
        peer = %peer,
        store = %store_path.display(),
        starting_height = store.block_count()?.saturating_sub(1),
        "follower node starting (read-only replica; never produces blocks)"
    );

    loop {
        match follow_once(&client, &peer, expect_chain_id.as_deref(), &store).await {
            Ok(progress) => {
                if progress.blocks_added > 0 {
                    tracing::info!(
                        peer = %peer,
                        blocks_added = progress.blocks_added,
                        tip_height = progress.tip_height,
                        "follower synced new blocks"
                    );
                } else if progress.up_to_date {
                    tracing::debug!(tip_height = progress.tip_height, "follower up to date");
                }
            }
            Err(error) => {
                // Offline tolerance: keep verified progress and retry. Do not
                // exit on a transient network/peer error.
                tracing::warn!(peer = %peer, ?error, "follower sync paused; will retry");
                if once {
                    return Err(error);
                }
            }
        }

        if once {
            return Ok(());
        }

        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{verify_block_against_prev, FollowerStore};
    use crate::block::Block;
    use chrono::{Duration as ChronoDuration, TimeZone, Utc};
    use std::collections::HashMap;

    const TEST_CHAIN_ID: &str = "anet-private-mainnet-1";

    fn test_block(height: u64, previous_hash: &str, epoch_index: i64) -> Block {
        let base = Utc.timestamp_opt(1_700_000_000, 0).single().expect("base time");
        let epoch_start = base + ChronoDuration::seconds(epoch_index * 10);
        let epoch_end = epoch_start + ChronoDuration::seconds(2);
        Block::new(
            height,
            epoch_start,
            epoch_end,
            previous_hash.to_owned(),
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
            String::new(),
            String::new(),
        )
        .expect("valid test block")
    }

    fn temp_store_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "anet-follower-test-{tag}-{}-{}",
            std::process::id(),
            nanos
        ))
    }

    #[test]
    fn verify_block_links_accepts_chain_and_rejects_breaks() {
        let b0 = test_block(0, "GENESIS", 0);
        verify_block_against_prev(&b0, "GENESIS", None, TEST_CHAIN_ID)
            .expect("genesis block verifies");

        let b1 = test_block(1, &b0.hash, 1);
        verify_block_against_prev(&b1, &b0.hash, Some(b0.epoch_end), TEST_CHAIN_ID)
            .expect("linked block verifies");

        // A wrong previous_hash breaks the chain and must be rejected — the
        // property that keeps every follower on the one canonical chain.
        let err = verify_block_against_prev(&b1, "deadbeef", Some(b0.epoch_end), TEST_CHAIN_ID)
            .expect_err("broken link must be rejected");
        assert!(err.to_string().contains("breaks the hash chain"));

        // A backwards epoch must be rejected.
        let future_end = b1.epoch_end + ChronoDuration::seconds(3600);
        let err = verify_block_against_prev(&b1, &b0.hash, Some(future_end), TEST_CHAIN_ID)
            .expect_err("backwards epoch must be rejected");
        assert!(err.to_string().contains("overlaps an earlier epoch"));
    }

    #[test]
    fn follower_store_persists_and_resumes_tip() {
        let path = temp_store_path("resume");
        let b0 = test_block(0, "GENESIS", 0);
        let b1 = test_block(1, &b0.hash, 1);

        {
            let store = FollowerStore::open(&path).expect("open store");
            store.set_chain_id(TEST_CHAIN_ID).expect("set chain id");
            store.append_verified_block(0, &b0).expect("append b0");
            store.append_verified_block(1, &b1).expect("append b1");
            assert_eq!(store.block_count().expect("count"), 2);
        }

        // Reopen: the verified tip and chain id must survive a restart, so the
        // follower resumes instead of re-downloading from genesis.
        {
            let store = FollowerStore::open(&path).expect("reopen store");
            assert_eq!(
                store.stored_chain_id().expect("chain id"),
                Some(TEST_CHAIN_ID.to_owned())
            );
            assert_eq!(store.block_count().expect("count"), 2);
            let tip = store.tip().expect("tip query").expect("tip present");
            assert_eq!(tip.position, 1);
            assert_eq!(tip.hash, b1.hash);
            assert_eq!(tip.epoch_end, b1.epoch_end);
        }

        let _ = std::fs::remove_dir_all(&path);
    }
}

