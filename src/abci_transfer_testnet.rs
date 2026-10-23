//! Isolated A-Network transfer ABCI app for testnet experiments only.
//! This module is not present in default builds and does not alter production.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tendermint_abci::{Application, ServerBuilder};
use tendermint_proto::v0_38::abci::{
    response_process_proposal::ProposalStatus, ExecTxResult, RequestCheckTx, RequestFinalizeBlock,
    RequestInfo, RequestInitChain, RequestPrepareProposal, RequestProcessProposal, RequestQuery,
    ResponseCheckTx, ResponseCommit, ResponseFinalizeBlock, ResponseInfo, ResponseInitChain,
    ResponsePrepareProposal, ResponseProcessProposal, ResponseQuery,
};

use crate::{
    activation::{self, GenesisConfig},
    block::Block,
    events::ChainEvent,
    oracle::{snapshot_signing_hash, verify_session_snapshot, SignedSessionSnapshot},
    session_commit::{verify_inclusion, SessionInclusionProof, SessionTree},
    state::{self, AccountState},
    transaction::{
        canonical_json_string, is_valid_anet_wallet, SignedTransactionRequest, Transaction,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppState {
    chain_id: String,
    session_oracle: String,
    session_root: String,
    session_snapshot_as_of_ms: i64,
    height: i64,
    accounts: HashMap<String, AccountState>,
    account_nonces: HashMap<String, u64>,
    last_anet_block_hash: String,
    #[serde(default)]
    imported_from: Option<ImportProvenance>,
    #[serde(default)]
    carried_dex_pools: BTreeMap<String, Value>,
    #[serde(default)]
    carried_token_registry: BTreeMap<String, Value>,
    app_hash: Vec<u8>,
}

/// Where an imported state came from; committed into the app hash so every
/// validator must have replayed the identical source chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ImportProvenance {
    source_chain_id: String,
    source_tip_hash: String,
    source_tip_height: u64,
    source_block_count: u64,
}

struct Runtime {
    committed: AppState,
    pending: Option<AppState>,
    mempool: Vec<TestnetCommand>,
}

#[derive(Debug, Clone)]
enum TestnetCommand {
    Transfer(Transaction),
    SessionSnapshot(SignedSessionSnapshot),
}

#[derive(Clone)]
struct TestnetAbciApp {
    chain_id: String,
    oracle_address: String,
    runtime: Arc<Mutex<Runtime>>,
    state_path: PathBuf,
}

impl TestnetAbciApp {
    fn open(
        chain_id: String,
        oracle_address: String,
        genesis_path: PathBuf,
        state_path: PathBuf,
    ) -> Result<Self> {
        let oracle_address = normalize_oracle(&oracle_address)?;
        let genesis: GenesisConfig =
            serde_json::from_slice(&fs::read(&genesis_path).with_context(|| {
                format!("failed to read test genesis {}", genesis_path.display())
            })?)
            .context("failed to parse test genesis")?;
        if genesis.chain_id != chain_id {
            bail!("test genesis chain ID does not match ANET_CHAIN_ID");
        }
        let session_entries = genesis
            .accounts
            .iter()
            .map(|account| (account.address.clone(), account.sessions))
            .collect::<Vec<_>>();
        let session_root = SessionTree::build(&session_entries).root();
        let genesis_time_ms = genesis.genesis_time.timestamp_millis();
        let accounts = genesis
            .accounts
            .into_iter()
            .map(|account| {
                let address = account.address.trim().to_uppercase();
                let balance = account.ants_balance;
                (
                    address.clone(),
                    AccountState {
                        address,
                        ants_balance: balance,
                        activated_ants: balance,
                        total_activated_ants: account.total_activated_ants.max(balance),
                        sessions: account.sessions,
                        asset_balances: HashMap::new(),
                    },
                )
            })
            .collect();
        let initial = AppState {
            chain_id: chain_id.clone(),
            session_oracle: oracle_address.clone(),
            session_root,
            session_snapshot_as_of_ms: genesis_time_ms,
            height: 0,
            accounts,
            account_nonces: HashMap::new(),
            last_anet_block_hash: "GENESIS".to_owned(),
            imported_from: None,
            carried_dex_pools: BTreeMap::new(),
            carried_token_registry: BTreeMap::new(),
            app_hash: Vec::new(),
        };
        Self::from_initial_state(chain_id, oracle_address, initial, state_path)
    }

    /// Start the test consensus from a verified replica of another chain: the
    /// replica is replayed with the production rules and the first new block
    /// links to the replica's tip hash.
    fn open_from_replica(
        chain_id: String,
        oracle_address: String,
        replica_path: PathBuf,
        expected_source_chain_id: &str,
        state_path: PathBuf,
    ) -> Result<Self> {
        let oracle_address = normalize_oracle(&oracle_address)?;
        let (source_chain_id, blocks) = crate::sync::load_follower_replica(&replica_path)?;
        if source_chain_id != expected_source_chain_id {
            bail!(
                "replica chain ID {source_chain_id} does not match ANET_ABCI_IMPORT_SOURCE_CHAIN_ID"
            );
        }
        if source_chain_id == chain_id {
            bail!("imported test consensus must run under a different chain ID than its source");
        }
        let replayed = state::replay_verified_chain(&blocks)?;
        let tip_time_ms = blocks
            .last()
            .map(|block| block.epoch_end.timestamp_millis())
            .unwrap_or_default();
        let session_entries = replayed
            .accounts
            .values()
            .map(|account| (account.address.clone(), account.sessions))
            .collect::<Vec<_>>();
        let session_root = SessionTree::build(&session_entries).root();
        let to_value_map = |map: &HashMap<String, _>| -> Result<BTreeMap<String, Value>> {
            map.iter()
                .map(|(key, value)| Ok((key.clone(), serde_json::to_value(value)?)))
                .collect()
        };
        let dex_pools: HashMap<String, Value> = replayed
            .dex_pools
            .iter()
            .map(|(key, pool)| Ok((key.clone(), serde_json::to_value(pool)?)))
            .collect::<Result<_>>()?;
        let tokens: HashMap<String, Value> = replayed
            .token_registry
            .iter()
            .map(|(key, token)| Ok((key.clone(), serde_json::to_value(token)?)))
            .collect::<Result<_>>()?;
        let initial = AppState {
            chain_id: chain_id.clone(),
            session_oracle: oracle_address.clone(),
            session_root,
            session_snapshot_as_of_ms: tip_time_ms,
            height: 0,
            accounts: replayed.accounts,
            account_nonces: replayed.account_nonces,
            last_anet_block_hash: replayed.tip_hash.clone(),
            imported_from: Some(ImportProvenance {
                source_chain_id,
                source_tip_hash: replayed.tip_hash,
                source_tip_height: replayed.tip_height,
                source_block_count: replayed.block_count,
            }),
            carried_dex_pools: to_value_map(&dex_pools)?,
            carried_token_registry: to_value_map(&tokens)?,
            app_hash: Vec::new(),
        };
        Self::from_initial_state(chain_id, oracle_address, initial, state_path)
    }

    fn from_initial_state(
        chain_id: String,
        oracle_address: String,
        initial: AppState,
        state_path: PathBuf,
    ) -> Result<Self> {
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut committed = if state_path.exists() {
            let state: AppState = serde_json::from_slice(&fs::read(&state_path)?)
                .context("failed to parse persisted ABCI test state")?;
            if state.chain_id != chain_id {
                bail!("persisted test state belongs to a different chain ID");
            }
            if state.session_oracle != oracle_address {
                bail!("persisted test oracle does not match ANET_ABCI_TEST_ORACLE_ADDRESS");
            }
            if state.imported_from != initial.imported_from {
                bail!("persisted test state was initialized from a different source chain");
            }
            if state.imported_from.is_none() && state.session_root != initial.session_root {
                bail!("persisted session root does not match the test genesis");
            }
            state
        } else {
            initial
        };
        let expected_app_hash = deterministic_app_hash(&committed)?;
        if committed.app_hash.is_empty() {
            committed.app_hash = expected_app_hash;
        } else if committed.app_hash != expected_app_hash {
            bail!("persisted ABCI test state app hash does not match its contents");
        }

        Ok(Self {
            chain_id,
            oracle_address,
            runtime: Arc::new(Mutex::new(Runtime {
                committed,
                pending: None,
                mempool: Vec::new(),
            })),
            state_path,
        })
    }

    fn parse_command(&self, raw: &[u8]) -> std::result::Result<TestnetCommand, String> {
        if let Ok(snapshot) = serde_json::from_slice::<SignedSessionSnapshot>(raw) {
            if snapshot.chain_id.trim() != self.chain_id {
                return Err("session snapshot chain ID does not match test app".to_owned());
            }
            return Ok(TestnetCommand::SessionSnapshot(snapshot));
        }

        let request: SignedTransactionRequest =
            serde_json::from_slice(raw).map_err(|error| error.to_string())?;
        let transaction = request
            .into_transaction()
            .map_err(|error| error.to_string())?;
        if transaction.chain_id != self.chain_id {
            return Err("transaction chain ID does not match test app".to_owned());
        }
        Ok(TestnetCommand::Transfer(transaction))
    }

    fn persist(&self, state: &AppState) -> Result<()> {
        let bytes = serde_json::to_vec(state)?;
        let temporary = self.state_path.with_extension("tmp");
        fs::write(&temporary, bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        fs::rename(&temporary, &self.state_path)
            .with_context(|| format!("failed to persist {}", self.state_path.display()))
    }
}

#[derive(Serialize)]
struct CanonicalAccount {
    address: String,
    ants_balance: u64,
    activated_ants: u64,
    total_activated_ants: u64,
    sessions: u64,
    asset_balances: BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct CanonicalAppState {
    chain_id: String,
    session_oracle: String,
    session_root: String,
    session_snapshot_as_of_ms: i64,
    height: i64,
    last_anet_block_hash: String,
    accounts: BTreeMap<String, CanonicalAccount>,
    account_nonces: BTreeMap<String, u64>,
    imported_from: Option<ImportProvenance>,
    carried_dex_pools: BTreeMap<String, Value>,
    carried_token_registry: BTreeMap<String, Value>,
}

fn normalize_oracle(oracle_address: &str) -> Result<String> {
    let oracle_address = oracle_address.trim().to_uppercase();
    if !is_valid_anet_wallet(&oracle_address) {
        bail!("test session oracle address is not a valid ANET wallet");
    }
    Ok(oracle_address)
}

fn deterministic_app_hash(state: &AppState) -> Result<Vec<u8>> {
    let accounts = state
        .accounts
        .iter()
        .map(|(key, account)| {
            let canonical = CanonicalAccount {
                address: account.address.clone(),
                ants_balance: account.ants_balance,
                activated_ants: account.activated_ants,
                total_activated_ants: account.total_activated_ants,
                sessions: account.sessions,
                asset_balances: account
                    .asset_balances
                    .iter()
                    .map(|(symbol, amount)| (symbol.clone(), *amount))
                    .collect(),
            };
            (key.clone(), canonical)
        })
        .collect();
    let account_nonces = state
        .account_nonces
        .iter()
        .map(|(address, nonce)| (address.clone(), *nonce))
        .collect();
    let canonical = CanonicalAppState {
        chain_id: state.chain_id.clone(),
        session_oracle: state.session_oracle.clone(),
        session_root: state.session_root.clone(),
        session_snapshot_as_of_ms: state.session_snapshot_as_of_ms,
        height: state.height,
        last_anet_block_hash: state.last_anet_block_hash.clone(),
        accounts,
        account_nonces,
        imported_from: state.imported_from.clone(),
        carried_dex_pools: state.carried_dex_pools.clone(),
        carried_token_registry: state.carried_token_registry.clone(),
    };
    // Canonical (sorted-key) JSON so nested carried values hash identically.
    let canonical_json = canonical_json_string(&serde_json::to_value(&canonical)?)?;
    Ok(Sha256::digest(canonical_json.as_bytes()).to_vec())
}

fn block_time(
    timestamp: Option<&tendermint_proto::google::protobuf::Timestamp>,
) -> std::result::Result<DateTime<Utc>, String> {
    let timestamp = timestamp.ok_or_else(|| "consensus timestamp is missing".to_owned())?;
    let nanos = u32::try_from(timestamp.nanos)
        .map_err(|_| "consensus timestamp nanoseconds are invalid".to_owned())?;
    DateTime::from_timestamp(timestamp.seconds, nanos)
        .ok_or_else(|| "consensus timestamp is invalid".to_owned())
}

fn decode_commands(
    app: &TestnetAbciApp,
    raw_transactions: &[Bytes],
) -> std::result::Result<Vec<TestnetCommand>, String> {
    raw_transactions
        .iter()
        .map(|raw| app.parse_command(raw))
        .collect()
}

fn command_id(command: &TestnetCommand) -> std::result::Result<String, String> {
    match command {
        TestnetCommand::Transfer(transaction) => {
            transaction.id().map_err(|error| error.to_string())
        }
        TestnetCommand::SessionSnapshot(snapshot) => Ok(snapshot_signing_hash(
            &snapshot.chain_id,
            snapshot.as_of_ms,
            &snapshot.entries,
        )),
    }
}

fn ordered_ids(commands: &[TestnetCommand]) -> Vec<String> {
    commands
        .iter()
        .map(|command| command_id(command).unwrap_or_default())
        .collect()
}

fn canonicalize_commands(
    mut commands: Vec<TestnetCommand>,
) -> std::result::Result<Vec<TestnetCommand>, String> {
    if commands.iter().all(|command| matches!(command, TestnetCommand::Transfer(_))) {
        let mut transactions = commands
            .drain(..)
            .filter_map(|command| match command {
                TestnetCommand::Transfer(transaction) => Some(transaction),
                TestnetCommand::SessionSnapshot(_) => None,
            })
            .collect::<Vec<_>>();
        state::sort_abci_testnet_transactions(&mut transactions);
        return Ok(transactions
            .into_iter()
            .map(TestnetCommand::Transfer)
            .collect());
    }
    if commands.len() == 1
        && matches!(commands.first(), Some(TestnetCommand::SessionSnapshot(_)))
    {
        return Ok(commands);
    }
    Err("a proposal must contain either transfers or one session snapshot".to_owned())
}

fn verify_session_eligibility_proof(
    transaction: &Transaction,
    side: &str,
    expected_wallet: &str,
    expected_root: &str,
) -> std::result::Result<(), String> {
    let proof_value = transaction
        .payload
        .get("session_proofs")
        .and_then(Value::as_object)
        .and_then(|proofs| proofs.get(side))
        .cloned()
        .ok_or_else(|| format!("missing {side} session inclusion proof"))?;
    let proof: SessionInclusionProof = serde_json::from_value(proof_value)
        .map_err(|error| format!("invalid {side} session inclusion proof: {error}"))?;
    if proof.wallet.trim().to_uppercase() != expected_wallet {
        return Err(format!(
            "{side} session proof wallet does not match transaction"
        ));
    }
    if proof.root != expected_root || !verify_inclusion(&proof) {
        return Err(format!(
            "{side} session inclusion proof is not under the test genesis root"
        ));
    }
    if !activation::is_session_eligible(proof.sessions) {
        return Err(format!(
            "{side} wallet does not meet the testnet 1,000-session gate"
        ));
    }
    Ok(())
}

fn build_next_block(
    state_snapshot: &AppState,
    commands: Vec<TestnetCommand>,
    height: i64,
    time: DateTime<Utc>,
    oracle_address: &str,
) -> std::result::Result<(AppState, Block), String> {
    let expected_height = state_snapshot.height.saturating_add(1);
    if height != expected_height {
        return Err(format!("expected height {expected_height}, got {height}"));
    }
    let commands = canonicalize_commands(commands)?;
    let mut accounts = state_snapshot.accounts.clone();
    let mut account_nonces = state_snapshot.account_nonces.clone();
    let mut session_root = state_snapshot.session_root.clone();
    let mut session_snapshot_as_of_ms = state_snapshot.session_snapshot_as_of_ms;
    let mut events = Vec::new();
    let transactions = match commands.as_slice() {
        [TestnetCommand::SessionSnapshot(snapshot)] => {
            let verified = verify_session_snapshot(
                snapshot,
                oracle_address,
                &state_snapshot.chain_id,
                0,
            )
            .map_err(|error| error.to_string())?;
            let block_time_ms = time.timestamp_millis();
            if snapshot.as_of_ms <= state_snapshot.session_snapshot_as_of_ms {
                return Err("session snapshot timestamp was already applied".to_owned());
            }
            if snapshot.as_of_ms > block_time_ms {
                return Err("session snapshot timestamp is after the consensus block time".to_owned());
            }
            if block_time_ms.saturating_sub(snapshot.as_of_ms) > 600_000 {
                return Err("session snapshot is stale at the consensus block time".to_owned());
            }

            let entries_by_wallet = verified
                .entries
                .iter()
                .map(|entry| (entry.wallet.clone(), entry.sessions))
                .collect::<HashMap<_, _>>();
            for (wallet, account) in &state_snapshot.accounts {
                if (account.ants_balance > 0 || account.sessions > 0)
                    && !entries_by_wallet.contains_key(wallet)
                {
                    return Err(format!("session snapshot omitted active account {wallet}"));
                }
            }
            for entry in &verified.entries {
                let wallet = entry.wallet.trim().to_uppercase();
                let account = accounts.entry(wallet.clone()).or_insert(AccountState {
                    address: wallet.clone(),
                    ants_balance: 0,
                    activated_ants: 0,
                    total_activated_ants: 0,
                    sessions: 0,
                    asset_balances: HashMap::new(),
                });
                if entry.sessions < account.sessions {
                    return Err(format!("session count decreased for {wallet}"));
                }
                account.sessions = entry.sessions;
            }

            let entries = verified
                .entries
                .iter()
                .map(|entry| (entry.wallet.clone(), entry.sessions))
                .collect::<Vec<_>>();
            session_root = SessionTree::build(&entries).root();
            session_snapshot_as_of_ms = snapshot.as_of_ms;
            let mut attributes = BTreeMap::new();
            attributes.insert("root".to_owned(), session_root.clone());
            attributes.insert("leaf_count".to_owned(), verified.entries.len().to_string());
            attributes.insert("as_of_ms".to_owned(), snapshot.as_of_ms.to_string());
            events.push(ChainEvent {
                event_type: "SessionProgressRoot".to_owned(),
                timestamp: time,
                tx_hash: None,
                attributes,
            });
            Vec::new()
        }
        commands => {
            let transactions = commands
                .iter()
                .map(|command| match command {
                    TestnetCommand::Transfer(transaction) => Ok(transaction.clone()),
                    TestnetCommand::SessionSnapshot(_) => Err(
                        "session snapshots cannot be mixed with transfers".to_owned(),
                    ),
                })
                .collect::<std::result::Result<Vec<_>, String>>()?;
            for transaction in &transactions {
                transaction
                    .validate_signed_for_chain(&state_snapshot.chain_id)
                    .map_err(|error| error.to_string())?;
                if !state_snapshot.accounts.contains_key(&transaction.from) {
                    return Err("sender account not found".to_owned());
                }
                if !state_snapshot.accounts.contains_key(&transaction.to) {
                    return Err("recipient account not found".to_owned());
                }
                verify_session_eligibility_proof(
                    transaction,
                    "from",
                    &transaction.from,
                    &state_snapshot.session_root,
                )?;
                verify_session_eligibility_proof(
                    transaction,
                    "to",
                    &transaction.to,
                    &state_snapshot.session_root,
                )?;
                let expected_nonce = account_nonces
                    .get(&transaction.from)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| "transaction nonce overflow".to_owned())?;
                if transaction.nonce != expected_nonce {
                    return Err(format!(
                        "sender nonce mismatch: expected {expected_nonce}, got {}",
                        transaction.nonce
                    ));
                }
                account_nonces.insert(transaction.from.clone(), transaction.nonce);
            }
            events = transactions
                .iter()
                .map(|transaction| {
                    let mut attributes = BTreeMap::new();
                    attributes.insert("amount".to_owned(), transaction.amount_ants.to_string());
                    attributes.insert("from".to_owned(), transaction.from.clone());
                    attributes.insert("symbol".to_owned(), "ANET".to_owned());
                    attributes.insert("to".to_owned(), transaction.to.clone());
                    Ok(ChainEvent {
                        event_type: "TokenTransferred".to_owned(),
                        timestamp: time,
                        tx_hash: Some(transaction.id().map_err(|error| error.to_string())?),
                        attributes,
                    })
                })
                .collect::<std::result::Result<Vec<_>, String>>()?;
            transactions
        }
    };

    if !transactions.is_empty() {
        let mut block = Block::new(
            height as u64,
            time,
            time + ChronoDuration::seconds(2),
            state_snapshot.last_anet_block_hash.clone(),
            transactions.clone(),
            0,
            state::compute_validators_from_accounts(&accounts),
            None,
            events,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            Vec::<Value>::new(),
            Vec::new(),
            String::new(),
            state::abci_testnet_proof_root(&[]).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        state::apply_abci_testnet_block(&mut accounts, &block)
            .map_err(|error| error.to_string())?;
        block.account_state_changes = accounts
            .iter()
            .filter(|(address, account)| state_snapshot.accounts.get(*address) != Some(*account))
            .map(|(address, account)| (address.clone(), account.clone()))
            .collect();
        block.state_root = state::abci_testnet_state_root(&block.account_state_changes)
            .map_err(|error| error.to_string())?;
        block.hash = block.compute_hash().map_err(|error| error.to_string())?;
        block
            .validate_structure()
            .map_err(|error| error.to_string())?;
        if !block.validate_hash().map_err(|error| error.to_string())? {
            return Err("constructed ANET block hash is invalid".to_owned());
        }

        let mut next_state = state_snapshot.clone();
        next_state.height = height;
        next_state.accounts = accounts;
        next_state.account_nonces = account_nonces;
        next_state.last_anet_block_hash = block.hash.clone();
        next_state.app_hash =
            deterministic_app_hash(&next_state).map_err(|error| error.to_string())?;
        return Ok((next_state, block));
    }

    let mut block = Block::new(
        height as u64,
        time,
        time + ChronoDuration::seconds(2),
        state_snapshot.last_anet_block_hash.clone(),
        Vec::new(),
        0,
        state::compute_validators_from_accounts(&accounts),
        None,
        events,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        Vec::<Value>::new(),
        Vec::new(),
        String::new(),
        state::abci_testnet_proof_root(&[]).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    block.account_state_changes = accounts
        .iter()
        .filter(|(address, account)| state_snapshot.accounts.get(*address) != Some(*account))
        .map(|(address, account)| (address.clone(), account.clone()))
        .collect();
    block.state_root = state::abci_testnet_state_root(&block.account_state_changes)
        .map_err(|error| error.to_string())?;
    block.hash = block.compute_hash().map_err(|error| error.to_string())?;
    block
        .validate_structure()
        .map_err(|error| error.to_string())?;
    if !block.validate_hash().map_err(|error| error.to_string())? {
        return Err("constructed ANET block hash is invalid".to_owned());
    }

    let mut next_state = state_snapshot.clone();
    next_state.height = height;
    next_state.accounts = accounts;
    next_state.account_nonces = account_nonces;
    next_state.session_root = session_root;
    next_state.session_snapshot_as_of_ms = session_snapshot_as_of_ms;
    next_state.last_anet_block_hash = block.hash.clone();
    next_state.app_hash = deterministic_app_hash(&next_state).map_err(|error| error.to_string())?;
    Ok((next_state, block))
}

fn response_check(code: u32, log: impl Into<String>) -> ResponseCheckTx {
    ResponseCheckTx {
        code,
        data: Bytes::new(),
        log: log.into(),
        info: String::new(),
        gas_wanted: 0,
        gas_used: 0,
        events: Vec::new(),
        codespace: "anet-testnet".to_owned(),
    }
}

impl Application for TestnetAbciApp {
    fn info(&self, _request: RequestInfo) -> ResponseInfo {
        let runtime = self.runtime.lock().expect("ABCI test state poisoned");
        ResponseInfo {
            data: "anet-abci-test-only".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: 1,
            last_block_height: runtime.committed.height,
            last_block_app_hash: Bytes::copy_from_slice(&runtime.committed.app_hash),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        let runtime = self.runtime.lock().expect("ABCI test state poisoned");
        assert_eq!(
            request.chain_id, runtime.committed.chain_id,
            "Comet and ANET test chain IDs must match"
        );
        ResponseInitChain {
            app_hash: Bytes::copy_from_slice(&runtime.committed.app_hash),
            ..Default::default()
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        if request.path == "/import" {
            let runtime = self.runtime.lock().expect("ABCI test state poisoned");
            let committed = &runtime.committed;
            let value = serde_json::to_vec(&serde_json::json!({
                "chain_id": committed.chain_id,
                "imported_from": committed.imported_from,
                "last_anet_block_hash": committed.last_anet_block_hash,
                "session_root": committed.session_root,
                "account_count": committed.accounts.len(),
                "total_ants": committed.accounts.values().map(|a| a.ants_balance as u128).sum::<u128>().to_string(),
                "carried_dex_pools": committed.carried_dex_pools.keys().collect::<Vec<_>>(),
                "carried_tokens": committed.carried_token_registry.keys().collect::<Vec<_>>(),
                "app_hash": hex::encode(&committed.app_hash),
            }))
            .unwrap_or_default();
            return ResponseQuery {
                log: "import provenance".to_owned(),
                value: Bytes::from(value),
                height: committed.height,
                ..Default::default()
            };
        }
        if request.path != "/account" {
            return ResponseQuery {
                code: 1,
                log: "supported test query paths: /account, /import".to_owned(),
                height: self
                    .runtime
                    .lock()
                    .expect("ABCI test state poisoned")
                    .committed
                    .height,
                ..Default::default()
            };
        }
        let address = match std::str::from_utf8(&request.data) {
            Ok(address) => address.trim().to_uppercase(),
            Err(error) => {
                return ResponseQuery {
                    code: 1,
                    log: error.to_string(),
                    ..Default::default()
                }
            }
        };
        let runtime = self.runtime.lock().expect("ABCI test state poisoned");
        let Some(account) = runtime.committed.accounts.get(&address) else {
            return ResponseQuery {
                code: 1,
                log: "account not found".to_owned(),
                height: runtime.committed.height,
                ..Default::default()
            };
        };
        let value = serde_json::to_vec(&serde_json::json!({
            "account": account,
            "nonce": runtime.committed.account_nonces.get(&address).copied().unwrap_or(0),
            "chain_id": runtime.committed.chain_id,
            "session_oracle": runtime.committed.session_oracle,
            "session_root": runtime.committed.session_root,
            "session_snapshot_as_of_ms": runtime.committed.session_snapshot_as_of_ms,
        }))
        .unwrap_or_default();
        ResponseQuery {
            log: "account found".to_owned(),
            key: request.data,
            value: Bytes::from(value),
            height: runtime.committed.height,
            ..Default::default()
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        let command = match self.parse_command(&request.tx) {
            Ok(command) => command,
            Err(error) => return response_check(1, error),
        };
        let mut runtime = self.runtime.lock().expect("ABCI test state poisoned");
        let tx_id = match command_id(&command) {
            Ok(tx_id) => tx_id,
            Err(error) => return response_check(1, error),
        };
        if runtime
            .mempool
            .iter()
            .any(|pending| command_id(pending).as_deref() == Ok(tx_id.as_str()))
        {
            return response_check(0, "already admitted to test mempool");
        }
        let mut candidate = runtime.mempool.clone();
        candidate.push(command.clone());
        candidate = match canonicalize_commands(candidate) {
            Ok(candidate) => candidate,
            Err(error) => return response_check(1, error),
        };
        let time = Utc::now();
        match build_next_block(
            &runtime.committed,
            candidate,
            runtime.committed.height.saturating_add(1),
            time,
            &self.oracle_address,
        ) {
            Ok(_) => {
                runtime.mempool.push(command);
                response_check(0, "accepted by isolated ANET test app")
            }
            Err(error) => response_check(1, error),
        }
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        let time = match block_time(request.time.as_ref()) {
            Ok(time) => time,
            Err(_) => return ResponsePrepareProposal { txs: Vec::new() },
        };
        let runtime = self.runtime.lock().expect("ABCI test state poisoned");
        let mut candidates = Vec::new();
        let mut raw_by_id = HashMap::new();
        for raw in request.txs {
            let Ok(command) = self.parse_command(&raw) else {
                continue;
            };
            let Ok(tx_id) = command_id(&command) else {
                continue;
            };
            raw_by_id.entry(tx_id).or_insert(raw);
            candidates.push(command);
        }
        let candidates = match canonicalize_commands(candidates) {
            Ok(candidates) => candidates,
            Err(_) => return ResponsePrepareProposal { txs: Vec::new() },
        };
        let max_bytes = usize::try_from(request.max_tx_bytes).unwrap_or(usize::MAX);
        let mut selected_commands = Vec::new();
        let mut selected_bytes = Vec::new();
        let mut selected_total_bytes = 0usize;
        for command in candidates {
            let tx_id = match command_id(&command) {
                Ok(tx_id) => tx_id,
                Err(_) => continue,
            };
            let Some(encoded) = raw_by_id.get(&tx_id) else {
                continue;
            };
            if selected_total_bytes.saturating_add(encoded.len()) > max_bytes {
                continue;
            }
            let mut candidate = selected_commands.clone();
            candidate.push(command.clone());
            if build_next_block(
                &runtime.committed,
                candidate,
                request.height,
                time,
                &self.oracle_address,
            )
            .is_ok()
            {
                selected_total_bytes = selected_total_bytes.saturating_add(encoded.len());
                selected_commands.push(command);
                selected_bytes.push(encoded.clone());
            }
        }
        ResponsePrepareProposal {
            txs: selected_bytes,
        }
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        let reject = || ResponseProcessProposal {
            status: ProposalStatus::Reject as i32,
        };
        let time = match block_time(request.time.as_ref()) {
            Ok(time) => time,
            Err(_) => return reject(),
        };
        let mut commands = match decode_commands(self, &request.txs) {
            Ok(commands) => commands,
            Err(_) => return reject(),
        };
        let original_ids = ordered_ids(&commands);
        commands = match canonicalize_commands(commands) {
            Ok(commands) => commands,
            Err(_) => return reject(),
        };
        if ordered_ids(&commands) != original_ids {
            return reject();
        }
        let runtime = self.runtime.lock().expect("ABCI test state poisoned");
        let status = if build_next_block(
            &runtime.committed,
            commands,
            request.height,
            time,
            &self.oracle_address,
        )
        .is_ok()
        {
            ProposalStatus::Accept
        } else {
            ProposalStatus::Reject
        };
        ResponseProcessProposal {
            status: status as i32,
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let parsed = decode_commands(self, &request.txs);
        let time = block_time(request.time.as_ref());
        let mut runtime = self.runtime.lock().expect("ABCI test state poisoned");
        match time.and_then(|time| {
            parsed.and_then(|commands| {
                let original_ids = ordered_ids(&commands);
                let sorted = canonicalize_commands(commands)?;
                if ordered_ids(&sorted) != original_ids {
                    return Err(
                        "committed proposal is not in canonical ANET command order".to_owned(),
                    );
                }
                build_next_block(
                    &runtime.committed,
                    sorted,
                    request.height,
                    time,
                    &self.oracle_address,
                )
            })
        }) {
            Ok((next_state, _block)) => {
                let tx_results = request
                    .txs
                    .iter()
                    .map(|_| ExecTxResult {
                        code: 0,
                        ..Default::default()
                    })
                    .collect();
                let app_hash = Bytes::copy_from_slice(&next_state.app_hash);
                runtime.pending = Some(next_state);
                ResponseFinalizeBlock {
                    tx_results,
                    app_hash,
                    ..Default::default()
                }
            }
            Err(error) => ResponseFinalizeBlock {
                tx_results: request
                    .txs
                    .iter()
                    .map(|_| ExecTxResult {
                        code: 1,
                        log: error.clone(),
                        ..Default::default()
                    })
                    .collect(),
                app_hash: Bytes::copy_from_slice(&runtime.committed.app_hash),
                ..Default::default()
            },
        }
    }

    fn commit(&self) -> ResponseCommit {
        let mut runtime = self.runtime.lock().expect("ABCI test state poisoned");
        if let Some(pending) = runtime.pending.take() {
            if let Err(error) = self.persist(&pending) {
                panic!("failed to persist isolated ANET ABCI state: {error}");
            }
            runtime.committed = pending;
            runtime.mempool.clear();
        }
        ResponseCommit::default()
    }
}

pub fn run_from_env() -> Result<()> {
    if std::env::var("ANET_ENV").unwrap_or_default() != "testnet" {
        bail!("ABCI testnet mode requires ANET_ENV=testnet");
    }
    let chain_id = std::env::var("ANET_CHAIN_ID").context("ANET_CHAIN_ID is required")?;
    if chain_id.is_empty() || chain_id == activation::CHAIN_ID {
        bail!("ABCI testnet mode requires a non-production chain ID");
    }
    let state_path = std::env::var_os("ANET_ABCI_TEST_STATE")
        .map(PathBuf::from)
        .context("ANET_ABCI_TEST_STATE must be unique per validator")?;
    let oracle_address = std::env::var("ANET_ABCI_TEST_ORACLE_ADDRESS")
        .context("ANET_ABCI_TEST_ORACLE_ADDRESS is required")?;
    let bind =
        std::env::var("ANET_ABCI_TEST_BIND").unwrap_or_else(|_| "127.0.0.1:27558".to_owned());

    let app = match std::env::var_os("ANET_ABCI_IMPORT_REPLICA") {
        Some(replica) => {
            let source_chain_id = std::env::var("ANET_ABCI_IMPORT_SOURCE_CHAIN_ID")
                .context("ANET_ABCI_IMPORT_SOURCE_CHAIN_ID is required with a replica")?;
            TestnetAbciApp::open_from_replica(
                chain_id,
                oracle_address,
                PathBuf::from(replica),
                &source_chain_id,
                state_path,
            )?
        }
        None => {
            let genesis_path = std::env::var_os("ANET_ABCI_TEST_GENESIS")
                .map(PathBuf::from)
                .context("ANET_ABCI_TEST_GENESIS is required")?;
            TestnetAbciApp::open(chain_id, oracle_address, genesis_path, state_path)?
        }
    };
    ServerBuilder::default()
        .bind(bind.as_str(), app)
        .with_context(|| format!("failed to bind ABCI test server on {bind}"))?
        .listen()
        .context("ABCI test server stopped")?;
    Ok(())
}
