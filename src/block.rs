use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::{
    dex::DexPool,
    events::ChainEvent,
    state::{AccountState, BRIDGE_CREDIT_MEMO_PREFIX, BRIDGE_TREASURY_ADDRESS, MIGRATION_SWEEP_MEMO_PREFIX},
    token::Anrc20Token,
    transaction::{canonical_json_string, Transaction},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    #[serde(default)]
    pub hash_version: u8,
    pub block_height: u64,
    pub epoch_start: DateTime<Utc>,
    pub epoch_end: DateTime<Utc>,
    pub previous_hash: String,
    pub hash: String,
    pub transactions: Vec<Transaction>,
    pub activated_supply_ants: u64,
    pub total_fees_ants: u64,
    pub miners: Vec<String>,
    pub fee_per_miner: u64,
    pub block_event: Option<String>,
    #[serde(default)]
    pub events: Vec<ChainEvent>,
    #[serde(default)]
    pub account_state_changes: HashMap<String, AccountState>,
    #[serde(default)]
    pub dex_pools: HashMap<String, DexPool>,
    #[serde(default)]
    pub token_registry: HashMap<String, Anrc20Token>,
    #[serde(default)]
    pub tpow_proofs: Vec<serde_json::Value>,
    #[serde(default)]
    pub validator_votes: Vec<serde_json::Value>,
    #[serde(default)]
    pub state_root: String,
    #[serde(default)]
    pub proof_root: String,
}

#[derive(Debug, Clone, Serialize)]
struct BlockHashPayload<'a> {
    hash_version: u8,
    block_height: u64,
    epoch_start: DateTime<Utc>,
    epoch_end: DateTime<Utc>,
    previous_hash: &'a str,
    transactions: &'a [Transaction],
    activated_supply_ants: u64,
    total_fees_ants: u64,
    miners: &'a [String],
    fee_per_miner: u64,
    block_event: &'a Option<String>,
    events: &'a [ChainEvent],
    account_state_changes: &'a HashMap<String, AccountState>,
    dex_pools: &'a HashMap<String, DexPool>,
    token_registry: &'a HashMap<String, Anrc20Token>,
    tpow_proofs: &'a [serde_json::Value],
    validator_votes: &'a [serde_json::Value],
    state_root: &'a str,
    proof_root: &'a str,
}

#[derive(Debug, Clone, Serialize)]
struct BlockHashPayloadV3<'a> {
    block_height: u64,
    epoch_start: DateTime<Utc>,
    epoch_end: DateTime<Utc>,
    previous_hash: &'a str,
    transactions: &'a [Transaction],
    activated_supply_ants: u64,
    total_fees_ants: u64,
    miners: &'a [String],
    fee_per_miner: u64,
    events: &'a [ChainEvent],
    dex_pools: &'a HashMap<String, DexPool>,
    token_registry: &'a HashMap<String, Anrc20Token>,
}

#[derive(Debug, Clone, Serialize)]
struct BlockHashPayloadLegacy<'a> {
    block_height: u64,
    epoch_start: DateTime<Utc>,
    epoch_end: DateTime<Utc>,
    previous_hash: &'a str,
    transactions: &'a [Transaction],
    activated_supply_ants: u64,
    total_fees_ants: u64,
    miners: &'a [String],
    fee_per_miner: u64,
}

#[derive(Debug, Clone, Serialize)]
struct LegacyTransactionHashPayload {
    from: String,
    to: String,
    amount_ants: u64,
    fee_ants: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    memo: String,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct BlockHashPayloadLegacyTx {
    block_height: u64,
    epoch_start: DateTime<Utc>,
    epoch_end: DateTime<Utc>,
    previous_hash: String,
    transactions: Vec<LegacyTransactionHashPayload>,
    activated_supply_ants: u64,
    total_fees_ants: u64,
    miners: Vec<String>,
    fee_per_miner: u64,
}

impl Block {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_height: u64,
        epoch_start: DateTime<Utc>,
        epoch_end: DateTime<Utc>,
        previous_hash: String,
        transactions: Vec<Transaction>,
        activated_supply_ants: u64,
        miners: Vec<String>,
        block_event: Option<String>,
        events: Vec<ChainEvent>,
        account_state_changes: HashMap<String, AccountState>,
        dex_pools: HashMap<String, DexPool>,
        token_registry: HashMap<String, Anrc20Token>,
        tpow_proofs: Vec<serde_json::Value>,
        validator_votes: Vec<serde_json::Value>,
        state_root: String,
        proof_root: String,
    ) -> Result<Self> {
        if epoch_end <= epoch_start {
            anyhow::bail!("block epoch_end must be greater than epoch_start");
        }

        for transaction in &transactions {
            transaction.validate()?;
        }

        let total_fees_ants = transactions.iter().try_fold(0_u64, |total, transaction| {
            total
                .checked_add(transaction.fee_ants)
                .ok_or_else(|| anyhow::anyhow!("block transaction fees overflowed"))
        })?;
        let fee_per_miner = if miners.is_empty() {
            0
        } else {
            total_fees_ants / miners.len() as u64
        };

        let mut block = Self {
            hash_version: 4,
            block_height,
            epoch_start,
            epoch_end,
            previous_hash,
            hash: String::new(),
            transactions,
            activated_supply_ants,
            total_fees_ants,
            miners,
            fee_per_miner,
            block_event,
            events,
            account_state_changes,
            dex_pools,
            token_registry,
            tpow_proofs,
            validator_votes,
            state_root,
            proof_root,
        };
        block.validate_structure()?;
        block.hash = block.compute_hash()?;
        Ok(block)
    }

    /// v4 (canonical): sorted-key, recursive JSON committing every persisted
    /// consensus field. New blocks use this format.
    pub fn compute_hash(&self) -> Result<String> {
        let payload = BlockHashPayload {
            hash_version: self.hash_version,
            block_height: self.block_height,
            epoch_start: self.epoch_start,
            epoch_end: self.epoch_end,
            previous_hash: &self.previous_hash,
            transactions: &self.transactions,
            activated_supply_ants: self.activated_supply_ants,
            total_fees_ants: self.total_fees_ants,
            miners: &self.miners,
            fee_per_miner: self.fee_per_miner,
            block_event: &self.block_event,
            events: &self.events,
            account_state_changes: &self.account_state_changes,
            dex_pools: &self.dex_pools,
            token_registry: &self.token_registry,
            tpow_proofs: &self.tpow_proofs,
            validator_votes: &self.validator_votes,
            state_root: &self.state_root,
            proof_root: &self.proof_root,
        };
        let value = serde_json::to_value(&payload)?;
        let preimage = canonical_json_string(&value)?;
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// v3 canonical payload used before all persisted proof/root fields were
    /// committed to the block hash.
    fn compute_hash_v3_canonical(&self) -> Result<String> {
        let payload = BlockHashPayloadV3 {
            block_height: self.block_height,
            epoch_start: self.epoch_start,
            epoch_end: self.epoch_end,
            previous_hash: &self.previous_hash,
            transactions: &self.transactions,
            activated_supply_ants: self.activated_supply_ants,
            total_fees_ants: self.total_fees_ants,
            miners: &self.miners,
            fee_per_miner: self.fee_per_miner,
            events: &self.events,
            dex_pools: &self.dex_pools,
            token_registry: &self.token_registry,
        };
        let value = serde_json::to_value(&payload)?;
        let preimage = canonical_json_string(&value)?;
        let mut hasher = Sha256::new();
        hasher.update(preimage.as_bytes());
        Ok(hex::encode(hasher.finalize()))
    }

    /// v2 (pre-S1-1): `serde_json::to_vec` on the full payload with events,
    /// dex_pools, token_registry. Kept ONLY for validating blocks that were
    /// produced by previous node versions before canonical hashing landed.
    /// New blocks are never produced with this format.
    fn compute_hash_v2_noncanonical(&self) -> Result<String> {
        let payload = BlockHashPayloadV3 {
            block_height: self.block_height,
            epoch_start: self.epoch_start,
            epoch_end: self.epoch_end,
            previous_hash: &self.previous_hash,
            transactions: &self.transactions,
            activated_supply_ants: self.activated_supply_ants,
            total_fees_ants: self.total_fees_ants,
            miners: &self.miners,
            fee_per_miner: self.fee_per_miner,
            events: &self.events,
            dex_pools: &self.dex_pools,
            token_registry: &self.token_registry,
        };
        let encoded = serde_json::to_vec(&payload)?;
        let mut hasher = Sha256::new();
        hasher.update(encoded);
        Ok(hex::encode(hasher.finalize()))
    }

    fn compute_hash_legacy(&self) -> Result<String> {
        let payload = BlockHashPayloadLegacy {
            block_height: self.block_height,
            epoch_start: self.epoch_start,
            epoch_end: self.epoch_end,
            previous_hash: &self.previous_hash,
            transactions: &self.transactions,
            activated_supply_ants: self.activated_supply_ants,
            total_fees_ants: self.total_fees_ants,
            miners: &self.miners,
            fee_per_miner: self.fee_per_miner,
        };
        let encoded = serde_json::to_vec(&payload)?;
        let mut hasher = Sha256::new();
        hasher.update(encoded);
        Ok(hex::encode(hasher.finalize()))
    }

    fn compute_hash_legacy_tx_shape(&self) -> Result<String> {
        let legacy_transactions = self
            .transactions
            .iter()
            .map(|tx| LegacyTransactionHashPayload {
                from: tx.from.clone(),
                to: tx.to.clone(),
                amount_ants: tx.amount_ants,
                fee_ants: tx.fee_ants,
                memo: tx.memo.clone(),
                timestamp: tx.timestamp,
            })
            .collect::<Vec<_>>();

        let payload = BlockHashPayloadLegacyTx {
            block_height: self.block_height,
            epoch_start: self.epoch_start,
            epoch_end: self.epoch_end,
            previous_hash: self.previous_hash.clone(),
            transactions: legacy_transactions,
            activated_supply_ants: self.activated_supply_ants,
            total_fees_ants: self.total_fees_ants,
            miners: self.miners.clone(),
            fee_per_miner: self.fee_per_miner,
        };

        let encoded = serde_json::to_vec(&payload)?;
        let mut hasher = Sha256::new();
        hasher.update(encoded);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn validate_hash(&self) -> Result<bool> {
        let new_hash = self.compute_hash()?;
        if self.hash == new_hash {
            return Ok(true);
        }

        // S1-5: operators bringing up a fresh deployment can opt out of the
        // legacy hash-format fallbacks by setting ANET_REJECT_LEGACY_HASHES=true.
        // Existing chains keep the relaxed behavior (default) so historical
        // blocks continue to validate; new chains can lock down their preimage
        // surface from day one.
        if self.hash_version >= 4 || reject_legacy_hashes() {
            return Ok(false);
        }

        let v3_hash = self.compute_hash_v3_canonical()?;
        if self.hash == v3_hash {
            tracing::warn!(
                "block {} validated using canonical v3 hash that omitted proof/root fields",
                self.block_height
            );
            return Ok(true);
        }

        // v2 non-canonical: blocks produced before S1-1 used the same payload
        // shape but `serde_json::to_vec` (declaration-ordered keys). Accept
        // these so existing chains keep replaying.
        let v2_hash = self.compute_hash_v2_noncanonical()?;
        if self.hash == v2_hash {
            tracing::warn!(
                "block {} validated using pre-canonical v2 hash; new blocks use canonical v4",
                self.block_height
            );
            return Ok(true);
        }

        // Try legacy hash computation for backward compatibility with pre-events blocks
        let legacy_hash = self.compute_hash_legacy()?;
        if self.hash == legacy_hash {
            tracing::warn!(
                "block {} validated using legacy hash format (pre-events); new blocks use canonical v4",
                self.block_height
            );
            return Ok(true);
        }

        // Oldest chains hashed transactions before signed fields existed on Transaction.
        let legacy_tx_shape_hash = self.compute_hash_legacy_tx_shape()?;
        if self.hash == legacy_tx_shape_hash {
            tracing::warn!(
                "block {} validated using legacy transaction hash shape; new blocks use canonical v4",
                self.block_height
            );
            return Ok(true);
        }

        Ok(false)
    }

    pub fn validate_structure(&self) -> Result<()> {
        if self.hash_version != 0 && self.hash_version != 4 {
            anyhow::bail!(
                "stored block {} uses unsupported hash version {}",
                self.block_height,
                self.hash_version
            );
        }
        if self.epoch_end <= self.epoch_start {
            anyhow::bail!(
                "stored block {} has invalid epoch window",
                self.block_height
            );
        }

        for transaction in &self.transactions {
            transaction.validate()?;
            if self.hash_version >= 4
                && transaction.is_legacy_unsigned()
                && !is_allowed_system_transaction(transaction)
            {
                anyhow::bail!(
                    "stored block {} contains an unauthorized unsigned transaction",
                    self.block_height
                );
            }
        }

        let expected_total_fees =
            self.transactions
                .iter()
                .try_fold(0_u64, |total, transaction| {
                    total
                        .checked_add(transaction.fee_ants)
                        .ok_or_else(|| anyhow::anyhow!("stored block transaction fees overflowed"))
                })?;
        if self.total_fees_ants != expected_total_fees {
            anyhow::bail!(
                "stored block {} has invalid total_fees_ants",
                self.block_height
            );
        }

        let expected_fee_per_miner = if self.miners.is_empty() {
            0
        } else {
            expected_total_fees / self.miners.len() as u64
        };
        if self.fee_per_miner != expected_fee_per_miner {
            anyhow::bail!(
                "stored block {} has invalid fee_per_miner",
                self.block_height
            );
        }
        if self.hash_version >= 4 {
            let mut unique_miners = HashSet::new();
            for miner in &self.miners {
                if !crate::transaction::is_valid_anet_wallet(miner) {
                    anyhow::bail!(
                        "stored block {} contains an invalid miner address",
                        self.block_height
                    );
                }
                if !unique_miners.insert(miner) {
                    anyhow::bail!(
                        "stored block {} contains a duplicate miner",
                        self.block_height
                    );
                }
            }
            for (address, account) in &self.account_state_changes {
                if address != &account.address {
                    anyhow::bail!(
                        "stored block {} has a mismatched account-state key",
                        self.block_height
                    );
                }
            }
        }

        Ok(())
    }
}

fn is_allowed_system_transaction(transaction: &Transaction) -> bool {
    let bridge_credit = transaction.tx_type == "bridge_credit"
        && transaction.from == BRIDGE_TREASURY_ADDRESS
        && transaction.memo.starts_with(BRIDGE_CREDIT_MEMO_PREFIX)
        && transaction.nonce == 0
        && transaction.fee_ants == crate::transaction::MIN_FEE_ANTS;
    let pi_settlement = transaction.tx_type == "pi_settlement"
        && transaction.memo.starts_with("Pi Payment Settlement: ")
        && transaction.nonce == 0
        && transaction.amount_ants == 1
        && transaction.fee_ants == crate::transaction::MIN_FEE_ANTS;
    // Durable legacy -> secp migration re-sweep (recovers funds credited to a
    // legacy address after it was migrated). Only ever produced by the
    // admin-gated resweep path; external callers cannot inject unsigned txs
    // (mempool admission rejects them), so authorizing this shape is safe.
    let migration_sweep = transaction.tx_type == "migration_sweep"
        && transaction.memo.starts_with(MIGRATION_SWEEP_MEMO_PREFIX)
        && transaction.nonce == 0
        && transaction.amount_ants > 0
        && transaction.fee_ants == crate::transaction::MIN_FEE_ANTS;

    bridge_credit || pi_settlement || migration_sweep
}

fn reject_legacy_hashes() -> bool {
    std::env::var("ANET_REJECT_LEGACY_HASHES")
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::Block;
    use crate::state::AccountState;
    use crate::transaction::{Transaction, MIN_FEE_ANTS};

    fn sample_block() -> Block {
        Block::new(
            1,
            Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            Utc.timestamp_opt(1_700_000_002, 0).single().unwrap(),
            "previous".to_owned(),
            Vec::new(),
            0,
            Vec::new(),
            Some("sample".to_owned()),
            Vec::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec![json!({"proof_hash": "abc"})],
            vec![json!({"validator": "ANET1234567890ABCDEF1234567890ABCDEF1234"})],
            "state-root".to_owned(),
            "proof-root".to_owned(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_hash_commits_all_persisted_consensus_fields() {
        let block = sample_block();

        let mut mutated = block.clone();
        mutated.block_event = Some("changed".to_owned());
        assert_ne!(
            block.compute_hash().unwrap(),
            mutated.compute_hash().unwrap()
        );

        let mut mutated = block.clone();
        mutated.tpow_proofs.push(json!({"proof_hash": "def"}));
        assert_ne!(
            block.compute_hash().unwrap(),
            mutated.compute_hash().unwrap()
        );

        let mut mutated = block.clone();
        mutated.account_state_changes.insert(
            "ANET1234567890ABCDEF1234567890ABCDEF1234".to_owned(),
            AccountState {
                address: "ANET1234567890ABCDEF1234567890ABCDEF1234".to_owned(),
                ants_balance: 1,
                activated_ants: 0,
                total_activated_ants: 0,
                sessions: 0,
                asset_balances: HashMap::new(),
            },
        );
        assert_ne!(
            block.compute_hash().unwrap(),
            mutated.compute_hash().unwrap()
        );

        let mut mutated = block.clone();
        mutated.validator_votes.clear();
        assert_ne!(
            block.compute_hash().unwrap(),
            mutated.compute_hash().unwrap()
        );

        let mut mutated = block.clone();
        mutated.state_root = "changed".to_owned();
        assert_ne!(
            block.compute_hash().unwrap(),
            mutated.compute_hash().unwrap()
        );

        let mut mutated = block.clone();
        mutated.proof_root = "changed".to_owned();
        assert_ne!(
            block.compute_hash().unwrap(),
            mutated.compute_hash().unwrap()
        );
    }

    #[test]
    fn structure_rejects_tampered_fee_metadata() {
        let mut block = sample_block();
        block.total_fees_ants = 1;
        assert!(block.validate_structure().is_err());
    }

    #[test]
    fn v4_blocks_reject_arbitrary_unsigned_transactions() {
        let transaction = Transaction {
            tx_type: "transfer".to_owned(),
            from: "ANET1234567890ABCDEF1234567890ABCDEF1234".to_owned(),
            to: "ANETABCDEF1234567890ABCDEF1234567890ABCD".to_owned(),
            amount_ants: 1,
            fee_ants: MIN_FEE_ANTS,
            nonce: 0,
            memo: String::new(),
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            chain_id: "anet-mainnet".to_owned(),
            payload: serde_json::Value::Object(serde_json::Map::new()),
            signature: String::new(),
            tx_hash: String::new(),
        };
        let result = Block::new(
            1,
            Utc.timestamp_opt(1_700_000_000, 0).single().unwrap(),
            Utc.timestamp_opt(1_700_000_002, 0).single().unwrap(),
            "previous".to_owned(),
            vec![transaction],
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
        );
        assert!(result.is_err());
    }
}
