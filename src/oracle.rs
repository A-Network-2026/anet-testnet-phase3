//! Phase 2 (decentralization): signed Web2 session oracle.
//!
//! Today the chain trusts whatever session counts PostgreSQL returns (see
//! `main::load_postgres_sync_data`). That is an *unsigned* trust edge: anyone
//! who can write the database — or sit between it and the node — could alter
//! who becomes a validator. This module closes that gap without changing the
//! economic model: the Web2 backend signs a canonical snapshot of session
//! counts with a dedicated **oracle key**, and the chain (and any third-party
//! verifier) cryptographically checks that the snapshot genuinely came from
//! that oracle authority and was not tampered with.
//!
//! This is the "make Web2 logic and consensus consistent" layer:
//!   * the eligibility rule is defined exactly once
//!     (`activation::is_session_eligible`) and chain callers apply it, and
//!   * the session data crossing the Web2→chain boundary is signed, so the
//!     boundary is auditable rather than blindly trusted.
//!
//! Honest scope: this makes the oracle edge *verifiable*, not *trustless* — the
//! chain still trusts the holder of the oracle key. Removing that trust
//! entirely requires recording session credits as on-chain events so the chain
//! derives eligibility from its own history; this signed snapshot is designed
//! so that the very same signed records can later become those on-chain events.

use anyhow::{anyhow, Result};
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::transaction::{is_valid_anet_wallet, recover_address_from_signature};

/// One wallet's session count inside a signed oracle snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleSessionEntry {
    pub wallet: String,
    pub sessions: u64,
}

/// A signed snapshot of Web2 session counts.
///
/// The Web2 backend builds this from its database, signs the canonical preimage
/// (see [`snapshot_signing_hash`]) with the oracle key, and submits it to the
/// chain. The chain verifies the signature recovers to the configured oracle
/// address before applying any session counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSessionSnapshot {
    pub chain_id: String,
    /// Unix-millis timestamp the snapshot was produced (freshness guard).
    pub as_of_ms: i64,
    pub entries: Vec<OracleSessionEntry>,
    /// ANET address claimed as the oracle signer; the recovered signature
    /// address must equal this AND the node's configured oracle address.
    pub signer: String,
    /// 65-byte recoverable secp256k1 signature (r||s||v), hex-encoded.
    pub signature: String,
}

/// A snapshot whose signature has been verified against the configured oracle
/// address and this node's chain id. Wallets are normalized to upper-case.
#[derive(Debug, Clone)]
pub struct VerifiedSessionSnapshot {
    pub as_of: DateTime<Utc>,
    pub entries: Vec<OracleSessionEntry>,
}

/// Canonical signing preimage for a snapshot.
///
/// Entries are normalized (wallet upper-cased) and sorted by wallet ASC, then
/// serialized as `WALLET:SESSIONS` joined by `,`. This guarantees the Web2
/// signer and the chain verifier hash byte-identical input regardless of the
/// order rows came out of the database.
fn canonical_snapshot_preimage(
    chain_id: &str,
    as_of_ms: i64,
    entries: &[OracleSessionEntry],
) -> String {
    let mut normalized: Vec<(String, u64)> = entries
        .iter()
        .map(|entry| (entry.wallet.trim().to_uppercase(), entry.sessions))
        .collect();
    normalized.sort_by(|left, right| left.0.cmp(&right.0));
    let body = normalized
        .iter()
        .map(|(wallet, sessions)| format!("{wallet}:{sessions}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "session-oracle-v1|{}|{}|{}",
        chain_id.trim(),
        as_of_ms,
        body
    )
}

/// SHA-256 of the canonical snapshot preimage, hex-encoded. This is the digest
/// the oracle key signs and the chain re-derives to verify.
pub fn snapshot_signing_hash(
    chain_id: &str,
    as_of_ms: i64,
    entries: &[OracleSessionEntry],
) -> String {
    let preimage = canonical_snapshot_preimage(chain_id, as_of_ms, entries);
    hex::encode(Sha256::digest(preimage.as_bytes()))
}

/// Verify a signed session snapshot.
///
/// Checks, in order: configured oracle address validity; chain-id match;
/// claimed signer equals configured oracle; non-empty signature/entries;
/// freshness within `max_age_seconds` (0 disables the freshness check); every
/// entry wallet is a valid ANET address; and finally that the signature
/// recovers to the configured oracle address.
pub fn verify_session_snapshot(
    snapshot: &SignedSessionSnapshot,
    expected_oracle_address: &str,
    expected_chain_id: &str,
    max_age_seconds: i64,
) -> Result<VerifiedSessionSnapshot> {
    let expected_oracle = expected_oracle_address.trim().to_uppercase();
    if !is_valid_anet_wallet(&expected_oracle) {
        return Err(anyhow!(
            "configured oracle address is not a valid ANET wallet"
        ));
    }
    if snapshot.chain_id.trim() != expected_chain_id.trim() {
        return Err(anyhow!("snapshot chain_id does not match this node"));
    }
    let claimed_signer = snapshot.signer.trim().to_uppercase();
    if claimed_signer != expected_oracle {
        return Err(anyhow!(
            "snapshot signer is not the configured oracle address"
        ));
    }
    if snapshot.signature.trim().is_empty() {
        return Err(anyhow!("snapshot signature is required"));
    }
    if snapshot.entries.is_empty() {
        return Err(anyhow!("snapshot has no entries"));
    }
    if snapshot.entries.len() > 100_000 {
        return Err(anyhow!("snapshot contains too many entries"));
    }

    let as_of = Utc
        .timestamp_millis_opt(snapshot.as_of_ms)
        .single()
        .ok_or_else(|| anyhow!("snapshot as_of_ms is out of range"))?;
    if max_age_seconds > 0 {
        let age_seconds = Utc::now().signed_duration_since(as_of).num_seconds();
        // Stale snapshots could replay an old validator set; future-dated ones
        // suggest clock skew or forgery. Reject both.
        if age_seconds > max_age_seconds {
            return Err(anyhow!("snapshot is stale ({age_seconds}s old)"));
        }
        if age_seconds < -max_age_seconds {
            return Err(anyhow!("snapshot timestamp is in the future"));
        }
    }

    let mut seen_wallets = std::collections::HashSet::new();
    for entry in &snapshot.entries {
        let wallet = entry.wallet.trim().to_uppercase();
        if !is_valid_anet_wallet(&wallet) {
            return Err(anyhow!(
                "snapshot contains an invalid wallet address: {wallet}"
            ));
        }
        if !seen_wallets.insert(wallet.clone()) {
            return Err(anyhow!(
                "snapshot contains duplicate wallet address: {wallet}"
            ));
        }
    }

    let hash = snapshot_signing_hash(&snapshot.chain_id, snapshot.as_of_ms, &snapshot.entries);
    let recovered = recover_address_from_signature(&hash, &snapshot.signature)?;
    if recovered != expected_oracle {
        return Err(anyhow!(
            "snapshot signature does not recover to the oracle address"
        ));
    }

    let entries = snapshot
        .entries
        .iter()
        .map(|entry| OracleSessionEntry {
            wallet: entry.wallet.trim().to_uppercase(),
            sessions: entry.sessions,
        })
        .collect();

    Ok(VerifiedSessionSnapshot { as_of, entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::is_session_eligible;
    use crate::transaction::derive_address_from_public_key;
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

    const ORACLE_SECRET_HEX: &str =
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f7a4f6f7d6f7f6f7f6";
    const OTHER_SECRET_HEX: &str =
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const WALLET_A: &str = "ANET1234567890ABCDEF1234567890ABCDEF1234";
    const WALLET_B: &str = "ANETABCDEF1234567890ABCDEF1234567890ABCD";
    const CHAIN_ID: &str = "anet-mainnet";

    fn address_for(secret_hex: &str) -> String {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);
        derive_address_from_public_key(&pubkey)
    }

    fn sign_hash(hash_hex: &str, secret_hex: &str) -> String {
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(&hex::decode(hash_hex).unwrap()).unwrap();
        let secret = SecretKey::from_slice(&hex::decode(secret_hex).unwrap()).unwrap();
        let sig = secp.sign_ecdsa_recoverable(&message, &secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut out = Vec::from(compact);
        out.push(recovery_id.to_i32() as u8);
        hex::encode(out)
    }

    fn signed_snapshot(
        entries: Vec<OracleSessionEntry>,
        as_of_ms: i64,
        chain_id: &str,
        secret_hex: &str,
    ) -> SignedSessionSnapshot {
        let hash = snapshot_signing_hash(chain_id, as_of_ms, &entries);
        let signature = sign_hash(&hash, secret_hex);
        SignedSessionSnapshot {
            chain_id: chain_id.to_owned(),
            as_of_ms,
            entries,
            signer: address_for(secret_hex),
            signature,
        }
    }

    fn sample_entries() -> Vec<OracleSessionEntry> {
        vec![
            OracleSessionEntry {
                wallet: WALLET_A.to_owned(),
                sessions: 1_500,
            },
            OracleSessionEntry {
                wallet: WALLET_B.to_owned(),
                sessions: 999,
            },
        ]
    }

    #[test]
    fn eligibility_rule_matches_threshold() {
        assert!(!is_session_eligible(999));
        assert!(is_session_eligible(1_000));
        assert!(is_session_eligible(50_000));
    }

    #[test]
    fn preimage_is_order_independent() {
        let forward = sample_entries();
        let mut reversed = sample_entries();
        reversed.reverse();
        assert_eq!(
            snapshot_signing_hash(CHAIN_ID, 1_000, &forward),
            snapshot_signing_hash(CHAIN_ID, 1_000, &reversed),
            "entry order must not change the signing hash"
        );
    }

    #[test]
    fn accepts_valid_signed_snapshot() {
        let oracle = address_for(ORACLE_SECRET_HEX);
        let now_ms = Utc::now().timestamp_millis();
        let snapshot = signed_snapshot(sample_entries(), now_ms, CHAIN_ID, ORACLE_SECRET_HEX);

        let verified = verify_session_snapshot(&snapshot, &oracle, CHAIN_ID, 600)
            .expect("valid snapshot should verify");
        assert_eq!(verified.entries.len(), 2);
        let eligible: Vec<&OracleSessionEntry> = verified
            .entries
            .iter()
            .filter(|entry| is_session_eligible(entry.sessions))
            .collect();
        assert_eq!(
            eligible.len(),
            1,
            "only the 1500-session wallet is eligible"
        );
        assert_eq!(eligible[0].wallet, WALLET_A);
    }

    #[test]
    fn rejects_wrong_oracle_signer() {
        let oracle = address_for(ORACLE_SECRET_HEX);
        let now_ms = Utc::now().timestamp_millis();
        // Signed by a DIFFERENT key than the configured oracle.
        let snapshot = signed_snapshot(sample_entries(), now_ms, CHAIN_ID, OTHER_SECRET_HEX);
        let error = verify_session_snapshot(&snapshot, &oracle, CHAIN_ID, 600)
            .expect_err("snapshot signed by a non-oracle key must be rejected");
        assert!(error.to_string().contains("oracle"));
    }

    #[test]
    fn rejects_tampered_sessions() {
        let oracle = address_for(ORACLE_SECRET_HEX);
        let now_ms = Utc::now().timestamp_millis();
        let mut snapshot = signed_snapshot(sample_entries(), now_ms, CHAIN_ID, ORACLE_SECRET_HEX);
        // Tamper: bump a wallet above the eligibility threshold post-signing.
        snapshot.entries[1].sessions = 100_000;
        let error = verify_session_snapshot(&snapshot, &oracle, CHAIN_ID, 600)
            .expect_err("mutating entries after signing must break verification");
        assert!(error.to_string().contains("recover"));
    }

    #[test]
    fn rejects_chain_id_mismatch() {
        let oracle = address_for(ORACLE_SECRET_HEX);
        let now_ms = Utc::now().timestamp_millis();
        let snapshot = signed_snapshot(sample_entries(), now_ms, CHAIN_ID, ORACLE_SECRET_HEX);
        let error = verify_session_snapshot(&snapshot, &oracle, "anet-testnet", 600)
            .expect_err("a snapshot for another chain must be rejected");
        assert!(error.to_string().contains("chain_id"));
    }

    #[test]
    fn rejects_stale_snapshot() {
        let oracle = address_for(ORACLE_SECRET_HEX);
        // 1 hour old, max age 60s.
        let stale_ms = Utc::now().timestamp_millis() - 3_600_000;
        let snapshot = signed_snapshot(sample_entries(), stale_ms, CHAIN_ID, ORACLE_SECRET_HEX);
        let error = verify_session_snapshot(&snapshot, &oracle, CHAIN_ID, 60)
            .expect_err("a stale snapshot must be rejected");
        assert!(error.to_string().contains("stale"));
    }

    #[test]
    fn rejects_duplicate_wallet_entries() {
        let oracle = address_for(ORACLE_SECRET_HEX);
        let duplicate = OracleSessionEntry {
            wallet: WALLET_A.to_owned(),
            sessions: 2_000,
        };
        let snapshot = signed_snapshot(
            vec![duplicate.clone(), duplicate],
            Utc::now().timestamp_millis(),
            CHAIN_ID,
            ORACLE_SECRET_HEX,
        );
        let error = verify_session_snapshot(&snapshot, &oracle, CHAIN_ID, 600)
            .expect_err("duplicate wallets must be rejected");
        assert!(error.to_string().contains("duplicate"));
    }
}
