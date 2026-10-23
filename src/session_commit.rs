//! Session-progress commitment: a Merkle tree over **every** miner's completed
//! session count, so the full mining ledger — including miners who have not yet
//! reached the 1,000-session spend threshold — is committed on-chain as a
//! single root per sync.
//!
//! This is the "both" design:
//!   * the **root** is sealed into a block (every node, including a phone, stores
//!     just one 32-byte hash per commitment), and
//!   * the **leaves** are served on request (`/sessions/proof/:wallet`) with a
//!     Merkle inclusion proof, so any miner can prove their exact session count
//!     is committed on-chain without every node storing all leaves forever.
//!
//! Hashing reuses the chain's Bitcoin-style double-SHA256 (`bitcoin::sha256d`)
//! with Bitcoin's odd-leaf duplication rule, so the root is consistent with the
//! `bitcoin::merkle_root` primitive already used for block roots. Hashes are
//! emitted as plain (non-reversed) hex for unambiguous reproduction in any
//! language.

use crate::bitcoin::sha256d;
use serde::{Deserialize, Serialize};

/// Canonical leaf hash for one wallet's session count.
///
/// Preimage: `session-progress-v1|{WALLET_UPPER}|{SESSIONS}`. Any third party
/// reproduces this from the wallet address and session count alone.
pub fn leaf_hash(wallet: &str, sessions: u64) -> [u8; 32] {
    let preimage = format!(
        "session-progress-v1|{}|{}",
        wallet.trim().to_uppercase(),
        sessions
    );
    sha256d(preimage.as_bytes())
}

/// Normalize raw `(wallet, sessions)` rows into canonical leaf order:
/// wallets upper-cased and de-duplicated (keeping the highest session count),
/// then sorted ascending by wallet. This makes the root independent of the
/// order rows came out of the database.
pub fn canonical_entries(entries: &[(String, u64)]) -> Vec<(String, u64)> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, u64> = BTreeMap::new();
    for (wallet, sessions) in entries {
        let normalized = wallet.trim().to_uppercase();
        if normalized.is_empty() {
            continue;
        }
        let slot = map.entry(normalized).or_insert(0);
        if *sessions > *slot {
            *slot = *sessions;
        }
    }
    map.into_iter().collect()
}

/// One sibling on an inclusion path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofNode {
    /// Sibling hash as plain (non-reversed) hex.
    pub hash: String,
    /// Where the sibling sits relative to the running hash: `"left"` means the
    /// sibling is concatenated before the running hash, `"right"` after.
    pub position: String,
}

/// A full inclusion proof a client can verify against the on-chain root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInclusionProof {
    pub wallet: String,
    pub sessions: u64,
    pub leaf: String,
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub path: Vec<ProofNode>,
    pub root: String,
}

/// An in-memory Merkle tree over canonical session-progress leaves. Built once
/// per commitment; serves inclusion proofs for any committed wallet.
#[derive(Debug, Clone)]
pub struct SessionTree {
    entries: Vec<(String, u64)>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl SessionTree {
    /// Build the tree from raw `(wallet, sessions)` rows (canonicalized here).
    pub fn build(entries: &[(String, u64)]) -> Self {
        let entries = canonical_entries(entries);
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|(wallet, sessions)| leaf_hash(wallet, *sessions))
            .collect();
        let levels = build_levels(leaves);
        Self { entries, levels }
    }

    pub fn leaf_count(&self) -> usize {
        self.entries.len()
    }

    /// The canonical `(wallet, sessions)` leaves under this commitment, sorted
    /// ascending by wallet. Used to diff against a previous commitment for
    /// per-wallet milestone detection.
    pub fn entries(&self) -> &[(String, u64)] {
        &self.entries
    }

    /// Root as plain hex. An empty tree commits to the all-zero hash so the
    /// "no miners yet" state still has a well-defined, reproducible root.
    pub fn root(&self) -> String {
        let root = self
            .levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .unwrap_or([0_u8; 32]);
        hex::encode(root)
    }

    /// Build an inclusion proof for `wallet`, if it is committed.
    pub fn inclusion_proof(&self, wallet: &str) -> Option<SessionInclusionProof> {
        let normalized = wallet.trim().to_uppercase();
        let leaf_index = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == &normalized)?;
        let sessions = self.entries[leaf_index].1;

        let mut path = Vec::new();
        let mut index = leaf_index;
        for level in &self.levels {
            if level.len() <= 1 {
                break;
            }
            let (sibling, position) = if index % 2 == 0 {
                // Even index: sibling is to the right; the last odd-one-out
                // duplicates itself (Bitcoin rule).
                let sibling_index = (index + 1).min(level.len() - 1);
                (level[sibling_index], "right")
            } else {
                (level[index - 1], "left")
            };
            path.push(ProofNode {
                hash: hex::encode(sibling),
                position: position.to_owned(),
            });
            index /= 2;
        }

        Some(SessionInclusionProof {
            wallet: normalized,
            sessions,
            leaf: hex::encode(self.levels[0][leaf_index]),
            leaf_index,
            leaf_count: self.entries.len(),
            path,
            root: self.root(),
        })
    }
}

/// Build the Merkle tree levels bottom-up with Bitcoin odd-leaf duplication.
/// `levels[0]` is the leaves; the final level holds the single root.
fn build_levels(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return vec![vec![]];
    }
    let mut levels = vec![leaves];
    while levels.last().map(|level| level.len()).unwrap_or(0) > 1 {
        let current = levels.last().expect("non-empty while building");
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut preimage = Vec::with_capacity(64);
            preimage.extend_from_slice(&left);
            preimage.extend_from_slice(&right);
            next.push(sha256d(&preimage));
        }
        levels.push(next);
    }
    levels
}

/// Reference verifier: recompute the root from a proof's leaf + path and check
/// it equals the claimed root. The node uses this to self-check a proof before
/// serving it; external clients reproduce the same logic to verify against the
/// on-chain root.
pub fn verify_inclusion(proof: &SessionInclusionProof) -> bool {
    let expected_leaf = leaf_hash(&proof.wallet, proof.sessions);
    if hex::encode(expected_leaf) != proof.leaf {
        return false;
    }
    let mut current = expected_leaf;
    for node in &proof.path {
        let sibling = match hex::decode(&node.hash) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut out = [0_u8; 32];
                out.copy_from_slice(&bytes);
                out
            }
            _ => return false,
        };
        let mut preimage = Vec::with_capacity(64);
        match node.position.as_str() {
            "left" => {
                preimage.extend_from_slice(&sibling);
                preimage.extend_from_slice(&current);
            }
            "right" => {
                preimage.extend_from_slice(&current);
                preimage.extend_from_slice(&sibling);
            }
            _ => return false,
        }
        current = sha256d(&preimage);
    }
    hex::encode(current) == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{display_hash, merkle_root};

    fn sample(n: usize) -> Vec<(String, u64)> {
        (0..n)
            .map(|i| (format!("ANET{:036X}", i), (i as u64) + 1))
            .collect()
    }

    #[test]
    fn root_is_order_independent_and_canonical() {
        let mut a = sample(5);
        let mut b = a.clone();
        b.reverse();
        // Duplicate a wallet with a lower count; canonicalization keeps the max.
        b.push((a[0].0.clone(), 0));
        a.push((a[0].0.clone(), a[0].1));

        let root_a = SessionTree::build(&a).root();
        let root_b = SessionTree::build(&b).root();
        assert_eq!(root_a, root_b);
    }

    #[test]
    fn root_matches_bitcoin_merkle_primitive() {
        let entries = sample(6);
        let canonical = canonical_entries(&entries);
        let leaves: Vec<[u8; 32]> = canonical
            .iter()
            .map(|(w, s)| leaf_hash(w, *s))
            .collect();
        // The commitment root (plain hex) must equal the chain's Bitcoin merkle
        // primitive over the same leaves — `display_hash` reverses, so reverse
        // back to compare against our non-reversed hex.
        let mut bitcoin_root = hex::decode(display_hash(&merkle_root(&leaves))).unwrap();
        bitcoin_root.reverse();
        assert_eq!(SessionTree::build(&entries).root(), hex::encode(bitcoin_root));
    }

    #[test]
    fn every_leaf_has_a_verifiable_proof_for_odd_and_even_counts() {
        for n in [1_usize, 2, 3, 5, 8, 17] {
            let entries = sample(n);
            let tree = SessionTree::build(&entries);
            let canonical = canonical_entries(&entries);
            for (wallet, _) in &canonical {
                let proof = tree
                    .inclusion_proof(wallet)
                    .expect("every committed wallet has a proof");
                assert_eq!(proof.root, tree.root());
                assert!(
                    verify_inclusion(&proof),
                    "proof for {wallet} in tree of {n} must verify"
                );
            }
        }
    }

    #[test]
    fn tampered_session_count_fails_verification() {
        let entries = sample(5);
        let tree = SessionTree::build(&entries);
        let wallet = &canonical_entries(&entries)[2].0;
        let mut proof = tree.inclusion_proof(wallet).expect("proof");
        proof.sessions += 1; // claim more sessions than committed
        assert!(!verify_inclusion(&proof));
    }

    #[test]
    fn unknown_wallet_has_no_proof() {
        let tree = SessionTree::build(&sample(4));
        assert!(tree
            .inclusion_proof("ANETFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            .is_none());
    }

    #[test]
    fn empty_tree_has_zero_root() {
        let tree = SessionTree::build(&[]);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root(), hex::encode([0_u8; 32]));
    }

    #[test]
    fn leaf_and_root_match_cross_language_vectors() {
        // Pinned vectors reproduced independently in Node.js (SHA256d over the
        // documented preimage). Locking them here guarantees a third party in
        // any language can recompute the same commitment from the public rules.
        let l0 = leaf_hash("ANET000000000000000000000000000000000000", 1);
        assert_eq!(
            hex::encode(l0),
            "12eba3c677b28548792336db5c275d52f8ddfd7d2c7760f40c971c61974ffb1c"
        );
        let entries = vec![
            ("ANET000000000000000000000000000000000000".to_owned(), 1_u64),
            ("ANET000000000000000000000000000000000001".to_owned(), 2_u64),
        ];
        assert_eq!(
            SessionTree::build(&entries).root(),
            "5ad392e71db9e6c142a1031abef43e39a408a50a79287c47b593796dc42f2e29"
        );
    }
}
