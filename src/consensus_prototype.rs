//! Test-only quorum prototype; this is not connected to production block creation.

use std::collections::{BTreeMap, BTreeSet};

use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::transaction::{derive_address_from_public_key, recover_address_from_signature};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedVote {
    chain_id: String,
    height: u64,
    round: u32,
    block_hash: String,
    validator: String,
    signature: String,
}

#[derive(Debug, PartialEq, Eq)]
enum VoteError {
    InvalidQuorumSet,
    WrongChain,
    WrongHeight,
    WrongRound,
    InvalidBlockHash,
    UnknownValidator,
    InvalidSignature,
    DoubleVote,
    ValidatorAlreadyEquivocated,
}

struct VoteCollector {
    chain_id: String,
    height: u64,
    round: u32,
    quorum: usize,
    validators: BTreeSet<String>,
    votes: BTreeMap<String, String>,
    equivocated: BTreeSet<String>,
}

impl VoteCollector {
    fn new(
        chain_id: &str,
        height: u64,
        round: u32,
        validators: Vec<String>,
    ) -> Result<Self, VoteError> {
        let validators: BTreeSet<String> = validators.into_iter().collect();
        if validators.is_empty() {
            return Err(VoteError::InvalidQuorumSet);
        }
        let quorum = validators.len() * 2 / 3 + 1;
        Ok(Self {
            chain_id: chain_id.to_owned(),
            height,
            round,
            quorum,
            validators,
            votes: BTreeMap::new(),
            equivocated: BTreeSet::new(),
        })
    }

    fn submit(&mut self, vote: SignedVote) -> Result<Option<String>, VoteError> {
        if vote.chain_id != self.chain_id {
            return Err(VoteError::WrongChain);
        }
        if vote.height != self.height {
            return Err(VoteError::WrongHeight);
        }
        if vote.round != self.round {
            return Err(VoteError::WrongRound);
        }
        if vote.block_hash.len() != 64 || !vote.block_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(VoteError::InvalidBlockHash);
        }
        if !self.validators.contains(&vote.validator) {
            return Err(VoteError::UnknownValidator);
        }
        if self.equivocated.contains(&vote.validator) {
            return Err(VoteError::ValidatorAlreadyEquivocated);
        }

        let digest = hex::encode(Sha256::digest(vote_signing_bytes(
            &vote.chain_id,
            vote.height,
            vote.round,
            &vote.block_hash,
        )));
        let recovered = recover_address_from_signature(&digest, &vote.signature)
            .map_err(|_| VoteError::InvalidSignature)?;
        if recovered != vote.validator {
            return Err(VoteError::InvalidSignature);
        }

        if let Some(previous_hash) = self.votes.get(&vote.validator) {
            if previous_hash == &vote.block_hash {
                return Ok(self.committed_hash(&vote.block_hash));
            }
            self.votes.remove(&vote.validator);
            self.equivocated.insert(vote.validator);
            return Err(VoteError::DoubleVote);
        }

        self.votes.insert(vote.validator, vote.block_hash.clone());
        Ok(self.committed_hash(&vote.block_hash))
    }

    fn committed_hash(&self, block_hash: &str) -> Option<String> {
        let votes = self
            .votes
            .values()
            .filter(|hash| hash.as_str() == block_hash)
            .count();
        (votes >= self.quorum).then(|| block_hash.to_owned())
    }
}

fn vote_signing_bytes(chain_id: &str, height: u64, round: u32, block_hash: &str) -> Vec<u8> {
    format!(
        "anet-vote-v1|{chain_id}|{height}|{round}|{}",
        block_hash.to_ascii_lowercase()
    )
    .into_bytes()
}

fn test_wallet(secret_byte: u8) -> (SecretKey, String) {
    let secret = SecretKey::from_slice(&[secret_byte; 32]).expect("test key");
    let public = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &secret);
    let address = derive_address_from_public_key(&public);
    (secret, address)
}

fn sign_vote(secret: &SecretKey, validator: &str, block_hash: &str) -> SignedVote {
    let chain_id = "anet-quorum-lab".to_owned();
    let height = 7;
    let round = 0;
    let digest = Sha256::digest(vote_signing_bytes(&chain_id, height, round, block_hash));
    let message = Message::from_digest_slice(&digest).expect("vote digest");
    let signature = Secp256k1::new().sign_ecdsa_recoverable(&message, secret);
    let (recovery_id, compact) = signature.serialize_compact();
    let mut bytes = Vec::from(compact);
    bytes.push(recovery_id.to_i32() as u8);
    SignedVote {
        chain_id,
        height,
        round,
        block_hash: block_hash.to_owned(),
        validator: validator.to_owned(),
        signature: hex::encode(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::{sign_vote, test_wallet, VoteCollector, VoteError};

    fn four_validators() -> Vec<(secp256k1::SecretKey, String)> {
        (1..=4).map(test_wallet).collect()
    }

    fn collector(validators: &[(secp256k1::SecretKey, String)]) -> VoteCollector {
        VoteCollector::new(
            "anet-quorum-lab",
            7,
            0,
            validators
                .iter()
                .map(|(_, address)| address.clone())
                .collect(),
        )
        .expect("four-validator set")
    }

    #[test]
    fn three_of_four_commits_when_one_validator_is_offline() {
        let validators = four_validators();
        let mut collector = collector(&validators);
        let hash = "ab".repeat(32);
        for (secret, address) in validators.iter().take(2) {
            assert_eq!(
                collector.submit(sign_vote(secret, address, &hash)),
                Ok(None)
            );
        }
        assert_eq!(
            collector.submit(sign_vote(&validators[2].0, &validators[2].1, &hash)),
            Ok(Some(hash))
        );
    }

    #[test]
    fn two_of_four_does_not_commit() {
        let validators = four_validators();
        let mut collector = collector(&validators);
        let hash = "cd".repeat(32);
        for (secret, address) in validators.iter().take(2) {
            assert_eq!(
                collector.submit(sign_vote(secret, address, &hash)),
                Ok(None)
            );
        }
    }

    #[test]
    fn conflicting_blocks_stall_when_validators_split_and_equivocation_is_rejected() {
        let validators = four_validators();
        let mut collector = collector(&validators);
        let first_hash = "31".repeat(32);
        let second_hash = "42".repeat(32);

        for (secret, address) in validators.iter().take(2) {
            assert_eq!(
                collector.submit(sign_vote(secret, address, &first_hash)),
                Ok(None)
            );
        }
        for (secret, address) in validators.iter().skip(2) {
            assert_eq!(
                collector.submit(sign_vote(secret, address, &second_hash)),
                Ok(None)
            );
        }

        assert_eq!(
            collector.submit(sign_vote(&validators[0].0, &validators[0].1, &second_hash)),
            Err(VoteError::DoubleVote)
        );
        assert_eq!(
            collector.submit(sign_vote(&validators[1].0, &validators[1].1, &second_hash)),
            Err(VoteError::DoubleVote)
        );
        assert_eq!(collector.committed_hash(&first_hash), None);
        assert_eq!(collector.committed_hash(&second_hash), None);
    }

    #[test]
    fn one_validator_cannot_vote_for_two_blocks_at_the_same_height_and_round() {
        let validators = four_validators();
        let mut collector = collector(&validators);
        let first_hash = "11".repeat(32);
        let second_hash = "22".repeat(32);
        let (secret, address) = &validators[0];
        assert_eq!(
            collector.submit(sign_vote(secret, address, &first_hash)),
            Ok(None)
        );
        assert_eq!(
            collector.submit(sign_vote(secret, address, &second_hash)),
            Err(VoteError::DoubleVote)
        );
        assert_eq!(
            collector.submit(sign_vote(secret, address, &first_hash)),
            Err(VoteError::ValidatorAlreadyEquivocated)
        );
    }

    #[test]
    fn transaction_vote_is_bound_to_chain_height_round_and_validator_signature() {
        let validators = four_validators();
        let mut collector = collector(&validators);
        let hash = "ef".repeat(32);
        let mut vote = sign_vote(&validators[0].0, &validators[0].1, &hash);
        vote.chain_id = "production-chain-id".to_owned();
        assert_eq!(collector.submit(vote), Err(VoteError::WrongChain));

        let mut vote = sign_vote(&validators[0].0, &validators[0].1, &hash);
        vote.height += 1;
        assert_eq!(collector.submit(vote), Err(VoteError::WrongHeight));

        let mut vote = sign_vote(&validators[0].0, &validators[0].1, &hash);
        vote.round += 1;
        assert_eq!(collector.submit(vote), Err(VoteError::WrongRound));

        let mut vote = sign_vote(&validators[0].0, &validators[0].1, &hash);
        vote.validator = validators[1].1.clone();
        assert_eq!(collector.submit(vote), Err(VoteError::InvalidSignature));

        let mut vote = sign_vote(&validators[0].0, &validators[0].1, &hash);
        vote.validator = "ANETFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_owned();
        assert_eq!(collector.submit(vote), Err(VoteError::UnknownValidator));
    }
}
