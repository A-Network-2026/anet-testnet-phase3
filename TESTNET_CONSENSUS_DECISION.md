# A-Network Testnet Consensus Decision

**Status:** testnet plan only; no production changes authorized or made.

## Decision

Evaluate CometBFT as the testnet consensus and transaction-gossip layer, with the A-Network Rust logic exposed as a deterministic ABCI application. CometBFT is a candidate, not yet an adopted production dependency. Pin a supported release only after a minimal ABCI adapter builds, passes protocol compatibility checks, and demonstrates recovery behavior.

Do not extend the hand-written `VoteCollector` prototype into the production block path. Its tests cover a few quorum rules, but it does not implement network transport, proposer rotation, timeouts, durable certificates, validator changes, replay protection across restarts, or application-state replication.

## Testnet Topology

- Four independently keyed validators, each with its own process, database, and persistent test volume.
- Equal test voting power; three-of-four commit quorum. One unavailable validator should not stop commits; a two/two partition must not commit either side.
- A unique chain ID, genesis hash, test accounts, and keys. Never use production genesis, production database credentials, treasury keys, or live RPC URLs.
- No shared PostgreSQL between validator processes. Consensus history and deterministic application state must replicate through the consensus protocol; local storage is per validator.
- Static test validator membership initially. The 1,000-session wallet eligibility rule remains a separate application rule; it is not the consensus quorum and does not require 1,000 people to begin testing.
- In the transfer-only ABCI experiment, both transfer parties must provide signed Merkle inclusion proofs against the current committed session root. Root updates are separate signed commands authorized by a configured test oracle and committed through consensus; this remains a trusted-oracle model, not trustless session issuance.
- Test validators run only on private/local endpoints until the safety suite passes. No public node-discovery page or production wallet endpoint change in this phase.

## Transaction Path

1. Wallet signs the transaction locally with the existing chain ID and domain-separated transaction payload.
2. The wallet submits it to any test validator endpoint.
3. The validator performs stateless signature/chain checks and application admission checks, then gossips the transaction through CometBFT mempool.
4. Validators deterministically execute the same ordered transactions through the ABCI application.
5. The client treats a transaction as confirmed only after a committed block/finality proof; HTTP admission is not confirmation.
6. Wallet reads may query multiple validators and verify chain ID, genesis hash, height, and block hash before displaying a result.

## Render-Outage Scope

The first Render-off goal is narrowly scoped: existing on-chain balances can transfer and finalize while Render is unavailable. Registration, OTP, mining-session creation, and new session eligibility remain unavailable until their data/proofs are moved to a verifiable protocol input. Do not claim the whole mobile application is Render-independent until each of those dependencies is removed or replicated.

For new organic eligibility, replace trusted PostgreSQL session reads with a protocol-verifiable session credential or proof that every validator can independently check. A Merkle root written by one operator is an audit commitment, not by itself proof that the committed counts are truthful.

## Required Gates

1. Four isolated nodes start from the same test genesis and independently report the same chain ID, height, app hash, and finalized block hash.
2. The same signed transaction submitted to different nodes is committed once and appears identically on all nodes.
3. Conflicting transactions using the same sender nonce never both finalize.
4. A one-node outage permits progress with three of four validators. A two/two partition makes no progress; after healing, all nodes converge to the same committed history.
5. A restart from durable local storage recovers the same committed state and rejects duplicate/replayed votes and transactions.
6. Invalid signatures, wrong chain IDs, stale heights/rounds, and equivocation are rejected or safely halt progress; no partition independently finalizes a conflicting block.
7. Sender and recipient session proofs reconstruct the current committed root; tampered and below-threshold proofs are rejected without state mutation.
8. Signed session-root updates enforce configured oracle identity, chain ID, strictly increasing timestamps, consensus-time freshness, complete active-account coverage, and nondecreasing session counts; replayed, stale, wrong-signer, decreasing, and active-wallet-omitting snapshots are rejected.
9. With Render blocked, existing-wallet P2P submission, finality, account reads, and follower verification continue using only independent test nodes.
10. Testnet validator membership changes and software upgrades are explicitly versioned, replayable, and agreed by the active quorum.
11. Crash, network-partition, delayed-message, disk-recovery, and adversarial tests pass before any external testnet invitation.

## Local Smoke-Test Evidence (2026-10-23)

- Existing A-Network Rust producer, two isolated PostgreSQL databases, same synthetic test genesis: both nodes independently accepted a different valid transfer from the same sender/nonce and committed different block-1 hashes. This is a reproduced split-brain failure in the current producer architecture.
- Existing Rust producer plus follower: a signed test transfer was queued and committed, and a clean follower independently verified and stored the transaction-containing block.
- CometBFT `v0.40.0` plus its built-in KVStore ABCI application: a four-validator genesis was generated; three local validator processes ran while one remained unavailable. The three processes agreed on committed block hashes. With one of the three stopped, a `broadcast_tx_commit` attempt timed out and the two remaining nodes stayed at height 5. After the third process restarted and caught up, the pending test transaction committed at height 6 with matching hashes on the participating nodes.
- ANET transfer-only ABCI experiment: four fresh local CometBFT homes used isolated app state and a synthetic genesis. A signed transfer was committed and indexed with the same raw transaction hash; invalid signatures, wrong chain IDs, duplicate nonces, tampered session proofs, and a 999-session recipient were rejected without state mutation. Two of four validators could not finalize and retained the transfer pending; restoring quorum committed it. Three of four committed another transfer. Restarting a validator replayed to the same account state and block/app hashes. The feature-enabled Rust suite passed 102 tests.
- Signed session-root update experiment: a dedicated synthetic oracle key signed a newer snapshot; all four validators committed the same root and session counts. Stale, replayed, wrong-signer, decreasing-count, and active-wallet-omitting snapshots were rejected without state changes. A wallet advanced from 999 to 1,000 sessions became eligible and received a proof-backed transfer. Later transfer and quorum tests still passed, and a restarted validator replayed to the same root, account state, block hash, and app hash.
- Limitation: the signed root updater still trusts one configured oracle key. It validates authenticity and monotonicity, not whether the oracle's session data is truthful. The existing sealed TPoW proofs are not equivalent to completed-session credits: submission is limited to active validators, and the current protocol does not define a one-proof/one-session rule. No production transfer path, external operator, Render outage, or mobile client has been tested with this app.
- Production-replica continuity experiment: a read-only follower download re-verified all 33,855 production blocks (113 MB). Four validators imported the replica with the production replay rules and derived the identical app hash in ~16–19 s each; the replica tip was confirmed to be a live production block. Replayed state (12 accounts, 23,959,021,715 ANTS, pools ANET-USDC/ANET-WANET, tokens CJ/CJC/DG/WANET) equals the live node's activated supply exactly, and sampled wallet balances match the live explorer. A wallet absent from production was rejected; the validators then extended the chain from the production tip and stayed identical. Import provenance (source chain id, tip hash, height, block count) is committed into the app hash.
- Clarification: the 186,770 registered accounts / 158,368 miners are a pre-activation Web2 ledger. No wallet has yet passed the 1,000-session gate (`eligible: 0` in the published genesis), so none of them hold on-chain balances; block history already carries the full chain state. Those Web2 ledgers would only enter chain state through the (still trusted) session-oracle path.
- Carried DEX pools and tokens are frozen state in the test app: swaps, wrap/unwrap, bridge, and token operations are not executable there yet.
- All test keys, genesis files, databases, node homes, and binaries were under `/tmp/anet-consensus-lab-20261023`; all test processes and local database were stopped afterward. The production chain checkout remained clean.

## Production No-Go Conditions

- No consensus implementation is currently connected to A-Network's block creation; the existing node has a local producer loop and `--follow-peer` is read-only.
- The recent two-producer simulation produced different block-1 hashes from the same genesis. This is a confirmed split-brain failure, so the current producer must not be enabled on multiple independent databases.
- The current validator recruitment document's governance-seat promise is not implemented by the L1 consensus code. Governance rights require a separate, explicit protocol design.
- No production DNS, Render service, production database, wallet release, or chain state should be changed as part of this testnet phase.

## Cutover Rule

There is no automatic cutover. A future production migration needs a separately reviewed decision covering audited implementation, independent operator/key custody, genesis or state migration, activation height, wallet endpoint discovery, rollback/fork handling, user communication, and legal review. Until that approval, the current production network remains unchanged and must be described as operator-run.
