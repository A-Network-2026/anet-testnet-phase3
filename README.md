# A-Network — Phase 3 Closed Testnet

**Status: closed, invite-only testnet. Not production. No real value. Decentralization is not yet claimed.**

This repository is the test package for the whitepaper's Phase 3 milestone: the first
BFT-capable configuration (4 validators, 3-of-4 quorum) for the A-Network Layer 1.
It is published so independent operators can run a validator, read every line of the
code they are running, and report what they find. Per the whitepaper, A-Network does
not claim system-wide decentralization until this milestone is complete and
**externally verified** — this repository exists to make that verification possible.

## What you are running

| Component | Role |
|---|---|
| CometBFT **v0.40.0** (tag commit `0880b4d378f347ab16e54ec677ff50d803f37d62`) | Consensus, P2P, mempool, block storage |
| `anet-private-mainnet` built with `--features abci-testnet` | The A-Network L1 node exposed as a deterministic ABCI application (transfers, signed session-root updates, production-replica import). The default build (feature off) is the unchanged production node. |
| `scripts/phase3-operator-node.py` | Operator tool: `init` → `genesis` (coordinator) → `start` / `stop` |
| `tools/testnet-signer` | Test-only signer for synthetic transfers and session snapshots |

On `start`, your node first downloads and **re-verifies every block of the live production chain**
(`anet-private-mainnet-1`, ~113 MB) using the production follower rules — hash links, signatures,
commitment roots — then replays it to derive the starting state. Every validator must derive the
same app hash from that replay or the network will not form. The testnet chain then extends from the
production tip hash under a **different chain id**. Production is never written to.

## Honest scope (read before joining)

- **Lab-verified only, so far.** Everything here passed on one machine (4 local validators, 102 Rust
  tests, quorum/recovery/restart matrix, replica-import continuity). It has not yet run across
  independent machines. That is what this testnet is for.
- **Session eligibility is still oracle-trusted.** New 1,000-session eligibility reaches the chain only
  through a signed snapshot from the coordinator's testnet oracle key (address below). Validators verify
  authenticity, freshness, monotonicity and replay — not whether the counts are truthful. This is the
  whitepaper's documented Phase 2 trust edge; it is disclosed, not solved.
- **Carried-but-frozen state.** DEX pools, ANRC-20 tokens, wANET and bridge state from production are
  imported and hash-committed, but swaps, wrap/unwrap, bridge and token operations are **not executable**
  on the test app yet.
- **No bonding, no slashing.** Validator membership is the static genesis set.
- **AI-assisted, single-author code, ~3,000 new lines, no independent human review yet.** The ABCI
  app, import path, harnesses and operator tool were written with an AI coding assistant under the
  maintainer's direction and verified only by the automated tests and local runs described here.
  Independent human review is one of the explicit goals of this testnet; please read before you run.
- **No tokens of value.** Nothing earned, minted or transferred here has any value or any effect on
  production balances.

## Requirements

- Linux x86_64 or macOS (Windows 11 works; see notes). 2 vCPU / 2 GB RAM is plenty.
- Rust **1.88.0** via [rustup](https://rustup.rs) (pinned by `rust-toolchain.toml`; Windows: MSVC Build
  Tools "Desktop development with C++").
- Python 3.9+.
- CometBFT v0.40.0 — build from the pinned tag (needs Go ≥ 1.25):
  ```sh
  git clone --depth 1 --branch v0.40.0 https://github.com/cometbft/cometbft
  cd cometbft && git rev-parse HEAD   # must print 0880b4d378f347ab16e54ec677ff50d803f37d62
  go build -o ../cometbft-0.40.0 ./cmd/cometbft
  ```
  Reference checksums of the coordinator's own builds are in `testnet/phase3/COMETBFT_PIN.txt`
  (Go builds are not bit-reproducible across hosts; the commit hash is the authority).
- Inbound TCP on your P2P port (default `26656`) reachable by the other validators (public IP or
  port-forward). RPC (`26657`) should stay bound to localhost.
- ~150 MB of download for the production replica.

## Operator steps

```sh
git clone https://github.com/A-Network-2026/anet-testnet-phase3
cd anet-testnet-phase3
cargo build --locked --features abci-testnet
(cd tools/testnet-signer && cargo build --locked)

# 1) Create your validator identity. Share ONLY the printed JSON with the coordinator.
python3 scripts/phase3-operator-node.py init \
  --home ~/anet-phase3 --comet /path/to/cometbft-0.40.0 \
  --moniker <your-name> --public-host <your public IP or DNS> --p2p-port 26656
```

Never share `~/anet-phase3/config/priv_validator_key.json` or `node_key.json`.

The coordinator combines all identities into `testnet/phase3/genesis.json` and publishes the
`persistent_peers` string. Then:

```sh
git pull
python3 scripts/phase3-operator-node.py start \
  --home ~/anet-phase3 --comet /path/to/cometbft-0.40.0 \
  --app target/debug/anet-private-mainnet \
  --genesis testnet/phase3/genesis.json \
  --peers "<persistent_peers from the coordinator>" \
  --replica ~/anet-phase3/prod-replica \
  --oracle "$(python3 -c 'import json;print(json.load(open("testnet/phase3/TESTNET_PARAMS.json"))["session_oracle_address"])')"
```

Check your node:

```sh
curl -s localhost:26657/status | python3 -c 'import json,sys;s=json.load(sys.stdin)["result"]["sync_info"];print(s["latest_block_height"],s["latest_block_hash"],s["catching_up"])'
curl -s 'localhost:26657/abci_query?path="/import"' | python3 -c 'import json,sys,base64;print(base64.b64decode(json.load(sys.stdin)["result"]["response"]["value"]).decode())'
```

Stop with `python3 scripts/phase3-operator-node.py stop --home ~/anet-phase3`.
Logs: `~/anet-phase3/anet-app.log`, `~/anet-phase3/cometbft.log`.

## What we will measure together

1. All validators report the **same imported app hash** and the same production tip hash.
2. Blocks commit with 4/4 and with 3/4; **no commits with 2/4**.
3. A validator that goes offline and returns **catches up to the same hash**.
4. Signed transfers commit once, with identical results on every node; invalid signatures, wrong chain
   ids, replayed nonces and tampered session proofs are rejected everywhere.
5. Behaviour under real latency, restarts, clock skew and operator mistakes.

Please file findings as GitHub issues in this repository (logs welcome; never post private keys).

## Reproducing the lab evidence yourself (single machine)

```sh
python3 scripts/abci-broadcast-tx-commit-probe.py --port-base 30558        # synthetic 4-validator matrix
python3 scripts/abci-production-replica-continuity.py --port-base 31558     # replica import + live cross-check
```

Both start four local validators, assert the results, and stop everything. The design record,
required gates and all evidence so far are in `TESTNET_CONSENSUS_DECISION.md`.

## Windows 11 notes

Use the Windows CometBFT build (checksum in `COMETBFT_PIN.txt`) or build with Go. Paths in the commands
above become `C:\...`. Allow inbound TCP 26656 in Windows Defender Firewall. The operator tool's `stop`
sends SIGTERM/SIGKILL semantics that map to `TerminateProcess` on Windows.

## License

Same license as the A-Network L1 node — see `LICENSE`.
