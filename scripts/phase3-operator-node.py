#!/usr/bin/env python3
"""Phase 3 testnet operator tool: init a validator identity, assemble a genesis,
and run one validator (ANET ABCI app imported from a verified production replica
+ CometBFT). Testnet only: refuses the production chain id for the new network."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

PRODUCTION_CHAIN_ID = "anet-private-mainnet-1"
PRODUCTION_PEER = "https://explorer.a-network.net"


def set_top_level(text, key, value):
    pattern = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
    updated, count = pattern.subn(f"{key} = {json.dumps(value)}", text, count=1)
    if count != 1:
        raise SystemExit(f"config.toml is missing top-level key {key}")
    return updated


def set_section_value(text, section, key, value):
    pattern = re.compile(rf"(?ms)(^\[{re.escape(section)}\]\s*\n)(.*?)(?=^\[|\Z)")
    match = pattern.search(text)
    if match is None:
        raise SystemExit(f"config.toml is missing section [{section}]")
    body, count = re.subn(
        rf"(?m)^{re.escape(key)}\s*=.*$", f"{key} = {json.dumps(value)}", match.group(2), count=1
    )
    if count != 1:
        raise SystemExit(f"config.toml is missing [{section}] key {key}")
    return text[: match.start(2)] + body + text[match.end(2) :]


def cmd_init(args):
    home = args.home
    if not (home / "config/priv_validator_key.json").exists():
        subprocess.run([str(args.comet), "init", "--home", str(home)], check=True, capture_output=True)
    key = json.loads((home / "config/priv_validator_key.json").read_text())
    node_id = subprocess.check_output(
        [str(args.comet), "show-node-id", "--home", str(home)], text=True
    ).strip()
    identity = {
        "moniker": args.moniker,
        "node_id": node_id,
        "p2p_address": f"{node_id}@{args.public_host}:{args.p2p_port}",
        "validator_address": key["address"],
        "pub_key": key["pub_key"],
    }
    (home / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    print(json.dumps(identity, indent=2))


def cmd_genesis(args):
    if args.chain_id == PRODUCTION_CHAIN_ID:
        raise SystemExit("refusing to create a testnet genesis with the production chain id")
    identities = [json.loads(Path(path).read_text()) for path in args.identity]
    if len(identities) < 4:
        raise SystemExit("Phase 3 requires at least 4 validators (3-of-4 quorum)")
    seen = set()
    validators = []
    for identity in identities:
        if identity["validator_address"] in seen:
            raise SystemExit(f"duplicate validator {identity['validator_address']}")
        seen.add(identity["validator_address"])
        validators.append(
            {
                "address": identity["validator_address"],
                "pub_key": identity["pub_key"],
                "power": "1",
                "name": identity["moniker"],
            }
        )
    template = json.loads(args.template.read_text()) if args.template else None
    consensus_params = (
        template["consensus_params"]
        if template
        else {
            "block": {"max_bytes": "22020096", "max_gas": "-1"},
            "evidence": {
                "max_age_num_blocks": "100000",
                "max_age_duration": "172800000000000",
                "max_bytes": "1048576",
            },
            "validator": {"pub_key_types": ["ed25519"]},
            "version": {"app": "0"},
            "abci": {"vote_extensions_enable_height": "0"},
            "authority": {"authority": ""},
        }
    )
    genesis = {
        "genesis_time": args.genesis_time,
        "chain_id": args.chain_id,
        "initial_height": "0",
        "consensus_params": consensus_params,
        "validators": validators,
        "app_hash": "",
    }
    args.out.write_text(json.dumps(genesis, indent=2) + "\n")
    peers = ",".join(identity["p2p_address"] for identity in identities)
    print(json.dumps({"genesis": str(args.out), "validators": len(validators), "persistent_peers": peers}, indent=2))


def sync_replica(args):
    if args.replica.exists() and any(args.replica.iterdir()):
        return
    subprocess.run(
        [
            str(args.app),
            "--follow-peer",
            args.replica_source,
            "--expect-chain-id",
            PRODUCTION_CHAIN_ID,
            "--follower-store",
            str(args.replica),
            "--follow-once",
        ],
        check=True,
    )


def cmd_start(args):
    home = args.home
    genesis = json.loads(args.genesis.read_text())
    if genesis["chain_id"] == PRODUCTION_CHAIN_ID:
        raise SystemExit("refusing to run the testnet app on the production chain id")
    if not (home / "config/priv_validator_key.json").exists():
        raise SystemExit("run `init` first")
    shutil.copyfile(args.genesis, home / "config/genesis.json")
    config_path = home / "config/config.toml"
    config = config_path.read_text()
    config = set_top_level(config, "proxy_app", f"tcp://127.0.0.1:{args.abci_port}")
    config = set_top_level(config, "moniker", json.loads((home / "identity.json").read_text())["moniker"])
    config = set_section_value(config, "rpc", "laddr", f"tcp://{args.rpc_bind}:{args.rpc_port}")
    config = set_section_value(config, "p2p", "laddr", f"tcp://0.0.0.0:{args.p2p_port}")
    config = set_section_value(config, "p2p", "persistent_peers", args.peers)
    config = set_section_value(config, "p2p", "addr_book_strict", False)
    config = set_section_value(config, "p2p", "allow_duplicate_ip", True)
    config_path.write_text(config)

    sync_replica(args)

    env = os.environ.copy()
    env.update(
        {
            "ANET_ENV": "testnet",
            "ANET_CHAIN_ID": genesis["chain_id"],
            "ANET_ABCI_TEST_ORACLE_ADDRESS": args.oracle,
            "ANET_ABCI_IMPORT_REPLICA": str(args.replica),
            "ANET_ABCI_IMPORT_SOURCE_CHAIN_ID": PRODUCTION_CHAIN_ID,
            "ANET_ABCI_TEST_STATE": str(home / "anet-app-state.json"),
            "ANET_ABCI_TEST_BIND": f"127.0.0.1:{args.abci_port}",
        }
    )
    app_log = (home / "anet-app.log").open("a")
    comet_log = (home / "cometbft.log").open("a")
    app = subprocess.Popen([str(args.app), "--abci-testnet"], env=env, stdout=app_log, stderr=subprocess.STDOUT)
    time.sleep(2)
    if app.poll() is not None:
        raise SystemExit(f"ANET app exited early; see {home / 'anet-app.log'}")
    comet = subprocess.Popen(
        [str(args.comet), "--home", str(home), "start"], stdout=comet_log, stderr=subprocess.STDOUT
    )
    (home / "pids.json").write_text(json.dumps({"app": app.pid, "comet": comet.pid}) + "\n")
    print(json.dumps({"app_pid": app.pid, "comet_pid": comet.pid, "rpc": f"http://{args.rpc_bind}:{args.rpc_port}"}))
    if args.foreground:
        try:
            comet.wait()
        finally:
            app.terminate()


def process_alive(pid):
    # os.kill(pid, 0) terminates on Windows; use Popen handles there instead.
    if os.name == "nt":
        import ctypes

        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def cmd_stop(args):
    pids = json.loads((args.home / "pids.json").read_text())
    # Stop Comet before the app; Comet may hang on a dead ABCI socket, so escalate.
    for name in ("comet", "app"):
        pid = pids[name]
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            continue
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and process_alive(pid):
            time.sleep(0.2)
        if process_alive(pid):
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
    print(json.dumps({"stopped": pids}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create validator + node keys and print the identity to share")
    init.add_argument("--home", type=Path, required=True)
    init.add_argument("--comet", type=Path, required=True)
    init.add_argument("--moniker", required=True)
    init.add_argument("--public-host", required=True, help="IP/DNS other validators dial")
    init.add_argument("--p2p-port", type=int, default=26656)
    init.set_defaults(func=cmd_init)

    gen = sub.add_parser("genesis", help="coordinator: combine identities into a testnet genesis")
    gen.add_argument("--identity", action="append", required=True)
    gen.add_argument("--chain-id", required=True)
    gen.add_argument("--genesis-time", required=True, help="RFC3339, e.g. 2026-11-01T00:00:00Z")
    gen.add_argument("--template", type=Path, help="existing Comet genesis to copy consensus_params from")
    gen.add_argument("--out", type=Path, required=True)
    gen.set_defaults(func=cmd_genesis)

    start = sub.add_parser("start", help="run the ANET app (imported from production replica) + CometBFT")
    start.add_argument("--home", type=Path, required=True)
    start.add_argument("--comet", type=Path, required=True)
    start.add_argument("--app", type=Path, required=True, help="anet node built with --features abci-testnet")
    start.add_argument("--genesis", type=Path, required=True)
    start.add_argument("--peers", required=True, help="persistent_peers from the genesis step")
    start.add_argument("--replica", type=Path, required=True, help="follower store; synced if empty")
    start.add_argument("--replica-source", default=PRODUCTION_PEER)
    start.add_argument("--oracle", required=True, help="agreed testnet session-oracle ANET address")
    start.add_argument("--p2p-port", type=int, default=26656)
    start.add_argument("--rpc-port", type=int, default=26657)
    start.add_argument("--rpc-bind", default="127.0.0.1")
    start.add_argument("--abci-port", type=int, default=26658)
    start.add_argument("--foreground", action="store_true")
    start.set_defaults(func=cmd_start)

    stop = sub.add_parser("stop", help="stop a validator started with `start`")
    stop.add_argument("--home", type=Path, required=True)
    stop.set_defaults(func=cmd_stop)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
