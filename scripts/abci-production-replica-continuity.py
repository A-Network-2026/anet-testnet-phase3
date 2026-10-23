#!/usr/bin/env python3
"""Continuity test: start the isolated ANET consensus from a verified production replica."""

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts/abci-broadcast-tx-commit-probe.py"
SOURCE_CHAIN_ID = "anet-private-mainnet-1"
EXPLORER = "https://explorer.a-network.net"
NODE_COUNT = 4

spec = importlib.util.spec_from_file_location("probe", PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def abci_query(rpc_port, path, data=""):
    query = urlencode({"path": json.dumps(path), "data": json.dumps(data), "prove": "false"})
    response = probe.http_json(f"http://127.0.0.1:{rpc_port}/abci_query?{query}", timeout=30)[
        "result"
    ]["response"]
    if response["code"] != 0:
        raise RuntimeError(f"query {path} failed at {rpc_port}: {response}")
    return json.loads(base64.b64decode(response["value"]))


def wait_for_import(rpc_port, timeout=600):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            return abci_query(rpc_port, "/import")
        except Exception as error:  # replica replay can take a while
            last = error
            time.sleep(1)
    raise RuntimeError(f"validator {rpc_port} never finished import: {last}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comet", type=Path, default=ROOT / "gobin/cometbft-0.40.0")
    parser.add_argument("--app", type=Path, default=ROOT / "target/debug/anet-private-mainnet")
    parser.add_argument("--replica", type=Path, default=ROOT / "prod-replica/follower-store")
    parser.add_argument(
        "--tx-generator",
        type=Path,
        default=ROOT / "tools/testnet-signer/target/debug/anet-testnet-signer",
    )
    parser.add_argument(
        "--check-account",
        action="append",
        default=[],
        help="production wallet to cross-check against the live explorer",
    )
    parser.add_argument("--port-base", type=int, default=54558)
    args = parser.parse_args()

    for path in (args.comet, args.app, args.replica, args.tx_generator):
        if not path.exists():
            raise RuntimeError(f"required file does not exist: {path}")
    probe.ensure_ports_free(args.port_base)

    run_root = Path(tempfile.mkdtemp(prefix="abci-continuity-", dir=ROOT))
    # Each validator gets its own read-only copy so sled never shares a lock.
    replicas = []
    for index in range(NODE_COUNT):
        copy = run_root / f"replica{index}"
        shutil.copytree(args.replica, copy)
        replicas.append(copy)

    oracle_address, _, _, _ = probe.signed_session_snapshot(
        args.tx_generator, [{"wallet": probe.SENDER, "sessions": 1000}]
    )

    homes = [run_root / f"node{index}" for index in range(NODE_COUNT)]
    app_ports = [args.port_base + i for i in range(NODE_COUNT)]
    p2p_ports = [args.port_base + 100 + i for i in range(NODE_COUNT)]
    rpc_ports = [args.port_base + 200 + i for i in range(NODE_COUNT)]
    processes, logs = [], []

    try:
        probe.init_local_validators(args.comet, homes, probe.CHAIN_ID)
        node_ids = []
        for index, home in enumerate(homes):
            (home / "data/priv_validator_state_probe.json").write_text(
                '{"height":"0","round":0,"step":0}\n'
            )
            config_path = home / "config/config.toml"
            config = config_path.read_text()
            config = probe.set_top_level(config, "proxy_app", f"tcp://127.0.0.1:{app_ports[index]}")
            config = probe.set_top_level(config, "db_dir", "probe-data")
            config = probe.set_top_level(
                config, "priv_validator_state_file", "data/priv_validator_state_probe.json"
            )
            config = probe.set_section_value(config, "rpc", "laddr", f"tcp://127.0.0.1:{rpc_ports[index]}")
            config = probe.set_section_value(config, "p2p", "laddr", f"tcp://127.0.0.1:{p2p_ports[index]}")
            config = probe.set_section_value(config, "p2p", "persistent_peers", "")
            config = probe.set_section_value(config, "p2p", "addr_book_strict", False)
            config = probe.set_section_value(config, "p2p", "allow_duplicate_ip", True)
            config_path.write_text(config)
            node_ids.append(
                subprocess.check_output(
                    [str(args.comet), "show-node-id", "--home", str(home)], text=True
                ).strip()
            )
        for index, home in enumerate(homes):
            peers = ",".join(
                f"{node_ids[p]}@127.0.0.1:{p2p_ports[p]}" for p in range(NODE_COUNT) if p != index
            )
            config_path = home / "config/config.toml"
            config_path.write_text(
                probe.set_section_value(config_path.read_text(), "p2p", "persistent_peers", peers)
            )

        import_started = time.monotonic()
        for index in range(NODE_COUNT):
            log = (run_root / f"abci{index}.log").open("w")
            logs.append(log)
            env = os.environ.copy()
            env.update(
                {
                    "ANET_ENV": "testnet",
                    "ANET_CHAIN_ID": probe.CHAIN_ID,
                    "ANET_ABCI_TEST_ORACLE_ADDRESS": oracle_address,
                    "ANET_ABCI_IMPORT_REPLICA": str(replicas[index]),
                    "ANET_ABCI_IMPORT_SOURCE_CHAIN_ID": SOURCE_CHAIN_ID,
                    "ANET_ABCI_TEST_STATE": str(run_root / f"app-state{index}.json"),
                    "ANET_ABCI_TEST_BIND": f"127.0.0.1:{app_ports[index]}",
                }
            )
            processes.append(
                subprocess.Popen([str(args.app), "--abci-testnet"], env=env, stdout=log, stderr=subprocess.STDOUT)
            )
        for index, home in enumerate(homes):
            log = (run_root / f"comet{index}.log").open("w")
            logs.append(log)
            processes.append(
                subprocess.Popen(
                    [str(args.comet), "--home", str(home), "start"], stdout=log, stderr=subprocess.STDOUT
                )
            )

        imports = [wait_for_import(port) for port in rpc_ports]
        import_seconds = round(time.monotonic() - import_started, 1)
        if len({item["app_hash"] for item in imports}) != 1:
            raise RuntimeError(f"validators derived different app hashes from the replica: {imports}")
        provenance = imports[0]["imported_from"]
        if provenance is None or provenance["source_chain_id"] != SOURCE_CHAIN_ID:
            raise RuntimeError(f"unexpected import provenance: {imports[0]}")
        if imports[0]["last_anet_block_hash"] != provenance["source_tip_hash"]:
            raise RuntimeError("imported state does not link to the replica tip hash")

        # The replica tip must be a real block on the live production chain.
        live_tip_block = probe.http_json(
            f"{EXPLORER}/blocks?from={provenance['source_block_count'] - 1}"
            f"&to={provenance['source_block_count'] - 1}&position=true",
            timeout=60,
        )
        live_tip_block = live_tip_block[0] if isinstance(live_tip_block, list) else live_tip_block["blocks"][0]
        if live_tip_block["hash"] != provenance["source_tip_hash"]:
            raise RuntimeError(
                f"replica tip {provenance['source_tip_hash']} is not production block "
                f"{provenance['source_block_count'] - 1} ({live_tip_block['hash']})"
            )
        live_head = probe.http_json(f"{EXPLORER}/sync/head", timeout=30)
        live_stats = probe.http_json(f"{EXPLORER}/stats/investor", timeout=60)
        live_activated_ants = int(live_stats["activated_supply_ants"])
        replayed_total_ants = int(imports[0]["total_ants"])
        if replayed_total_ants != live_activated_ants:
            raise RuntimeError(
                f"replayed supply {replayed_total_ants} != live activated supply {live_activated_ants}"
            )

        account_checks = []
        for wallet in args.check_account:
            local = abci_query(rpc_ports[0], "/account", wallet)["account"]
            live = probe.http_json(f"{EXPLORER}/accounts/{wallet}", timeout=30)
            account_checks.append(
                {
                    "wallet": wallet,
                    "replica_ants_balance": local["ants_balance"],
                    "live_ants_balance": live.get("ants_balance"),
                    "replica_sessions": local["sessions"],
                    "live_sessions": live.get("sessions"),
                    "balance_matches": local["ants_balance"] == live.get("ants_balance"),
                }
            )

        for port in rpc_ports:
            probe.wait_for_status(port)
        # A wallet that never existed on production cannot spend here either.
        reply = probe.rpc(
            rpc_ports[0],
            "broadcast_tx_sync",
            {
                "tx": base64.b64encode(
                    subprocess.check_output(
                        [str(args.tx_generator)],
                        env={**os.environ, "ANET_TX_CHAIN_ID": probe.CHAIN_ID, "ANET_TX_NONCE": "1"},
                    )
                ).decode()
            },
        )
        unknown_sender = reply["result"]
        if unknown_sender["code"] == 0:
            raise RuntimeError(f"a wallet absent from production was allowed to spend: {reply}")

        common_height, common_hash, common_app_hash, statuses = probe.common_block(rpc_ports)
        after = [abci_query(port, "/import") for port in rpc_ports]
        if len({item["app_hash"] for item in after}) != 1:
            raise RuntimeError(f"validators diverged after extending the imported chain: {after}")
        if after[0]["last_anet_block_hash"] == provenance["source_tip_hash"] and common_height > 0:
            raise RuntimeError("new blocks committed but the ANET chain did not extend past the tip")

        print(
            json.dumps(
                {
                    "run_dir": str(run_root),
                    "import_seconds": import_seconds,
                    "source": provenance,
                    "live_head_at_test": live_head,
                    "replica_tip_is_live_production_block": True,
                    "identical_app_hash_on_all_validators": imports[0]["app_hash"],
                    "imported_accounts": imports[0]["account_count"],
                    "imported_total_ants": imports[0]["total_ants"],
                    "live_activated_supply_ants": live_activated_ants,
                    "supply_matches_live_node": True,
                    "web2_preactivation_ledger": {
                        "registered_accounts": live_stats["metrics"]["total_registered_accounts"],
                        "miners": live_stats["metrics"]["total_real_miners"],
                        "note": "off-chain until a wallet passes the 1,000-session gate; not part of block state",
                    },
                    "carried_dex_pools": imports[0]["carried_dex_pools"],
                    "carried_tokens": imports[0]["carried_tokens"],
                    "account_cross_checks": account_checks,
                    "unknown_sender_rejected": unknown_sender["log"],
                    "extended_chain": {
                        "comet_common_height": common_height,
                        "comet_block_hash": common_hash,
                        "comet_app_hash": common_app_hash,
                        "anet_tip_after": after[0]["last_anet_block_hash"],
                        "latest_heights": [s["sync_info"]["latest_block_height"] for s in statuses],
                    },
                },
                indent=2,
            )
        )
    finally:
        probe.stop_processes(processes, logs)


if __name__ == "__main__":
    main()
