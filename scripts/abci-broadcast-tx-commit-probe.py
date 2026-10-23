#!/usr/bin/env python3
"""Probe CometBFT broadcast_tx_commit against the isolated ANET ABCI app."""

import argparse
import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
CHAIN_ID = "anet-p2p-testnet-2026-10-23"
SENDER = "ANETBD6D976AF908505D3D52946C3DAD12B5AEC6"
NODE_COUNT = 4
INELIGIBLE_WALLET = f"ANET{3:036X}"


def http_json(url, payload=None, timeout=3):
    data = None if payload is None else json.dumps(payload).encode()
    request = Request(url, data=data, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def set_top_level(text, key, value):
    pattern = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
    updated, count = pattern.subn(f"{key} = {json.dumps(value)}", text, count=1)
    if count != 1:
        raise RuntimeError(f"missing top-level Comet config key: {key}")
    return updated


def set_section_value(text, section, key, value):
    pattern = re.compile(rf"(?ms)(^\[{re.escape(section)}\]\s*\n)(.*?)(?=^\[|\Z)")
    match = pattern.search(text)
    if match is None:
        raise RuntimeError(f"missing Comet config section: {section}")
    body, count = re.subn(
        rf"(?m)^{re.escape(key)}\s*=.*$",
        f"{key} = {json.dumps(value)}",
        match.group(2),
        count=1,
    )
    if count != 1:
        raise RuntimeError(f"missing [{section}] Comet config key: {key}")
    return text[: match.start(2)] + body + text[match.end(2) :]


def ensure_ports_free(base):
    ports = [base + offset for offset in range(12)]
    for port in ports:
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError as error:
                raise RuntimeError(f"diagnostic port {port} is unavailable: {error}")


def rpc(rpc_port, method, params):
    return http_json(
        f"http://127.0.0.1:{rpc_port}",
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        timeout=15,
    )


def wait_for_status(rpc_port, timeout=30):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = http_json(f"http://127.0.0.1:{rpc_port}/status")["result"]
            if (
                result["node_info"]["network"] == CHAIN_ID
                and not result["sync_info"]["catching_up"]
            ):
                return result
        except (OSError, KeyError, URLError) as error:
            last_error = error
        time.sleep(0.1)
    raise RuntimeError(f"Comet RPC {rpc_port} did not become ready: {last_error}")


def account_query(rpc_port, address=SENDER):
    query = urlencode(
        {
            "path": json.dumps("/account"),
            "data": json.dumps(address),
            "prove": "false",
        }
    )
    response = http_json(f"http://127.0.0.1:{rpc_port}/abci_query?{query}")[
        "result"
    ]["response"]
    if response["code"] != 0:
        raise RuntimeError(f"account query failed at {rpc_port}: {response}")
    return json.loads(base64.b64decode(response["value"]))


def sha256d(value):
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def session_proofs(genesis_path, sender, recipient):
    genesis = json.loads(genesis_path.read_text())
    entries_by_wallet = {}
    for account in genesis["accounts"]:
        wallet = account["address"].strip().upper()
        entries_by_wallet[wallet] = max(
            entries_by_wallet.get(wallet, 0), int(account["sessions"])
        )
    entries = sorted(entries_by_wallet.items())
    leaves = [
        sha256d(f"session-progress-v1|{wallet}|{sessions}".encode())
        for wallet, sessions in entries
    ]
    levels = [leaves]
    while len(levels[-1]) > 1:
        current = levels[-1]
        parent = []
        for offset in range(0, len(current), 2):
            left = current[offset]
            right = current[offset + 1] if offset + 1 < len(current) else left
            parent.append(sha256d(left + right))
        levels.append(parent)
    root = levels[-1][0].hex() if levels[-1] else bytes(32).hex()

    def inclusion_proof(wallet):
        normalized = wallet.strip().upper()
        index = next(
            (position for position, (candidate, _) in enumerate(entries) if candidate == normalized),
            None,
        )
        if index is None:
            raise RuntimeError(f"session proof wallet is absent from synthetic genesis: {wallet}")
        sessions = entries[index][1]
        path = []
        cursor = index
        for level in levels:
            if len(level) <= 1:
                break
            if cursor % 2 == 0:
                sibling = min(cursor + 1, len(level) - 1)
                path.append({"hash": level[sibling].hex(), "position": "right"})
            else:
                path.append({"hash": level[cursor - 1].hex(), "position": "left"})
            cursor //= 2
        leaf = leaves[index].hex()
        return {
            "wallet": normalized,
            "sessions": sessions,
            "leaf": leaf,
            "leaf_index": index,
            "leaf_count": len(entries),
            "path": path,
            "root": root,
        }

    return {
        "from": inclusion_proof(sender),
        "to": inclusion_proof(recipient),
    }


def signed_transfer(
    tx_generator,
    nonce,
    genesis_path,
    chain_id=CHAIN_ID,
    recipient=None,
    proof_mutator=None,
):
    environment = os.environ.copy()
    recipient = recipient or "ANET1EFF93BB0219FA9DA5CE427481ED57C42EA1"
    proofs = session_proofs(
        genesis_path,
        SENDER,
        recipient,
    )
    if proof_mutator is not None:
        proof_mutator(proofs)
    payload = {
        "memo": "isolated p2p failover test",
        "session_proofs": proofs,
    }
    environment.update(
        {
            "ANET_TX_CHAIN_ID": chain_id,
            "ANET_TX_NONCE": str(nonce),
            "ANET_TX_TO": recipient,
            "ANET_TX_PAYLOAD": json.dumps(payload, separators=(",", ":")),
        }
    )
    transaction = json.loads(subprocess.check_output([str(tx_generator)], env=environment))
    raw = json.dumps(transaction, separators=(",", ":")).encode()
    return raw, hashlib.sha256(raw).hexdigest().upper()


def signed_session_snapshot(tx_generator, entries, as_of_ms=None):
    environment = os.environ.copy()
    environment["ANET_TX_CHAIN_ID"] = CHAIN_ID
    environment["ANET_SESSION_SNAPSHOT_ENTRIES"] = json.dumps(
        entries, separators=(",", ":")
    )
    if as_of_ms is None:
        environment.pop("ANET_SESSION_AS_OF_MS", None)
    else:
        environment["ANET_SESSION_AS_OF_MS"] = str(as_of_ms)
    signed = json.loads(
        subprocess.check_output([str(tx_generator)], env=environment)
    )
    raw = json.dumps(signed["snapshot"], separators=(",", ":")).encode()
    return (
        signed["oracle_address"],
        signed["snapshot"],
        raw,
        hashlib.sha256(raw).hexdigest().upper(),
    )


def signed_session_snapshot(tx_generator, entries, as_of_ms=None):
    environment = os.environ.copy()
    environment["ANET_TX_CHAIN_ID"] = CHAIN_ID
    environment["ANET_SESSION_SNAPSHOT_ENTRIES"] = json.dumps(entries, separators=(",", ":"))
    if as_of_ms is not None:
        environment["ANET_SESSION_AS_OF_MS"] = str(as_of_ms)
    else:
        environment.pop("ANET_SESSION_AS_OF_MS", None)
    signed = json.loads(
        subprocess.check_output([str(tx_generator)], env=environment)
    )
    raw = json.dumps(signed["snapshot"], separators=(",", ":")).encode()
    return signed["oracle_address"], signed["snapshot"], raw, hashlib.sha256(raw).hexdigest().upper()


def assert_check_tx_rejected(rpc_port, raw_transaction, expected_text):
    reply = rpc(
        rpc_port,
        "broadcast_tx_sync",
        {"tx": base64.b64encode(raw_transaction).decode()},
    )
    result = reply.get("result")
    if result is None or result["code"] == 0:
        raise RuntimeError(f"invalid transaction was not rejected: {reply}")
    if expected_text.lower() not in result["log"].lower():
        raise RuntimeError(f"wrong transaction rejection reason: {reply}")
    return result


def find_indexed_tx(rpc_port, tx_hash, timeout=20):
    deadline = time.monotonic() + timeout
    last_reply = None
    while time.monotonic() < deadline:
        try:
            last_reply = http_json(
                f"http://127.0.0.1:{rpc_port}/tx_search?"
                + urlencode(
                    {
                        "query": json.dumps(f"tx.hash='{tx_hash}'"),
                        "prove": "false",
                    }
                )
            )
            transactions = last_reply.get("result", {}).get("txs") or []
            if transactions:
                transaction = transactions[0]
                if transaction["hash"] != tx_hash:
                    raise RuntimeError(f"tx index hash mismatch: {transaction}")
                return transaction
        except HTTPError as error:
            last_reply = {
                "http_status": error.code,
                "body": error.read().decode(errors="replace"),
            }
        except (OSError, URLError):
            pass
        time.sleep(0.1)
    raise RuntimeError(f"transaction {tx_hash} was not indexed: {last_reply}")


def assert_commit_reply(reply, tx_hash):
    result = reply.get("result")
    if result is None:
        raise RuntimeError(f"broadcast_tx_commit failed: {reply}")
    if result["check_tx"]["code"] != 0 or result["tx_result"]["code"] != 0:
        raise RuntimeError(f"transaction was not accepted and executed: {result}")
    if result["hash"] != tx_hash:
        raise RuntimeError(f"commit RPC returned a different transaction hash: {result}")
    return result


def assert_account_state(rpc_ports, nonce, balance=None, timeout=30):
    deadline = time.monotonic() + timeout
    states = []
    while time.monotonic() < deadline:
        states = [account_query(port) for port in rpc_ports]
        converged = (
            all(state["nonce"] == nonce for state in states)
            and (
                balance is None
                or all(state["account"]["ants_balance"] == balance for state in states)
            )
            and len({json.dumps(state, sort_keys=True) for state in states}) == 1
        )
        if converged:
            return states[0]
        time.sleep(0.1)
    raise RuntimeError(
        f"account state did not converge to nonce {nonce}/balance {balance}: {states}"
    )


def common_block(rpc_ports, timeout=30):
    deadline = time.monotonic() + timeout
    last_statuses = []
    while time.monotonic() < deadline:
        last_statuses = [wait_for_status(port) for port in rpc_ports]
        height = min(
            int(status["sync_info"]["latest_block_height"])
            for status in last_statuses
        )
        if height < 1:
            continue
        blocks = [
            http_json(f"http://127.0.0.1:{port}/block?height={height}")["result"]
            for port in rpc_ports
        ]
        block_hashes = [block["block_id"]["hash"] for block in blocks]
        if len(set(block_hashes)) == 1:
            return height, block_hashes[0], blocks[0]["block"]["header"]["app_hash"], last_statuses
        time.sleep(0.1)
    raise RuntimeError(f"validator histories did not converge: {last_statuses}")


def init_local_validators(comet, homes, chain_id):
    """Fresh keys per run; one shared genesis so the homes form a 4-validator set."""
    validators = []
    for home in homes:
        subprocess.run([str(comet), "init", "--home", str(home)], check=True, capture_output=True)
        key = json.loads((home / "config/priv_validator_key.json").read_text())
        validators.append(
            {"address": key["address"], "pub_key": key["pub_key"], "power": "1", "name": home.name}
        )
    genesis = json.loads((homes[0] / "config/genesis.json").read_text())
    genesis["chain_id"] = chain_id
    genesis["validators"] = validators
    genesis["app_hash"] = ""
    encoded = json.dumps(genesis, indent=2)
    for home in homes:
        (home / "config/genesis.json").write_text(encoded)


def stop_processes(processes, logs):
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in reversed(processes):
        if process.poll() is None:
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)
    for log in logs:
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--comet",
        type=Path,
        default=ROOT / "gobin/cometbft-0.40.0",
    )
    parser.add_argument(
        "--app",
        type=Path,
        default=ROOT / "target/debug/anet-private-mainnet",
    )
    parser.add_argument(
        "--genesis",
        type=Path,
        default=ROOT / "testnet/phase3/synthetic-genesis.json",
    )
    parser.add_argument(
        "--tx-generator",
        type=Path,
        default=ROOT / "tools/testnet-signer/target/debug/anet-testnet-signer",
    )
    parser.add_argument("--port-base", type=int, default=30558)
    args = parser.parse_args()

    for path in (args.comet, args.app, args.genesis, args.tx_generator):
        if not path.exists():
            raise RuntimeError(f"required test-only file does not exist: {path}")
    if json.loads(args.genesis.read_text())["chain_id"] != CHAIN_ID:
        raise RuntimeError("synthetic ANET genesis chain ID is unexpected")
    ensure_ports_free(args.port_base)

    run_root = Path(tempfile.mkdtemp(prefix="abci-rpc-probe-", dir=ROOT))
    test_genesis = json.loads(args.genesis.read_text())
    test_genesis["accounts"].append(
        {
            "address": INELIGIBLE_WALLET,
            "ants_balance": 0,
            "sessions": 999,
            "total_activated_ants": 0,
        }
    )
    test_genesis_path = run_root / "test-genesis.json"
    test_genesis_path.write_text(json.dumps(test_genesis, separators=(",", ":")))
    updated_genesis = json.loads(json.dumps(test_genesis))
    for account in updated_genesis["accounts"]:
        if account["address"].strip().upper() == INELIGIBLE_WALLET:
            account["sessions"] = 1_000
    updated_genesis_path = run_root / "updated-test-genesis.json"
    updated_genesis_path.write_text(
        json.dumps(updated_genesis, separators=(",", ":"))
    )
    updated_entries = [
        {"wallet": account["address"], "sessions": int(account["sessions"])}
        for account in updated_genesis["accounts"]
    ]
    oracle_address, update_snapshot, update_snapshot_raw, update_snapshot_hash = (
        signed_session_snapshot(args.tx_generator, updated_entries)
    )
    oracle_address, update_snapshot, update_snapshot_raw, update_snapshot_hash = (
        signed_session_snapshot(args.tx_generator, updated_entries)
    )
    genesis_time_ms = int(
        datetime.fromisoformat(
            test_genesis["genesis_time"].replace("Z", "+00:00")
        ).timestamp()
        * 1_000
    )
    homes = [run_root / f"node{index}" for index in range(NODE_COUNT)]
    app_ports = [args.port_base + index for index in range(NODE_COUNT)]
    p2p_ports = [args.port_base + 100 + index for index in range(NODE_COUNT)]
    rpc_ports = [args.port_base + 200 + index for index in range(NODE_COUNT)]
    processes = []
    logs = []
    comet_processes = {}

    def start_comet_node(index):
        log = (run_root / f"comet{index}-{len(logs)}.log").open("w")
        logs.append(log)
        process = subprocess.Popen(
            [str(args.comet), "--home", str(homes[index]), "start"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        processes.append(process)
        comet_processes[index] = process
        return process

    def stop_comet_node(index):
        process = comet_processes[index]
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=4)

    try:
        init_local_validators(args.comet, homes, CHAIN_ID)
        node_ids = []
        for index, home in enumerate(homes):
            state_path = home / "data/priv_validator_state_probe.json"
            state_path.write_text('{"height":"0","round":0,"step":0}\n')
            config_path = home / "config/config.toml"
            config = config_path.read_text()
            config = set_top_level(config, "proxy_app", f"tcp://127.0.0.1:{app_ports[index]}")
            config = set_top_level(config, "db_dir", "probe-data")
            config = set_top_level(config, "priv_validator_state_file", "data/priv_validator_state_probe.json")
            config = set_section_value(config, "rpc", "laddr", f"tcp://127.0.0.1:{rpc_ports[index]}")
            config = set_section_value(config, "p2p", "laddr", f"tcp://127.0.0.1:{p2p_ports[index]}")
            config = set_section_value(config, "p2p", "persistent_peers", "")
            config = set_section_value(config, "p2p", "addr_book_strict", False)
            config = set_section_value(config, "p2p", "allow_duplicate_ip", True)
            config_path.write_text(config)
            node_id = subprocess.check_output(
                [str(args.comet), "show-node-id", "--home", str(home)], text=True
            ).strip()
            node_ids.append(node_id)

        for index, home in enumerate(homes):
            peers = ",".join(
                f"{node_ids[peer]}@127.0.0.1:{p2p_ports[peer]}"
                for peer in range(NODE_COUNT)
                if peer != index
            )
            config_path = home / "config/config.toml"
            config = set_section_value(config_path.read_text(), "p2p", "persistent_peers", peers)
            config_path.write_text(config)

        for index in range(NODE_COUNT):
            log = (run_root / f"abci{index}.log").open("w")
            logs.append(log)
            environment = os.environ.copy()
            environment.update(
                {
                    "ANET_ENV": "testnet",
                    "ANET_CHAIN_ID": CHAIN_ID,
                    "ANET_ABCI_TEST_ORACLE_ADDRESS": oracle_address,
                    "ANET_ABCI_TEST_GENESIS": str(test_genesis_path),
                    "ANET_ABCI_TEST_STATE": str(run_root / f"app-state{index}.json"),
                    "ANET_ABCI_TEST_BIND": f"127.0.0.1:{app_ports[index]}",
                }
            )
            processes.append(
                subprocess.Popen(
                    [str(args.app), "--abci-testnet"],
                    env=environment,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
            )

        for index in range(NODE_COUNT):
            start_comet_node(index)

        for port in rpc_ports:
            wait_for_status(port)

        raw_tx1, hash1 = signed_transfer(args.tx_generator, 1, test_genesis_path)
        commit1 = rpc(
            rpc_ports[0],
            "broadcast_tx_commit",
            {"tx": base64.b64encode(raw_tx1).decode()},
        )
        result1 = assert_commit_reply(commit1, hash1)
        indexed1 = find_indexed_tx(rpc_ports[0], hash1)
        if indexed1["height"] != result1["height"]:
            raise RuntimeError(f"commit and tx index heights differ: {result1}, {indexed1}")
        state1 = assert_account_state(rpc_ports, 1, 99_989_500)

        invalid_signature_tx, _ = signed_transfer(
            args.tx_generator, 2, test_genesis_path
        )
        invalid_signature = json.loads(invalid_signature_tx)
        invalid_signature["signature"] = invalid_signature["signature"][:-2] + "02"
        invalid_signature_tx = json.dumps(invalid_signature, separators=(",", ":")).encode()
        invalid_signature_result = assert_check_tx_rejected(
            rpc_ports[0], invalid_signature_tx, "signature"
        )

        wrong_chain_tx, _ = signed_transfer(
            args.tx_generator,
            2,
            test_genesis_path,
            chain_id="anet-unexpected-testnet",
        )
        wrong_chain_result = assert_check_tx_rejected(
            rpc_ports[0], wrong_chain_tx, "chain ID"
        )

        duplicate_nonce_tx, _ = signed_transfer(
            args.tx_generator, 1, test_genesis_path
        )
        duplicate_nonce_result = assert_check_tx_rejected(
            rpc_ports[0], duplicate_nonce_tx, "nonce mismatch"
        )
        tampered_proof_tx, _ = signed_transfer(
            args.tx_generator,
            2,
            test_genesis_path,
            proof_mutator=lambda proofs: proofs["to"].update(
                sessions=proofs["to"]["sessions"] + 1
            ),
        )
        tampered_proof_result = assert_check_tx_rejected(
            rpc_ports[0], tampered_proof_tx, "session inclusion proof"
        )
        ineligible_recipient_tx, _ = signed_transfer(
            args.tx_generator,
            2,
            test_genesis_path,
            recipient=INELIGIBLE_WALLET,
        )
        ineligible_recipient_result = assert_check_tx_rejected(
            rpc_ports[0], ineligible_recipient_tx, "1,000-session gate"
        )
        assert_account_state(rpc_ports, 1, 99_989_500)

        _, _, stale_snapshot_raw, _ = signed_session_snapshot(
            args.tx_generator,
            updated_entries,
            as_of_ms=genesis_time_ms + 1_000,
        )
        stale_snapshot_result = assert_check_tx_rejected(
            rpc_ports[0], stale_snapshot_raw, "session snapshot is stale"
        )

        update_reply = rpc(
            rpc_ports[0],
            "broadcast_tx_commit",
            {"tx": base64.b64encode(update_snapshot_raw).decode()},
        )
        update_result = assert_commit_reply(update_reply, update_snapshot_hash)
        update_index = find_indexed_tx(rpc_ports[0], update_snapshot_hash)
        if update_index["height"] != update_result["height"]:
            raise RuntimeError(
                f"session snapshot commit and index heights differ: {update_result}, {update_index}"
            )
        expected_updated_root = session_proofs(
            updated_genesis_path, SENDER, INELIGIBLE_WALLET
        )["to"]["root"]
        updated_wallet_states = [
            account_query(port, INELIGIBLE_WALLET) for port in rpc_ports
        ]
        if any(
            state["account"]["sessions"] != 1_000
            or state["session_root"] != expected_updated_root
            for state in updated_wallet_states
        ):
            raise RuntimeError(
                f"session root update did not converge: {updated_wallet_states}"
            )

        wrong_signer_snapshot = json.loads(json.dumps(update_snapshot))
        wrong_signer_snapshot["signer"] = "ANET" + ("F" * 36)
        wrong_signer_result = assert_check_tx_rejected(
            rpc_ports[0],
            json.dumps(wrong_signer_snapshot, separators=(",", ":")).encode(),
            "not the configured oracle",
        )

        decreased_entries = [dict(entry) for entry in updated_entries]
        for entry in decreased_entries:
            if entry["wallet"].strip().upper() == SENDER:
                entry["sessions"] = 999
        _, _, decreased_snapshot_raw, _ = signed_session_snapshot(
            args.tx_generator,
            decreased_entries,
            as_of_ms=update_snapshot["as_of_ms"] + 1,
        )
        decreased_snapshot_result = assert_check_tx_rejected(
            rpc_ports[0], decreased_snapshot_raw, "session count decreased"
        )

        omitted_entries = [
            dict(entry)
            for entry in updated_entries
            if entry["wallet"].strip().upper() != SENDER
        ]
        _, _, omitted_snapshot_raw, _ = signed_session_snapshot(
            args.tx_generator,
            omitted_entries,
            as_of_ms=update_snapshot["as_of_ms"] + 2,
        )
        omitted_snapshot_result = assert_check_tx_rejected(
            rpc_ports[0], omitted_snapshot_raw, "omitted active account"
        )
        state_after_rejected_root_updates = account_query(rpc_ports[0], SENDER)
        if state_after_rejected_root_updates["session_root"] != expected_updated_root:
            raise RuntimeError("rejected session snapshots changed the committed root")
        if state_after_rejected_root_updates["nonce"] != 1:
            raise RuntimeError("rejected session snapshots changed transaction state")

        _, _, replayed_snapshot_raw, _ = signed_session_snapshot(
            args.tx_generator,
            updated_entries,
            as_of_ms=update_snapshot["as_of_ms"] - 1,
        )
        replayed_snapshot_result = assert_check_tx_rejected(
            rpc_ports[0], replayed_snapshot_raw, "timestamp was already applied"
        )

        raw_updated_transfer, updated_transfer_hash = signed_transfer(
            args.tx_generator,
            2,
            updated_genesis_path,
            recipient=INELIGIBLE_WALLET,
        )
        updated_transfer_reply = rpc(
            rpc_ports[0],
            "broadcast_tx_commit",
            {"tx": base64.b64encode(raw_updated_transfer).decode()},
        )
        updated_transfer_result = assert_commit_reply(
            updated_transfer_reply, updated_transfer_hash
        )
        updated_transfer_index = find_indexed_tx(rpc_ports[0], updated_transfer_hash)
        if updated_transfer_index["height"] != updated_transfer_result["height"]:
            raise RuntimeError(
                "newly eligible transfer commit and index heights differ"
            )
        updated_wallet_after_transfer = account_query(
            rpc_ports[0], INELIGIBLE_WALLET
        )
        if updated_wallet_after_transfer["account"]["ants_balance"] <= 0:
            raise RuntimeError(
                "transfer to the wallet made eligible by the root update did not apply"
            )
        state_after_updated_transfer = assert_account_state(rpc_ports, 2)

        stop_comet_node(2)
        stop_comet_node(3)
        before_stall = [wait_for_status(rpc_ports[index]) for index in (0, 1)]
        raw_tx3, hash3 = signed_transfer(args.tx_generator, 3, updated_genesis_path)
        stalled_reply = rpc(
            rpc_ports[0],
            "broadcast_tx_commit",
            {"tx": base64.b64encode(raw_tx3).decode()},
        )
        if "error" not in stalled_reply or "timed out" not in stalled_reply["error"].get("data", ""):
            raise RuntimeError(f"2-of-4 unexpectedly committed or failed differently: {stalled_reply}")
        mempools_during_stall = [
            http_json(f"http://127.0.0.1:{rpc_ports[index]}/num_unconfirmed_txs")["result"]
            for index in (0, 1)
        ]
        after_stall = [wait_for_status(rpc_ports[index]) for index in (0, 1)]
        if any(pool["n_txs"] == "0" for pool in mempools_during_stall):
            raise RuntimeError(f"nonce-2 transfer did not remain pending: {mempools_during_stall}")
        for before, after in zip(before_stall, after_stall):
            if before["sync_info"]["latest_block_hash"] != after["sync_info"]["latest_block_hash"]:
                raise RuntimeError("a block finalized with only 2 of 4 validators online")

        start_comet_node(2)
        start_comet_node(3)
        for port in rpc_ports:
            wait_for_status(port)
        indexed3 = find_indexed_tx(rpc_ports[0], hash3)
        state3 = assert_account_state(rpc_ports, 3)

        stop_comet_node(3)
        raw_tx4, hash4 = signed_transfer(args.tx_generator, 4, updated_genesis_path)
        commit4 = rpc(
            rpc_ports[0],
            "broadcast_tx_commit",
            {"tx": base64.b64encode(raw_tx4).decode()},
        )
        result4 = assert_commit_reply(commit4, hash4)
        indexed4 = find_indexed_tx(rpc_ports[0], hash4)
        if indexed4["height"] != result4["height"]:
            raise RuntimeError(f"3-of-4 commit and index heights differ: {result4}, {indexed4}")
        state4 = assert_account_state(rpc_ports[:3], 4)

        start_comet_node(3)
        for port in rpc_ports:
            wait_for_status(port)
        state_after_restart = assert_account_state(rpc_ports, 4)
        common_height, common_hash, common_app_hash, status_states = common_block(rpc_ports)

        print(json.dumps({
            "run_dir": str(run_root),
            "chain_id": CHAIN_ID,
            "four_of_four": {
                "tx_hash": hash1,
                "commit_height": result1["height"],
                "index_height": indexed1["height"],
                "nonce": state1["nonce"],
                "sender_balance": state1["account"]["ants_balance"],
            },
            "rejections": {
                "invalid_signature": invalid_signature_result["log"],
                "wrong_chain": wrong_chain_result["log"],
                "duplicate_nonce": duplicate_nonce_result["log"],
                "tampered_session_proof": tampered_proof_result["log"],
                "below_threshold_proof": ineligible_recipient_result["log"],
                "stale_snapshot": stale_snapshot_result["log"],
                "replayed_snapshot": replayed_snapshot_result["log"],
                "wrong_snapshot_signer": wrong_signer_result["log"],
                "decreased_sessions": decreased_snapshot_result["log"],
                "omitted_active_wallet": omitted_snapshot_result["log"],
                "state_unchanged": True,
            },
            "session_root_update": {
                "tx_hash": update_snapshot_hash,
                "commit_height": update_result["height"],
                "index_height": update_index["height"],
                "root": expected_updated_root,
                "as_of_ms": update_snapshot["as_of_ms"],
                "newly_eligible_sessions": updated_wallet_after_transfer["account"]["sessions"],
                "newly_eligible_balance": updated_wallet_after_transfer["account"]["ants_balance"],
                "sender_nonce": state_after_updated_transfer["nonce"],
                "sender_balance": state_after_updated_transfer["account"]["ants_balance"],
            },
            "two_of_four": {
                "commit_timed_out": True,
                "pending_counts": [pool["n_txs"] for pool in mempools_during_stall],
                "no_finality": True,
            },
            "quorum_recovery": {
                "tx_hash": hash3,
                "index_height": indexed3["height"],
                "nonce": state3["nonce"],
                "sender_balance": state3["account"]["ants_balance"],
            },
            "three_of_four": {
                "tx_hash": hash4,
                "commit_height": result4["height"],
                "index_height": indexed4["height"],
                "nonce": state4["nonce"],
                "sender_balance": state4["account"]["ants_balance"],
            },
            "restart_replay": {
                "nonce": state_after_restart["nonce"],
                "sender_balance": state_after_restart["account"]["ants_balance"],
                "common_height": common_height,
                "common_block_hash": common_hash,
                "common_app_hash": common_app_hash,
                "latest_heights": [state["sync_info"]["latest_block_height"] for state in status_states],
            },
        }, indent=2))
    finally:
        stop_processes(processes, logs)


if __name__ == "__main__":
    main()