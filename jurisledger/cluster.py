"""Run several validator processes on one machine, then exercise them like a user would.

    jurisledger cluster --out cluster/ [--n 4]

Writes a genesis, one key file per validator, launches N ``jurisledger node`` processes,
submits real transactions through the client, kills one validator, restarts it from its
store and checks that it catches up.  Prints what a real deployment's command lines look
like (same commands, different hostnames).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from . import state as S
from .contracts import Wallet
from .crypto import KeyPair
from .net import Client, free_ports


def write_cluster_files(out: Path, n: int, chain_id: str = "cluster-local") -> Dict[str, Any]:
    """A fresh ledger every run: keys and genesis are regenerated, so stores from an earlier run
    (which belong to a different founding record) are removed first."""
    import shutil
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("store-*"):
        shutil.rmtree(old, ignore_errors=True)
    for old in out.glob("validator-*.log"):
        old.unlink()
    keys = [KeyPair.generate() for _ in range(n)]
    ports = free_ports(n)
    people = {name: Wallet(KeyPair.generate(), chain_id) for name in ("ana", "cafe", "roaster", "city")}
    roles = {"ana": (S.HOUSEHOLD, ""), "cafe": (S.FIRM, "services"),
             "roaster": (S.FIRM, "manufacturing"), "city": (S.GOVERNMENT, "")}
    genesis = {"chain_id": chain_id, "validators": [k.address for k in keys],
               "accounts": [{"address": w.address, "name": nm, "role": roles[nm][0], "sector": roles[nm][1],
                             "balance": 100_000_00} for nm, w in people.items()]
               + [{"address": k.address, "name": f"validator-{i}", "role": S.VALIDATOR, "sector": "", "balance": 0}
                  for i, k in enumerate(keys)]}
    (out / "genesis.json").write_text(json.dumps(genesis, indent=1))
    peers = [f"127.0.0.1:{p}" for p in ports]
    (out / "peers.json").write_text(json.dumps(peers, indent=1))
    for i, k in enumerate(keys):
        (out / f"validator-{i}.key.json").write_text(json.dumps({"secret": k.secret_hex(), "address": k.address}))
    (out / "wallets.json").write_text(json.dumps({nm: w.key.secret_hex() for nm, w in people.items()}))
    return {"genesis": genesis, "peers": peers, "ports": ports, "people": people, "keys": keys}


def node_command(out: Path, i: int) -> List[str]:
    return [sys.executable, "-m", "jurisledger", "node", "--genesis", str(out / "genesis.json"),
            "--key", str(out / f"validator-{i}.key.json"), "--peers", str(out / "peers.json"),
            "--store", str(out / f"store-{i}"), "--index", str(i)]


def wait_height(client: Client, height: int, timeout: float) -> Dict[str, Any]:
    deadline = time.time() + timeout
    st: Dict[str, Any] = {}
    while time.time() < deadline:
        try:
            st = client.status()
            if st.get("height", 0) >= height:
                return st
        except OSError:
            pass
        time.sleep(0.3)
    return st


def run(out_dir: str, n: int = 4, log: Any = print) -> Dict[str, Any]:
    out = Path(out_dir)
    setup = write_cluster_files(out, n)
    procs = [subprocess.Popen(node_command(out, i), stdout=open(out / f"validator-{i}.log", "w"),
                              stderr=subprocess.STDOUT) for i in range(n)]
    clients = [Client("127.0.0.1", p) for p in setup["ports"]]
    people = setup["people"]
    result: Dict[str, Any] = {}
    try:
        log(f"started {n} validator processes; waiting for the first block")
        st = wait_height(clients[0], 1, 30)
        result["first_block"] = st.get("height", 0) >= 1
        log(f"  block 1 finalised: {result['first_block']}")
        if not result["first_block"]:
            dead = [i for i, p in enumerate(procs) if p.poll() is not None]
            log(f"  no block after 30 s; validators that exited: {dead}. See {out}/validator-*.log")
            result["ok"] = False
            return result

        txs = [people["ana"].pay(people["cafe"].address, 4_50, S.FINAL_CONSUMPTION),
               people["cafe"].pay(people["roaster"].address, 720_00, S.INTERMEDIATE),
               people["city"].pay(people["cafe"].address, 300_00, S.GOVERNMENT_PURCHASE)]
        for i, t in enumerate(txs):
            clients[i % n].submit(t)                              # different entry points on purpose
        h = clients[0].status()["height"]
        wait_height(clients[0], h + 3, 30)
        chain = clients[0].export()                               # re-audited locally
        got = {t.txid for _, t in chain.iter_txs()}
        result["txs_finalised"] = all(t.txid in got for t in txs)
        log(f"  3 transactions sent to 3 different validators, all finalised: {result['txs_finalised']}")

        roots = set()
        for c in clients:
            s = wait_height(c, chain.height, 15)
            roots.add(c.export().state.root() if s.get("height", 0) >= chain.height else "lagging")
        result["all_agree"] = len(roots) == 1 and "lagging" not in roots
        log(f"  all {n} validators hold the same state: {result['all_agree']}")

        victim = n - 1
        procs[victim].kill(); procs[victim].wait()
        log(f"  killed validator {victim}")
        h = clients[0].status()["height"]
        st = wait_height(clients[0], h + 3, 30)
        result["live_without_one"] = st.get("height", 0) >= h + 3
        log(f"  the other {n - 1} keep finalising blocks: {result['live_without_one']}")
        for t in (people["ana"].pay(people["cafe"].address, 1_25, S.FINAL_CONSUMPTION),):
            clients[0].submit(t)
        time.sleep(1.5)
        procs[victim] = subprocess.Popen(node_command(out, victim), stdout=open(out / f"validator-{victim}.log", "a"),
                                         stderr=subprocess.STDOUT)
        target = clients[0].status()["height"]
        st = wait_height(clients[victim], target, 40)
        caught_up = st.get("height", 0) >= target
        same = caught_up and clients[victim].export().state.root() == clients[0].export().state.root() \
            if caught_up else False
        result["rejoined"] = caught_up and same
        log(f"  validator {victim} restarted from its store and caught up to block {st.get('height')}: {result['rejoined']}")
        result["height"] = clients[0].status()["height"]
        result["ok"] = all(result.get(k) for k in ("first_block", "txs_finalised", "all_agree", "live_without_one", "rejoined"))
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    log("\nTo run this on separate machines, give each one its key file, the genesis, and a peers.json with the")
    log("others' hostnames, then start:  " + " ".join(node_command(Path("<dir>"), 0)[2:]))
    return result
