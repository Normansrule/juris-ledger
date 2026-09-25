import json
import subprocess
import time
from pathlib import Path

import pytest

from jurisledger import tx as T
from jurisledger.contracts import Wallet
from jurisledger.deploy import init
from jurisledger.experiments import MiniWorld
from jurisledger.net import Client
from jurisledger.cluster import wait_height


def test_policy_changes_need_a_validator_quorum_and_take_effect_at_once():
    m = MiniWorld(issuers=("a", "b"), policy={"min_attestations": 2, "unverified_payment_limit": 100, "recovery_delay": 2})
    vw = [Wallet(k, m.chain_id) for k in m.vkeys]
    vote = lambda w: w.make(T.VALIDATOR_VOTE, {"action": "SET_POLICY", "target": "unverified_payment_limit", "value": 5000})
    m.send(vote(vw[0]), vote(vw[1]))
    assert m.chain.state.policy["unverified_payment_limit"] == 100
    m.send(vote(vw[2]))
    assert m.chain.state.policy["unverified_payment_limit"] == 5000
    m.send(m.w["alice"].pay(m.w["bakery"].address, 4000, "FINAL_CONSUMPTION"))     # unverified, now allowed
    assert m.balance("alice") == 1_000_000_00 - 4000
    bad = vw[0].make(T.VALIDATOR_VOTE, {"action": "SET_POLICY", "target": "quorum", "value": 1})
    m.send(bad)
    assert "quorum" not in m.chain.state.policy
    outsider = m.w["alice"].make(T.VALIDATOR_VOTE, {"action": "SET_POLICY", "target": "min_attestations", "value": 0})
    m.send(outsider)
    assert m.chain.state.policy["min_attestations"] == 2


@pytest.mark.timeout(120)
def test_init_folders_start_a_working_network(tmp_path):
    from jurisledger.net import free_ports
    ports = free_ports(4)
    hosts = [f"127.0.0.1:{p}" for p in ports]
    init(str(tmp_path), hosts, ["registry"], "init-test", 1, 100, 5, 10_000_00)
    genesis = json.loads((tmp_path / "genesis.json").read_text())
    assert genesis["policy"]["min_attestations"] == 1 and len(genesis["issuers"]) == 1
    for i in range(4):
        assert not (tmp_path / f"validator-{i}" / f"validator-{(i + 1) % 4}.key.json").exists()  # no key leaks across folders
    procs = [subprocess.Popen(["bash", str(tmp_path / f"validator-{i}" / "start.sh")],
                              stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) for i in range(4)]
    try:
        st = wait_height(Client("127.0.0.1", ports[0]), 2, 40)
        assert st.get("height", 0) >= 2
        assert Client("127.0.0.1", ports[1]).export().chain_id == "init-test"
    finally:
        for p in procs:
            p.kill()
