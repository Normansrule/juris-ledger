import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from jurisledger import privacy as PV
from jurisledger import state as S
from jurisledger.chain import Chain, InvalidBlock
from jurisledger.contracts import ConfidentialWallet
from jurisledger.crypto import KeyPair
from jurisledger.experiments import MiniWorld
from jurisledger.contracts import audit_trail
from jurisledger.__main__ import main


def test_snapshot_roundtrip_continues_and_detects_tampering():
    m = MiniWorld()
    mill, bakery = m.w["mill"], m.w["bakery"]
    t = mill.create_contract("lease", "text", {}, [mill.address, bakery.address])
    m.send(t); m.send(bakery.sign_contract(t.txid, "text")); m.send(bakery.access(t.txid, "VIEW", "look"))
    snap = json.loads(json.dumps(m.chain.make_snapshot()))
    joined = Chain.from_snapshot(m.genesis, snap, m.genesis["validators"])
    assert joined.height == 3 and joined.state.root() == m.chain.state.root()
    assert [e["action"] for e in audit_trail(joined, t.txid)] == ["VIEW"]
    # the joined chain keeps accepting real blocks
    m.send(m.w["alice"].pay(bakery.address, 1_00, S.FINAL_CONSUMPTION))
    joined.add_block(m.chain.blocks[-1])
    assert joined.state.root() == m.chain.state.root() and joined.find_tx(m.chain.blocks[-1].txs[0].txid) == (4, 0)
    assert Chain.load(joined.export()).state.root() == m.chain.state.root()
    # tampering: a balance changed inside the snapshot, or a certificate stripped
    bad = json.loads(json.dumps(snap)); bad["state"]["accounts"][bakery.address]["balance"] += 1
    with pytest.raises(InvalidBlock, match="state_root"):
        Chain.from_snapshot(m.genesis, bad, m.genesis["validators"])
    thin = json.loads(json.dumps(snap)); thin["votes"] = dict(list(thin["votes"].items())[:2])
    with pytest.raises(InvalidBlock, match="quorum"):
        Chain.from_snapshot(m.genesis, thin, m.genesis["validators"])
    bad = json.loads(json.dumps(snap)); bad["state"]["access_log"] = []
    with pytest.raises(ValueError, match="digest"):
        Chain.from_snapshot(m.genesis, bad, m.genesis["validators"])


def test_snapshot_cli(tmp_path, capsys):
    m = MiniWorld()
    m.send(m.w["alice"].pay(m.w["bakery"].address, 1_00, S.FINAL_CONSUMPTION))
    chain, snap = tmp_path / "chain.json", tmp_path / "snap.json"
    chain.write_text(m.chain.export())
    assert main(["jurisledger", "snapshot", str(chain), "-o", str(snap)]) == 0
    assert main(["jurisledger", "audit", str(snap)]) == 0
    assert "Snapshot after block 1" in capsys.readouterr().out


def test_encrypted_note_lets_recipient_recover_the_opening_from_the_chain():
    m = MiniWorld()
    alice, bakery = m.w["alice"], m.w["bakery"]
    ca, cb = ConfidentialWallet(alice), ConfidentialWallet(bakery)
    m.send(ca.shield(500_00))
    tx, _ = ca.pay(bakery.address, 120_00, S.FINAL_CONSUMPTION)        # note travels encrypted in the tx
    m.send(tx)
    assert cb.scan(m.chain) == 1 and cb.amount == 120_00
    assert PV.verify_opening(m.chain.state.hidden(bakery.address), cb.opening)
    assert cb.scan(m.chain) == 0                                        # not counted twice
    stranger = ConfidentialWallet(m.w["mill"])
    assert stranger.scan(m.chain) == 0
    assert '"amount": 12000' not in json.dumps(tx.to_dict())          # the note is not plaintext


@pytest.mark.timeout(180)
def test_wallet_cli_against_a_live_validator(tmp_path, capsys):
    from jurisledger.cluster import node_command, write_cluster_files, wait_height
    from jurisledger.net import Client
    out = tmp_path / "c"
    setup = write_cluster_files(out, 4)
    procs = [subprocess.Popen(node_command(out, i), stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) for i in range(4)]
    try:
        target = f"127.0.0.1:{setup['ports'][0]}"
        wait_height(Client("127.0.0.1", setup["ports"][0]), 1, 30)
        wallets = json.loads((out / "wallets.json").read_text())
        ana, cafe = tmp_path / "ana.json", tmp_path / "cafe.json"
        ana.write_text(json.dumps({"secret": wallets["ana"]}))
        assert main(["jurisledger", "wallet", "new", "-o", str(cafe)]) == 0
        assert main(["jurisledger", "wallet", "balance", target, "--key", str(ana)]) == 0
        assert "100,000.00" in capsys.readouterr().out
        assert main(["jurisledger", "wallet", "register", target, "--key", str(cafe), "--name", "Corner Cafe",
                     "--role", "firm", "--sector", "services"]) == 0
        cafe_addr = KeyPair.from_secret_hex(json.loads(cafe.read_text())["secret"]).address
        assert main(["jurisledger", "wallet", "pay", target, "--key", str(ana), "--to", cafe_addr,
                     "--amount", "12.50", "--purpose", "FINAL_CONSUMPTION"]) == 0
        assert main(["jurisledger", "wallet", "balance", target, "--key", str(cafe)]) == 0
        assert "12.50" in capsys.readouterr().out
        with pytest.raises(SystemExit):
            main(["jurisledger", "wallet", "pay", target, "--key", str(ana), "--to", cafe_addr,
                  "--amount", "twelve", "--purpose", "FINAL_CONSUMPTION"])
    finally:
        for p in procs:
            p.kill()
