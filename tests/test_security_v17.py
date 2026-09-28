import json
import os

import pytest

from jurisledger import state as S
from jurisledger import tx as T
from jurisledger.contracts import Wallet
from jurisledger.crypto import KeyPair
from jurisledger.experiments import MiniWorld
from jurisledger.keystore import KeystoreError, load, open_sealed, save, seal


def test_keystore_roundtrip_wrong_passphrase_and_tampering(tmp_path):
    k = KeyPair.generate()
    p = tmp_path / "k.json"
    save(k, p, "correct horse battery")
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    data = json.loads(p.read_text())
    assert "secret" not in data and k.secret_hex() not in p.read_text()
    assert load(p, "correct horse battery").address == k.address
    with pytest.raises(KeystoreError, match="wrong passphrase"):
        load(p, "incorrect horse")
    moved = dict(data, address=KeyPair.generate().address)      # try to pass the sealed key off as another account
    with pytest.raises(KeystoreError):
        open_sealed(moved, "correct horse battery")
    with pytest.raises(KeystoreError, match="at least 8"):
        seal(k, "short")


def test_keystore_passphrase_from_environment(tmp_path, monkeypatch):
    k = KeyPair.generate()
    save(k, tmp_path / "k.json", "from the environment")
    monkeypatch.setenv("JURISLEDGER_PASSPHRASE", "from the environment")
    assert load(tmp_path / "k.json").address == k.address


def test_plain_key_files_still_load(tmp_path):
    k = KeyPair.generate()
    save(k, tmp_path / "plain.json")
    assert load(tmp_path / "plain.json").address == k.address


def test_per_account_block_quota_limits_spam_but_not_institutions():
    m = MiniWorld(issuers=("a",), policy={"max_tx_per_block": 3})
    alice, bakery, treasury = m.w["alice"], m.w["bakery"], m.w["treasury"]
    spam = [alice.pay(bakery.address, 1_00 + i, S.FINAL_CONSUMPTION) for i in range(10)]
    gov = [treasury.pay(bakery.address, 1_00 + i, S.GOVERNMENT_PURCHASE) for i in range(6)]
    for t in spam + gov:
        m.net.submit(t)
    m.net.produce_block()
    first = m.chain.blocks[-1].txs
    assert sum(t.sender == alice.address for t in first) == 3
    assert sum(t.sender == treasury.address for t in first) == 6          # government is exempt
    m.net.run_until_empty()
    assert m.chain.state.accounts[alice.address]["nonce"] == 10            # nothing lost, only spread out
    bad = m.chain.state.copy()
    height = m.chain.height + 1
    extra = [Wallet(alice.key, m.chain_id, next_nonce=10 + i).pay(bakery.address, 5, S.FINAL_CONSUMPTION) for i in range(4)]
    for t in extra[:3]:
        bad.apply(t, height)
    with pytest.raises(S.InvalidTx, match="quota"):
        bad.apply(extra[3], height)


def test_quota_can_be_set_by_validator_vote():
    m = MiniWorld()
    vw = [Wallet(k, m.chain_id) for k in m.vkeys]
    m.send(*[v.make(T.VALIDATOR_VOTE, {"action": "SET_POLICY", "target": "max_tx_per_block", "value": 2}) for v in vw[:3]])
    assert m.chain.state.policy["max_tx_per_block"] == 2
