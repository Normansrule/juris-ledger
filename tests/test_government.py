"""Identity, keys, storage, the command line and the browsable register."""
import json

import pytest

from jurisledger import state as S
from jurisledger.__main__ import main
from jurisledger.chain import Chain, InvalidBlock
from jurisledger.contracts import Wallet
from jurisledger.crypto import KeyPair
from jurisledger.dashboard import render
from jurisledger.demo import build
from jurisledger.experiments import MiniWorld
from jurisledger.ledgernet import LedgerNetwork
from jurisledger.storage import BlockStore

POLICY = {"min_attestations": 2, "unverified_payment_limit": 100, "recovery_delay": 2}


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    out = tmp_path_factory.mktemp("demo")
    return build(str(out))


def test_open_network_has_no_identity_rules():
    m = MiniWorld()
    assert m.chain.state.is_verified(m.w["alice"].address)


def test_attestations_from_the_same_issuer_count_once():
    m = MiniWorld(issuers=("a", "b"), policy=POLICY)
    alice = m.w["alice"].address
    m.send(m.issuers["a"].attest(alice, "one"))
    m.send(m.issuers["a"].attest(alice, "again"))
    assert m.chain.state.attestation_count(alice) == 1 and not m.chain.state.is_verified(alice)


def test_rotation_to_a_key_in_use_is_rejected_and_payments_to_dead_keys_fail():
    m = MiniWorld()
    alice, bakery = m.w["alice"], m.w["bakery"]
    m.send(alice.rotate_key(bakery.address))
    assert "successor" not in m.chain.state.accounts[alice.address]
    alice.resync(m.chain)
    new = KeyPair.from_seed("alice-2")
    m.send(alice.rotate_key(new.address))
    m.send(bakery.pay(alice.address, 5, S.FINANCIAL))
    assert m.chain.state.accounts[new.address]["balance"] == 1_000_000_00
    assert m.chain.state.accounts[alice.address]["balance"] == 0


def test_validators_cannot_rotate_outside_governance():
    m = MiniWorld()
    v = Wallet(m.vkeys[0], m.chain_id)
    m.send(v.rotate_key(KeyPair.from_seed("v-new").address))
    assert "successor" not in m.chain.state.accounts[v.address]


def test_store_roundtrip_torn_write_and_tamper(tmp_path):
    m = MiniWorld(network=LedgerNetwork)
    for i in range(3):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 100 + i, S.FINAL_CONSUMPTION))
    store = BlockStore.create(tmp_path / "s", m.genesis)
    assert store.save(m.chain) == 3 and store.save(m.chain) == 0
    assert store.load().state.root() == m.chain.state.root()
    with open(store.blocks_path, "ab") as f:
        f.write(b'{"header": {"chain')                       # power cut mid-append
    again = BlockStore(tmp_path / "s")
    assert again.load().height == 3 and again.recovered_partial_write
    text = store.blocks_path.read_text().replace('"amount": 101', '"amount": 999')
    store.blocks_path.write_text(text)
    with pytest.raises(InvalidBlock):
        BlockStore(tmp_path / "s").load()


def test_cli_audit_and_verify(demo, tmp_path, capsys):
    assert main(["jurisledger", "audit", demo["chain"]]) == 0
    assert main(["jurisledger", "verify", demo["evidence"], demo["validators"]]) == 0
    assert "VERIFIED" in capsys.readouterr().out

    bundle = json.loads(open(demo["evidence"]).read())
    bundle["prose"] = bundle["prose"].replace("12,000.00", "1,200.00")
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(bundle))
    assert main(["jurisledger", "verify", str(forged), demo["validators"]]) == 1
    assert "REJECTED" in capsys.readouterr().out

    ledger = json.loads(open(demo["chain"]).read())
    ledger["blocks"][3]["votes"] = {}
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(ledger))
    assert main(["jurisledger", "audit", str(bad)]) == 1
    assert main(["jurisledger", "register", str(bad), "-o", str(tmp_path / "x.html")]) == 1


def test_register_is_self_contained_and_escapes_user_text(demo):
    html = open(demo["register"]).read()
    assert "Independently re-verified" in html and "Cold-storage lease" in html
    assert "http://" not in html.replace("http://www.w3.org", "") and "<link" not in html and "src=" not in html

    m = MiniWorld()
    mill, bakery = m.w["mill"], m.w["bakery"]
    m.send(mill.create_contract('<script>alert("x")</script>', "t", {}, [mill.address, bakery.address]))
    page = render(m.chain)
    assert "<script>alert" not in page and "&lt;script&gt;alert" in page


def test_demo_ledger_is_consistent(demo):
    chain = Chain.load(open(demo["chain"]).read())
    assert chain.state.policy["min_attestations"] == 2
    assert all(c["status"] == S.ACTIVE for c in chain.state.contracts.values())
    assert any(b.vote_round >= b.header.round for b in chain.blocks)


def test_explainer_site_is_self_contained_and_covers_every_step():
    import re
    from pathlib import Path
    html = Path(__file__).resolve().parent.parent / "site" / "index.html"
    text = html.read_text()
    assert "<link" not in text and 'src="http' not in text and "@import" not in text
    for anchor in ("final", "attack", "contract", "identity", "hidden", "gdp", "fraud"):
        assert f'id="{anchor}"' in text
    assert "prefers-reduced-motion" in text and "prefers-color-scheme" in text
