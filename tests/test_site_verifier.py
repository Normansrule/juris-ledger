"""The browser verifier (site/verify.js) must agree with the Python one on every file."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from jurisledger import legal
from jurisledger import state as S
from jurisledger.contracts import Wallet
from jurisledger.crypto import KeyPair
from jurisledger.experiments import LEASE_PROSE, MiniWorld

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")


def _node_ok() -> bool:
    if not NODE:
        return False
    r = subprocess.run([NODE, "-e", "crypto.subtle.generateKey({name:'Ed25519'},true,['sign']).then(()=>process.exit(0),()=>process.exit(1))"])
    return r.returncode == 0


needs_node = pytest.mark.skipif(not _node_ok(), reason="Node.js with WebCrypto Ed25519 not available")


def js_verify(tmp_path, bundle, validators):
    ev, vals = tmp_path / "ev.json", tmp_path / "vals.json"
    ev.write_text(json.dumps(bundle)); vals.write_text(json.dumps(validators))
    out = subprocess.run([NODE, str(ROOT / "tests/js/verify_cli.mjs"), str(ev), str(vals)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def lease_with_rotation():
    m = MiniWorld()
    mill, bakery = m.w["mill"], m.w["bakery"]
    t = mill.create_contract("Oven lease", LEASE_PROSE,
                             {"obligations": [legal.obligation("rent", bakery.address, mill.address, 300_00, 99)]},
                             [mill.address, bakery.address])
    m.send(t); m.send(bakery.sign_contract(t.txid, LEASE_PROSE))
    new = Wallet(KeyPair.from_seed("mill-rotated"), m.chain_id)
    m.send(mill.rotate_key(new.address))
    m.send(bakery.pay(new.address, 300_00, S.INTERMEDIATE, contract=t.txid, obligation="rent"))
    return m, json.loads(json.dumps(legal.evidence_bundle(m.chain, t.txid, LEASE_PROSE)))


@needs_node
def test_browser_and_python_agree_on_genuine_and_tampered_files(tmp_path):
    m, bundle = lease_with_rotation()
    vals = m.genesis["validators"]
    cases = {"genuine": bundle}
    t = json.loads(json.dumps(bundle)); t["items"][-1]["tx"]["payload"]["amount"] += 1; cases["amount"] = t
    t = json.loads(json.dumps(bundle)); t["prose"] = t["prose"].replace("500.00", "50.00"); cases["prose"] = t
    t = json.loads(json.dumps(bundle)); t["items"][0]["inclusion"]["votes"] = {}; cases["votes"] = t
    t = json.loads(json.dumps(bundle)); t["key_changes"] = []; cases["no key change"] = t
    for name, b in cases.items():
        py = legal.verify_evidence_bundle(b, vals)
        js = js_verify(tmp_path, b, vals)
        assert js["valid"] == py["valid"], (name, js, py["problems"])
        assert js["fully_signed"] == py.get("fully_signed"), name
    assert js_verify(tmp_path, bundle, vals)["valid"] is True
    assert js_verify(tmp_path, bundle, [KeyPair.from_seed(f"x{i}").address for i in range(4)])["valid"] is False


def test_committed_site_sample_verifies():
    text = (ROOT / "site/sample-evidence.js").read_text()
    data = json.loads(text[text.index("=") + 1:].rstrip().rstrip(";"))
    report = legal.verify_evidence_bundle(data["bundle"], data["validators"])
    assert report["valid"] and report["fully_signed"] and report["prose_matches"]
