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


@needs_node
def test_browser_ledger_audit_and_gdp_agree_with_python(tmp_path):
    from jurisledger.chain import Chain, InvalidBlock
    from jurisledger.demo import build
    from jurisledger.stats import gdp
    made = build(str(tmp_path / "demo"))
    text = Path(made["chain"]).read_text()

    def js(script, obj):
        f = tmp_path / "c.json"; f.write_text(json.dumps(obj))
        return json.loads(subprocess.run([NODE, str(ROOT / "tests/js" / script), str(f)], capture_output=True, text=True, check=True).stdout)

    genuine = json.loads(text)
    assert js("audit_cli.mjs", genuine)["valid"] is True
    assert js("gdp_cli.mjs", genuine)["gdp"] == gdp(Chain.load(text)).expenditure
    tampers = []
    t = json.loads(text); t["blocks"][4]["txs"][0]["payload"]["amount"] += 1; tampers.append(t)
    t = json.loads(text); t["blocks"][2]["header"]["prev_hash"] = "00" * 32; tampers.append(t)
    t = json.loads(text); t["blocks"].pop(3); tampers.append(t)
    t = json.loads(text); t["blocks"][1]["votes"] = dict(list(t["blocks"][1]["votes"].items())[:1]); tampers.append(t)
    for t in tampers:
        assert js("audit_cli.mjs", t)["valid"] is False
        with pytest.raises(InvalidBlock):
            Chain.load(json.dumps(t))
    snap = Chain.load(text)
    snap_export = {"genesis": snap.genesis, "snapshot": snap.make_snapshot(), "blocks": []}
    r = js("audit_cli.mjs", snap_export)
    assert r["valid"] is True and r["base_height"] == snap.height


def test_committed_site_sample_chain_audits():
    from jurisledger.chain import Chain
    text = (ROOT / "site/sample-chain.js").read_text()
    body = text[text.index("=") + 1:].rstrip().rstrip(";")
    assert Chain.load(body).height == 12


@needs_node
def test_browser_fraud_flags_match_python_on_all_four_detectors(tmp_path):
    from jurisledger import fraud
    from jurisledger.crypto import sha256_hex
    from jurisledger.sim import SimConfig, run_simulation
    res = run_simulation(SimConfig(periods=3))
    eco, net = res.economy, res.network
    f = eco.firms
    ring = [f[1], f[6], f[11]]
    for i, a in enumerate(ring):
        net.submit(a.pay(ring[(i + 1) % 3].address, 250_000_00 + i * 1_000_00, S.INTERMEDIATE))
    for i in range(6):
        net.submit(f[3].pay(eco.banks[0].address, 9_400_00 + i * 50_00, "FINANCIAL"))
    for k in range(80):
        net.submit(f[8].pay(f[9].address, eco.rng.randint(1_000_00, 9_999_00), S.INTERMEDIATE))
    inv = sha256_hex(b"receivable #77")
    for bank in eco.banks:
        net.submit(bank.pay(f[14].address, 80_000_00, "FINANCIAL", invoice=inv))
    net.run_until_empty()
    chain_file = tmp_path / "chain.json"
    chain_file.write_text(res.chain.export())
    out = subprocess.run([NODE, str(ROOT / "tests/js/flags_cli.mjs"), str(chain_file), "1000000"],
                         capture_output=True, text=True, check=True)
    js = json.loads(out.stdout)
    py = fraud.run_all(res.chain, 10_000_00)

    def key(flag):
        who = flag.get("accounts") or [flag.get("account") or flag.get("invoice")]
        return (flag["detector"], tuple(sorted(who)), flag.get("total"), flag.get("count"))

    assert sorted(map(key, js)) == sorted(map(key, py))
    assert {f["detector"] for f in js} == {"circular_flow", "structuring", "benford", "duplicate_invoice_financing"}


@needs_node
def test_browser_wallet_signs_byte_identically_and_keystores_cross_open(tmp_path):
    from jurisledger import keystore
    from jurisledger import tx as T
    from jurisledger.crypto import KeyPair
    k = KeyPair.from_seed("wallet-test")
    payload = {"to": "ab" * 32, "amount": 1250, "purpose": "FINAL_CONSUMPTION", "note": "café ☕ <b>"}
    run = lambda *a: subprocess.run([NODE, str(ROOT / "tests/js/wallet_cli.mjs"), *a], capture_output=True, text=True, check=True).stdout
    js = T.Transaction.from_dict(json.loads(run("sign", k.secret_hex(), "demo-republic", "PAYMENT", "7", json.dumps(payload))))
    py = T.Transaction.create("demo-republic", "PAYMENT", k, 7, payload)
    assert js.signature_valid() and js.signature == py.signature and js.txid == py.txid
    sealed_in_browser = json.loads(run("seal", k.secret_hex(), "browser passphrase"))
    assert sealed_in_browser["kdf"] == "pbkdf2-sha256" and k.secret_hex() not in json.dumps(sealed_in_browser)
    assert keystore.open_sealed(sealed_in_browser, "browser passphrase").address == k.address
    with pytest.raises(keystore.KeystoreError):
        keystore.open_sealed(sealed_in_browser, "wrong passphrase")
    f = tmp_path / "py.json"
    f.write_text(json.dumps(keystore.seal(k, "python passphrase", "pbkdf2-sha256")))
    assert json.loads(run("open", str(f), "python passphrase"))["address"] == k.address
