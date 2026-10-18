"""Run every reproduction from the v0.25.0 security audit against a source tree.

    python tools/audit_repro.py                    # this checkout
    python tools/audit_repro.py /path/to/v0.25.0   # any other tree (e.g. `git worktree add ../v025 v0.25.0`)

Each reproduction prints VULNERABLE (the defect is present), SAFE (it is refused or handled),
or N/A (the tree lacks what the check needs).  Uses only public behaviour, so the same script
gives the "before" and "after" columns of docs/SECURITY_FINDINGS.md.  The browser findings
(H12, H13) are reproduced by tests/test_browser_security.py with JURISLEDGER_SITE pointing at a tree.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

TREE = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent).resolve()
sys.path.insert(0, str(TREE))

from jurisledger import __version__, legal, net  # noqa: E402
from jurisledger import state as S  # noqa: E402
from jurisledger import tx as T  # noqa: E402
from jurisledger.chain import Chain  # noqa: E402
from jurisledger.contracts import ConfidentialWallet, Wallet  # noqa: E402
from jurisledger.crypto import KeyPair  # noqa: E402
from jurisledger.experiments import MiniWorld  # noqa: E402
from jurisledger.storage import BlockStore  # noqa: E402

RESULTS: list[tuple[str, str, str]] = []


def check(fid: str, title: str):
    def wrap(fn):
        try:
            verdict = fn()
        except Exception as err:  # noqa: BLE001
            verdict = f"ERROR {type(err).__name__}: {err}"[:120]
        RESULTS.append((fid, title, verdict))
        return fn
    return wrap


def world(protocol: int = 2, **kw):
    """A protocol-2 world where the tree supports it (the audited rules), else the default."""
    try:
        return MiniWorld(protocol=protocol, **kw)
    except TypeError:
        return MiniWorld(**kw)


def tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="jl-audit-"))


def validator(m, d: Path, idx: int = 0):
    port = net.free_ports(1)[0]
    st = BlockStore(d) if (d / "genesis.json").exists() else BlockStore.create(d, m.genesis)
    v = net.Validator(m.vkeys[idx], m.genesis, [("127.0.0.1", port)] + [("127.0.0.1", 1)] * 3, st,
                      ("127.0.0.1", port), log=lambda *_: None)
    return v, port


# --------------------------------------------------------------------------- #
@check("F01", "malformed transaction stops a validator")
def f01():
    m = MiniWorld(chain_id="repro-f01")
    v, port = validator(m, tmp() / "s")
    t = threading.Thread(target=v.run, daemon=True)
    t.start()
    time.sleep(0.5)
    try:
        net.Client("127.0.0.1", port)._call({"t": "tx", "tx": {"chain_id": "x"}}, expect_reply=False)
        time.sleep(0.8)
        return "SAFE" if t.is_alive() else "VULNERABLE (event loop died)"
    finally:
        v.stop_event.set()


@check("F02", "restarted validator signs a conflicting precommit")
def f02():
    m = MiniWorld(chain_id="repro-f02")
    d = tmp() / "s"
    v1, _ = validator(m, d)
    v1._start_height()
    v1.proto.round = 0
    v1.proto._sign("PRECOMMIT", 0, "aa" * 32)
    v1.store.unlock()
    v2, _ = validator(m, d)                                # same key, same store: a restart
    v2._start_height()
    try:
        v2.proto._sign("PRECOMMIT", 0, "bb" * 32)
        return "VULNERABLE (second, conflicting signature issued)"
    except Exception as err:  # noqa: BLE001
        return f"SAFE ({type(err).__name__})"
    finally:
        v2.store.unlock()


@check("F03", "cross-network key change completes a contract's signatures")
def f03():
    a = MiniWorld()
    bakery, alice = a.w["bakery"], a.w["alice"]
    a.send(bakery.create_contract("Bread", "text", {}, [bakery.address, alice.address]))
    cid = next(iter(a.chain.state.contracts))
    bundle = legal.evidence_bundle(a.chain, cid, "text")
    orig = KeyPair.from_seed
    KeyPair.from_seed = staticmethod(lambda s: orig(s.replace("other-net/validator", "jurisledger-mini/validator")
                                                      .replace("other-net/alice", "jurisledger-mini/alice")))
    try:
        b = MiniWorld(chain_id="other-net")
    finally:
        KeyPair.from_seed = staticmethod(orig)
    rot = b.w["alice"].rotate_key(bakery.address)
    b.send(rot)
    bundle["key_changes"].append({"tx": rot.to_dict(), "inclusion": b.chain.tx_proof(rot.txid)})
    r = legal.verify_evidence_bundle(bundle, a.genesis["validators"])
    return "VULNERABLE (fully_signed with alice unsigned)" if r.get("fully_signed") else "SAFE"


@check("F04", "forged snapshot names its own certifiers")
def f04():
    from jurisledger.block import BlockHeader, vote_message
    from jurisledger.state import State
    m = MiniWorld()
    for i in range(10):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 10 + i, S.FINAL_CONSUMPTION))
    d = tmp() / "s"
    st = BlockStore.create(d, m.genesis)
    st.save(m.chain)
    st.compact(3, keep_archive=False)
    snap = json.loads((d / "snapshot.json").read_text())
    snap["state"]["accounts"][m.w["alice"].address]["balance"] += 777_777
    h = snap["header"]
    hdr = BlockHeader(h["chain_id"], h["height"], h["round"], h["prev_hash"], h["tx_root"],
                      State.from_snapshot(snap["state"]).root(), h["proposer"], h.get("timestamp", 0))
    fakes = [KeyPair.from_seed(f"attacker-{i}") for i in range(4)]
    msg = vote_message(hdr.chain_id, hdr.height, snap.get("commit_round", hdr.round), hdr.hash)
    snap.update(header=hdr.to_dict(), votes={k.address: k.sign(msg) for k in fakes}, certified_by=[k.address for k in fakes])
    (d / "snapshot.json").write_text(json.dumps(snap))
    (d / "blocks.jsonl").write_bytes(b"")
    try:
        BlockStore(d).load()
        return "VULNERABLE (loaded with +777,777)"
    except Exception as err:  # noqa: BLE001
        return f"SAFE ({type(err).__name__})"


@check("H1", "note-less confidential payment freezes the recipient (protocol 2 where available)")
def h1():
    m = world()
    victim, attacker = ConfidentialWallet(m.w["bakery"]), ConfidentialWallet(m.w["alice"])
    m.send(victim.shield(100))
    m.send(attacker.shield(10))
    tx, _ = attacker.pay(m.w["bakery"].address, 1, S.FINAL_CONSUMPTION, encrypt=False)
    m.send(tx)
    victim.scan(m.chain)
    for c in getattr(victim, "outbox", []):
        m.send(c)
    if hasattr(victim, "sync"):
        victim.sync(m.chain)
    from jurisledger import privacy as PV
    opening = getattr(victim, "confirmed_opening", victim.opening)
    ok = PV.verify_opening(m.chain.state.hidden(victim.w.address), opening)
    return "SAFE" if ok else "VULNERABLE (known opening no longer opens the balance)"


@check("H2", "rejected confidential payment leaves the wallet inconsistent")
def h2():
    m = MiniWorld()
    cw = ConfidentialWallet(m.w["alice"])
    m.send(cw.shield(300))
    tx, _ = cw.pay(m.w["mill"].address, 50, "NOT_A_PURPOSE")
    m.send(tx)
    if not hasattr(cw, "sync"):
        return "VULNERABLE (no reconciliation: wallet believes 250, ledger holds 300)"
    cw.sync(m.chain)
    return "SAFE" if cw.matches_ledger(m.chain) and cw.amount == 300 else "VULNERABLE"


@check("H3", "recovery completes after its attestations were revoked (protocol 2 where available)")
def h3():
    m = world(issuers=("a", "b"), policy={"min_attestations": 2, "unverified_payment_limit": 100, "recovery_delay": 2})
    a, b, alice = m.issuers["a"], m.issuers["b"], m.w["alice"]
    m.send(a.attest(alice.address, "passport"), b.attest(alice.address, "bank"))
    new = Wallet(KeyPair.from_seed("h3-new"), m.chain_id)
    m.send(a.request_recovery(alice.address, new.address), b.request_recovery(alice.address, new.address))
    m.send(a.revoke_attestation(alice.address), b.revoke_attestation(alice.address))
    for _ in range(4):
        m.net.produce_block()
    m.send(a.finalize_recovery(alice.address, new.address))
    return "VULNERABLE (account moved)" if "successor" in m.chain.state.accounts[alice.address] else "SAFE"


@check("H4", "damaged custodian journal lets a receipt be reused")
def h4():
    from jurisledger import vault as Vt
    m = MiniWorld()
    bakery, mill = m.w["bakery"], m.w["mill"]
    t = mill.create_contract("L", "secret", {}, [mill.address, bakery.address], visibility="restricted")
    m.send(t)
    keys = [KeyPair.from_seed(f"h4-{i}") for i in range(3)]
    sealed = Vt.seal(t.txid, "secret", m.chain, [k.address for k in keys], 2)
    m.send(bakery.access(t.txid, "VIEW", "one"))
    j = tmp() / "c.jsonl"
    Vt.Custodian(keys[0], journal=str(j)).release(sealed, bakery.address, m.chain)
    lines = j.read_bytes().split(b"\n")
    j.write_bytes(b'{"damaged\n' + lines[0] + b"\n")          # a damaged complete record before the real one
    try:
        Vt.Custodian(keys[0], journal=str(j)).release(sealed, bakery.address, m.chain)
        return "VULNERABLE (receipt spent twice)"
    except Exception as err:  # noqa: BLE001
        return f"SAFE ({type(err).__name__})"


@check("H5", "key file with unbounded scrypt r/p reaches the key derivation")
def h5():
    from jurisledger import keystore as K
    data = K.seal(KeyPair.from_seed("h5"), "correct horse battery")
    data["r"] = 1 << 20
    called = []
    real = K._derive
    K._derive = lambda *a: called.append(a) or real("x", b"0" * 16, 2 ** 14, 1, 1)
    try:
        K.open_sealed(data, "correct horse battery")
    except Exception:  # noqa: BLE001
        pass
    finally:
        K._derive = real
    return "VULNERABLE (derivation attempted with r=2^20: 4 TiB of memory)" if called else "SAFE"


@check("H6", "privacy release noise is predictable by default")
def h6():
    from jurisledger.sim import SimConfig, run_simulation
    from jurisledger.stats import gdp, private_sector_release
    rep = gdp(run_simulation(SimConfig(periods=1)).chain)
    a = private_sector_release(rep, epsilon=1.0, clip=100_000_00, k_min=1)
    b = private_sector_release(rep, epsilon=1.0, clip=100_000_00, k_min=1)
    return "VULNERABLE (identical noise on every call)" if a == b else "SAFE"


@check("H7", "damaged middle block record truncates later history")
def h7():
    m = MiniWorld()
    for i in range(5):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 10 + i, S.FINAL_CONSUMPTION))
    d = tmp() / "s"
    st = BlockStore.create(d, m.genesis)
    st.save(m.chain)
    lines = st.blocks_path.read_bytes().splitlines(keepends=True)
    lines[1] = b'{"damaged": \n'
    st.blocks_path.write_bytes(b"".join(lines))
    try:
        BlockStore(d).load()
    except Exception as err:  # noqa: BLE001
        kept = len(st.blocks_path.read_bytes().splitlines())
        return f"SAFE ({type(err).__name__}; {kept} records kept)"
    return f"VULNERABLE (file cut to {len(st.blocks_path.read_bytes().splitlines())} of 5 records)"


@check("H8", "paid obligation reported OVERDUE on a pruned copy")
def h8():
    m = MiniWorld()
    mill, bakery = m.w["mill"], m.w["bakery"]
    t = mill.create_contract("L", "x", {"obligations": [legal.obligation("r", bakery.address, mill.address, 300, 4)]},
                             [mill.address, bakery.address])
    m.send(t)
    m.send(bakery.sign_contract(t.txid, "x"))
    m.send(bakery.pay(mill.address, 300, S.INTERMEDIATE, contract=t.txid, obligation="r"))
    for _ in range(6):
        m.net.produce_block()
    early = Chain.audit(m.genesis, m.chain.blocks[:4])
    pruned = Chain.from_snapshot(m.genesis, early.make_snapshot(), m.genesis["validators"])
    for blk in m.chain.blocks[4:]:
        pruned.add_block(blk)
    try:
        st = legal.compliance(pruned, t.txid)[0]["status"]
    except LookupError as err:
        return f"SAFE ({type(err).__name__})"
    return f"VULNERABLE (reported {st})" if st != "PAID" else "SAFE"


@check("H9", "second award raises an already reduced debt (protocol 2 where available)")
def h9():
    m = world()
    bakery, mill, arb = m.w["bakery"], m.w["mill"], m.w["auditor"]
    t = mill.create_contract("l", "t", {"obligations": [legal.obligation("rent", bakery.address, mill.address, 1000, 10)],
                                         "arbitration": {"arbitrator": arb.address}}, [mill.address, bakery.address])
    m.send(t)
    m.send(bakery.sign_contract(t.txid, "t"))
    for amount in (100, 900):
        d = bakery.open_dispute(t.txid, "c", ["rent"])
        m.send(d)
        m.send(arb.award(t.txid, d.txid, "SETTLED", "a", [{"obligation": "rent", "amount": amount}]))
    got = m.chain.state.contracts[t.txid]["adjustments"]["rent"]["amount"]
    return f"VULNERABLE (debt raised 100 -> {got})" if got > 100 else "SAFE"


@check("H10", "Python signs and admits integers JavaScript cannot represent")
def h10():
    try:
        T.Transaction.create("c", T.PAYMENT, KeyPair.from_seed("h10"), 0, {"amount": 2 ** 64})
        return "VULNERABLE (signs 2^64; a browser verifies 18446744073709552000)"
    except (TypeError, ValueError):
        pass
    try:
        T.Transaction.from_dict({"chain_id": "c", "kind": "PAYMENT", "sender": "ab" * 32, "nonce": 0,
                                 "payload": {"amount": 2 ** 64}, "signature": "00" * 64})
        return "VULNERABLE (network parser admits 2^64)"
    except (TypeError, ValueError):
        return "SAFE (refused when signing and at the network)"


@check("H11", "API next_nonce wrong for an index that starts from a snapshot")
def h11():
    import urllib.request
    from jurisledger.api import serve
    from jurisledger.index import Index
    m = MiniWorld()
    for i in range(4):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 10 + i, S.FINAL_CONSUMPTION))
    early = Chain.audit(m.genesis, m.chain.blocks[:2])
    pruned = Chain.from_snapshot(m.genesis, early.make_snapshot(), m.genesis["validators"])
    for blk in m.chain.blocks[2:]:
        pruned.add_block(blk)
    db = tmp() / "i.db"
    Index(db).sync(pruned)
    srv, stop = serve(str(db), port=0, log=lambda *_: None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/api/account/{m.w['alice'].address}"
        got = json.loads(urllib.request.urlopen(url).read())["next_nonce"]
    finally:
        srv.shutdown()
    want = m.chain.state.accounts[m.w["alice"].address]["nonce"]
    return "SAFE" if got == want else f"VULNERABLE (API says {got}, ledger says {want})"


if __name__ == "__main__":
    print(f"jurisledger {__version__} from {TREE}\n")
    for fid, title, verdict in RESULTS:
        print(f"{fid:<4} {verdict:<62} {title}")
    shutil.rmtree(tempfile.gettempdir() + "/jl-audit-", ignore_errors=True)
    bad = [r for r in RESULTS if r[2].startswith(("VULNERABLE", "ERROR"))]
    sys.exit(1 if bad else 0)
