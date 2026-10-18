"""Regressions for the external security audit of v0.25.0.

Each test is named after the finding it closes (F01, F02, ... and H-numbers for the
high-priority findings).  Every one of them failed against v0.25.0; see
docs/SECURITY_FINDINGS.md for the before/after evidence.
"""
import threading
import time

import pytest

from jurisledger import net
from jurisledger import tx as T
from jurisledger.crypto import KeyPair


# --------------------------------------------------------------------------- #
# F01  malformed network input stopped a validator
# --------------------------------------------------------------------------- #
BAD_TXS = [
    {"chain_id": "x"},                                                   # v0.25.0: KeyError -> loop died
    {"chain_id": "x", "kind": "PAYMENT", "sender": "zz", "nonce": "a", "payload": [], "signature": 5},
    "not-an-object",
    None,
    {"chain_id": "x", "kind": "PAYMENT", "sender": "ab" * 32, "nonce": 2 ** 64, "payload": {}, "signature": "00" * 64},
    {"chain_id": "x", "kind": "PAYMENT", "sender": "ab" * 32, "nonce": 0, "payload": {"amount": 1.5}, "signature": "00" * 64},
    {"chain_id": "x", "kind": "NOT_A_KIND", "sender": "ab" * 32, "nonce": 0, "payload": {}, "signature": "00" * 64},
]


@pytest.mark.parametrize("bad", BAD_TXS)
def test_F01_transaction_parser_raises_only_value_error(bad):
    with pytest.raises(ValueError):
        T.Transaction.from_dict(bad)


def test_F01_signature_check_never_raises_on_unsignable_content():
    k = KeyPair.from_seed("f01")
    t = T.Transaction("c", T.PAYMENT, k.address, 0, {"amount": 1.5}, "00" * 64)   # floats cannot be canonicalised
    assert t.signature_valid() is False


def test_F01_live_validator_survives_malformed_frames_and_keeps_serving(tmp_path):
    from tests.test_net import _one_validator
    m, v, port = _one_validator(tmp_path)
    runner = [th for th in threading.enumerate() if getattr(th, "_target", None) == v.run]
    try:
        client = net.Client("127.0.0.1", port, expect_address=m.vkeys[0].address)
        for bad in BAD_TXS:
            client._call({"t": "tx", "tx": bad}, expect_reply=False)
        # an authenticated peer sending garbage consensus frames must not stop it either
        s = net.tls_connect(("127.0.0.1", port), m.vkeys[0].address)
        ch = net._recv_frame(s)
        net._send_frame(s, {"t": "hello", "index": 1, "sig": m.vkeys[1].sign(net.HELLO_PREFIX + bytes.fromhex(ch["nonce"]))})
        net._send_frame(s, {"t": "msg", "via": 1, "h": "one"})
        net._send_frame(s, {"t": "msg", "via": 1, "h": 1, "kind": "garbage"})
        net._send_frame(s, {"t": "get_blocks", "from": "abc", "reply_to": "nobody"})
        net._send_frame(s, {"t": "blocks", "blocks": [{"not": "a block"}]})
        time.sleep(1.0)
        assert all(th.is_alive() for th in runner), "the validator loop stopped"
        assert v.rejected >= 7
        # ...and it still accepts a well-formed transaction afterwards
        good = T.Transaction.create(m.genesis["chain_id"], T.REGISTER, KeyPair.from_seed("after-f01"), 0,
                                    {"name": "after-f01", "role": "HOUSEHOLD", "sector": "", "residency": "resident"})
        client._call({"t": "tx", "tx": good.to_dict()}, expect_reply=False)
        time.sleep(0.5)
        assert good.txid in v.inner.mempool
        assert client.status()["index"] == 0
        s.close()
    finally:
        v.stop_event.set()


def test_F01_mempool_and_future_buffers_are_bounded(tmp_path):
    from jurisledger.consensus import Node
    from jurisledger.experiments import MiniWorld
    m = MiniWorld(chain_id="bounds")
    node = Node(m.vkeys[0], m.genesis)
    node.MAX_MEMPOOL = 3
    accepted = 0
    for i in range(10):
        k = KeyPair.from_seed(f"flood-{i}")
        accepted += node.receive_tx(T.Transaction.create("bounds", T.REGISTER, k, 0, {"name": f"f{i}"}))
    assert accepted == 3 and len(node.mempool) == 3
    assert net.FUTURE_HEIGHTS > 0 and net.FUTURE_PER_HEIGHT > 0


# --------------------------------------------------------------------------- #
# F02  a restarted validator could sign conflicting precommits
# --------------------------------------------------------------------------- #
def _protocol_instance(world, guard):
    from jurisledger.consensus import Node
    from jurisledger.ledgernet import TwoPhaseBlockNode
    p = TwoPhaseBlockNode(0, len(world.genesis["validators"]))
    p.guard = guard
    p.attach(Node(world.vkeys[0], world.genesis), list(world.genesis["validators"]), 1)
    return p


def test_F02_unguarded_instances_reproduce_the_double_sign():
    """Negative control: the v0.25.0 behaviour (no journal) really does equivocate."""
    from jurisledger.block import consensus_message
    from jurisledger.crypto import verify
    from jurisledger.experiments import MiniWorld
    w = MiniWorld(chain_id="f02")
    a, b = _protocol_instance(w, None), _protocol_instance(w, None)
    sa, sb = a._sign("PRECOMMIT", 0, "aa" * 32), b._sign("PRECOMMIT", 0, "bb" * 32)
    addr = w.vkeys[0].address
    assert verify(addr, consensus_message("PRECOMMIT", "f02", 1, 0, "aa" * 32), sa)
    assert verify(addr, consensus_message("PRECOMMIT", "f02", 1, 0, "bb" * 32), sb)


def test_F02_journal_refuses_conflicting_signature_after_restart(tmp_path):
    from jurisledger.experiments import MiniWorld
    from jurisledger.signguard import DoubleSignRefused, SignGuard
    w = MiniWorld(chain_id="f02")
    path = tmp_path / "sign_state.json"
    first = _protocol_instance(w, SignGuard.open(path))
    sig = first._sign("PRECOMMIT", 0, "aa" * 32)
    restarted = _protocol_instance(w, SignGuard.open(path))           # a new process, same key and journal
    with pytest.raises(DoubleSignRefused):
        restarted._sign("PRECOMMIT", 0, "bb" * 32)                     # v0.25.0: signed, conflicting
    with pytest.raises(DoubleSignRefused):
        restarted._sign("PREVOTE", 0, "bb" * 32)                       # going backwards is refused too
    assert restarted._sign("PRECOMMIT", 0, "aa" * 32) == sig           # the same vote again is harmless
    assert restarted.guard.lock_for(1) == (0, "aa" * 32)              # and the lock survives the restart
    assert restarted._sign("PREVOTE", 1, "cc" * 32)                    # later rounds proceed normally


def test_F02_refused_signature_is_silence_not_a_crash(tmp_path):
    from jurisledger.experiments import MiniWorld
    from jurisledger.signguard import SignGuard
    w = MiniWorld(chain_id="f02")
    path = tmp_path / "sign_state.json"
    _protocol_instance(w, SignGuard.open(path))._sign("PRECOMMIT", 0, "aa" * 32)
    p = _protocol_instance(w, SignGuard.open(path))
    sent = []

    class Wire:
        time = 0
        def broadcast(self, m): sent.append(m)
        def relay(self, m, i): pass
    p.sim = Wire()
    p.broadcast("PRECOMMIT", "bb" * 32)
    assert sent == [] and p.refused_signatures == 1


def test_F02_unreadable_journal_fails_closed(tmp_path):
    from jurisledger.signguard import CorruptSignState, SignGuard
    path = tmp_path / "sign_state.json"
    path.write_text('{"format": "jurisledger/sign-state/v1", "height": 7, "rou')   # torn write
    with pytest.raises(CorruptSignState):
        SignGuard.open(path)


# --------------------------------------------------------------------------- #
# F03  key-change records from another network manufactured a missing signature
# --------------------------------------------------------------------------- #
def _cross_network_bundle(monkeypatch):
    """Ledger A: bakery creates a contract with alice; alice never signs.
    Ledger B ("other-net") is run by the SAME validator keys (a test network, say) and alice
    uses the same key there.  On B, alice's key rotates to bakery's A-address.  Appending that
    finalised, validly signed B-record to A's bundle collapsed {alice, bakery} into one key."""
    from jurisledger import legal
    from jurisledger.experiments import MiniWorld
    a = MiniWorld()
    bakery, alice = a.w["bakery"], a.w["alice"]
    prose = "Bakery sells bread to Alice."
    a.send(bakery.create_contract("Bread", prose, {}, [bakery.address, alice.address]))
    cid = next(i for i in a.chain.state.contracts)
    bundle = legal.evidence_bundle(a.chain, cid, prose)

    orig = KeyPair.from_seed
    shared = lambda s: orig(s.replace("other-net/validator", "jurisledger-mini/validator")
                            .replace("other-net/alice", "jurisledger-mini/alice"))
    monkeypatch.setattr(KeyPair, "from_seed", staticmethod(shared))
    b = MiniWorld(chain_id="other-net")
    monkeypatch.setattr(KeyPair, "from_seed", staticmethod(orig))
    assert b.genesis["validators"] == a.genesis["validators"] and b.w["alice"].address == alice.address
    rot = b.w["alice"].rotate_key(bakery.address)
    b.send(rot)
    bundle["key_changes"].append({"tx": rot.to_dict(), "inclusion": b.chain.tx_proof(rot.txid)})
    return a, bundle


def test_F03_cross_network_key_change_cannot_complete_signatures(monkeypatch):
    from jurisledger import legal
    a, bundle = _cross_network_bundle(monkeypatch)
    r = legal.verify_evidence_bundle(bundle, a.genesis["validators"])
    assert r["fully_signed"] is False                         # v0.25.0: True
    assert not r["valid"]
    assert any("another network" in p for p in r["problems"])


def test_F03_parties_that_resolve_to_one_key_are_reported(monkeypatch):
    """Even from the same network, two parties must never be counted as one signer."""
    from jurisledger import legal
    a, bundle = _cross_network_bundle(monkeypatch)
    bundle["key_changes"][-1]["tx"]["chain_id"] = a.chain_id      # pretend it is ours: proof now fails
    r = legal.verify_evidence_bundle(bundle, a.genesis["validators"])
    assert r["fully_signed"] is False and not r["valid"]


def test_F03_signature_by_a_key_counts_only_from_its_rotation_height():
    from jurisledger import legal
    from jurisledger.experiments import MiniWorld
    m = MiniWorld()
    bakery, alice = m.w["bakery"], m.w["alice"]
    prose = "Rotate then sign."
    m.send(bakery.create_contract("R", prose, {}, [bakery.address, alice.address]))
    cid = next(iter(m.chain.state.contracts))
    new = KeyPair.from_seed("alice-new")
    m.send(alice.rotate_key(new.address))
    from jurisledger.contracts import Wallet
    m.send(Wallet(new, m.chain_id).sign_contract(cid, prose))
    r = legal.verify_evidence_bundle(legal.evidence_bundle(m.chain, cid, prose), m.genesis["validators"])
    assert r["valid"] and r["fully_signed"], r["problems"]


def test_F03_browser_verifier_agrees(tmp_path, monkeypatch):
    from tests.test_site_verifier import _node_ok, js_verify
    if not _node_ok():
        pytest.skip("Node.js with WebCrypto Ed25519 not available")
    from jurisledger import legal
    a, bundle = _cross_network_bundle(monkeypatch)
    js = js_verify(tmp_path, bundle, a.genesis["validators"])
    py = legal.verify_evidence_bundle(bundle, a.genesis["validators"])
    assert js["fully_signed"] is False and py["fully_signed"] is False        # v0.25.0: both True
    assert js["valid"] is False and py["valid"] is False
    assert js["unsigned"] == py["unsigned"] == [a.w["alice"].address]


# --------------------------------------------------------------------------- #
# F04  a modified local snapshot supplied its own validator trust anchor
# --------------------------------------------------------------------------- #
def _forge_snapshot(store_dir, world, bonus=777_777):
    """What an attacker with write access to the store does: raise a balance, re-certify the
    snapshot with keys of their own, and name those keys in the snapshot as its certifiers."""
    import json as _json
    from jurisledger.block import BlockHeader, vote_message
    from jurisledger.state import State
    path = store_dir / "snapshot.json"
    snap = _json.loads(path.read_text())
    alice = world.w["alice"].address
    snap["state"]["accounts"][alice]["balance"] += bonus
    st = State.from_snapshot(snap["state"])
    h = snap["header"]
    header = BlockHeader(h["chain_id"], h["height"], h["round"], h["prev_hash"], h["tx_root"], st.root(),
                         h["proposer"], h.get("timestamp", 0))
    fakes = [KeyPair.from_seed(f"attacker-{i}") for i in range(4)]
    msg = vote_message(header.chain_id, header.height, snap.get("commit_round", header.round), header.hash)
    snap["header"], snap["votes"] = header.to_dict(), {k.address: k.sign(msg) for k in fakes}
    snap["certified_by"] = [k.address for k in fakes]
    path.write_text(_json.dumps(snap, sort_keys=True))
    (store_dir / "blocks.jsonl").write_bytes(b"")             # later blocks would not chain to the forgery
    return alice


def test_F04_forged_snapshot_with_self_supplied_anchor_is_refused(tmp_path):
    from jurisledger.experiments import MiniWorld
    from jurisledger import state as S
    from jurisledger.storage import BlockStore, UntrustedSnapshot
    m = MiniWorld()
    for i in range(12):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 100 + i, S.FINAL_CONSUMPTION))
    st = BlockStore.create(tmp_path / "s", m.genesis)
    st.save(m.chain)
    st.compact(4, keep_archive=False)
    _forge_snapshot(tmp_path / "s", m)
    with pytest.raises(UntrustedSnapshot):                     # v0.25.0: loaded, alice +777,777
        BlockStore(tmp_path / "s").load()


def test_F04_genuine_snapshot_still_opens_and_archive_can_anchor_it(tmp_path):
    from jurisledger.experiments import MiniWorld
    from jurisledger import state as S
    from jurisledger.storage import BlockStore
    m = MiniWorld()
    for i in range(12):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 100 + i, S.FINAL_CONSUMPTION))
    st = BlockStore.create(tmp_path / "s", m.genesis)
    st.save(m.chain)
    st.compact(4)
    c = BlockStore(tmp_path / "s").load()
    assert (c.height, c.state.root()) == (m.chain.height, m.chain.state.root())


def test_F04_export_audit_reports_self_consistency_unless_genesis_is_supplied(tmp_path, capsys):
    import json as _json
    from jurisledger.__main__ import main
    from jurisledger.crypto import hash_obj
    from jurisledger.experiments import MiniWorld
    m = MiniWorld()
    m.send(m.w["alice"].pay(m.w["bakery"].address, 5, "FINAL_CONSUMPTION"))
    p = tmp_path / "chain.json"
    p.write_text(m.chain.export())
    assert main(["jurisledger", "audit", str(p)]) == 0
    out = capsys.readouterr().out
    assert hash_obj(m.genesis) in out and "independently" in out
    other = MiniWorld(chain_id="impostor")
    g = tmp_path / "g.json"
    g.write_text(_json.dumps(other.genesis))
    assert main(["jurisledger", "audit", str(p), "--genesis", str(g)]) == 1
    g.write_text(_json.dumps(m.genesis))
    assert main(["jurisledger", "audit", str(p), "--genesis", str(g)]) == 0


def test_F04_anchor_file_is_honoured_only_with_the_expected_signature(tmp_path):
    import json as _json
    from jurisledger.experiments import MiniWorld
    from jurisledger import state as S
    from jurisledger.storage import BlockStore
    m = MiniWorld()
    for i in range(8):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 10 + i, S.FINAL_CONSUMPTION))
    st = BlockStore.create(tmp_path / "s", m.genesis)
    st.save(m.chain)
    st.anchor_key = m.vkeys[0]
    st.compact(3)
    snap = st.snapshot()
    reader = BlockStore(tmp_path / "s")
    assert reader._anchor_validators(snap) is None                           # no expected signer: ignored
    reader.anchor_address = m.vkeys[0].address
    assert reader._anchor_validators(snap) == m.genesis["validators"]
    reader.anchor_address = m.vkeys[1].address
    assert reader._anchor_validators(snap) is None                           # someone else's anchor: ignored
    a = _json.loads(reader.anchor_path.read_text())
    a["validators"] = [KeyPair.from_seed("attacker").address]
    reader.anchor_path.write_text(_json.dumps(a))
    reader.anchor_address = m.vkeys[0].address
    assert reader._anchor_validators(snap) is None                           # edited anchor: ignored


# --------------------------------------------------------------------------- #
# H1  an unsolicited confidential payment without a usable note froze the recipient
# --------------------------------------------------------------------------- #
def _note_less_attack(protocol):
    from jurisledger import state as S
    from jurisledger.contracts import ConfidentialWallet
    from jurisledger.experiments import MiniWorld
    m = MiniWorld(protocol=protocol)
    alice, bakery = m.w["alice"], m.w["bakery"]
    victim, attacker = ConfidentialWallet(bakery), ConfidentialWallet(alice)
    m.send(victim.shield(100))
    m.send(attacker.shield(10))
    tx, _ = attacker.pay(bakery.address, 1, S.FINAL_CONSUMPTION, encrypt=False)   # no note for the recipient
    m.send(tx)
    assert m.chain.state.accounts[alice.address]["nonce"] == tx.nonce + 1        # it was accepted
    victim.scan(m.chain)
    for claim in victim.outbox:
        m.send(claim)
    victim.outbox.clear()
    victim.sync(m.chain)
    return m, victim


def test_H1_protocol1_reproduces_the_frozen_balance():
    """Negative control: under the v1 rules the recipient's known opening no longer matches."""
    m, victim = _note_less_attack(1)
    assert not victim.matches_ledger(m.chain)


def test_H1_protocol2_recipient_keeps_control_and_can_still_withdraw():
    m, victim = _note_less_attack(2)
    assert victim.matches_ledger(m.chain)                     # the unsolicited payment was refused
    before = m.chain.state.accounts[victim.w.address]["balance"]
    m.send(victim.unshield(100))
    assert m.chain.state.accounts[victim.w.address]["balance"] == before + 100


def test_H1_protocol2_genuine_payment_is_credited_only_when_claimed():
    from jurisledger import state as S
    from jurisledger.contracts import ConfidentialWallet
    from jurisledger.experiments import MiniWorld
    m = MiniWorld(protocol=2)
    ca, cb = ConfidentialWallet(m.w["alice"]), ConfidentialWallet(m.w["bakery"])
    m.send(ca.shield(500))
    tx, _ = ca.pay(cb.w.address, 120, S.FINAL_CONSUMPTION)
    m.send(tx)
    st = m.chain.state
    assert tx.txid in st.accounts[cb.w.address]["incoming"]        # waiting, not credited
    assert cb.scan(m.chain) == 1 and len(cb.outbox) == 1
    m.send(*cb.outbox)
    cb.outbox.clear()
    cb.sync(m.chain)
    assert cb.confirmed[0] == 120 and cb.matches_ledger(m.chain)
    assert "incoming" not in m.chain.state.accounts[cb.w.address]
    ca.sync(m.chain)
    assert ca.matches_ledger(m.chain)


def test_H1_protocol1_state_roots_are_unchanged():
    """No silent change to stored protocol state: a v1 ledger's genesis root is what v0.25.0 produced."""
    from jurisledger.experiments import MiniWorld
    from jurisledger.state import State
    m = MiniWorld()
    assert "protocol_version" not in m.genesis
    s = State.from_genesis(m.genesis)
    assert "protocol" not in s.to_snapshot()
    m2 = MiniWorld(protocol=2)
    assert State.from_genesis(m2.genesis).root() != State.from_genesis({**m2.genesis, "protocol_version": 1}).root()


def test_H1_claims_are_refused_on_protocol1():
    from jurisledger import tx as T
    from jurisledger.experiments import MiniWorld
    from jurisledger.state import InvalidTx
    m = MiniWorld()
    t = m.w["bakery"].make(T.CONFIDENTIAL_CLAIM, {"payment": "00" * 32, "accept": True})
    with pytest.raises(InvalidTx):
        m.chain.state.copy().apply(t, m.chain.height + 1)


# --------------------------------------------------------------------------- #
# H2  the confidential wallet changed state before finality
# --------------------------------------------------------------------------- #
def test_H2_rejected_transaction_is_rolled_back():
    from jurisledger import state as S
    from jurisledger.contracts import ConfidentialWallet
    from jurisledger.experiments import MiniWorld
    m = MiniWorld()
    ca = ConfidentialWallet(m.w["alice"])
    m.send(ca.shield(300))
    ca.sync(m.chain)
    good = ca.confirmed
    tx, _ = ca.pay(m.w["mill"].address, 50, "NOT_A_PURPOSE")      # the ledger will reject it
    m.send(tx)
    assert ca.amount == 250                                       # projected (v0.25.0 kept this forever)
    r = ca.sync(m.chain)
    assert r["rolled_back"] == 1 and ca.confirmed == good and ca.amount == 300
    assert ca.matches_ledger(m.chain)
    tx2, _ = ca.pay(m.w["mill"].address, 50, S.FINAL_CONSUMPTION)     # and the wallet can carry on
    m.send(tx2)
    ca.sync(m.chain)
    assert ca.confirmed[0] == 250 and ca.matches_ledger(m.chain)


# --------------------------------------------------------------------------- #
# H3  a recovery completed after its issuers' attestations were revoked
# --------------------------------------------------------------------------- #
def _recovery_after_revocation(protocol):
    from jurisledger.contracts import Wallet
    from jurisledger.experiments import MiniWorld
    m = MiniWorld(issuers=("a", "b"), policy={"min_attestations": 2, "unverified_payment_limit": 100,
                                              "recovery_delay": 2}, protocol=protocol)
    a, b, alice = m.issuers["a"], m.issuers["b"], m.w["alice"]
    m.send(a.attest(alice.address, "passport"), b.attest(alice.address, "bank"))
    new = Wallet(KeyPair.from_seed(f"h3-new-{protocol}"), m.chain_id)
    m.send(a.request_recovery(alice.address, new.address), b.request_recovery(alice.address, new.address))
    m.send(a.revoke_attestation(alice.address), b.revoke_attestation(alice.address))   # authority withdrawn
    for _ in range(4):
        m.net.produce_block()
    m.send(a.finalize_recovery(alice.address, new.address))
    return "successor" in m.chain.state.accounts[alice.address]


def test_H3_protocol1_reproduces_recovery_on_revoked_authority():
    assert _recovery_after_revocation(1) is True                  # negative control: the v1 rule


def test_H3_protocol2_revocation_cancels_the_recovery():
    assert _recovery_after_revocation(2) is False


# --------------------------------------------------------------------------- #
# H4  a damaged custodian journal let a consumed receipt be used again
# --------------------------------------------------------------------------- #
def _vault_setup(tmp_path):
    from jurisledger import vault as Vt
    from jurisledger.experiments import MiniWorld
    m = MiniWorld()
    bakery, mill = m.w["bakery"], m.w["mill"]
    text = "Confidential lease terms."
    t = mill.create_contract("Lease", text, {}, [mill.address, bakery.address], visibility="restricted")
    m.send(t)
    keys = [KeyPair.from_seed(f"h4-custodian-{i}") for i in range(3)]
    sealed = Vt.seal(t.txid, text, m.chain, [k.address for k in keys], 2)
    m.send(bakery.access(t.txid, "VIEW", "first"), )
    m.send(bakery.access(t.txid, "VIEW", "second"))
    j = tmp_path / "c0.jsonl"
    c = Vt.Custodian(keys[0], journal=str(j))
    c.release(sealed, bakery.address, m.chain)
    c.release(sealed, bakery.address, m.chain)                 # both receipts spent
    return m, sealed, keys, j


def test_H4_damaged_middle_line_fails_closed(tmp_path):
    from jurisledger import vault as Vt
    m, sealed, keys, j = _vault_setup(tmp_path)
    lines = j.read_bytes().split(b"\n")
    lines[0] = b'{"contract_id": "damag'                     # a complete but corrupt FIRST record
    j.write_bytes(b"\n".join(lines))
    with pytest.raises(Vt.VaultJournalCorrupt):               # v0.25.0: forgot both releases -> reusable
        Vt.Custodian(keys[0], journal=str(j))


def test_H4_deleted_middle_line_is_detected(tmp_path):
    from jurisledger import vault as Vt
    m, sealed, keys, j = _vault_setup(tmp_path)
    m.send(m.w["bakery"].access(sealed["contract_id"], "VIEW", "third"))
    Vt.Custodian(keys[0], journal=str(j)).release(sealed, m.w["bakery"].address, m.chain)
    lines = j.read_bytes().split(b"\n")
    del lines[1]
    j.write_bytes(b"\n".join(lines))
    with pytest.raises(Vt.VaultJournalCorrupt):
        Vt.Custodian(keys[0], journal=str(j))


def test_H4_torn_last_line_is_cut_and_receipts_stay_spent(tmp_path):
    from jurisledger import vault as Vt
    m, sealed, keys, j = _vault_setup(tmp_path)
    with open(j, "ab") as f:
        f.write(b'{"contract_id": "half-writ')                  # power loss during the next release
    c = Vt.Custodian(keys[0], journal=str(j))
    assert c.released[(sealed["contract_id"], m.w["bakery"].address)] == 2
    with pytest.raises(Vt.VaultError, match="unspent"):
        c.release(sealed, m.w["bakery"].address, m.chain)
    assert j.read_bytes().endswith(b"\n")


# --------------------------------------------------------------------------- #
# H5  scrypt r and p were unbounded: a crafted key file could exhaust memory or CPU
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("change", [
    {"r": 1 << 20}, {"p": 1 << 16}, {"r": 0}, {"p": 0}, {"n": 2 ** 20, "r": 32},      # memory: 4 GiB
    {"n": 3 * 2 ** 14}, {"n": "16384"}, {"kdf": "argon9"}, {"salt": "00"}, {"nonce": "00" * 4},
])
def test_H5_keystore_parameters_are_bounded_before_derivation(change, monkeypatch):
    from jurisledger import keystore as K
    data = K.seal(KeyPair.from_seed("h5"), "correct horse battery")
    data.update(change)
    called = []
    monkeypatch.setattr(K, "_derive", lambda *a: called.append(a) or b"\0" * 32)
    with pytest.raises(K.KeystoreError):
        K.open_sealed(data, "correct horse battery")
    assert called == []                                        # refused before any expensive work


def test_H5_default_keystores_still_open():
    from jurisledger import keystore as K
    k = KeyPair.from_seed("h5-ok")
    for kdf in ("scrypt", "pbkdf2-sha256"):
        assert K.open_sealed(K.seal(k, "correct horse battery", kdf), "correct horse battery").address == k.address


# --------------------------------------------------------------------------- #
# H6  predictable noise and deterministic suppression did not justify a privacy claim
# --------------------------------------------------------------------------- #
def test_H6_unseeded_releases_use_fresh_noise():
    from jurisledger.sim import SimConfig, run_simulation
    from jurisledger.stats import gdp, private_sector_release
    rep = gdp(run_simulation(SimConfig(periods=1)).chain)
    a = private_sector_release(rep, epsilon=1.0, clip=100_000_00, k_min=1)
    b = private_sector_release(rep, epsilon=1.0, clip=100_000_00, k_min=1)
    assert a != b                                              # v0.25.0: seed=0 by default, identical noise
    assert private_sector_release(rep, 1.0, 100_000_00, 1, seed=7) == private_sector_release(rep, 1.0, 100_000_00, 1, seed=7)


def test_H6_suppression_is_randomised_near_the_threshold():
    """Deterministic suppression distinguishes neighbouring ledgers with certainty; noisy suppression does not."""
    from jurisledger.sim import SimConfig, run_simulation
    from jurisledger.stats import gdp, private_sector_release
    rep = gdp(run_simulation(SimConfig(periods=1)).chain)
    n = max(rep.firms_per_sector().values())
    outcomes = {private_sector_release(rep, 1.0, 100_000_00, k_min=n, seed=s)[
        max(rep.firms_per_sector(), key=rep.firms_per_sector().get)] is None for s in range(100)}
    assert outcomes == {True, False}


def test_H6_integer_noise_is_symmetric_and_scaled():
    import random
    from jurisledger.stats import two_sided_geometric
    rng = random.Random(1)
    xs = [two_sided_geometric(rng, 10.0) for _ in range(20000)]
    assert all(isinstance(x, int) for x in xs)
    mean, mad = sum(xs) / len(xs), sum(abs(x) for x in xs) / len(xs)
    assert abs(mean) < 0.5 and 8 < mad < 12                    # E|X| ~ scale for discrete Laplace


# --------------------------------------------------------------------------- #
# H7  a damaged middle record truncated all later history
# --------------------------------------------------------------------------- #
def _store_with_blocks(tmp_path, n=6):
    from jurisledger import state as S
    from jurisledger.experiments import MiniWorld
    from jurisledger.storage import BlockStore
    m = MiniWorld()
    for i in range(n):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 10 + i, S.FINAL_CONSUMPTION))
    st = BlockStore.create(tmp_path / "s", m.genesis)
    st.save(m.chain)
    return m, st


def test_H7_damaged_middle_record_fails_closed_without_truncating(tmp_path):
    from jurisledger.storage import BlockStore, CorruptStore
    m, st = _store_with_blocks(tmp_path)
    lines = st.blocks_path.read_bytes().splitlines(keepends=True)
    lines[2] = b'{"header": {"chain_id": "garbled' + b"\n"
    damaged = b"".join(lines)
    st.blocks_path.write_bytes(damaged)
    with pytest.raises(CorruptStore):
        BlockStore(tmp_path / "s").load()
    assert st.blocks_path.read_bytes() == damaged            # v0.25.0: cut to 2 records, 4 lost


def test_H7_torn_last_record_is_still_recovered(tmp_path):
    from jurisledger.storage import BlockStore
    m, st = _store_with_blocks(tmp_path)
    with open(st.blocks_path, "ab") as f:
        f.write(b'{"header": {"chain_id": "half')
    s2 = BlockStore(tmp_path / "s")
    assert s2.load().height == m.chain.height and s2.recovered_partial_write


# --------------------------------------------------------------------------- #
# H8  pruned history silently omitted records: a paid obligation showed as OVERDUE
# --------------------------------------------------------------------------- #
def test_H8_pruned_history_raises_instead_of_reporting_overdue():
    from jurisledger import legal
    from jurisledger import state as S
    from jurisledger.chain import Chain, HistoryPruned
    from jurisledger.experiments import MiniWorld
    m = MiniWorld()
    mill, bakery = m.w["mill"], m.w["bakery"]
    t = mill.create_contract("Lease", "Pay 300 by block 4.", {"obligations": [
        legal.obligation("rent", bakery.address, mill.address, 300, 4)]}, [mill.address, bakery.address])
    m.send(t)
    m.send(bakery.sign_contract(t.txid, "Pay 300 by block 4."))
    m.send(bakery.pay(mill.address, 300, S.INTERMEDIATE, contract=t.txid, obligation="rent"))
    for _ in range(6):
        m.net.produce_block()
    assert legal.compliance(m.chain, t.txid)[0]["status"] == "PAID"
    blocks = m.chain.blocks
    early = Chain.audit(m.genesis, blocks[:4])
    pruned = Chain.from_snapshot(m.genesis, early.make_snapshot(), m.genesis["validators"])
    for b in blocks[4:]:
        pruned.add_block(b)
    with pytest.raises(HistoryPruned):                         # v0.25.0: status "OVERDUE"
        legal.compliance(pruned, t.txid)
    assert list(pruned.iter_txs(5)) == list(m.chain.iter_txs(5))   # ranges after the snapshot still work


# --------------------------------------------------------------------------- #
# H9  consecutive awards could raise the debt, bring a deadline forward, or undo a waiver
# --------------------------------------------------------------------------- #
def _two_awards(protocol, first, second):
    from jurisledger import legal
    from jurisledger.experiments import MiniWorld
    m = MiniWorld(protocol=protocol)
    bakery, mill, arb = m.w["bakery"], m.w["mill"], m.w["auditor"]
    terms = {"obligations": [legal.obligation("rent", bakery.address, mill.address, 1000, 10)],
             "arbitration": {"arbitrator": arb.address}}
    t = mill.create_contract("lease", "text", terms, [mill.address, bakery.address])
    m.send(t)
    m.send(bakery.sign_contract(t.txid, "text"))
    for adj in (first, second):
        d = bakery.open_dispute(t.txid, "claim", ["rent"])
        m.send(d)
        m.send(arb.award(t.txid, d.txid, "SETTLED", "award", [{"obligation": "rent", **adj}]))
    return m.chain.state.contracts[t.txid]["adjustments"]["rent"]


@pytest.mark.parametrize("first,second,field,expected", [
    ({"amount": 100}, {"amount": 900}, "amount", 100),                 # cannot raise 100 -> 900
    ({"due_height": 50}, {"due_height": 20}, "due_height", 50),        # cannot pull 50 -> 20
    ({"waived": True}, {"amount": 999}, "waived", True),               # cannot reinstate a waived debt
])
def test_H9_second_award_cannot_worsen_effective_terms(first, second, field, expected):
    v1 = _two_awards(1, first, second)                                  # negative control: v1 lets it through
    assert v1.get(field) != expected
    v2 = _two_awards(2, first, second)
    assert v2.get(field) == expected


def test_H9_second_award_may_still_improve_terms():
    assert _two_awards(2, {"amount": 500}, {"amount": 200})["amount"] == 200
    assert _two_awards(2, {"amount": 500}, {"due_height": 90}) == {
        "amount": 500, "due_height": 90, "height": pytest.approx(0, abs=10 ** 6), "dispute_id": _ANY}


class _Any:
    def __eq__(self, other): return True
_ANY = _Any()


# --------------------------------------------------------------------------- #
# H10  Python and JavaScript produced different signing bytes for the same record
# --------------------------------------------------------------------------- #
VECTORS = __import__("pathlib").Path(__file__).parent / "vectors" / "canonical.json"


def test_H10_python_matches_the_canonical_vectors():
    import json as _json
    from jurisledger.crypto import canonical
    for case in _json.loads(VECTORS.read_text())["cases"]:
        try:
            got = canonical(_json.loads(case["value"]), portable=True).hex()
        except (TypeError, ValueError):
            got = None
        assert got == case["canonical_hex"], case["name"]


def test_H10_javascript_matches_the_canonical_vectors():
    import json as _json
    import subprocess
    from tests.test_site_verifier import NODE, ROOT, _node_ok
    if not _node_ok():
        pytest.skip("Node.js not available")
    got = _json.loads(subprocess.run([NODE, str(ROOT / "tests/js/canonical_cli.mjs"), str(VECTORS)],
                                     capture_output=True, text=True, check=True).stdout)
    for case, g in zip(_json.loads(VECTORS.read_text())["cases"], got):
        assert g == case["canonical_hex"], case["name"]          # v0.25.0: 2 of these disagreed


def test_H10_unsafe_integers_cannot_enter_through_the_network_parser():
    with pytest.raises(ValueError):
        T.Transaction.from_dict({"chain_id": "c", "kind": "PAYMENT", "sender": "ab" * 32, "nonce": 0,
                                 "payload": {"amount": 2 ** 60}, "signature": "00" * 64})


# --------------------------------------------------------------------------- #
# H11  the API's next_nonce counted indexed transactions instead of reading nonces
# --------------------------------------------------------------------------- #
def test_H11_next_nonce_is_right_for_an_index_that_starts_from_a_snapshot(tmp_path):
    from jurisledger import state as S
    from jurisledger.api import next_nonce
    from jurisledger.chain import Chain
    from jurisledger.experiments import MiniWorld
    from jurisledger.index import Index
    m = MiniWorld()
    alice, bakery = m.w["alice"], m.w["bakery"]
    for i in range(5):
        m.send(alice.pay(bakery.address, 10 + i, S.FINAL_CONSUMPTION))
    m.send(bakery.pay(m.w["mill"].address, 1, S.INTERMEDIATE))
    blocks = m.chain.blocks
    early = Chain.audit(m.genesis, blocks[:3])
    pruned = Chain.from_snapshot(m.genesis, early.make_snapshot(), m.genesis["validators"])
    for b in blocks[3:]:
        pruned.add_block(b)
    idx = Index(tmp_path / "i.db")
    idx.sync(pruned)
    truth = m.chain.state.accounts
    assert next_nonce(idx, alice.address) == truth[alice.address]["nonce"] == 5   # v0.25.0: 2
    assert next_nonce(idx, bakery.address) == truth[bakery.address]["nonce"]
    assert next_nonce(idx, m.w["treasury"].address) is None   # sent nothing since the snapshot: unknown, not 0


# --------------------------------------------------------------------------- #
# H12  API and file data reached innerHTML unescaped (script injection)
# --------------------------------------------------------------------------- #
import re as _re
from pathlib import Path as _Path

SITE = _Path(__file__).resolve().parent.parent / "site"


def _innerhtml_violations(text):
    """Every `x.innerHTML = RHS` must be html`...`, raw(<repository constant>), a plain string
    literal, or a template literal with no ${...}.  Anything else could carry data as markup."""
    bad = []
    for m in _re.finditer(r"\.innerHTML\s*=(?!=)\s*", text):
        rest, line = text[m.end():], text.count("\n", 0, m.start()) + 1
        if rest.startswith(("html`", "raw(")):
            continue
        q = rest[:1]
        if q in "\"'`":
            i, esc = 1, False
            while i < len(rest):
                c = rest[i]
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif q == "`" and rest.startswith("${", i):
                    bad.append((line, "untagged template with ${}"))
                    break
                elif c == q:
                    after = rest[i + 1:].lstrip()
                    if not after.startswith((";", "}", ")", ",", "\n")):
                        bad.append((line, "string concatenated into innerHTML"))
                    break
                i += 1
            continue
        bad.append((line, "innerHTML assigned from an expression: " + rest[:40]))
    return bad


@pytest.mark.parametrize("page", ["dashboard.html", "explorer.html", "index.html", "wallet.html", "ledger3d.js", "wallet.js"])
def test_H12_no_page_assigns_unescaped_markup(page):
    assert _innerhtml_violations((SITE / page).read_text()) == []


def test_H12_checker_catches_the_v025_dashboard_pattern():
    v025 = '''$("#top").innerHTML = "<tr>" + rows.map(a => `<td>${a.role}</td>`).join("");'''
    assert _innerhtml_violations(v025)
    assert _innerhtml_violations('el.innerHTML = `<b>${name}</b>`;')
    assert not _innerhtml_violations('el.innerHTML = html`<b>${name}</b>`;')


# --------------------------------------------------------------------------- #
# Intermittent cluster re-run: copies were compared at different heights
# --------------------------------------------------------------------------- #
def test_cluster_comparison_tolerates_a_block_finalised_between_exports():
    from jurisledger import state as S
    from jurisledger.chain import Chain
    from jurisledger.cluster import same_history
    from jurisledger.experiments import MiniWorld
    m = MiniWorld()
    m.send(m.w["alice"].pay(m.w["bakery"].address, 5, S.FINAL_CONSUMPTION))
    earlier = Chain.audit(m.genesis, list(m.chain.blocks))
    m.send(m.w["alice"].pay(m.w["bakery"].address, 6, S.FINAL_CONSUMPTION))   # finalised "in between"
    assert earlier.state.root() != m.chain.state.root()                       # v0.25.0 called this disagreement
    assert same_history([earlier, m.chain])
    other = MiniWorld(chain_id="jurisledger-mini")
    other.send(other.w["alice"].pay(other.w["bakery"].address, 7, S.FINAL_CONSUMPTION))
    assert not same_history([other.chain, m.chain])                           # a real fork is still caught


# --------------------------------------------------------------------------- #
# Release hygiene: README version labels must not drift (audit: "version labels need reconciliation")
# --------------------------------------------------------------------------- #
def test_readme_states_the_package_version():
    import re as re_
    import jurisledger
    readme = (_Path(__file__).resolve().parent.parent / "README.md").read_text()
    versions = set(re_.findall(r"version (\d+\.\d+(?:\.\d+)?)", readme))
    assert versions == {jurisledger.__version__}, versions


def test_H10_history_hashing_is_unchanged_for_legacy_values():
    """No silent change to historical identifiers: hashing still reproduces v0.25.0's bytes for a
    value outside the portable range, while signing and network admission refuse it."""
    from jurisledger.crypto import canonical
    assert canonical({"a": 2 ** 64}) == b'{"a":18446744073709551616}'          # what v0.25.0 hashed
    with pytest.raises(ValueError):
        canonical({"a": 2 ** 64}, portable=True)
    with pytest.raises(ValueError):
        T.Transaction.create("c", T.PAYMENT, KeyPair.from_seed("h10"), 0, {"amount": 2 ** 64})
    legacy = {"chain_id": "c", "kind": "PAYMENT", "sender": "ab" * 32, "nonce": 0,
              "payload": {"amount": 2 ** 64}, "signature": "00" * 64}
    assert T.Transaction.from_dict(legacy, strict=False).payload["amount"] == 2 ** 64   # blocks still parse


def test_H10_protocol2_state_refuses_non_portable_payloads():
    from jurisledger.experiments import MiniWorld
    from jurisledger.state import InvalidTx
    for protocol, refused_for_portability in ((1, False), (2, True)):
        m = MiniWorld(protocol=protocol)
        k = m.w["alice"].key
        raw = T.Transaction(m.chain_id, T.PAYMENT, k.address, 0, {"to": m.w["bakery"].address, "amount": 5,
                                                                 "purpose": "FINAL_CONSUMPTION", "memo": 2 ** 60})
        t = T.Transaction(raw.chain_id, raw.kind, raw.sender, raw.nonce, raw.payload, k.sign(raw.signing_bytes()))
        try:
            m.chain.state.copy().apply(t, 1)
            refused = False
        except InvalidTx as err:
            refused = "portable" in str(err)
        assert refused is refused_for_portability, protocol


# --------------------------------------------------------------------------- #
# Findings of the independent review of the 0.26 fixes (R1-R7, docs/SECURITY_FINDINGS.md)
# --------------------------------------------------------------------------- #
def test_R1_peer_proposal_with_mistyped_header_cannot_stop_the_loop(tmp_path):
    from jurisledger.block import Block, BlockHeader, consensus_message
    from tests.test_net import _one_validator
    m, v, port = _one_validator(tmp_path)
    runner = [th for th in threading.enumerate() if getattr(th, "_target", None) == v.run]
    try:
        byz = m.vkeys[1]
        blk = {"header": {"chain_id": m.chain_id, "height": 1, "round": 4, "prev_hash": v.chain.tip_hash, "tx_root": "00",
                          "state_root": "00", "proposer": byz.address, "timestamp": "not-a-number"}, "txs": [], "votes": {}}
        s = net.tls_connect(("127.0.0.1", port), m.vkeys[0].address)
        ch = net._recv_frame(s)
        net._send_frame(s, {"t": "hello", "index": 1, "sig": byz.sign(net.HELLO_PREFIX + bytes.fromhex(ch["nonce"]))})
        net._send_frame(s, {"t": "msg", "h": 1, "kind": "PROPOSAL", "round": 4, "value": "ab" * 32, "src": 1, "dst": 0,
                            "valid_round": -1, "via": 1, "sig": "00" * 64, "payload": blk})
        net._send_frame(s, {"t": "msg", "h": 2, "kind": "PROPOSAL", "round": 0, "value": "ab" * 32, "src": 1, "dst": 0,
                            "valid_round": -1, "via": 1, "sig": "00" * 64, "payload": blk})      # future-height path
        time.sleep(1.0)
        assert all(th.is_alive() for th in runner)
        s.close()
    finally:
        v.stop_event.set()
    with pytest.raises(ValueError):
        BlockHeader.from_dict(blk["header"])


def test_R1_wrongly_typed_payload_is_an_invalid_transaction_not_an_exception():
    from jurisledger.experiments import MiniWorld
    from jurisledger.state import InvalidTx
    m = MiniWorld()
    k = m.w["alice"].key
    for payload in ([1, 2], {"to": 5, "amount": "x", "purpose": []}, {"contract_id": {"a": 1}, "prose_hash": 3}):
        for kind in (T.PAYMENT, T.CONTRACT_SIGN, T.DISPUTE_OPEN):
            raw = T.Transaction(m.chain_id, kind, k.address, 0, payload)
            t = T.Transaction(raw.chain_id, kind, k.address, 0, payload, k.sign(raw.signing_bytes()))
            with pytest.raises(InvalidTx):
                m.chain.state.copy().apply(t, 1)


def test_R2_an_idle_proposer_never_times_out_its_own_round(tmp_path):
    """v0.25.0: an idle proposer signed nil prevote and precommit, then its block, in one round."""
    from jurisledger.experiments import MiniWorld
    from jurisledger.storage import BlockStore
    m = MiniWorld(chain_id="idle", n_validators=1)
    port = net.free_ports(1)[0]
    v = net.Validator(m.vkeys[0], m.genesis, [("127.0.0.1", port)], BlockStore.create(tmp_path / "s", m.genesis),
                      ("127.0.0.1", port), log=lambda *_: None)
    th = threading.Thread(target=v.run, kwargs={"until_height": 3}, daemon=True)
    th.start()
    th.join(60)
    v.stop_event.set()
    assert v.chain.height >= 3
    assert [b.vote_round for b in v.chain.blocks] == [0] * len(v.chain.blocks)
    assert v.guard.refused == 0


def test_R3_a_failed_journal_write_releases_nothing(tmp_path, monkeypatch):
    import os
    from jurisledger.block import consensus_message
    from jurisledger.signguard import DoubleSignRefused, SignGuard
    k = KeyPair.from_seed("r3")
    p = tmp_path / "sign_state.json"
    g = SignGuard.open(p)
    mk = lambda v: (lambda: k.sign(consensus_message("PRECOMMIT", "c", 5, 0, v)))
    real = os.replace
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError(28, "No space left on device")))
    with pytest.raises(OSError):
        g.check_and_record("PRECOMMIT", 5, 0, "aa" * 32, mk("aa" * 32))
    monkeypatch.setattr(os, "replace", real)
    assert g.position() == (0, -1, 0)                         # memory unchanged by the failed write
    g.check_and_record("PRECOMMIT", 5, 0, "aa" * 32, mk("aa" * 32))   # the retry writes before releasing
    with pytest.raises(DoubleSignRefused):
        SignGuard.open(p).check_and_record("PRECOMMIT", 5, 0, "bb" * 32, mk("bb" * 32))


def test_R4_journal_chain_cannot_be_stripped_or_recomputed(tmp_path):
    import hashlib
    import json as _json
    from jurisledger import vault as Vt
    m, sealed, keys, j = _vault_setup(tmp_path)
    m.send(m.w["bakery"].access(sealed["contract_id"], "VIEW", "third"))
    Vt.Custodian(keys[0], journal=str(j)).release(sealed, m.w["bakery"].address, m.chain)
    lines = [_json.loads(x) for x in j.read_bytes().splitlines()]                          # receipts 1, 2, 3
    kept = [lines[0], {k: v for k, v in lines[2].items() if k != "prev"}]                  # delete 2, strip the next
    j.write_text("".join(_json.dumps(e) + "\n" for e in kept))
    with pytest.raises(Vt.VaultJournalCorrupt):
        Vt.Custodian(keys[0], journal=str(j))
    head, out = "0" * 64, []                                   # recompute an UNKEYED chain without receipt 2
    for e in (lines[0], lines[2]):
        line = _json.dumps({**e, "prev": head}, sort_keys=True).encode()
        out.append(line)
        head = hashlib.sha256(line).hexdigest()
    j.write_bytes(b"\n".join(out) + b"\n")
    with pytest.raises(Vt.VaultJournalCorrupt):
        Vt.Custodian(keys[0], journal=str(j))


def test_R4_pre_026_journals_migrate_only_when_asked(tmp_path):
    import json as _json
    from jurisledger import vault as Vt
    m, sealed, keys, j = _vault_setup(tmp_path)
    legacy = b"".join(_json.dumps({k: v for k, v in _json.loads(x).items() if k != "prev"}).encode() + b"\n"
                      for x in j.read_bytes().splitlines())
    j.write_bytes(legacy)
    with pytest.raises(Vt.VaultJournalCorrupt):
        Vt.Custodian(keys[0], journal=str(j))
    c = Vt.Custodian(keys[0], journal=str(j), migrate_legacy=True)
    assert c.released[(sealed["contract_id"], m.w["bakery"].address)] == 2
    assert all("prev" in _json.loads(x) for x in j.read_bytes().splitlines())
    Vt.Custodian(keys[0], journal=str(j))                      # now opens normally


def test_R5_a_refused_payment_returns_to_a_payer_whose_wallet_follows(monkeypatch):
    from jurisledger.contracts import ConfidentialWallet
    from jurisledger.experiments import MiniWorld
    m = MiniWorld(protocol=2)
    payer, payee = ConfidentialWallet(m.w["alice"]), ConfidentialWallet(m.w["mill"])
    m.send(payer.shield(500))
    tx, _ = payer.pay(m.w["mill"].address, 120, "FINAL_CONSUMPTION", encrypt=False)   # the payee cannot open it
    m.send(tx)
    payee.scan(m.chain)
    m.send(*payee.outbox)                                     # refused
    payer.scan(m.chain)
    assert payer.matches_ledger(m.chain) and payer.confirmed[0] == 500


def test_R6_one_payer_cannot_fill_a_recipients_inbox(monkeypatch):
    from jurisledger import state as S_
    from jurisledger.contracts import ConfidentialWallet
    from jurisledger.experiments import MiniWorld
    from jurisledger.state import InvalidTx
    monkeypatch.setattr(S_, "MAX_INCOMING_PER_SENDER", 1)
    m = MiniWorld(protocol=2)
    a = ConfidentialWallet(m.w["alice"])
    m.send(a.shield(10))
    t1, _ = a.pay(m.w["bakery"].address, 1, "FINAL_CONSUMPTION")
    m.send(t1)
    t2, _ = a.pay(m.w["bakery"].address, 1, "FINAL_CONSUMPTION")
    with pytest.raises(InvalidTx, match="too many unclaimed"):
        m.chain.state.copy().apply(t2, m.chain.height + 1)


def test_R6_unregistered_senders_cannot_fill_the_mempool():
    from jurisledger.consensus import Node
    from jurisledger.experiments import MiniWorld
    m = MiniWorld()
    node = Node(m.vkeys[0], m.genesis)
    stranger = KeyPair.from_seed("stranger")
    pay = T.Transaction.create(m.chain_id, T.PAYMENT, stranger, 0, {"to": m.w["alice"].address, "amount": 1, "purpose": "FINANCIAL"})
    reg = T.Transaction.create(m.chain_id, T.REGISTER, stranger, 0, {"name": "s", "role": "HOUSEHOLD", "sector": ""})
    assert node.receive_tx(pay) is False and node.receive_tx(reg) is True


def test_R7_browser_and_python_agree_on_non_integer_number_text(tmp_path):
    import json as _json
    import subprocess
    from jurisledger import legal
    from tests.test_site_verifier import NODE, ROOT, _node_ok, lease_with_rotation
    if not _node_ok():
        pytest.skip("Node.js not available")
    m, bundle = lease_with_rotation()
    text = _json.dumps(bundle).replace('"height": 1,', '"height": 1.0,', 1)
    ev, vals = tmp_path / "ev.json", tmp_path / "v.json"
    ev.write_text(text)
    vals.write_text(_json.dumps(m.genesis["validators"]))
    js = _json.loads(subprocess.run([NODE, str(ROOT / "tests/js/verify_cli.mjs"), str(ev), str(vals)],
                                    capture_output=True, text=True, check=True).stdout)
    py = legal.verify_evidence_bundle(_json.loads(text), m.genesis["validators"])
    assert js["valid"] is False and py["valid"] is False      # v0.26 before review: browser True, Python False
