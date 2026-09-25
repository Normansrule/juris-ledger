import json

import pytest

from jurisledger import privacy as PV
from jurisledger import state as S
from jurisledger import tx as T
from jurisledger.contracts import ConfidentialWallet
from jurisledger.ec import BASE, Point
from jurisledger.experiments import MiniWorld
from jurisledger.state import InvalidTx


def test_range_proof_accepts_valid_and_rejects_tampered_and_negative():
    c, o = PV.commit(4_200_00)
    proof = PV.range_proof(o)
    assert PV.verify_range_proof(c, proof)
    assert not PV.verify_range_proof(PV.commit(4_200_00)[0], proof)          # different blinding
    with pytest.raises(ValueError):
        PV.range_proof(PV.Opening(-1, 5))
    with pytest.raises(ValueError):
        PV.range_proof(PV.Opening(PV.MAX_HIDDEN + 1, 5))
    forged = json.loads(json.dumps(proof))
    forged["bits"][0][1] = hex((int(forged["bits"][0][1], 16) + 1) % PV.Q)
    assert not PV.verify_range_proof(c, forged)


def test_small_order_point_is_refused_as_commitment():
    from jurisledger.ec import P as FP
    low = Point(0, FP - 1, 1, 0)                                      # (0, -1) has order 2
    assert not low.in_subgroup()
    with pytest.raises(ValueError):
        PV.commitment_from_hex(low.hex())


def test_shield_pay_unshield_roundtrip_and_overspend():
    m = MiniWorld()
    alice, bakery = m.w["alice"], m.w["bakery"]
    ca, cb = ConfidentialWallet(alice), ConfidentialWallet(bakery)
    m.send(ca.shield(1_000_00))
    assert m.balance("alice") == 1_000_000_00 - 1_000_00 and "hidden" in m.chain.state.accounts[alice.address]
    tx, note = ca.pay(bakery.address, 300_00, S.FINAL_CONSUMPTION)
    m.send(tx)
    assert m.chain.find_tx(tx.txid) is not None
    cb.receive(note)
    assert PV.verify_opening(m.chain.state.hidden(bakery.address), cb.opening)
    assert PV.verify_opening(m.chain.state.hidden(alice.address), ca.opening)
    m.send(cb.unshield(300_00))
    assert m.balance("bakery") == 1_000_000_00 + 300_00
    assert PV.verify_opening(m.chain.state.hidden(bakery.address), cb.opening) and cb.amount == 0
    with pytest.raises(ValueError):
        ca.pay(bakery.address, 800_00, S.FINAL_CONSUMPTION)                # wallet refuses: 700 left
    # a hand-forged overspend: real proof on the amount, remaining would be negative
    c_big, o_big = PV.commit(800_00)
    fake_remaining = PV.Opening(0, 0)
    forged = alice.make(T.CONFIDENTIAL_PAYMENT, {"to": bakery.address, "purpose": S.FINAL_CONSUMPTION,
                                                 "commitment": c_big.hex(), "proof_amount": PV.range_proof(o_big),
                                                 "proof_remaining": PV.range_proof(fake_remaining)})
    with pytest.raises(InvalidTx, match="remaining"):
        m.chain.state.copy().apply(forged, 99)
    alice.resync(m.chain)


def test_confidential_payments_need_verified_parties_when_policy_says_so():
    m = MiniWorld(issuers=("a", "b"), policy={"min_attestations": 2, "unverified_payment_limit": 10, "recovery_delay": 2})
    ca = ConfidentialWallet(m.w["alice"])
    with pytest.raises(InvalidTx, match="attestations"):
        m.chain.state.copy().apply(ca.shield(50), 1)
