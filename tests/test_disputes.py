import pytest

from jurisledger import legal
from jurisledger import state as S
from jurisledger.experiments import MiniWorld
from jurisledger.state import InvalidTx


def setup(arbitration=True):
    m = MiniWorld()
    bakery, mill, arb = m.w["bakery"], m.w["mill"], m.w["auditor"]
    terms = {"obligations": [legal.obligation("rent", bakery.address, mill.address, 1000, 3)]}
    if arbitration:
        terms["arbitration"] = {"arbitrator": arb.address}
    t = mill.create_contract("lease", "text", terms, [mill.address, bakery.address])
    m.send(t)
    m.send(bakery.sign_contract(t.txid, "text"))
    return m, t.txid


def test_arbitrator_must_be_registered_and_independent():
    m = MiniWorld()
    mill, bakery = m.w["mill"], m.w["bakery"]
    state = m.chain.state.copy()
    for bad in ({"arbitrator": "ff" * 32}, {"arbitrator": mill.address}, "nobody"):
        with pytest.raises(InvalidTx):
            state.apply(mill.create_contract("x", "t", {"arbitration": bad}, [mill.address, bakery.address]), 1)
        mill.resync(m.chain)


def test_no_clause_no_dispute():
    m, cid = setup(arbitration=False)
    state = m.chain.state.copy()
    with pytest.raises(InvalidTx, match="no arbitration clause"):
        state.apply(m.w["mill"].open_dispute(cid, "claim", ["rent"]), 3)


def test_withdrawal_only_by_claimant_and_closes_the_dispute():
    m, cid = setup()
    mill, bakery, arb = m.w["mill"], m.w["bakery"], m.w["auditor"]
    claim = mill.open_dispute(cid, "unpaid", ["rent"])
    m.send(claim)
    state = m.chain.state.copy()
    with pytest.raises(InvalidTx, match="claimant"):
        state.apply(bakery.withdraw_dispute(cid, claim.txid), 4)
    m.send(mill.withdraw_dispute(cid, claim.txid))
    assert m.chain.state.disputes[claim.txid]["status"] == S.WITHDRAWN
    with pytest.raises(InvalidTx, match="no longer open"):
        m.chain.state.copy().apply(arb.award(cid, claim.txid, "UPHELD", "late", []), 5)


@pytest.mark.parametrize("adjustment", [
    {"obligation": "rent", "amount": 1001}, {"obligation": "rent", "amount": 0},
    {"obligation": "rent", "due_height": 2}, {"obligation": "rent", "waived": False},
    {"obligation": "rent"}, {"obligation": "other"}])
def test_award_limits(adjustment):
    m, cid = setup()
    claim = m.w["mill"].open_dispute(cid, "unpaid", ["rent"])
    m.send(claim)
    with pytest.raises(InvalidTx):
        m.chain.state.copy().apply(m.w["auditor"].award(cid, claim.txid, "UPHELD", "text", [adjustment]), 4)


def test_waiver():
    m, cid = setup()
    claim = m.w["bakery"].open_dispute(cid, "the grinder never arrived", ["rent"])
    m.send(claim)
    m.send(m.w["auditor"].award(cid, claim.txid, "UPHELD", "rent waived", [{"obligation": "rent", "waived": True}]))
    assert legal.compliance(m.chain, cid)[0]["status"] == "WAIVED"
    assert legal.compliance(m.chain, cid, at_height=3)[0]["status"] == "DISPUTED"
