import pytest

from jurisledger import legal
from jurisledger import state as S
from jurisledger.experiments import MiniWorld
from jurisledger.state import InvalidTx, State


def lease(m, obligations):
    mill, bakery = m.w["mill"], m.w["bakery"]
    return mill.create_contract("lease", "text", {"obligations": obligations}, [mill.address, bakery.address])


@pytest.mark.parametrize("bad", [
    lambda a, b, c: [legal.obligation("x", a, a, 100, 5)],                 # payer == payee
    lambda a, b, c: [legal.obligation("x", a, c, 100, 5)],                 # payee is not a party
    lambda a, b, c: [legal.obligation("x", a, b, 0, 5)],                   # zero amount
    lambda a, b, c: [legal.obligation("x", a, b, 100, 5)] * 2,             # duplicate id
    lambda a, b, c: "not a list",
])
def test_malformed_obligations_rejected(bad):
    m = MiniWorld()
    a, b, c = m.w["bakery"].address, m.w["mill"].address, m.w["alice"].address
    state = State.from_genesis(m.genesis)
    with pytest.raises(InvalidTx):
        state.apply(lease(m, bad(a, b, c)), 1)


def test_obligation_payment_needs_contract_and_right_direction():
    m = MiniWorld()
    bakery, mill = m.w["bakery"], m.w["mill"]
    t = lease(m, [legal.obligation("rent", bakery.address, mill.address, 100, 9)])
    m.send(t)
    m.send(bakery.sign_contract(t.txid, "text"))
    state = m.chain.state.copy()
    with pytest.raises(InvalidTx, match="name its contract"):
        state.apply(bakery.pay(mill.address, 100, S.INTERMEDIATE, obligation="rent"), 3)
    bakery.resync(m.chain)
    with pytest.raises(InvalidTx, match="unknown obligation"):
        state.apply(bakery.pay(mill.address, 100, S.INTERMEDIATE, contract=t.txid, obligation="nope"), 3)
    bakery.resync(m.chain)
    m.send(bakery.pay(mill.address, 100, S.INTERMEDIATE, contract=t.txid, obligation="rent"))
    assert legal.compliance(m.chain, t.txid)[0]["status"] == "PAID"


def test_bundle_without_creating_transaction_is_invalid():
    m = MiniWorld()
    t = lease(m, [])
    m.send(t)
    bundle = legal.evidence_bundle(m.chain, t.txid)
    assert legal.verify_evidence_bundle(bundle, m.genesis["validators"])["valid"]
    bundle["items"] = []
    assert not legal.verify_evidence_bundle(bundle, m.genesis["validators"])["valid"]
