import pytest

from jurisledger import state as S
from jurisledger import tx as T
from jurisledger.contracts import Wallet, cite
from jurisledger.crypto import KeyPair
from jurisledger.state import InvalidTx, State

CHAIN = "test-chain"


def world():
    names = [("hh", S.HOUSEHOLD, ""), ("firm", S.FIRM, "services"), ("firm2", S.FIRM, "manufacturing"),
             ("gov", S.GOVERNMENT, ""), ("row", S.FOREIGN, "")]
    w = {n: Wallet(KeyPair.from_seed(n), CHAIN) for n, _, _ in names}
    v = KeyPair.from_seed("v0")
    genesis = {"chain_id": CHAIN, "validators": [v.address],
               "accounts": [{"address": w[n].address, "name": n, "role": r, "sector": s, "balance": 1000}
                            for n, r, s in names]}
    return State.from_genesis(genesis), w


def test_payment_moves_money_and_bumps_nonce():
    s, w = world()
    s.apply(w["hh"].pay(w["firm"].address, 300, S.FINAL_CONSUMPTION), 1)
    assert s.accounts[w["hh"].address]["balance"] == 700
    assert s.accounts[w["firm"].address]["balance"] == 1300
    assert s.accounts[w["hh"].address]["nonce"] == 1


@pytest.mark.parametrize("amount", [0, -5, True, "10", 10 ** 6])
def test_bad_amounts_rejected(amount):
    s, w = world()
    before = s.root()
    with pytest.raises(InvalidTx):
        s.apply(w["hh"].pay(w["firm"].address, amount, S.FINAL_CONSUMPTION), 1)
    assert s.root() == before                      # failed transactions leave no trace


def test_replay_and_wrong_chain_rejected():
    s, w = world()
    t = w["hh"].pay(w["firm"].address, 10, S.FINAL_CONSUMPTION)
    s.apply(t, 1)
    with pytest.raises(InvalidTx, match="nonce"):
        s.apply(t, 2)
    foreign = Wallet(w["hh"].key, "another-chain", next_nonce=1).pay(w["firm"].address, 10, S.FINAL_CONSUMPTION)
    with pytest.raises(InvalidTx, match="chain_id"):
        s.apply(foreign, 2)


def test_tampered_payload_fails_signature():
    s, w = world()
    t = w["hh"].pay(w["firm"].address, 10, S.FINAL_CONSUMPTION)
    evil = T.Transaction(t.chain_id, t.kind, t.sender, t.nonce, {**t.payload, "amount": 999}, t.signature)
    with pytest.raises(InvalidTx, match="signature"):
        s.apply(evil, 1)


@pytest.mark.parametrize("payer,payee,purpose", [
    ("hh", "firm", S.GOVERNMENT_PURCHASE), ("firm", "firm2", S.FINAL_CONSUMPTION),
    ("firm", "hh", S.INTERMEDIATE), ("hh", "firm", S.EXPORT), ("row", "hh", S.EXPORT),
    ("firm", "firm2", S.WAGES), ("hh", "firm", S.TAX)])
def test_purpose_tags_are_validated_against_roles(payer, payee, purpose):
    s, w = world()
    with pytest.raises(InvalidTx):
        s.apply(w[payer].pay(w[payee].address, 10, purpose, tax_type="income"), 1)


def test_register_rules():
    s, _ = world()
    new = Wallet(KeyPair.from_seed("newcomer"), CHAIN)
    with pytest.raises(InvalidTx, match="self-registered"):
        s.apply(new.register("fake ministry", S.GOVERNMENT), 1)
    new.next_nonce = 0
    s.apply(new.register("corner shop", S.FIRM, "services"), 1)
    assert s.accounts[new.address]["balance"] == 0


def test_contract_lifecycle_and_reference_checks():
    s, w = world()
    parties = [w["firm"].address, w["firm2"].address]
    with pytest.raises(InvalidTx, match="does not exist"):
        s.apply(w["firm"].create_contract("x", "text", {}, parties, [cite("00" * 32)]), 1)
    w["firm"].next_nonce = 0
    c = w["firm"].create_contract("supply", "text", {"qty": 1}, parties)
    s.apply(c, 1)
    assert s.contracts[c.txid]["status"] == S.DRAFT
    with pytest.raises(InvalidTx, match="named party"):
        s.apply(w["hh"].sign_contract(c.txid, "text"), 2)
    with pytest.raises(InvalidTx, match="exact prose"):
        s.apply(w["firm2"].sign_contract(c.txid, "other text"), 2)
    w["firm2"].next_nonce = 0
    s.apply(w["firm2"].sign_contract(c.txid, "text"), 2)
    assert s.contracts[c.txid]["status"] == S.ACTIVE
    with pytest.raises(InvalidTx, match="parties to the contract"):
        s.apply(w["firm"].pay(w["gov"].address, 5, S.TAX, tax_type="production", contract=c.txid), 3)
