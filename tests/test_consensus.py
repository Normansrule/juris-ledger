import json

import pytest

from jurisledger import state as S
from jurisledger import tx as T
from jurisledger.block import vote_message
from jurisledger.chain import Chain, InvalidBlock
from jurisledger.contracts import Wallet
from jurisledger.crypto import KeyPair
from jurisledger.experiments import MiniWorld
from jurisledger.state import quorum


def test_quorum_is_more_than_two_thirds():
    assert [quorum(n) for n in (1, 3, 4, 6, 7, 10)] == [1, 3, 3, 5, 5, 7]


def test_all_honest_nodes_agree():
    m = MiniWorld()
    for i in range(5):
        m.send(m.w["alice"].pay(m.w["bakery"].address, 100 + i, S.FINAL_CONSUMPTION))
    assert len({n.chain.state.root() for n in m.net.nodes}) == 1
    assert m.chain.height == 5


def test_wrong_proposer_rejected():
    m = MiniWorld()
    wrong = next(n for n in m.net.nodes if n.address != m.chain.expected_proposer(1, 0))
    with pytest.raises(InvalidBlock, match="turn"):
        m.chain.execute(wrong.build_block(1, 0))


def test_votes_from_outsiders_do_not_count():
    m = MiniWorld()
    proposer = m.net.node(m.chain.expected_proposer(1, 0))
    blk = proposer.build_block(1, 0)
    blk.votes = {proposer.address: proposer.sign_vote(blk)}
    for i in range(5):                                   # five signatures from non-validators
        k = KeyPair.from_seed(f"sybil-{i}")
        blk.votes[k.address] = k.sign(vote_message(m.chain_id, 1, 0, blk.hash))
    with pytest.raises(InvalidBlock, match="quorum"):
        Chain(m.genesis).add_block(blk)


def test_export_roundtrip_and_tamper_detection():
    m = MiniWorld()
    m.send(m.w["alice"].pay(m.w["bakery"].address, 100, S.FINAL_CONSUMPTION))
    text = m.chain.export()
    assert Chain.load(text).state.root() == m.chain.state.root()
    d = json.loads(text)
    d["blocks"][0]["header"]["state_root"] = "00" * 32
    with pytest.raises(InvalidBlock):
        Chain.load(json.dumps(d))


def test_validator_set_governance():
    m = MiniWorld()
    newcomer = KeyPair.from_seed("new-validator")
    vw = [Wallet(k, m.chain_id) for k in m.vkeys]
    for w in vw[:2]:
        m.send(w.make(T.VALIDATOR_VOTE, {"action": "ADD", "target": newcomer.address}))
    assert newcomer.address not in m.chain.state.validators          # 2 of 4 is not a quorum
    m.send(vw[2].make(T.VALIDATOR_VOTE, {"action": "ADD", "target": newcomer.address}))
    assert newcomer.address in m.chain.state.validators
    m.send(m.w["alice"].make(T.VALIDATOR_VOTE, {"action": "REMOVE", "target": m.vkeys[0].address}))
    assert m.vkeys[0].address in m.chain.state.validators            # outsiders have no say


def test_fake_evidence_is_rejected():
    m = MiniWorld()
    proposer = m.net.node(m.chain.expected_proposer(1, 0))
    blk = proposer.build_block(1, 0)
    sig = proposer.sign_vote(blk)
    accuser = Wallet(m.vkeys[0], m.chain_id)
    m.send(accuser.make(T.EVIDENCE, {"validator": proposer.address, "header_a": blk.header.to_dict(),
                                     "sig_a": sig, "header_b": blk.header.to_dict(), "sig_b": sig}))
    assert proposer.address in m.chain.state.validators and not m.chain.state.slashed
