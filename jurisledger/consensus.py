"""Validator nodes and a simulated network.

Consensus is a rotating-proposer, quorum-certificate protocol in the family of
Practical Byzantine Fault Tolerance (PBFT; Castro & Liskov 1999) and Tendermint
(Buchman, Kwon & Milosevic 2018):

* the proposer for ``(height, round)`` is fixed by rotation,
* every validator independently re-executes the proposal and signs a vote only
  if every rule in :mod:`jurisledger.chain` holds,
* a block is final once more than two thirds of validators have voted for it,
* an honest validator signs at most one block per ``(height, round)``; signing
  two is *equivocation*, provable to anyone, and gets the validator removed.

SIMPLIFICATION (stated loudly): the simulated network is synchronous and votes
are collected in one phase.  A deployment over a real, asynchronous network
needs the two-phase lock/commit rules of Tendermint or HotStuff to stay safe
across round changes.  The *validity* and *accountability* rules demonstrated
here carry over unchanged.  See docs/THREAT_MODEL.md.

Byzantine behaviours are included so the experiments can attack the system:

``equivocator``  proposes two different blocks at one height to split the vote
``forger``       proposes a block containing a payment it forged from a victim
``censor``       leaves a target account's transactions out of its proposals
``silent``       never proposes and never votes (crash / denial of service)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import tx as T
from .block import Block, BlockHeader, vote_message
from .chain import Chain, InvalidBlock
from .crypto import KeyPair, merkle_root, verify
from .state import InvalidTx, quorum

HONEST, EQUIVOCATOR, FORGER, CENSOR, SILENT = "honest", "equivocator", "forger", "censor", "silent"


class Node:
    def __init__(self, key: KeyPair, genesis: Dict[str, Any], behaviour: str = HONEST,
                 target: Optional[str] = None, max_block_txs: int = 2000):
        self.key = key
        self.chain = Chain(genesis)
        self.behaviour = behaviour
        self.target = target                      # victim (forger) or censored account (censor)
        self.max_block_txs = max_block_txs
        self.mempool: Dict[str, T.Transaction] = {}
        self.voted: Dict[Tuple[int, int], str] = {}
        self.seen: Dict[Tuple[str, int, int], Tuple[BlockHeader, str]] = {}
        self.reported: set = set()

    @property
    def address(self) -> str:
        return self.key.address

    # -- mempool -------------------------------------------------------- #
    def receive_tx(self, tx: T.Transaction) -> None:
        if tx.signature_valid() and tx.chain_id == self.chain.chain_id:
            self.mempool.setdefault(tx.txid, tx)

    # -- proposing ------------------------------------------------------ #
    def build_block(self, height: int, round_: int, skip_sender: Optional[str] = None,
                    extra: Optional[List[T.Transaction]] = None, reverse: bool = False) -> Block:
        state = self.chain.state.copy()
        chosen: List[T.Transaction] = []
        taken: set = set()
        pool = list(self.mempool.values())
        if reverse:
            pool.reverse()
        progress = True
        while progress and len(chosen) < self.max_block_txs:   # loop lets later nonces follow earlier ones
            progress = False
            for t in pool:
                if t.txid in taken or t.sender == skip_sender or len(chosen) >= self.max_block_txs:
                    continue
                try:
                    state.apply(t, height)
                    chosen.append(t)
                    taken.add(t.txid)
                    progress = True
                except InvalidTx:
                    continue
        for t in extra or []:                     # Byzantine: append without validating
            chosen.append(t)
        header = BlockHeader(self.chain.chain_id, height, round_, self.chain.tip_hash,
                             merkle_root([t.txid for t in chosen]), state.root(), self.address)
        return Block(header, chosen)

    def sign_vote(self, block: Block) -> str:
        h = block.header
        return self.key.sign(vote_message(h.chain_id, h.height, h.round, block.hash))

    def propose(self, height: int, round_: int, all_nodes: List["Node"]) -> List[Tuple[Block, str, List["Node"]]]:
        """Returns [(block, proposer_signature, recipients)]."""
        if self.behaviour == SILENT:
            return []
        if self.behaviour == EQUIVOCATOR:
            a = self.build_block(height, round_)
            b = self.build_block(height, round_, reverse=True, skip_sender=self._any_sender())
            if a.hash == b.hash:
                return [(a, self.sign_vote(a), all_nodes)]
            half = (len(all_nodes) + 1) // 2
            return [(a, self.sign_vote(a), all_nodes[:half]), (b, self.sign_vote(b), all_nodes[half:])]
        if self.behaviour == FORGER and self.target:
            victim_nonce = self.chain.state.accounts[self.target]["nonce"]
            forged = T.Transaction(self.chain.chain_id, T.PAYMENT, self.target, victim_nonce,
                                   {"to": self.address, "amount": 10 ** 9, "purpose": "FINANCIAL"},
                                   signature=self.key.sign(b"this is not the victim's key"))
            blk = self.build_block(height, round_, extra=[forged])
            return [(blk, self.sign_vote(blk), all_nodes)]
        if self.behaviour == CENSOR:
            blk = self.build_block(height, round_, skip_sender=self.target)
            return [(blk, self.sign_vote(blk), all_nodes)]
        blk = self.build_block(height, round_)
        return [(blk, self.sign_vote(blk), all_nodes)]

    def _any_sender(self) -> Optional[str]:
        for t in self.mempool.values():
            return t.sender
        return None

    # -- voting --------------------------------------------------------- #
    def on_proposal(self, block: Block, proposer_sig: str) -> Optional[str]:
        """Validate a proposal; return a vote signature or None."""
        h = block.header
        if self.behaviour == SILENT:
            return None
        if self.behaviour == EQUIVOCATOR and h.proposer == self.address:
            return self.sign_vote(block)          # happily votes for both of its own blocks
        if (h.height, h.round) in self.voted and self.voted[(h.height, h.round)] != block.hash:
            return None                           # honest rule: one vote per (height, round)
        try:
            self.chain.execute(block)
        except InvalidBlock:
            return None
        self.voted[(h.height, h.round)] = block.hash
        return self.sign_vote(block)

    # -- accountability ------------------------------------------------- #
    def observe(self, header: BlockHeader, signer: str, sig: str) -> Optional[T.Transaction]:
        """Record a signed header; if it conflicts with an earlier one, build EVIDENCE."""
        if not verify(signer, vote_message(header.chain_id, header.height, header.round, header.hash), sig):
            return None
        key = (signer, header.height, header.round)
        prev = self.seen.get(key)
        if prev is None:
            self.seen[key] = (header, sig)
            return None
        if prev[0].hash == header.hash or key in self.reported or self.behaviour != HONEST:
            return None
        self.reported.add(key)
        nonce = self.chain.state.accounts[self.address]["nonce"] + sum(
            1 for t in self.mempool.values() if t.sender == self.address)
        ev = T.Transaction.create(self.chain.chain_id, T.EVIDENCE, self.key, nonce, {
            "validator": signer, "header_a": prev[0].to_dict(), "sig_a": prev[1],
            "header_b": header.to_dict(), "sig_b": sig})
        return ev

    def commit(self, block: Block) -> None:
        self.chain.add_block(block)
        for t in block.txs:
            self.mempool.pop(t.txid, None)
        # Mempool policy: keep only what is valid against the new tip.  (A censored
        # transaction is still valid, so it survives until an honest proposer takes it.)
        trial, alive, progress = self.chain.state.copy(), set(), True
        while progress:
            progress = False
            for txid, t in self.mempool.items():
                if txid in alive:
                    continue
                try:
                    trial.apply(t, self.chain.height + 1)
                    alive.add(txid)
                    progress = True
                except InvalidTx:
                    pass
        for txid in [x for x in self.mempool if x not in alive]:
            self.mempool.pop(txid)


@dataclass
class RoundLog:
    height: int
    round: int
    proposer: str
    outcome: str
    votes: int = 0
    needed: int = 0
    txs: int = 0


@dataclass
class Network:
    nodes: List[Node]
    log: List[RoundLog] = field(default_factory=list)

    @staticmethod
    def create(genesis: Dict[str, Any], validator_keys: List[KeyPair],
               behaviours: Optional[Dict[int, Tuple[str, Optional[str]]]] = None) -> "Network":
        behaviours = behaviours or {}
        nodes = []
        for i, k in enumerate(validator_keys):
            b, target = behaviours.get(i, (HONEST, None))
            nodes.append(Node(k, genesis, b, target))
        return Network(nodes)

    # ------------------------------------------------------------------ #
    @property
    def reference(self) -> Node:
        """An honest node whose chain we read results from."""
        return next(n for n in self.nodes if n.behaviour == HONEST)

    def submit(self, tx: T.Transaction) -> None:
        for n in self.nodes:
            n.receive_tx(tx)

    def node(self, address: str) -> Optional[Node]:
        return next((n for n in self.nodes if n.address == address), None)

    def produce_block(self, max_rounds: Optional[int] = None) -> Optional[Block]:
        """Run rounds until a block is finalised.  None means liveness was lost."""
        ref = self.reference
        height = ref.chain.height + 1
        validators = list(ref.chain.state.validators)
        need = quorum(len(validators))
        for round_ in range(max_rounds or len(validators)):
            proposer_addr = ref.chain.expected_proposer(height, round_)
            proposer = self.node(proposer_addr)
            proposals = proposer.propose(height, round_, self.nodes) if proposer else []
            if not proposals:
                self.log.append(RoundLog(height, round_, proposer_addr, "no proposal", 0, need))
                continue

            tallies: List[Tuple[Block, Dict[str, str]]] = []
            for block, psig, recipients in proposals:
                votes: Dict[str, str] = {}
                for n in recipients:
                    if n.address not in validators:
                        continue
                    sig = n.on_proposal(block, psig)
                    if sig:
                        votes[n.address] = sig
                if proposer.address in validators and proposer.behaviour != SILENT:
                    votes.setdefault(proposer.address, psig)
                tallies.append((block, votes))

            # gossip: every signed header reaches every node, so equivocation is noticed
            for block, votes in tallies:
                for signer, sig in votes.items():
                    for n in self.nodes:
                        ev = n.observe(block.header, signer, sig)
                        if ev is not None:
                            self.submit(ev)

            winner = next(((b, v) for b, v in tallies if len(v) >= need), None)
            best = max(len(v) for _, v in tallies)
            if winner is None:
                kind = "split vote" if len(tallies) > 1 else "no quorum"
                self.log.append(RoundLog(height, round_, proposer_addr, kind, best, need))
                continue
            block, votes = winner
            block.votes = votes
            for n in self.nodes:
                try:
                    n.commit(block)
                except InvalidBlock:
                    pass                          # a Byzantine node's local view may differ
            outcome = "committed (proposer equivocated)" if len(tallies) > 1 else "committed"
            self.log.append(RoundLog(height, round_, proposer_addr, outcome, len(votes), need, len(block.txs)))
            return block
        return None

    def run_until_empty(self, max_blocks: int = 50) -> int:
        made = 0
        while self.reference.mempool and made < max_blocks:
            if self.produce_block() is None:
                break
            made += 1
        return made
