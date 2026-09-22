"""The real ledger, driven by two-phase consensus over a network that may be hostile.

:mod:`jurisledger.bft` proved the voting protocol on placeholder values.  Here the
values are real blocks:

* a proposal carries the block; validators prevote for it only if
  :meth:`Chain.execute` accepts every transaction in it,
* every consensus message is signed with the validator's Ed25519 key and checked on
  receipt - an unsigned or forged vote is dropped,
* a quorum of signed PRECOMMITs *is* the block's commit certificate, stored with the
  round it was cast in, so :meth:`Chain.add_block` and every auditor can re-check it,
* two PRECOMMITs by one validator for different blocks in the same round are
  self-contained proof of equivocation; honest validators turn them into an
  ``EVIDENCE`` transaction and the offender loses its seat,
* a validator that missed the votes adopts a block only after verifying its certificate.

:class:`LedgerNetwork` has the same interface as :class:`consensus.Network`, so every
experiment can run on either.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import bft
from . import consensus as C
from . import tx as T
from .block import Block, consensus_message
from .chain import InvalidBlock
from .consensus import Node, RoundLog
from .crypto import KeyPair, verify


class _BlockMixin:
    """Turns a bft node into a validator that votes on real, signed blocks."""

    FINAL = bft.PRECOMMIT

    def attach(self, inner: Node, addresses: List[str], height: int) -> "_BlockMixin":
        self.inner, self.addresses, self.height = inner, addresses, height
        self.chain_id = inner.chain.chain_id
        self.blocks: Dict[str, Block] = {}
        self.validity: Dict[str, bool] = {}
        self.sigs: Dict[Tuple[str, int, Optional[str], int], str] = {}
        self.decided_block: Optional[Block] = None
        self.evidence: List[T.Transaction] = []
        self.rejected_messages = 0
        self._accused: Set[Tuple[int, int]] = set()
        return self

    # -- identity and rotation follow the chain, not the simulator ---------- #
    def proposer(self, round_: int) -> int:
        return self.addresses.index(self.inner.chain.expected_proposer(self.height, round_))

    def _final_table(self) -> Dict[int, Dict[Optional[str], Set[int]]]:
        return self.precommits if self.FINAL == bft.PRECOMMIT else self.votes   # type: ignore[attr-defined]

    # -- producing ---------------------------------------------------------- #
    def _new_value(self, r: int) -> str:
        n = self.inner
        extra, skip = None, None
        if n.behaviour == C.CENSOR:
            skip = n.target
        if n.behaviour == C.FORGER and n.target:
            nonce = n.chain.state.accounts[n.target]["nonce"]
            extra = [T.Transaction(self.chain_id, T.PAYMENT, n.target, nonce,
                                   {"to": n.address, "amount": 10 ** 9, "purpose": "FINANCIAL"},
                                   signature=n.key.sign(b"this is not the victim's key"))]
        block = n.build_block(self.height, r, skip_sender=skip, extra=extra)
        self.blocks[block.hash] = block
        return block.hash

    def _sign(self, kind: str, round_: int, value: Optional[str]) -> str:
        return self.inner.key.sign(consensus_message(kind, self.chain_id, self.height, round_, value))

    def _make(self, kind: str, value: Optional[str], valid_round: int) -> bft.Msg:
        m = bft.Msg(kind, self.round, value, self.i, valid_round=valid_round)     # type: ignore[attr-defined]
        if kind == bft.DECIDE:
            m.payload = self.decided_block
        else:
            m.sig = self._sign(kind, m.round, value)
            if kind == bft.PROPOSAL:
                m.payload = self.blocks[value]                                     # type: ignore[index]
        return m

    # -- receiving ---------------------------------------------------------- #
    def _new(self, m: bft.Msg) -> bool:
        if not 0 <= m.src < len(self.addresses) or not verify(
                self.addresses[m.src], consensus_message(m.kind, self.chain_id, self.height, m.round, m.value), m.sig):
            self.rejected_messages += 1
            return False
        if m.kind == bft.PROPOSAL:
            blk = m.payload
            if not isinstance(blk, Block) or blk.hash != m.value or blk.header.height != self.height:
                self.rejected_messages += 1
                return False
            self.blocks.setdefault(blk.hash, blk)
        if not super()._new(m):                                                    # type: ignore[misc]
            return False
        if m.kind == self.FINAL:
            self.sigs[(m.kind, m.round, m.value, m.src)] = m.sig
        self._scan_for_equivocation()
        return True

    def _valid(self, value: Optional[str]) -> bool:
        if value not in self.blocks:
            return False
        if value not in self.validity:
            try:
                if not self.inner.clock_ok(self.blocks[value]):
                    raise InvalidBlock("timestamp too far from local clock")
                self.inner.chain.execute(self.blocks[value])
                self.validity[value] = True
            except InvalidBlock:
                self.validity[value] = False
        return self.validity[value]

    def _can_decide(self, value: str) -> bool:
        return self._valid(value)

    # -- deciding ----------------------------------------------------------- #
    def _decide(self, value: str, announce: bool = True, block: Optional[Block] = None) -> None:
        if self.decision is not None:                                              # type: ignore[has-type]
            return
        if block is None:
            for r, by_value in self._final_table().items():
                senders = by_value.get(value, set())
                if len(senders) >= self.q:                                         # type: ignore[attr-defined]
                    cert = {self.addresses[s]: self.sigs[(self.FINAL, r, value, s)] for s in senders}
                    src = self.blocks[value]
                    block = Block(src.header, src.txs, cert, commit_round=r)
                    break
        if block is None:
            return
        self.decided_block = block
        super()._decide(value, announce)                                           # type: ignore[misc]

    def _adopt(self, m: bft.Msg) -> bool:
        if m.kind != bft.DECIDE:
            return False
        blk = m.payload
        try:                                       # never trust an announcement: verify the certificate
            if isinstance(blk, Block) and blk.hash == m.value:
                self.inner.chain.execute(blk)
                self.inner.chain.check_certificate(blk, self.addresses)
                self._decide(blk.hash, announce=False, block=blk)
        except InvalidBlock:
            self.rejected_messages += 1
        return True

    # -- accountability ----------------------------------------------------- #
    def _scan_for_equivocation(self) -> None:
        if self.inner.behaviour != C.HONEST:
            return
        for r, by_value in self._final_table().items():
            seen: Dict[int, str] = {}
            for value, senders in by_value.items():
                if value is None or value not in self.blocks:
                    continue
                for s in senders:
                    if s in seen and (s, r) not in self._accused:
                        self._accused.add((s, r))
                        a, b = seen[s], value
                        n = self.inner
                        nonce = n.chain.state.accounts[n.address]["nonce"] + sum(
                            1 for t in n.mempool.values() if t.sender == n.address) + len(self.evidence)
                        self.evidence.append(T.Transaction.create(self.chain_id, T.EVIDENCE, n.key, nonce, {
                            "validator": self.addresses[s], "round": r,
                            "header_a": self.blocks[a].header.to_dict(), "sig_a": self.sigs[(self.FINAL, r, a, s)],
                            "header_b": self.blocks[b].header.to_dict(), "sig_b": self.sigs[(self.FINAL, r, b, s)]}))
                    seen.setdefault(s, value)


class TwoPhaseBlockNode(_BlockMixin, bft.TwoPhaseNode):
    FINAL = bft.PRECOMMIT


class SinglePhaseBlockNode(_BlockMixin, bft.SinglePhaseNode):
    FINAL = bft.VOTE


class EquivocatingBlockNode(TwoPhaseBlockNode):
    """When it is the proposer it tells each half of the network a different, fully signed story."""

    def start_round(self, r: int) -> None:
        if self.proposer(r) != self.i:
            return super().start_round(r)
        self.round = r
        self._enter("precommit")
        first = self.inner.build_block(self.height, r)
        victim = next((t.sender for t in self.inner.mempool.values()), None)
        second = self.inner.build_block(self.height, r, skip_sender=victim, reverse=True)
        self.blocks[first.hash], self.blocks[second.hash] = first, second
        if first.hash == second.hash:
            return super().start_round(r)
        half = (self.n + 1) // 2
        for dst in range(self.n):
            if dst == self.i:
                continue
            blk = first if dst < half else second
            for kind in (bft.PROPOSAL, bft.PREVOTE, bft.PRECOMMIT):
                self.sim.send(bft.Msg(kind, r, blk.hash, self.i, dst, via=self.i,
                                      sig=self._sign(kind, r, blk.hash),
                                      payload=blk if kind == bft.PROPOSAL else None))


class SilentBlockNode(TwoPhaseBlockNode):
    def start_round(self, r: int) -> None:
        self.round = r

    def receive(self, m: bft.Msg) -> None:
        pass

    def tick(self) -> None:
        pass


# --------------------------------------------------------------------------- #
@dataclass
class LedgerNetwork:
    nodes: List[Node]
    two_phase: bool = True
    delay: Optional[Callable[[bft.Msg], int]] = None
    hold: Optional[Callable[[int], Optional[bft.Hold]]] = None     # height -> adversary for that height
    heal_after: Optional[int] = None                               # ticks until sim.flags['healed'] is set
    max_ticks: int = 400
    log: List[RoundLog] = field(default_factory=list)
    forks: List[int] = field(default_factory=list)                 # heights at which honest nodes diverged
    rejected_messages: int = 0
    ticks: int = 0

    @staticmethod
    def create(genesis: Dict[str, Any], validator_keys: List[KeyPair],
               behaviours: Optional[Dict[int, Tuple[str, Optional[str]]]] = None, **kw: Any) -> "LedgerNetwork":
        behaviours = behaviours or {}
        nodes = [Node(k, genesis, *behaviours.get(i, (C.HONEST, None))) for i, k in enumerate(validator_keys)]
        return LedgerNetwork(nodes, **kw)

    # -- same surface as consensus.Network ---------------------------------- #
    @property
    def reference(self) -> Node:
        return next(n for n in self.nodes if n.behaviour == C.HONEST)

    def submit(self, tx: T.Transaction) -> None:
        for n in self.nodes:
            n.receive_tx(tx)

    def node(self, address: str) -> Optional[Node]:
        return next((n for n in self.nodes if n.address == address), None)

    def _protocol_node(self, inner: Node, index: int, n: int) -> bft._Node:
        if not self.two_phase:
            cls: type = SinglePhaseBlockNode
        elif inner.behaviour == C.EQUIVOCATOR:
            cls = EquivocatingBlockNode
        elif inner.behaviour == C.SILENT:
            cls = SilentBlockNode
        else:
            cls = TwoPhaseBlockNode
        return cls(index, n)

    def produce_block(self, max_rounds: Optional[int] = None) -> Optional[Block]:
        ref = self.reference
        height = ref.chain.height + 1
        addresses = list(ref.chain.state.validators)
        inners = [self.node(a) for a in addresses]
        if any(i is None or i.chain.height != ref.chain.height for i in inners):
            self.sync()
        pnodes = []
        for idx, inner in enumerate(inners):
            p = self._protocol_node(inner, idx, len(addresses))                    # type: ignore[arg-type]
            p.attach(inner, addresses, height)                                     # type: ignore[attr-defined]
            pnodes.append(p)
        honest = {i for i, inner in enumerate(inners) if inner.behaviour in (C.HONEST, C.CENSOR, C.FORGER)}
        sim = bft.Sim(pnodes, hold=self.hold(height) if self.hold else None, delay=self.delay)

        first_decision = None
        for tick in range(self.max_ticks):
            if self.heal_after is not None and tick == self.heal_after:
                sim.flags["healed"] = True
            sim.step()
            decided = [i for i in honest if pnodes[i].decision is not None]
            if decided and first_decision is None:
                first_decision = tick
            healed = self.heal_after is None or tick > self.heal_after
            if len(decided) == len(honest) and healed:
                break
            if first_decision is not None and healed and tick - first_decision > 60:
                break                                # stragglers catch up by block sync below
        self.ticks += sim.time
        self.rejected_messages += sum(p.rejected_messages for p in pnodes)         # type: ignore[attr-defined]

        blocks = {p.decided_block.hash: p.decided_block for p in pnodes            # type: ignore[attr-defined]
                  if p.i in honest and p.decided_block is not None}                # type: ignore[attr-defined]
        if not blocks:
            self.log.append(RoundLog(height, max(p.round for p in pnodes), "", "no quorum",
                                     0, bft.quorum(len(addresses))))
            return None
        if len(blocks) > 1:
            self.forks.append(height)
        any_block = next(iter(blocks.values()))
        for inner in self.nodes:
            p = next((x for x in pnodes if x.inner is inner), None)                # type: ignore[attr-defined]
            mine = p.decided_block if p is not None and p.decided_block is not None else any_block
            try:
                inner.commit(mine)
            except InvalidBlock:
                pass
        for p in pnodes:
            for ev in p.evidence:                                                  # type: ignore[attr-defined]
                self.submit(ev)
        committed = ref.chain.blocks[-1]
        for r in range(committed.vote_round):
            self.log.append(RoundLog(height, r, addresses[(height + r) % len(addresses)], "no quorum",
                                     0, bft.quorum(len(addresses))))
        self.log.append(RoundLog(height, committed.vote_round, committed.header.proposer, "committed",
                                 len(committed.votes), bft.quorum(len(addresses)), len(committed.txs)))
        return committed

    def sync(self) -> None:
        """Block sync: a lagging node replays finalised blocks, re-verifying every certificate."""
        best = max((n for n in self.nodes if n.behaviour == C.HONEST), key=lambda n: n.chain.height)
        for n in self.nodes:
            for blk in best.chain.blocks[n.chain.height:]:
                try:
                    n.commit(blk)
                except InvalidBlock:
                    break

    def run_until_empty(self, max_blocks: int = 50) -> int:
        made = 0
        while self.reference.mempool and made < max_blocks:
            if self.produce_block() is None:
                break
            made += 1
        return made
