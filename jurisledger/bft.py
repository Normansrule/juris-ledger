"""A consensus laboratory: why one round of voting is not enough.

:mod:`jurisledger.consensus` collects votes in a single phase over a network that
delivers every message instantly.  Real networks delay and reorder messages.
This module models exactly that -- an *adversarial scheduler* that may hold any
message for as long as it likes (but never forge or drop one) -- and runs two
protocols on it, deciding one block height:

``SinglePhaseNode``   what consensus.py does: vote once per round, finalise on a
                      quorum of votes, move to the next round on timeout.
``TwoPhaseNode``      Tendermint (Buchman, Kwon & Milosevic 2018, Algorithm 1):
                      PREVOTE then PRECOMMIT, with a *lock*.  A validator that
                      sees a quorum of prevotes for a block locks on it and, in
                      later rounds, refuses to prevote anything else unless it
                      sees a newer quorum.  Any two quorums share an honest
                      validator, and that validator's lock is what makes two
                      conflicting decisions impossible.

Values are opaque block identifiers; block *validity* is the business of
:mod:`jurisledger.chain` and is unchanged by which voting protocol carries it.

Simplifications, stated: step timers are unconditional and grow linearly with the
round (the paper starts them only after hearing from a quorum), a decision needs a quorum of precommits but
not the matching proposal.  Honest validators relay every signed message they
receive (gossip), which is the network assumption Tendermint's liveness rests on:
what one honest validator has seen, all eventually see.  A lying validator's
conflicting votes are all counted, as in the paper - safety must survive that.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

PROPOSAL, VOTE, PREVOTE, PRECOMMIT, DECIDE = "PROPOSAL", "VOTE", "PREVOTE", "PRECOMMIT", "DECIDE"
NIL = None


def quorum(n: int) -> int:
    return (2 * n) // 3 + 1


@dataclass
class Msg:
    kind: str
    round: int
    value: Optional[str]
    src: int
    dst: int = -1
    valid_round: int = -1
    sent: int = 0
    via: int = -1                 # who transmitted this copy (the signer, or an honest relayer)
    sig: str = ""                 # used when the protocol carries real blocks (ledgernet.py)
    payload: Any = None           # the proposed or decided block, when there is one

    @property
    def final(self) -> bool:
        """True for the message type whose quorum finalises a block."""
        return self.kind in (VOTE, PRECOMMIT)


# --------------------------------------------------------------------------- #
class _Node:
    def __init__(self, index: int, n: int, timeout: int = 4):
        self.i, self.n, self.q, self.timeout = index, n, quorum(n), timeout
        self.round, self.step, self.step_started = 0, "propose", 0
        self.decision: Optional[str] = None
        self.decided_at: Optional[int] = None
        self.sim: "Sim" = None  # type: ignore[assignment]
        self.proposals: Dict[int, Dict[Optional[str], Msg]] = {}
        self.seen: Set[Tuple[str, int, Optional[str], int]] = set()

    def _new(self, m: Msg) -> bool:
        """Record a signed message once, and gossip it on to everyone else."""
        key = (m.kind, m.round, m.value, m.src)
        if key in self.seen:
            return False
        self.seen.add(key)
        if m.src != self.i:
            self.sim.relay(m, self.i)
        return True

    @staticmethod
    def _add(table: Dict[int, Dict[Optional[str], Set[int]]], m: Msg) -> None:
        table.setdefault(m.round, {}).setdefault(m.value, set()).add(m.src)

    @staticmethod
    def _n(table: Dict[int, Dict[Optional[str], Set[int]]], round_: int, value: Optional[str]) -> int:
        return len(table.get(round_, {}).get(value, ()))

    def _quorum_value(self, table: Dict[int, Dict[Optional[str], Set[int]]]) -> Optional[str]:
        for by_value in table.values():
            for v, senders in by_value.items():
                if v is not NIL and len(senders) >= self.q and self._can_decide(v):
                    return v
        return None

    def proposer(self, round_: int) -> int:
        return round_ % self.n

    def _make(self, kind: str, value: Optional[str], valid_round: int) -> Msg:
        return Msg(kind, self.round, value, self.i, valid_round=valid_round)

    def broadcast(self, kind: str, value: Optional[str], valid_round: int = -1) -> None:
        self.sim.broadcast(self._make(kind, value, valid_round))

    # hooks overridden when values are real blocks
    def _new_value(self, r: int) -> str:
        return f"block-r{r}-by-v{self.i}"

    def _valid(self, value: Optional[str]) -> bool:
        return True

    def _can_decide(self, value: str) -> bool:
        return True

    def _timed_out(self) -> bool:
        """Timeouts grow with the round number, so that rounds eventually outlast any finite delay."""
        return self.sim.time - self.step_started >= self.timeout + 2 * self.round

    def _enter(self, step: str) -> None:
        self.step, self.step_started = step, self.sim.time

    def _decide(self, value: str, announce: bool = True) -> None:
        """Finalise.  The quorum of signed votes is a transferable certificate, so the
        node forwards it; a validator that missed the votes can adopt the decision
        (in a deployment it would verify the signatures - they cannot be forged,
        which is why ByzantineNode never sends DECIDE)."""
        if self.decision is None:
            self.decision, self.decided_at = value, self.sim.time
            if announce:
                self.broadcast(DECIDE, value)

    def _adopt(self, m: Msg) -> bool:
        if m.kind == DECIDE:
            self._decide(m.value, announce=False)       # type: ignore[arg-type]
            return True
        return False


class SinglePhaseNode(_Node):
    """One vote per round; a quorum of votes finalises."""

    def __init__(self, index: int, n: int, timeout: int = 4):
        super().__init__(index, n, timeout)
        self.votes: Dict[int, Dict[Optional[str], Set[int]]] = {}
        self.voted: Set[int] = set()

    def start_round(self, r: int) -> None:
        self.round = r
        self._enter("propose")
        if self.proposer(r) == self.i:
            self.broadcast(PROPOSAL, self._new_value(r))

    def receive(self, m: Msg) -> None:
        if self._adopt(m) or not self._new(m):
            return
        if m.kind == PROPOSAL and m.src == self.proposer(m.round):
            self.proposals.setdefault(m.round, {}).setdefault(m.value, m)
        elif m.kind == VOTE:
            self._add(self.votes, m)
        self.evaluate()

    def evaluate(self) -> None:
        if self.decision is not None:
            return
        ps = self.proposals.get(self.round)
        if ps and self.step == "propose" and self.round not in self.voted:
            choice = next((v for v in ps if self._valid(v)), None)
            if choice is not None:
                self.voted.add(self.round)        # the honest rule: one vote per (height, round)
                self._enter("vote")
                self.broadcast(VOTE, choice)
        v = self._quorum_value(self.votes)
        if v is not None:
            self._decide(v)

    def tick(self) -> None:
        if self.decision is None and self._timed_out():
            if self.step == "propose":
                self._enter("vote")
            else:
                self.start_round(self.round + 1)


class TwoPhaseNode(_Node):
    """Tendermint-style prevote / precommit with locking."""

    def __init__(self, index: int, n: int, timeout: int = 4):
        super().__init__(index, n, timeout)
        self.prevotes: Dict[int, Dict[Optional[str], Set[int]]] = {}
        self.precommits: Dict[int, Dict[Optional[str], Set[int]]] = {}
        self.locked_value: Optional[str] = None
        self.locked_round = -1
        self.valid_value: Optional[str] = None
        self.valid_round = -1
        self.polka_seen: Set[int] = set()

    def start_round(self, r: int) -> None:
        self.round = r
        self._enter("propose")
        if self.proposer(r) == self.i:
            value = self.valid_value or self._new_value(r)
            self.broadcast(PROPOSAL, value, self.valid_round)

    def receive(self, m: Msg) -> None:
        if self._adopt(m) or not self._new(m):
            return
        if m.kind == PROPOSAL and m.src == self.proposer(m.round):
            self.proposals.setdefault(m.round, {}).setdefault(m.value, m)
        elif m.kind == PREVOTE:
            self._add(self.prevotes, m)
        elif m.kind == PRECOMMIT:
            self._add(self.precommits, m)
        self.evaluate()

    def _prevote(self, value: Optional[str]) -> None:
        self._enter("prevote")
        self.broadcast(PREVOTE, value)

    def _precommit(self, value: Optional[str]) -> None:
        self._enter("precommit")
        self.broadcast(PRECOMMIT, value)

    def _acceptable(self, p: Msg) -> Optional[bool]:
        """None: cannot judge this proposal yet.  True / False: prevote for it / for nil."""
        if not self._valid(p.value):
            return False
        if p.valid_round == -1:
            return self.locked_round == -1 or self.locked_value == p.value
        if 0 <= p.valid_round < self.round and self._n(self.prevotes, p.valid_round, p.value) >= self.q:
            return self.locked_round <= p.valid_round or self.locked_value == p.value
        return None

    def evaluate(self) -> None:
        changed = True
        while changed and self.decision is None:
            changed = False
            r = self.round
            v = self._quorum_value(self.precommits)       # a quorum of precommits in ANY round decides
            if v is not None:
                self._decide(v)
                return
            if self.step == "propose":
                for p in self.proposals.get(r, {}).values():
                    ok = self._acceptable(p)
                    if ok is not None:
                        self._prevote(p.value if ok else NIL)
                        changed = True
                        break
                if changed:
                    continue
            if self.step in ("prevote", "precommit") and r not in self.polka_seen:
                for value in self.proposals.get(r, {}):
                    if self._n(self.prevotes, r, value) >= self.q:
                        self.polka_seen.add(r)
                        self.valid_value, self.valid_round = value, r
                        if self.step == "prevote":
                            self.locked_value, self.locked_round = value, r      # THE LOCK
                            self._precommit(value)
                        changed = True
                        break
                if changed:
                    continue
            if self.step == "prevote" and self._n(self.prevotes, r, NIL) >= self.q:
                self._precommit(NIL)
                changed = True
                continue
            ahead: Dict[int, Set[int]] = {}               # round skip: f + 1 validators are already ahead
            for table in (self.prevotes, self.precommits):
                for rr, by_value in table.items():
                    if rr > r:
                        for senders in by_value.values():
                            ahead.setdefault(rr, set()).update(senders)
            late = [rr for rr, who in ahead.items() if len(who) >= self.n - self.q + 1]
            if late:
                self.start_round(min(late))
                changed = True

    def tick(self) -> None:
        if self.decision is not None or not self._timed_out():
            return
        if self.step == "propose":
            self._prevote(NIL)
        elif self.step == "prevote":
            self._precommit(NIL)
        else:
            self.start_round(self.round + 1)
        self.evaluate()


class ByzantineNode(_Node):
    """Says something different to everyone: conflicting proposals, conflicting votes."""

    def __init__(self, index: int, n: int, two_phase: bool, rng: random.Random, timeout: int = 4):
        super().__init__(index, n, timeout)
        self.two_phase, self.rng = two_phase, rng
        self.values: List[Optional[str]] = [NIL]

    def start_round(self, r: int) -> None:
        self.round = r
        self._enter("propose")
        kinds = (PREVOTE, PRECOMMIT) if self.two_phase else (VOTE,)
        mine = [f"block-r{r}-evil-{c}" for c in "ab"]
        self.values += mine
        for dst in range(self.n):
            if dst == self.i:
                continue
            if self.proposer(r) == self.i:
                self.sim.send(Msg(PROPOSAL, r, mine[dst % 2], self.i, dst, via=self.i))
            for k in kinds:
                self.sim.send(Msg(k, r, self.rng.choice(self.values), self.i, dst, via=self.i))

    def receive(self, m: Msg) -> None:
        if m.kind == DECIDE:
            return
        if m.value is not NIL and m.value not in self.values:
            self.values.append(m.value)
        if m.round > self.round:
            self.start_round(m.round)

    def evaluate(self) -> None:
        pass

    def tick(self) -> None:
        if self.sim.time - self.step_started >= 3 * self.timeout:
            self.start_round(self.round + 1)


class ColludingNode(_Node):
    """One of a coordinated pair that tells each honest validator a different, consistent story."""

    def __init__(self, index: int, n: int, story: Dict[int, str]):
        super().__init__(index, n)
        self.story = story                        # honest validator -> the block it is told about

    def start_round(self, r: int) -> None:
        self.round = r
        self._enter("propose")
        if r > 0:
            return
        for dst, value in self.story.items():
            if self.proposer(0) == self.i:
                self.sim.send(Msg(PROPOSAL, 0, value, self.i, dst, via=self.i))
            for kind in (PREVOTE, PRECOMMIT):
                self.sim.send(Msg(kind, 0, value, self.i, dst, via=self.i))

    def receive(self, m: Msg) -> None:
        pass

    def tick(self) -> None:
        pass


def equivocators(node: "TwoPhaseNode") -> Set[int]:
    """Validators this node can PROVE signed two different blocks in one round."""
    guilty: Set[int] = set()
    for table in (node.prevotes, node.precommits):
        for by_value in table.values():
            signed: Dict[int, int] = {}
            for value, senders in by_value.items():
                if value is not NIL:
                    for sender in senders:
                        signed[sender] = signed.get(sender, 0) + 1
            guilty |= {sender for sender, k in signed.items() if k > 1}
    return guilty


# --------------------------------------------------------------------------- #
Hold = Callable[[Msg, "Sim"], bool]


@dataclass
class Sim:
    nodes: List[_Node]
    hold: Optional[Hold] = None                 # the adversary: True = keep this message back for now
    delay: Optional[Callable[[Msg], int]] = None
    time: int = 0
    queue: List[Tuple[int, int, Msg]] = field(default_factory=list)
    delivered: int = 0
    flags: Dict[str, bool] = field(default_factory=dict)
    _seq: int = 0

    def __post_init__(self) -> None:
        for nd in self.nodes:
            nd.sim = self
        for nd in self.nodes:
            nd.start_round(0)

    def send(self, m: Msg) -> None:
        m.sent = self.time
        self._seq += 1
        self.queue.append((self.time + (self.delay(m) if self.delay else 1), self._seq, m))

    def broadcast(self, m: Msg) -> None:
        for dst in range(len(self.nodes)):
            copy = replace(m, dst=dst, via=m.src)
            if dst == m.src:
                copy.sent = self.time
                self.nodes[dst].receive(copy)   # a node hears itself at once
            else:
                self.send(copy)

    def relay(self, m: Msg, relayer: int) -> None:
        for dst in range(len(self.nodes)):
            if dst not in (relayer, m.src, m.via):
                self.send(replace(m, dst=dst, via=relayer))

    def step(self) -> None:
        self.time += 1
        ready = sorted((x for x in self.queue if x[0] <= self.time and not (self.hold and self.hold(x[2], self))),
                       key=lambda x: (x[0], x[1]))
        taken = {x[1] for x in ready}
        self.queue = [x for x in self.queue if x[1] not in taken]
        for _, _, m in ready:
            self.delivered += 1
            self.nodes[m.dst].receive(m)
        for nd in self.nodes:
            nd.tick()

    def run(self, ticks: int, until_decided: Optional[Set[int]] = None) -> None:
        for _ in range(ticks):
            self.step()
            if until_decided and all(self.nodes[i].decision is not None for i in until_decided):
                break

    def decisions(self, honest: Optional[Set[int]] = None) -> Dict[int, Optional[str]]:
        idx = honest if honest is not None else set(range(len(self.nodes)))
        return {i: self.nodes[i].decision for i in sorted(idx)}

    def forked(self, honest: Optional[Set[int]] = None) -> bool:
        return len({d for d in self.decisions(honest).values() if d is not None}) > 1


# --------------------------------------------------------------------------- #
# The scripted adversary.  It forges nothing and drops nothing -- it only delays.
# --------------------------------------------------------------------------- #
def make_partition_adversary(first: int = 0, cut: int = 1) -> Hold:
    """Three delays, applied identically to both protocols.

    ``first`` is the round-0 proposer, ``cut`` the round-1 proposer.
    1. ``cut`` is cut off during round 0, until every undecided validator has left round 0.
    2. Round-0 *finalising* messages (VOTE / PRECOMMIT) reach only ``first``.
    3. As soon as ``first`` decides, it is cut off: nothing new from it, nothing to it.
    Delays 2 and 3 last until ``sim.flags['healed']`` is set.
    """
    def hold(m: Msg, sim: Sim) -> bool:
        in_round_0 = any(nd.decision is None and nd.round == 0 for nd in sim.nodes)
        if m.round == 0 and cut in (m.via, m.dst) and in_round_0:
            return True
        if sim.flags.get("healed", False):
            return False
        if m.round == 0 and m.final and m.dst != first:
            return True
        leader = sim.nodes[first]
        return leader.decision is not None and (
            m.dst == first or (m.via == first and m.sent >= (leader.decided_at or 0)))
    return hold


partition_adversary = make_partition_adversary(0, 1)


def run_partition(two_phase: bool, ticks: int = 80) -> Sim:
    cls = TwoPhaseNode if two_phase else SinglePhaseNode
    sim = Sim([cls(i, 4) for i in range(4)], hold=partition_adversary)
    sim.run(ticks)
    sim.flags["healed"] = True                  # the partition ends; every delayed message arrives
    sim.run(ticks)
    return sim


def run_collusion(ticks: int = 40) -> Sim:
    """Beyond the bound: TWO of four validators collude while the honest two cannot talk."""
    story = {2: "block-told-to-v2", 3: "block-told-to-v3"}
    nodes: List[_Node] = [ColludingNode(0, 4, story), ColludingNode(1, 4, story),
                          TwoPhaseNode(2, 4), TwoPhaseNode(3, 4)]

    def hold(m: Msg, sim: Sim) -> bool:
        return not sim.flags.get("healed", False) and {m.via, m.dst} == {2, 3}

    sim = Sim(nodes, hold=hold)
    sim.run(ticks)
    sim.flags["healed"] = True
    sim.run(ticks)
    return sim


def run_fuzz(two_phase: bool, seed: int, byzantine: int = 1, n: int = 4, ticks: int = 1500) -> Sim:
    """Random delays (sometimes very long) plus ``byzantine`` validators that lie to everyone."""
    rng = random.Random(seed)
    cls = TwoPhaseNode if two_phase else SinglePhaseNode
    nodes: List[_Node] = [cls(i, n) for i in range(n)]
    honest = set(range(n))
    for bad in rng.sample(range(n), int(byzantine)):
        nodes[bad] = ByzantineNode(bad, n, two_phase, rng)
        honest.discard(bad)

    def delay(_: Msg) -> int:
        return rng.randint(1, 3) if rng.random() < 0.7 else rng.randint(4, 40)

    sim = Sim(nodes, delay=delay)
    sim.honest = honest                          # type: ignore[attr-defined]
    sim.run(ticks, until_decided=honest)
    return sim
