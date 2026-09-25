"""The blockchain: an append-only list of finalised blocks plus the state.

A block is accepted only if

1. it extends the current tip (height, ``prev_hash``),
2. its proposer is the validator whose turn it is: ``validators[(height + round) % n]``,
3. its Merkle root matches its transactions,
4. every transaction is valid when applied in order (see :mod:`jurisledger.state`),
5. the resulting state digest equals ``state_root``, and
6. it carries a *commit certificate*: valid vote signatures from a Byzantine
   quorum (more than two thirds) of the validator set in force at the parent.

Rule 6 is what removes the single central authority: no one validator -- and no
coalition of one third or fewer -- can finalise anything on its own.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .block import Block, BlockHeader, vote_message
from .crypto import hash_obj, merkle_proof, verify, verify_merkle_proof
from .state import InvalidTx, State, quorum
from .tx import Transaction


class InvalidBlock(Exception):
    pass


class Chain:
    def __init__(self, genesis: Dict[str, Any]):
        self.genesis = genesis
        self.chain_id: str = genesis["chain_id"]
        self.genesis_hash = hash_obj(genesis)
        self.state = State.from_genesis(genesis)
        self.blocks: List[Block] = []
        self.base_height, self.base_hash = 0, self.genesis_hash     # non-zero when started from a snapshot
        self.snapshot: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ #
    @property
    def height(self) -> int:
        return self.base_height + len(self.blocks)

    @property
    def tip_hash(self) -> str:
        return self.blocks[-1].hash if self.blocks else self.base_hash

    def block_at(self, height: int) -> Block:
        if height <= self.base_height:
            raise KeyError(f"block {height} is before this chain's snapshot (base height {self.base_height})")
        return self.blocks[height - self.base_height - 1]

    # ------------------------------------------------------------------ #
    @staticmethod
    def from_snapshot(genesis: Dict[str, Any], snapshot: Dict[str, Any], validators: List[str]) -> "Chain":
        """Start from a certified snapshot instead of block 1.

        ``snapshot`` = {"state": ..., "header": ..., "votes": ..., "commit_round": ...}.  The
        header's certificate is checked against ``validators`` -- a list the verifier
        already trusts (the genesis validators, or a set it learned through governance) --
        and the restored state's digest must equal the header's ``state_root``.  This is
        how a new validator or auditor joins in seconds instead of replaying years.  What
        a snapshot cannot give you is the history before it: audit trails start at the
        snapshot's access log, and older blocks must come from an archive.
        """
        c = Chain(genesis)
        header = BlockHeader.from_dict(snapshot["header"])
        if header.chain_id != c.chain_id:
            raise InvalidBlock("snapshot is for another chain")
        msg = vote_message(c.chain_id, header.height, snapshot.get("commit_round", header.round), header.hash)
        good = sum(1 for v, sig in snapshot["votes"].items() if v in validators and verify(v, msg, sig))
        if good < quorum(len(validators)):
            raise InvalidBlock(f"snapshot certificate has {good} valid votes, quorum is {quorum(len(validators))}")
        state = State.from_snapshot(snapshot["state"])
        if state.root() != header.state_root:
            raise InvalidBlock("snapshot state does not match the certified state_root")
        c.state, c.base_height, c.base_hash, c.snapshot = state, header.height, header.hash, snapshot
        return c

    def make_snapshot(self) -> Dict[str, Any]:
        if not self.blocks:
            raise ValueError("no finalised block to snapshot at")
        b = self.blocks[-1]
        return {"state": self.state.to_snapshot(), "header": b.header.to_dict(), "votes": dict(b.votes),
                "commit_round": b.vote_round}

    def expected_proposer(self, height: int, round_: int, state: Optional[State] = None) -> str:
        vals = (state or self.state).validators
        return vals[(height + round_) % len(vals)]

    # ------------------------------------------------------------------ #
    def execute(self, block: Block, parent: Optional[State] = None) -> State:
        """Rules 1-5.  Returns the post-state; raises :class:`InvalidBlock`."""
        parent = parent or self.state
        h = block.header
        if h.chain_id != self.chain_id:
            raise InvalidBlock("wrong chain_id")
        if h.height != self.height + 1:
            raise InvalidBlock(f"wrong height {h.height}, expected {self.height + 1}")
        if h.prev_hash != self.tip_hash:
            raise InvalidBlock("prev_hash does not match the current tip")
        if self.blocks and h.timestamp < self.blocks[-1].header.timestamp:
            raise InvalidBlock("timestamp runs backwards")
        if h.round < 0 or h.proposer != self.expected_proposer(h.height, h.round, parent):
            raise InvalidBlock("not this validator's turn to propose")
        if block.computed_tx_root() != h.tx_root:
            raise InvalidBlock("tx_root does not match transactions")
        if len({t.txid for t in block.txs}) != len(block.txs):
            raise InvalidBlock("duplicate transaction in block")
        new_state = parent.copy()
        for t in block.txs:
            try:
                new_state.apply(t, h.height)
            except InvalidTx as e:
                raise InvalidBlock(f"invalid transaction {t.txid[:12]}: {e}") from e
        if new_state.root() != h.state_root:
            raise InvalidBlock("state_root mismatch")
        return new_state

    def check_certificate(self, block: Block, validators: List[str]) -> int:
        """Rule 6.  Returns the number of valid votes; raises if below quorum."""
        h = block.header
        if block.vote_round < h.round:
            raise InvalidBlock("votes cannot predate the proposal")
        msg = vote_message(self.chain_id, h.height, block.vote_round, block.hash)
        good = sum(1 for v, sig in block.votes.items() if v in validators and verify(v, msg, sig))
        need = quorum(len(validators))
        if good < need:
            raise InvalidBlock(f"commit certificate has {good} valid votes, quorum is {need}")
        return good

    def add_block(self, block: Block) -> None:
        new_state = self.execute(block)
        self.check_certificate(block, self.state.validators)
        self.state = new_state
        self.blocks.append(block)

    # ------------------------------------------------------------------ #
    # Independent audit and light clients
    # ------------------------------------------------------------------ #
    @staticmethod
    def audit(genesis: Dict[str, Any], blocks: List[Block]) -> "Chain":
        """Re-verify an entire history from nothing but the genesis and blocks.

        This is what a statistics office, a court, a journalist or a rival bank
        would run.  It needs no permission and trusts no validator.
        """
        c = Chain(genesis)
        for b in blocks:
            c.add_block(b)
        return c

    def iter_txs(self, start: int = 1, end: Optional[int] = None) -> Iterator[Tuple[int, Transaction]]:
        """(height, tx) for every finalised transaction in blocks start..end inclusive."""
        end = self.height if end is None else end
        for b in self.blocks[max(0, start - self.base_height - 1):max(0, end - self.base_height)]:
            for t in b.txs:
                yield b.header.height, t

    def find_tx(self, txid: str) -> Optional[Tuple[int, int]]:
        for b in self.blocks:
            for i, t in enumerate(b.txs):
                if t.txid == txid:
                    return b.header.height, i
        return None

    def tx_proof(self, txid: str) -> Dict[str, Any]:
        """Everything a light client needs to check that a tx was finalised."""
        loc = self.find_tx(txid)
        if loc is None:
            raise KeyError("transaction not found")
        height, idx = loc
        b = self.block_at(height)
        return {"header": b.header.to_dict(), "votes": dict(b.votes), "commit_round": b.vote_round,
                "proof": merkle_proof([t.txid for t in b.txs], idx)}

    @staticmethod
    def verify_tx_proof(txid: str, proof: Dict[str, Any], validators: List[str]) -> bool:
        """Light-client check: header has a quorum certificate AND tx is under its Merkle root."""
        header = BlockHeader.from_dict(proof["header"])
        msg = vote_message(header.chain_id, header.height, proof.get("commit_round", header.round), header.hash)
        good = sum(1 for v, s in proof["votes"].items() if v in validators and verify(v, msg, s))
        if good < quorum(len(validators)):
            return False
        return verify_merkle_proof(txid, [tuple(p) for p in proof["proof"]], header.tx_root)

    # ------------------------------------------------------------------ #
    def export(self) -> str:
        return json.dumps({"genesis": self.genesis, "snapshot": self.snapshot,
                           "blocks": [b.to_dict() for b in self.blocks]})

    @staticmethod
    def load(text: str, validators: Optional[List[str]] = None) -> "Chain":
        """Re-verify an export.  If it starts from a snapshot, the snapshot's certificate is
        checked against ``validators`` (default: the genesis validators)."""
        d = json.loads(text)
        blocks = [Block.from_dict(b) for b in d["blocks"]]
        if d.get("snapshot"):
            c = Chain.from_snapshot(d["genesis"], d["snapshot"], validators or d["genesis"]["validators"])
            for b in blocks:
                c.add_block(b)
            return c
        return Chain.audit(d["genesis"], blocks)
