"""Blocks, headers and the message validators sign when they vote."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .crypto import canonical, hash_obj, merkle_root
from .tx import Transaction


@dataclass(frozen=True)
class BlockHeader:
    chain_id: str
    height: int
    round: int          # 0 normally; >0 when earlier proposers at this height failed
    prev_hash: str
    tx_root: str        # Merkle root of the transaction ids
    state_root: str     # digest of the ledger state AFTER applying this block
    proposer: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id, "height": self.height, "round": self.round,
            "prev_hash": self.prev_hash, "tx_root": self.tx_root,
            "state_root": self.state_root, "proposer": self.proposer,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "BlockHeader":
        return BlockHeader(d["chain_id"], d["height"], d["round"], d["prev_hash"],
                           d["tx_root"], d["state_root"], d["proposer"])

    @property
    def hash(self) -> str:
        return hash_obj(self.to_dict())


def vote_message(chain_id: str, height: int, round_: int, block_hash: str) -> bytes:
    """Bytes a validator signs to vote for (or propose) a block."""
    return b"jurisledger/vote/v1:" + canonical(
        {"chain_id": chain_id, "height": height, "round": round_, "block_hash": block_hash}
    )


@dataclass
class Block:
    header: BlockHeader
    txs: List[Transaction]
    votes: Dict[str, str] = field(default_factory=dict)   # validator address -> signature

    @property
    def hash(self) -> str:
        return self.header.hash

    def computed_tx_root(self) -> str:
        return merkle_root([t.txid for t in self.txs])

    def to_dict(self) -> Dict[str, Any]:
        return {"header": self.header.to_dict(), "txs": [t.to_dict() for t in self.txs],
                "votes": dict(self.votes)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Block":
        return Block(BlockHeader.from_dict(d["header"]),
                     [Transaction.from_dict(t) for t in d["txs"]], dict(d["votes"]))
