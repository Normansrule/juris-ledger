"""Durable, append-only block storage.

One directory: ``genesis.json`` plus ``blocks.jsonl`` (one finalised block per line).
Appends are flushed and fsync'ed before returning.  Opening a store re-audits every
block, so a file edited on disk is detected exactly like a forged block on the wire.
A half-written last line (power loss mid-append) is recognised, reported and cut off;
nothing finalised is lost because a block is only acknowledged after fsync.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .block import Block
from .chain import Chain


class BlockStore:
    def __init__(self, directory: str | os.PathLike):
        self.dir = Path(directory)
        self.genesis_path, self.blocks_path = self.dir / "genesis.json", self.dir / "blocks.jsonl"
        self.recovered_partial_write = False

    @staticmethod
    def create(directory: str | os.PathLike, genesis: Dict[str, Any]) -> "BlockStore":
        store = BlockStore(directory)
        store.dir.mkdir(parents=True, exist_ok=True)
        if store.genesis_path.exists():
            raise FileExistsError(f"{store.genesis_path} already exists")
        store.genesis_path.write_text(json.dumps(genesis, sort_keys=True))
        store.blocks_path.touch()
        return store

    def append(self, block: Block) -> None:
        with open(self.blocks_path, "ab") as f:
            f.write(json.dumps(block.to_dict(), sort_keys=True).encode() + b"\n")
            f.flush()
            os.fsync(f.fileno())

    def save(self, chain: Chain, start: Optional[int] = None) -> int:
        """Append the blocks of ``chain`` that are not stored yet.  Returns how many."""
        have = sum(1 for _ in open(self.blocks_path, "rb")) if start is None else start
        for b in chain.blocks[have:]:
            self.append(b)
        return len(chain.blocks) - have

    def genesis(self) -> Dict[str, Any]:
        return json.loads(self.genesis_path.read_text())

    def load(self) -> Chain:
        chain = Chain(self.genesis())
        raw = self.blocks_path.read_bytes()
        good = 0
        for line in raw.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                break                                  # torn final write
            try:
                block = Block.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError):
                break
            chain.add_block(block)                     # raises InvalidBlock if the file was tampered with
            good += len(line)
        if good < len(raw):
            self.recovered_partial_write = True
            with open(self.blocks_path, "r+b") as f:
                f.truncate(good)
        return chain
