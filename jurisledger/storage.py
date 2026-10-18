"""Durable, append-only block storage.

One directory: ``genesis.json`` plus ``blocks.jsonl`` (one finalised block per line).
Appends are flushed and fsync'ed before returning.  Opening a store re-audits every
block, so a file edited on disk is detected exactly like a forged block on the wire.
A half-written last line (power loss mid-append) is recognised, reported and cut off;
nothing finalised is lost because a block is only acknowledged after fsync.

Pruning (``compact``): a ledger grows forever, a validator's disk does not.  ``snapshot.json``
holds the certified state after some block H; ``blocks.jsonl`` then holds only the blocks
after H; the blocks up to H move, gzip-compressed, into ``archive/`` (or are dropped, if the
operator says so).  Every step is a write-to-temporary, fsync, rename, so a crash at any point
leaves a store that still opens: a snapshot newer than some lines of ``blocks.jsonl`` simply
makes those lines skipped.

Locking: a validator holds an exclusive lock on ``LOCK`` for as long as it runs, so a second
validator, or ``jurisledger prune``, cannot write the same store at the same time.  The
operating system releases the lock when the process dies, so a crash never leaves it stuck.
"""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import fcntl
except ImportError:                       # Windows: no advisory locks; WSL and Linux have them
    fcntl = None

from .block import Block
from .chain import Chain, InvalidBlock


class StoreBusy(Exception):
    pass


class CorruptStore(InvalidBlock):
    """A complete record in blocks.jsonl is damaged.  Nothing is truncated."""


class UntrustedSnapshot(InvalidBlock):
    """The snapshot's certificate cannot be tied to a trust anchor from outside the snapshot."""


ANCHOR_FORMAT = "jurisledger/anchor/v1"
ANCHOR_PREFIX = b"jurisledger/anchor/v1:"


class BlockStore:
    def __init__(self, directory: str | os.PathLike):
        self.dir = Path(directory)
        self.genesis_path, self.blocks_path = self.dir / "genesis.json", self.dir / "blocks.jsonl"
        self.snapshot_path, self.archive_dir = self.dir / "snapshot.json", self.dir / "archive"
        self.anchor_path = self.dir / "anchor.json"
        self.recovered_partial_write = False
        self._lock_fd: Optional[int] = None
        # Trust anchors for a snapshot whose certifiers are not the genesis validators.  They must come
        # from OUTSIDE the snapshot (v0.25.0 trusted the snapshot's own "certified_by" list: finding F04).
        self.trusted_validators: Optional[List[str]] = None   # operator-supplied (--trust-validators FILE)
        self.anchor_key: Any = None                            # a validator's KeyPair: signs anchor.json
        self.anchor_address: Optional[str] = None              # whose anchor.json signature we accept
        self.anchored_by = "genesis"                           # how the last load was anchored (reported)

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
        have = self.load().height if start is None else start
        new = [b for b in chain.blocks if b.header.height > have]
        for b in new:
            self.append(b)
        return len(new)

    # -- locking ------------------------------------------------------------ #
    def lock(self) -> None:
        """Take the store for this process.  Raises StoreBusy if another process has it."""
        if fcntl is None or self._lock_fd is not None:
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.dir / "LOCK", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise StoreBusy(f"another process (a running validator?) is using the store in {self.dir}") from None
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        self._lock_fd = fd

    def unlock(self) -> None:
        if self._lock_fd is not None:
            os.close(self._lock_fd)                     # closing releases the lock
            self._lock_fd = None

    # -- pruning ------------------------------------------------------------ #
    def _atomic_write(self, path: Path, data: bytes) -> None:
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(dfd)                               # make the rename itself durable
        finally:
            os.close(dfd)

    def snapshot(self) -> Optional[Dict[str, Any]]:
        return json.loads(self.snapshot_path.read_text()) if self.snapshot_path.exists() else None

    def install_snapshot(self, snapshot: Dict[str, Any], keep: List[Block], archive: List[Block],
                         certified_by: List[str], keep_archive: bool = True) -> None:
        """Replace everything up to the snapshot's height.  ``archive`` are the blocks being
        retired (written to archive/ first, so nothing is lost if the next step crashes)."""
        if archive and keep_archive:
            self.archive_dir.mkdir(exist_ok=True)
            lo, hi = archive[0].header.height, archive[-1].header.height
            name = self.archive_dir / f"blocks-{lo:09d}-{hi:09d}.jsonl.gz"
            self._atomic_write(name, gzip.compress(b"".join(
                json.dumps(b.to_dict(), sort_keys=True).encode() + b"\n" for b in archive)))
        # "certified_by" stays in the file for compatibility and inspection; it is NOT used as a trust anchor.
        self._atomic_write(self.snapshot_path, json.dumps({**snapshot, "certified_by": certified_by}, sort_keys=True).encode())
        if self.anchor_key is not None:
            self._write_anchor(snapshot, certified_by)
        self._atomic_write(self.blocks_path, b"".join(json.dumps(b.to_dict(), sort_keys=True).encode() + b"\n" for b in keep))

    def compact(self, keep_blocks: int, keep_archive: bool = True) -> Dict[str, Any]:
        """Prune so that only the last ``keep_blocks`` blocks stay in blocks.jsonl."""
        chain, vals_before = self._replay(record_validators=True)
        new_base = chain.height - keep_blocks
        if new_base <= chain.base_height:
            return {"pruned": 0, "height": chain.height, "base": chain.base_height}
        before = self.blocks_path.stat().st_size
        # the state after block new_base: replay up to it from whatever the store starts at
        partial = self._start_chain()
        for b in chain.blocks:
            if b.header.height > new_base:
                break
            partial.add_block(b)
        retired = [b for b in chain.blocks if b.header.height <= new_base]
        kept = [b for b in chain.blocks if b.header.height > new_base]
        self.install_snapshot(partial.make_snapshot(), kept, retired, vals_before[new_base], keep_archive)
        return {"pruned": len(retired), "height": chain.height, "base": new_base,
                "bytes_before": before, "bytes_after": self.blocks_path.stat().st_size}

    def archived(self) -> List[Path]:
        return sorted(self.archive_dir.glob("blocks-*.jsonl.gz")) if self.archive_dir.exists() else []

    def genesis(self) -> Dict[str, Any]:
        return json.loads(self.genesis_path.read_text())

    # -- trust anchors -------------------------------------------------------- #
    def _anchor_body(self, snapshot: Dict[str, Any], validators: List[str]) -> Dict[str, Any]:
        from .block import BlockHeader
        h = BlockHeader.from_dict(snapshot["header"])
        return {"format": ANCHOR_FORMAT, "chain_id": h.chain_id, "height": h.height, "header_hash": h.hash,
                "validators": list(validators)}

    def _write_anchor(self, snapshot: Dict[str, Any], validators: List[str]) -> None:
        from .crypto import canonical
        body = self._anchor_body(snapshot, validators)
        body["signer"] = self.anchor_key.address
        body["signature"] = self.anchor_key.sign(ANCHOR_PREFIX + canonical({k: v for k, v in body.items() if k != "signature"}))
        self._atomic_write(self.anchor_path, json.dumps(body, sort_keys=True).encode())

    def _anchor_validators(self, snap: Dict[str, Any]) -> Optional[List[str]]:
        """Validators from anchor.json, if it is signed by the key we were told to expect."""
        from .crypto import canonical, verify
        if not self.anchor_address or not self.anchor_path.exists():
            return None
        try:
            a = json.loads(self.anchor_path.read_text())
            want = self._anchor_body(snap, a["validators"])
            body = {k: v for k, v in a.items() if k != "signature"}
            if a.get("signer") != self.anchor_address or {k: v for k, v in body.items() if k != "signer"} != want:
                return None
            if not verify(self.anchor_address, ANCHOR_PREFIX + canonical(body), a["signature"]):
                return None
            return list(a["validators"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _archive_validators(self, genesis: Dict[str, Any], snap: Dict[str, Any]) -> Optional[List[str]]:
        """Replay the archive from genesis (every certificate checked, from the genesis set onward)
        up to the snapshot; return the set that certified the snapshot's block, or None."""
        from .block import BlockHeader
        base = BlockHeader.from_dict(snap["header"])
        files = self.archived()
        if not files:
            return None
        chain = Chain(genesis)
        try:
            for f in files:
                for line in gzip.decompress(f.read_bytes()).splitlines():
                    block = Block.from_dict(json.loads(line))
                    if block.header.height <= chain.height:
                        continue
                    if block.header.height > base.height:
                        break
                    before = list(chain.state.validators)
                    chain.add_block(block)
                    if block.header.height == base.height:
                        ok = block.header.hash == base.hash and chain.state.root() == base.state_root
                        return before if ok else None
        except (OSError, ValueError, KeyError, TypeError, InvalidBlock):
            return None
        return None

    def _start_chain(self) -> Chain:
        genesis, snap = self.genesis(), self.snapshot()
        self.anchored_by = "genesis"
        if not snap:
            return Chain(genesis)
        try:                                           # 1. the founding validators
            return Chain.from_snapshot(genesis, snap, genesis["validators"])
        except InvalidBlock as first:
            reason = str(first)
        # The set changed by vote before the snapshot.  Never trust the snapshot's own "certified_by".
        for how, vals in (("operator-supplied validator list", self.trusted_validators),     # 2.
                          ("anchor signed by this validator's key", self._anchor_validators(snap)),  # 3.
                          ("archive replayed from genesis", self._archive_validators(genesis, snap))):  # 4.
            if vals:
                try:
                    c = Chain.from_snapshot(genesis, snap, vals)
                except InvalidBlock as err:
                    reason = f"{how}: {err}"
                    continue
                self.anchored_by = how
                return c
        raise UntrustedSnapshot(
            f"the snapshot in {self.snapshot_path} is not certified by the genesis validators ({reason}), and no "
            f"independent trust anchor confirms the set that certified it. A snapshot cannot vouch for itself. "
            f"Supply the validator set you trust (--trust-validators FILE), keep the archive/ directory, or "
            f"re-sync from peers (when emptying the store, keep sign_state.json: it is what stops this validator "
            f"signing twice).")

    def _replay(self, record_validators: bool = False):
        chain = self._start_chain()
        vals = {chain.height: list(chain.state.validators)} if record_validators else None
        raw = self.blocks_path.read_bytes()
        good = 0
        lines = raw.splitlines(keepends=True)
        for n, line in enumerate(lines):
            if not line.endswith(b"\n"):
                break                                  # torn final write (only the last line can lack "\n")
            try:
                block = Block.from_dict(json.loads(line))
            except (ValueError, KeyError, TypeError):
                # Audit H7: a COMPLETE record that does not parse is damage, not a torn write.  v0.25.0
                # truncated here, silently discarding every valid block after it.  Fail closed instead.
                raise CorruptStore(f"{self.blocks_path}: record {n + 1} of {len(lines)} is damaged; "
                                   f"{len(lines) - n - 1} later records are intact and were NOT discarded. "
                                   f"Restore the file from a peer (jurisledger export) or backup. Keep sign_state.json: it is what stops "
                                   f"this validator signing twice.") from None
            if block.header.height <= chain.height:    # already covered by the snapshot (crash mid-prune)
                good += len(line)
                continue
            before = list(chain.state.validators)
            chain.add_block(block)                     # raises InvalidBlock if the file was tampered with
            if vals is not None:
                vals[block.header.height] = before     # the set that certified this block
            good += len(line)
        self._good, self._raw_len = good, len(raw)
        return (chain, vals) if record_validators else chain

    def load(self) -> Chain:
        chain = self._replay()
        if self._good < self._raw_len:
            self.recovered_partial_write = True
            with open(self.blocks_path, "r+b") as f:
                f.truncate(self._good)
        return chain
