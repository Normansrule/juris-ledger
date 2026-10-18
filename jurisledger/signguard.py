"""A durable signing journal: an honest validator never signs two values at one step.

Byzantine fault tolerance assumes honest validators never sign conflicting consensus
messages.  A validator that forgets what it signed (a crash, a restart, a second process
on the same key) can break that assumption without any malice: before v0.26 a restarted
validator could precommit block A, restart, and precommit block B at the same height and
round - both signatures valid, which is exactly the evidence that gets a validator removed.

The guard keeps the last signed position ``(height, round, step)`` and value on disk and
enforces, before every signature:

* a strictly later position may be signed (and is written to disk, with fsync, *first*);
* the *same* position may be re-signed only for the *same* value (that is the same vote);
* anything earlier, or a different value at the same position, is refused.

It also remembers the last non-nil PRECOMMIT, which is the Tendermint lock: a restarted
validator resumes locked on the block it precommitted rather than free to prevote another.

The design follows Tendermint / CometBFT's ``priv_validator_state.json``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

STEPS = {"PROPOSAL": 1, "PREVOTE": 2, "PRECOMMIT": 3, "VOTE": 3}
FORMAT = "jurisledger/sign-state/v1"


class DoubleSignRefused(RuntimeError):
    """The journal says this signature could conflict with one already given."""


class CorruptSignState(RuntimeError):
    """The journal exists but cannot be read; signing would be guesswork."""


def on_corrupt_journal(path: Path, raw: bytes) -> Optional[Dict[str, Any]]:
    """Decide what a validator does when its signing journal is unreadable.

    Return a state dict to continue from, or raise to refuse to start.

    Default: refuse (fail closed).  A torn or edited journal means we no longer know what
    this key has signed, so any signature could be a double-sign.  The operator must
    investigate and either restore the file from backup or delete it *after* making sure
    the network has moved past every height this validator might have voted on
    (see docs/DEPLOY.md, "Signing journal").

    Alternative policies an operator might prefer (each is a trade-off):
    * skip ahead: return {"height": <network height + 1>, ...} fetched from peers - stays
      live, but trusts peers about where we were;
    * quarantine: rename the file and start as a non-signing observer until the next height.
    """
    raise CorruptSignState(
        f"{path} is unreadable ({len(raw)} bytes). Refusing to sign: this validator can no longer prove "
        f"it has not already voted. Restore it from backup, or delete it only once the network has "
        f"finalised beyond the last height this key could have signed.")


@dataclass
class SignGuard:
    path: Optional[Path] = None             # None: in memory only (simulations)
    height: int = 0
    round: int = -1
    step: int = 0
    value: Optional[str] = None
    signature: str = ""
    lock_height: int = 0                    # the last non-nil precommit = the Tendermint lock
    lock_round: int = -1
    lock_value: Optional[str] = None
    refused: int = 0

    @staticmethod
    def open(path: Path) -> "SignGuard":
        path = Path(path)
        if not path.exists():
            g = SignGuard(path)
            g._save()
            return g
        raw = path.read_bytes()
        try:
            d = json.loads(raw)
            if d.get("format") != FORMAT:
                raise ValueError("unknown format")
            g = SignGuard(path, int(d["height"]), int(d["round"]), int(d["step"]), d.get("value"),
                          str(d.get("signature", "")), int(d.get("lock_height", 0)), int(d.get("lock_round", -1)),
                          d.get("lock_value"))
        except (ValueError, KeyError, TypeError):
            d = on_corrupt_journal(path, raw)
            g = SignGuard(path, **{k: v for k, v in (d or {}).items() if k in SignGuard.__dataclass_fields__ and k != "path"})
        return g

    # -- the rule ----------------------------------------------------------- #
    def position(self) -> Tuple[int, int, int]:
        return (self.height, self.round, self.step)

    def check_and_record(self, kind: str, height: int, round_: int, value: Optional[str],
                         sign: "callable") -> str:  # type: ignore[valid-type]
        """Return a signature for (kind, height, round, value), or raise DoubleSignRefused."""
        step = STEPS[kind]
        pos = (height, round_, step)
        if pos < self.position():
            self.refused += 1
            raise DoubleSignRefused(f"{kind} at {height}/{round_}: already signed up to {self.position()}")
        if pos == self.position():
            if value != self.value:
                self.refused += 1
                raise DoubleSignRefused(f"{kind} at {height}/{round_}: already signed a different value")
            if self.signature:
                return self.signature                       # the same vote again: harmless
        sig = sign()
        new = {"height": height, "round": round_, "step": step, "value": value, "signature": sig,
               "lock_height": self.lock_height, "lock_round": self.lock_round, "lock_value": self.lock_value}
        if step == 3 and value is not None:
            new.update(lock_height=height, lock_round=round_, lock_value=value)
        self._save(new)                     # on disk FIRST; if that fails, memory is untouched and nothing is released
        for k, v in new.items():            # (0.26 review: memory used to change first, so a failed write left a
            setattr(self, k, v)             #  cached signature that a retry would release with nothing on disk)
        return sig

    def lock_for(self, height: int) -> Tuple[int, Optional[str]]:
        return (self.lock_round, self.lock_value) if self.lock_height == height else (-1, None)

    def resume_round(self, height: int) -> int:
        return max(self.round, 0) if self.height == height else 0

    # -- durability --------------------------------------------------------- #
    def _save(self, fields: Optional[Dict[str, Any]] = None) -> None:
        if self.path is None:
            return
        d = {"format": FORMAT, "height": self.height, "round": self.round, "step": self.step, "value": self.value,
             "signature": self.signature, "lock_height": self.lock_height, "lock_round": self.lock_round,
             "lock_value": self.lock_value, **(fields or {})}
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        try:
            fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:                                   # some filesystems cannot fsync a directory
            pass
