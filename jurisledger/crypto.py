"""Cryptographic primitives used everywhere else in JurisLedger.

* Canonical JSON serialisation (so that every node hashes identical bytes).
* Secure Hash Algorithm 256 (SHA-256) helpers.
* Ed25519 digital signatures (Bernstein et al. 2012; RFC 8032) via the
  ``cryptography`` package.
* A Merkle tree with inclusion proofs (Merkle 1987) using the leaf/node domain
  separation from RFC 6962 (Certificate Transparency).

Nothing here is novel cryptography -- on purpose.  The framework composes
well-studied primitives; see docs/REFERENCES.md.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, List, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# --------------------------------------------------------------------------- #
# Serialisation and hashing
# --------------------------------------------------------------------------- #
def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding: sorted keys, no whitespace, UTF-8.

    Only ints, strings, bools, None, lists and dicts are allowed.  Floats are
    rejected because their textual form is not portable across platforms --
    all money amounts in JurisLedger are integers (minor currency units, "cents").
    """
    _reject_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _reject_floats(obj: Any) -> None:
    if isinstance(obj, float):
        raise TypeError("floats are not allowed in canonical data; use integer minor units")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError("canonical dict keys must be strings")
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    return sha256_hex(canonical(obj))


# --------------------------------------------------------------------------- #
# Keys and signatures
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 key pair.  ``address`` is the hex-encoded 32-byte public key."""

    _private: Ed25519PrivateKey
    address: str

    @staticmethod
    def generate() -> "KeyPair":
        return KeyPair._from_private(Ed25519PrivateKey.generate())

    @staticmethod
    def from_seed(seed: str) -> "KeyPair":
        """Deterministic key from a text seed.  FOR SIMULATIONS AND TESTS ONLY."""
        raw = hashlib.sha256(("jurisledger-seed:" + seed).encode()).digest()
        return KeyPair._from_private(Ed25519PrivateKey.from_private_bytes(raw))

    @staticmethod
    def _from_private(priv: Ed25519PrivateKey) -> "KeyPair":
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return KeyPair(priv, pub.hex())

    def sign(self, message: bytes) -> str:
        return self._private.sign(message).hex()


def verify(address: str, message: bytes, signature_hex: str) -> bool:
    """True iff ``signature_hex`` is a valid Ed25519 signature by ``address``."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(address))
        pub.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


# --------------------------------------------------------------------------- #
# Merkle tree
# --------------------------------------------------------------------------- #
_LEAF = b"\x00"
_NODE = b"\x01"
EMPTY_ROOT = sha256_hex(b"jurisledger-empty-merkle")


def _leaf_hash(item_hex: str) -> bytes:
    return hashlib.sha256(_LEAF + bytes.fromhex(item_hex)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE + left + right).digest()


def _levels(items: Sequence[str]) -> List[List[bytes]]:
    level = [_leaf_hash(i) for i in items]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                # An unpaired node is promoted unchanged.  (Duplicating it, as
                # Bitcoin does, permits the CVE-2012-2459 mutation.)
                nxt.append(level[i])
        level = nxt
        levels.append(level)
    return levels


def merkle_root(items: Sequence[str]) -> str:
    """Merkle root over a list of hex digests (e.g. transaction ids)."""
    if not items:
        return EMPTY_ROOT
    return _levels(items)[-1][0].hex()


def merkle_proof(items: Sequence[str], index: int) -> List[Tuple[str, str]]:
    """Inclusion proof for ``items[index]`` as a list of (side, sibling_hex)."""
    if not 0 <= index < len(items):
        raise IndexError("leaf index out of range")
    proof: List[Tuple[str, str]] = []
    idx = index
    for level in _levels(items)[:-1]:
        sibling = idx ^ 1
        if sibling < len(level):
            proof.append(("L" if sibling < idx else "R", level[sibling].hex()))
        idx //= 2
    return proof


def verify_merkle_proof(item_hex: str, proof: Sequence[Tuple[str, str]], root_hex: str) -> bool:
    acc = _leaf_hash(item_hex)
    for side, sibling in proof:
        sib = bytes.fromhex(sibling)
        acc = _node_hash(sib, acc) if side == "L" else _node_hash(acc, sib)
    return acc.hex() == root_hex
