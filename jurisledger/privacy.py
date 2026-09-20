"""EXPERIMENTAL: hide individual amounts, still prove the total.

A public ledger of every payment is a surveillance machine unless amounts can be
hidden.  Pedersen commitments (Pedersen 1991) are additively homomorphic:

    commit(a, r) * commit(b, s) = commit(a + b, r + s)      (mod p)

so anyone can multiply the public commitments of a sector's payments and check
them against a *single* opened total -- the statistics office learns the sector
sum, the public learns it is honest, and nobody sees an individual payment.

The group is the 2048-bit MODP group 14 of RFC 3526 (a safe prime p = 2q + 1);
commitments live in the order-q subgroup of quadratic residues.  ``h`` is derived
by hashing, so nobody knows log_g(h) -- which is what makes commitments binding.

NOT PRODUCTION CRYPTOGRAPHY.  Missing on purpose: range proofs (without them a
cheater can commit to a negative amount; Bulletproofs fix this), constant-time
arithmetic, and an elliptic-curve group for speed.  This module exists to make
the idea runnable and testable.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Iterable, List, Tuple

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
Q = (P - 1) // 2
G = 4                                   # 2^2: a generator of the quadratic-residue subgroup


def _derive_h() -> int:
    seed, out, counter = b"jurisledger/pedersen/h/v1", b"", 0
    while len(out) < 256:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return pow(int.from_bytes(out[:256], "big") % P, 2, P)   # squaring lands in the subgroup


H = _derive_h()


@dataclass(frozen=True)
class Opening:
    amount: int
    blinding: int


def commit(amount: int, blinding: int | None = None) -> Tuple[int, Opening]:
    """Returns (commitment, opening).  Publish the first, keep the second."""
    r = secrets.randbelow(Q) if blinding is None else blinding % Q
    return (pow(G, amount % Q, P) * pow(H, r, P)) % P, Opening(amount, r)


def verify_opening(commitment: int, opening: Opening) -> bool:
    return commitment == (pow(G, opening.amount % Q, P) * pow(H, opening.blinding, P)) % P


def combine(commitments: Iterable[int]) -> int:
    acc = 1
    for c in commitments:
        acc = (acc * c) % P
    return acc


def aggregate_opening(openings: List[Opening]) -> Opening:
    """What the parties (or a threshold of them) reveal: the total, never the parts."""
    return Opening(sum(o.amount for o in openings), sum(o.blinding for o in openings) % Q)
