"""Confidential amounts: hide each payment, still prove totals and non-negativity.

A public ledger of every payment is a surveillance machine unless amounts can be
hidden.  Pedersen commitments (Pedersen 1991) on the Ed25519 curve are additively
homomorphic:

    commit(a, r) + commit(b, s) = commit(a + b, r + s)

so anyone can add up a sector's public commitments and check them against a *single*
opened total -- the statistics office learns the sum, the public learns it is honest,
nobody sees an individual payment.

Homomorphic commitments alone are unsafe: a payer could commit to a negative amount
and mint money.  :func:`range_proof` closes that: a bit-decomposition proof that a
commitment hides a value in [0, 2**BITS), one Schnorr OR-proof per bit (Cramer,
Damgard & Schoenmakers 1994), non-interactive by Fiat-Shamir.

Honest costs: a 32-bit proof is about 6 kB and takes roughly 0.3 s to make or verify
in pure Python.  Bulletproofs would be ~700 bytes and far faster; the guarantee is
the same.  ``H`` is derived by hashing so nobody knows log_G(H), which is what makes
commitments binding.  Arithmetic is not constant-time (see ec.py).
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, List

from .ec import BASE, IDENTITY, L, Point, hash_to_point

G = BASE
H = hash_to_point(b"jurisledger/pedersen/h/v2")
Q = L                                     # group order: blindings live in Z_Q
BITS = 32
MAX_HIDDEN = 2 ** BITS - 1               # 42,949,672.95 in cents


@dataclass(frozen=True)
class Opening:
    amount: int
    blinding: int


def commit(amount: int, blinding: int | None = None):
    """Returns (commitment, opening).  Publish the first, keep the second."""
    r = secrets.randbelow(Q) if blinding is None else blinding % Q
    return G * (amount % Q) + H * r, Opening(amount, r)


def verify_opening(commitment: Point, opening: Opening) -> bool:
    return commitment == G * (opening.amount % Q) + H * (opening.blinding % Q)


def combine(commitments: Iterable[Point]) -> Point:
    acc = IDENTITY
    for c in commitments:
        acc = acc + c
    return acc


def subtract(c_total: Point, c_part: Point) -> Point:
    """Commitment to (a - b) from commitments to a and b."""
    return c_total - c_part


def aggregate_opening(openings: List[Opening]) -> Opening:
    """What the parties (or a threshold of them) reveal: the total, never the parts."""
    return Opening(sum(o.amount for o in openings), sum(o.blinding for o in openings) % Q)


def commitment_hex(c: Point) -> str:
    return c.hex()


def commitment_from_hex(s: str) -> Point:
    pt = Point.from_hex(s)
    if not pt.in_subgroup():
        raise ValueError("commitment is not in the prime-order subgroup")
    return pt


# --------------------------------------------------------------------------- #
# Range proofs
# --------------------------------------------------------------------------- #
def _challenge(*points: Point) -> int:
    data = b"jurisledger/rangeproof/v2" + b"".join(p.encode() for p in points)
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % Q


def range_proof(opening: Opening) -> Dict:
    """Prove that ``commit(opening)`` hides a value in [0, 2**BITS).  Prover side."""
    v, r = opening.amount, opening.blinding % Q
    if not 0 <= v <= MAX_HIDDEN:
        raise ValueError("value out of provable range")
    blindings = [secrets.randbelow(Q) for _ in range(BITS - 1)]
    blindings.append((r - sum(blindings)) % Q)              # bit blindings sum to r
    out = []
    for i in range(BITS):
        b, ri = (v >> i) & 1, blindings[i]
        Gi = G * (1 << i)
        Ci = (Gi if b else IDENTITY) + H * ri
        y = [Ci, Ci - Gi]                                    # y[b] == H * ri
        c_fake, s_fake = secrets.randbelow(Q), secrets.randbelow(Q)
        t_fake = H * s_fake - y[1 - b] * c_fake
        k = secrets.randbelow(Q)
        t_real = H * k
        t = [t_real, t_fake] if b == 0 else [t_fake, t_real]
        c = _challenge(Ci, t[0], t[1])
        c_real = (c - c_fake) % Q
        s_real = (k + c_real * ri) % Q
        cs = [c_real, c_fake] if b == 0 else [c_fake, c_real]
        ss = [s_real, s_fake] if b == 0 else [s_fake, s_real]
        out.append([Ci.hex(), hex(cs[0]), hex(cs[1]), hex(ss[0]), hex(ss[1])])
    return {"bits": out}


def verify_range_proof(commitment: Point, proof: Dict) -> bool:
    try:
        bits = proof["bits"]
        if len(bits) != BITS:
            return False
        product = IDENTITY
        for i, (ch, c0h, c1h, s0h, s1h) in enumerate(bits):
            Ci = Point.from_hex(ch)
            c0, c1, s0, s1 = (int(x, 16) for x in (c0h, c1h, s0h, s1h))
            if not all(0 <= x < Q for x in (c0, c1, s0, s1)):
                return False
            Gi = G * (1 << i)
            y0, y1 = Ci, Ci - Gi
            t0 = H * s0 - y0 * c0
            t1 = H * s1 - y1 * c1
            if (c0 + c1) % Q != _challenge(Ci, t0, t1):
                return False
            product = product + Ci
        return product == commitment
    except (KeyError, TypeError, ValueError, IndexError):
        return False
