"""Minimal arithmetic on the Ed25519 curve, for commitments and range proofs.

Twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 over GF(2^255 - 19), extended
coordinates (Hisil et al. 2008), point encoding as in RFC 8032.  Pure Python, not
constant-time: fine for verifying public proofs, NOT for handling long-term secrets
on a machine an attacker can measure.  Signatures still come from the ``cryptography``
package; this module only exists because that package exposes no point arithmetic.
"""
from __future__ import annotations

import hashlib
from typing import Tuple

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493       # order of the prime-order subgroup
D = (-121665 * pow(121666, P - 2, P)) % P
_I = pow(2, (P - 1) // 4, P)                                  # sqrt(-1)


class Point:
    __slots__ = ("X", "Y", "Z", "T")

    def __init__(self, X: int, Y: int, Z: int, T: int):
        self.X, self.Y, self.Z, self.T = X, Y, Z, T

    # -- group law ---------------------------------------------------------- #
    def __add__(self, o: "Point") -> "Point":
        A = (self.Y - self.X) * (o.Y - o.X) % P
        B = (self.Y + self.X) * (o.Y + o.X) % P
        C = 2 * self.T * o.T * D % P
        Dd = 2 * self.Z * o.Z % P
        E, F, G, H = B - A, Dd - C, Dd + C, B + A
        return Point(E * F % P, G * H % P, F * G % P, E * H % P)

    def double(self) -> "Point":
        return self + self

    def __neg__(self) -> "Point":
        return Point((-self.X) % P, self.Y, self.Z, (-self.T) % P)

    def __sub__(self, o: "Point") -> "Point":
        return self + (-o)

    def __mul__(self, k: int) -> "Point":
        return self._mul(k % L)

    def _mul(self, k: int) -> "Point":
        r, q = IDENTITY, self
        while k:
            if k & 1:
                r = r + q
            q = q.double()
            k >>= 1
        return r

    __rmul__ = __mul__

    def __eq__(self, o: object) -> bool:
        return isinstance(o, Point) and (self.X * o.Z - o.X * self.Z) % P == 0 and (self.Y * o.Z - o.Y * self.Z) % P == 0

    def __hash__(self) -> int:
        return hash(self.encode())

    # -- encoding ----------------------------------------------------------- #
    def affine(self) -> Tuple[int, int]:
        zi = pow(self.Z, P - 2, P)
        return self.X * zi % P, self.Y * zi % P

    def encode(self) -> bytes:
        x, y = self.affine()
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    def hex(self) -> str:
        return self.encode().hex()

    def in_subgroup(self) -> bool:
        """Prime order and not the identity.  Uses the unreduced multiply: L * P must be
        computed literally, since L reduces to 0 modulo itself."""
        return self._mul(L) == IDENTITY and self != IDENTITY

    @staticmethod
    def decode(data: bytes) -> "Point":
        if len(data) != 32:
            raise ValueError("bad point length")
        y = int.from_bytes(data, "little")
        sign = y >> 255
        y &= (1 << 255) - 1
        if y >= P:
            raise ValueError("bad point")
        x = _recover_x(y, sign)
        return Point(x, y, 1, x * y % P)

    @staticmethod
    def from_hex(s: str) -> "Point":
        return Point.decode(bytes.fromhex(s))


def _recover_x(y: int, sign: int) -> int:
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    if x2 == 0:
        if sign:
            raise ValueError("bad point")
        return 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _I % P
    if (x * x - x2) % P != 0:
        raise ValueError("not on curve")
    if x & 1 != sign:
        x = P - x
    return x


IDENTITY = Point(0, 1, 1, 0)
_By = 4 * pow(5, P - 2, P) % P
BASE = Point(_recover_x(_By, 0), _By, 1, _recover_x(_By, 0) * _By % P)


def hash_to_point(label: bytes) -> Point:
    """Try-and-increment hash to a point of prime order.  Nobody knows its discrete log."""
    counter = 0
    while True:
        y = int.from_bytes(hashlib.sha512(label + counter.to_bytes(4, "big")).digest()[:32], "little") % P
        try:
            x = _recover_x(y, 0)
        except ValueError:
            counter += 1
            continue
        pt = Point(x, y, 1, x * y % P) * 8                  # clear the cofactor
        if pt != IDENTITY:
            return pt
        counter += 1
