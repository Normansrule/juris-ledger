"""Threshold-encrypted contract vault.

`ContractVault` (contracts.py) refuses reads without an on-chain receipt, but whoever runs it
holds every restricted contract in plain text: one subpoena, one insider or one breach and
they are all out.  This vault removes that single point:

    prose --AES-256-GCM(data key)--> ciphertext            (stored anywhere; useless alone)
    data key --Shamir k-of-n--> n shares, each encrypted to one custodian's own key

A custodian (in practice: a validator, a court registry, the statistics office) releases its
share to a reader only when the chain shows that reader is authorised for the contract and has
recorded an unspent VIEW receipt; the share travels encrypted to the reader's key.  With k
shares the reader rebuilds the data key and decrypts; the text is checked against the hash the
parties signed.  Therefore:

* the storage host, or anyone who steals the sealed file, learns nothing;
* any k-1 custodians, colluding, learn nothing (Shamir's scheme is information-theoretic);
* every read leaves a trace on the public ledger *before* it can happen;
* a custodian that returns a bad share is caught: anyone can check a share against public
  commitments to the sharing polynomial (Feldman's verifiable secret sharing);
* custodians can be replaced, and the threshold changed, WITHOUT the key ever being rebuilt and
  WITHOUT re-encrypting the text (proactive re-sharing; see ``reshare``).

Version 2 (current): the secret is a scalar s modulo the order L of the Ed25519 group, the AES key
is SHA-256 of s, and the dealer publishes C_j = a_j * B for each coefficient a_j of the sharing
polynomial, so a share (x, y) is valid exactly when y * B = sum_j C_j * x^j.  Version 1 files
(shares modulo 2^521 - 1, per-share hashes) still open.

Shamir, "How to share a secret", CACM 22(11), 1979.  Feldman, "A practical scheme for
non-interactive verifiable secret sharing", FOCS 1987.  Herzberg, Jarecki, Krawczyk and Yung,
"Proactive secret sharing", CRYPTO 1995.  Desmedt and Jajodia, "Redistributing secret shares to
new access structures", 1997.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .chain import Chain
from .contracts import prose_hash
from .crypto import KeyPair
from .ec import BASE, IDENTITY, L, Point
from .privacy import decrypt_note, encrypt_note

P = 2 ** 521 - 1          # version-1 field
VERSION = 2


class VaultError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Shamir secret sharing
# --------------------------------------------------------------------------- #
def _poly(secret: int, k: int, q: int) -> List[int]:
    return [secret % q] + [secrets.randbelow(q) for _ in range(k - 1)]


def _eval(coeffs: Sequence[int], x: int, q: int) -> int:
    return sum(c * pow(x, j, q) for j, c in enumerate(coeffs)) % q


def split(secret: int, n: int, k: int, q: int = P) -> List[Tuple[int, int]]:
    if not 1 <= k <= n:
        raise ValueError("need 1 <= k <= n")
    coeffs = _poly(secret, k, q)
    return [(x, _eval(coeffs, x, q)) for x in range(1, n + 1)]


def lagrange_at_zero(xs: Sequence[int], q: int = P) -> Dict[int, int]:
    """lambda_i such that f(0) = sum lambda_i f(x_i) for any polynomial of degree < len(xs)."""
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share")
    out = {}
    for xi in xs:
        num = den = 1
        for xj in xs:
            if xj != xi:
                num = num * (-xj) % q
                den = den * (xi - xj) % q
        out[xi] = num * pow(den, -1, q) % q
    return out


def combine(shares: Sequence[Tuple[int, int]], q: int = P) -> int:
    """Lagrange interpolation at zero."""
    lam = lagrange_at_zero([x for x, _ in shares], q)
    return sum(y * lam[x] for x, y in shares) % q


# -- Feldman commitments on Ed25519 --------------------------------------------- #
def commit_poly(coeffs: Sequence[int]) -> List[str]:
    return [(BASE * c).hex() if c else IDENTITY.hex() for c in coeffs]


def _point(h: str) -> Point:
    pt = Point.from_hex(h)
    if not pt.in_subgroup():
        raise VaultError("commitment is not in the prime-order subgroup")
    return pt


def public_share(commitments: Sequence[str], x: int) -> Point:
    """sum_j C_j * x^j: the point every valid share for x must match."""
    acc = IDENTITY
    for j, c in enumerate(commitments):
        e = pow(x, j, L)
        if e:
            acc = acc + _point(c) * e
    return acc


def share_valid(commitments: Sequence[str], x: int, y: int) -> bool:
    try:
        return 0 <= y < L and (BASE * y if y else IDENTITY) == public_share(commitments, x)
    except (VaultError, ValueError):
        return False


def key_from_secret(s: int) -> bytes:
    return hashlib.sha256(b"jurisledger/vault-key/v2" + (s % L).to_bytes(32, "little")).digest()


def _share_digest(contract_id: str, x: int, y: int) -> str:
    return hashlib.sha256(f"jurisledger/vault-share/v1:{contract_id}:{x}:{y}".encode()).hexdigest()


# --------------------------------------------------------------------------- #
# sealing and opening
# --------------------------------------------------------------------------- #
def seal(contract_id: str, prose: str, chain: Chain, custodians: List[str], threshold: int) -> Dict[str, Any]:
    """Encrypt a contract's text for the vault.  The text must be the one the parties signed."""
    c = chain.state.contracts.get(contract_id)
    if c is None:
        raise VaultError("unknown contract")
    if prose_hash(prose) != c["prose_hash"]:
        raise VaultError("text does not match the hash the parties signed")
    if len(set(custodians)) != len(custodians) or not 1 <= threshold <= len(custodians):
        raise VaultError("need distinct custodians and 1 <= threshold <= number of custodians")
    secret = 1 + secrets.randbelow(L - 1)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key_from_secret(secret)).encrypt(nonce, prose.encode(), contract_id.encode())
    coeffs = _poly(secret, threshold, L)
    return {
        "version": VERSION, "contract_id": contract_id, "prose_hash": c["prose_hash"], "threshold": threshold,
        "epoch": 0, "nonce": nonce.hex(), "ciphertext": ct.hex(), "custodians": list(custodians),
        "commitments": commit_poly(coeffs),
        "shares": {cust: encrypt_note(cust, {"contract_id": contract_id, "epoch": 0, "x": x, "y": format(_eval(coeffs, x, L), "x")})
                   for x, cust in enumerate(custodians, start=1)},
    }


def open_sealed(sealed: Dict[str, Any], reader: KeyPair, releases: List[str]) -> Tuple[str, List[str]]:
    """Combine released shares (each encrypted to ``reader``) and decrypt.  Returns the text and
    the list of custodians whose release was rejected as invalid."""
    cid, good, bad = sealed["contract_id"], [], []
    for blob in releases:
        try:
            note = decrypt_note(reader.secret_hex(), reader.address, blob)
            x, y = int(note["x"]), int(note["y"], 16)
        except Exception:  # noqa: BLE001 - garbage in a release is a bad release, never a crash
            bad.append("?")
            continue
        v2 = sealed.get("version", 1) >= 2
        ok = note.get("contract_id") == cid and (
            (note.get("epoch", 0) == sealed.get("epoch", 0) and share_valid(sealed["commitments"], x, y)) if v2
            else sealed.get("share_digests", {}).get(str(x)) == _share_digest(cid, x, y))
        if not ok:
            bad.append(note.get("custodian", "?"))
            continue
        if x not in {g[0] for g in good}:
            good.append((x, y))
    k = sealed["threshold"]
    if len(good) < k:
        raise VaultError(f"{len(good)} valid shares, {k} needed")
    if sealed.get("version", 1) >= 2:
        key = key_from_secret(combine(good[:k], L))
    else:
        key = combine(good[:k]).to_bytes(32, "big")
    try:
        prose = AESGCM(key).decrypt(bytes.fromhex(sealed["nonce"]), bytes.fromhex(sealed["ciphertext"]), cid.encode()).decode()
    except Exception:  # noqa: BLE001
        raise VaultError("decryption failed: the sealed file was altered") from None
    if prose_hash(prose) != sealed["prose_hash"]:
        raise VaultError("decrypted text does not match the signed hash")
    return prose, bad


# --------------------------------------------------------------------------- #
# custodians
# --------------------------------------------------------------------------- #
@dataclass
class Custodian:
    """Holds one share per sealed contract and releases it only against an on-chain receipt.

    ``journal``: a file where every release is appended and fsync'ed before the share leaves.
    Without it, a restarted custodian would forget which receipts it has already honoured and a
    single receipt could be spent again after every restart."""
    key: KeyPair
    journal: Optional[str] = None
    released: Dict[Tuple[str, str], int] = field(default_factory=dict)
    log: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.journal and os.path.exists(self.journal):
            with open(self.journal) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        break                                   # torn last line: that release never left
                    self.released[(e["contract_id"], e["reader"])] = e["receipt"]
                    self.log.append(e)

    @property
    def address(self) -> str:
        return self.key.address

    def release(self, sealed: Dict[str, Any], reader: str, chain: Chain) -> str:
        cid = sealed["contract_id"]
        if self.address not in sealed["shares"]:
            raise VaultError("this custodian holds no share of that contract")
        c = chain.state.contracts.get(cid)
        if c is None or c["prose_hash"] != sealed["prose_hash"]:
            raise VaultError("the sealed file does not match a contract on this ledger")
        if not chain.state.can_read(cid, reader):
            raise VaultError("the reader is not authorised for this contract on the ledger")
        receipts = sum(1 for e in chain.state.access_log
                       if e["contract_id"] == cid and e["accessor"] == reader and e["action"] == "VIEW")
        used = self.released.get((cid, reader), 0)
        if used >= receipts:
            raise VaultError("no unspent VIEW receipt on the ledger: the reader must record CONTRACT_ACCESS first")
        note = decrypt_note(self.key.secret_hex(), self.address, sealed["shares"][self.address])
        if note.get("contract_id") != cid or note.get("epoch", 0) != sealed.get("epoch", 0):
            raise VaultError("share was sealed for another contract or an earlier set of custodians")
        entry = {"contract_id": cid, "reader": reader, "height": chain.height, "receipt": used + 1}
        if self.journal:                                        # durable before the share leaves
            with open(self.journal, "a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
        self.released[(cid, reader)] = used + 1
        self.log.append(entry)
        return encrypt_note(reader, {**note, "custodian": self.address})


    # -- proactive re-sharing ---------------------------------------------------- #
    def _own_share(self, sealed: Dict[str, Any]) -> Tuple[int, int]:
        if self.address not in sealed["shares"]:
            raise VaultError("this custodian holds no share of that contract")
        note = decrypt_note(self.key.secret_hex(), self.address, sealed["shares"][self.address])
        x, y = int(note["x"]), int(note["y"], 16)
        if note.get("contract_id") != sealed["contract_id"] or not share_valid(sealed["commitments"], x, y):
            raise VaultError("own share does not match the public commitments")
        return x, y

    def contribute(self, sealed: Dict[str, Any], new_custodians: List[str], new_threshold: int) -> Dict[str, Any]:
        """Re-share MY share: a fresh polynomial whose value at zero is my share, one point of it
        encrypted to each new custodian, and public commitments to it.  Reveals nothing about my
        share to anyone holding fewer than ``new_threshold`` of the points."""
        x, y = self._own_share(sealed)
        g = _poly(y, new_threshold, L)
        epoch = sealed["epoch"] + 1
        self.log.append({"contract_id": sealed["contract_id"], "reshare_to_epoch": epoch, "x": x})
        return {"from": self.address, "x": x, "epoch": epoch, "commitments": commit_poly(g),
                "subshares": {addr: encrypt_note(addr, {"contract_id": sealed["contract_id"], "epoch": epoch, "from_x": x,
                                                        "to_x": j, "v": format(_eval(g, j, L), "x")})
                              for j, addr in enumerate(new_custodians, start=1)}}

    def adopt(self, sealed: Dict[str, Any], contributions: List[Dict[str, Any]], new_custodians: List[str],
              new_threshold: int) -> Tuple[Optional[str], List[str]]:
        """As a NEW custodian: check every sub-share sent to me against its sender's commitments,
        and combine the valid ones into my new share.  Returns (my share sealed to me, or None if
        any sub-share was bad; the senders I accuse)."""
        j = new_custodians.index(self.address) + 1
        accused, vals = [], {}
        for c in contributions:
            try:
                note = decrypt_note(self.key.secret_hex(), self.address, c["subshares"][self.address])
                v = int(note["v"], 16)
                ok = (note["contract_id"] == sealed["contract_id"] and note["epoch"] == c["epoch"] and note["from_x"] == c["x"]
                      and note["to_x"] == j and share_valid(c["commitments"], j, v))
            except Exception:  # noqa: BLE001
                ok = False
            if ok:
                vals[c["x"]] = v
            else:
                accused.append(c["from"])
        if accused:
            return None, accused
        lam = lagrange_at_zero(list(vals), L)
        y = sum(lam[x] * v for x, v in vals.items()) % L
        epoch = sealed["epoch"] + 1
        return encrypt_note(self.address, {"contract_id": sealed["contract_id"], "epoch": epoch, "x": j, "y": format(y, "x")}), []


def contribution_valid(sealed: Dict[str, Any], c: Dict[str, Any], new_threshold: int) -> bool:
    """Public check: the re-shared polynomial really starts at the sender's share, and has the
    right degree.  Anyone can run it; no secrets needed."""
    try:
        return (c["epoch"] == sealed["epoch"] + 1 and len(c["commitments"]) == new_threshold
                and sealed["custodians"][c["x"] - 1] == c["from"]
                and _point(c["commitments"][0]) == public_share(sealed["commitments"], c["x"]))
    except (VaultError, ValueError, KeyError, IndexError, TypeError):
        return False


def reshare(sealed: Dict[str, Any], old: List["Custodian"], new: List["Custodian"], new_threshold: int,
            log=lambda m: None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Move a sealed contract to a new set of custodians and threshold.  The text is not
    re-encrypted and the key is never rebuilt anywhere; old shares stop matching the new file.

    1. each participating old custodian publishes a contribution (``contribute``);
    2. contributions whose constant term does not match the sender's public share are dropped;
    3. each new custodian checks its sub-shares and accuses senders of bad ones (``adopt``);
       accused senders are dropped and the round repeats with the rest;
    4. if at least the OLD threshold of contributions survive, the new public commitments are
       the Lagrange combination of theirs; otherwise nothing changes.
    """
    if sealed.get("version", 1) < 2:
        raise VaultError("re-sharing needs a version-2 sealed file (verifiable shares)")
    addrs = [c.address for c in new]
    if len(set(addrs)) != len(addrs) or not 1 <= new_threshold <= len(addrs):
        raise VaultError("need distinct new custodians and 1 <= threshold <= their number")
    contributions, excluded = [], {}
    for o in old:
        try:
            contributions.append(o.contribute(sealed, addrs, new_threshold))
        except VaultError as err:
            excluded[o.address] = str(err)
    for c in list(contributions):
        if not contribution_valid(sealed, c, new_threshold):
            excluded[c["from"]] = "its contribution does not start from its own committed share"
            contributions.remove(c)
    while True:
        if len(contributions) < sealed["threshold"]:
            raise VaultError(f"only {len(contributions)} valid contributions, {sealed['threshold']} needed; nothing changed")
        contributions = contributions[:]
        shares, accused = {}, set()
        for n in new:
            note, acc = n.adopt(sealed, contributions, addrs, new_threshold)
            shares[n.address] = note
            accused |= set(acc)
        if not accused:
            break
        for a in accused:
            excluded[a] = "sent a sub-share that does not match its commitments"
        contributions = [c for c in contributions if c["from"] not in accused]
        log(f"dropped {len(accused)} contributor(s); retrying with {len(contributions)}")
    lam = lagrange_at_zero([c["x"] for c in contributions], L)
    commitments = []
    for m in range(new_threshold):
        acc = IDENTITY
        for c in contributions:
            acc = acc + _point(c["commitments"][m]) * lam[c["x"]]
        commitments.append(acc.hex())
    new_sealed = {**sealed, "epoch": sealed["epoch"] + 1, "threshold": new_threshold, "custodians": addrs,
                  "commitments": commitments, "shares": shares}
    return new_sealed, {"contributors": [c["from"] for c in contributions], "excluded": excluded}


def collect(sealed: Dict[str, Any], reader: KeyPair, custodians: List[Custodian], chain: Chain) -> Tuple[str, Dict[str, str]]:
    """Ask every custodian; open with whatever valid shares come back.  Returns (text, refusals)."""
    releases, refusals = [], {}
    for cu in custodians:
        try:
            releases.append(cu.release(sealed, reader.address, chain))
        except VaultError as err:
            refusals[cu.address] = str(err)
    prose, bad = open_sealed(sealed, reader, releases)
    for b in bad:
        refusals[b] = "returned an invalid share"
    return prose, refusals


def sealed_bytes(sealed: Dict[str, Any]) -> int:
    return len(json.dumps(sealed))
